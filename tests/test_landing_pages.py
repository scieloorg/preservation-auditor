from __future__ import annotations

import json
import logging
import tempfile
import unittest
from pathlib import Path

from preservation_auditor.database import Database
from preservation_auditor.doi_audit import DoiAuditor
from preservation_auditor.landing_pages import (
    LandingPageError,
    LandingPageGenerator,
    load_links,
)
from preservation_auditor.metrics import render_metrics


def record(title: str = "Dataset <seguro>") -> dict:
    return {
        "id": "10.48331/scielodata.abc123",
        "attributes": {
            "doi": "10.48331/scielodata.abc123", "isActive": True,
            "state": "findable", "titles": [{"title": title}],
            "creators": [{"name": "Autora & Autor"}],
            "descriptions": [{"descriptionType": "Abstract", "description": "Resumo"}],
            "rightsList": [{"rights": "CC BY 4.0"}],
            "contributors": [{"contributorType": "ContactPerson", "name": "Contato"}],
            "types": {"resourceTypeGeneral": "Dataset"},
            "publisher": "SciELO Data", "publicationYear": 2026,
        },
    }


def landing(_doi: str) -> dict:
    return {
        "http_status": 200, "final_url": "https://data.scielo.org/dataset.xhtml",
        "redirects": [], "insecure_redirect": False, "title": True,
        "creators": 1, "abstract": True, "license": True, "doi": True,
        "contact": True, "status": True,
    }


class LandingPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = Database(self.root / "audit.db")
        self.logger = logging.getLogger("landing-test-{}".format(id(self)))
        self.logger.addHandler(logging.NullHandler())
        DoiAuditor(self.database, self.logger).check(
            prefix="10.48331", workers=1, source=[record()], landing_fetcher=landing,
        )

    def test_generates_escaped_html_json_and_index(self) -> None:
        output = self.root / "public"
        result = LandingPageGenerator(self.database, self.logger).generate(
            output=output, links_config=None, contact="data@scielo.org",
        )
        page = output / "10.48331" / "scielodata.abc123" / "index.html"
        status = page.with_name("status.json")
        self.assertEqual(1, result["generated"])
        self.assertTrue((output / "index.html").is_file())
        self.assertIn("Dataset &lt;seguro&gt;", page.read_text(encoding="utf-8"))
        self.assertNotIn("Dataset <seguro>", page.read_text(encoding="utf-8"))
        self.assertEqual("pending", json.loads(status.read_text())["preservation"]["code"])
        metrics = render_metrics(self.database)
        self.assertIn("scielo_preservation_landings_generated 1.0", metrics)
        self.assertIn("scielo_preservation_landings_pending 1.0", metrics)

    def test_linked_baseline_reports_preserved_with_alerts(self) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """INSERT INTO integrity_baselines
                   (resource_id, relative_path, algorithm, checksum, size_bytes, created_at)
                   VALUES ('rid', 'aip.7z', 'sha256', ?, 1, '2026-01-01T00:00:00+00:00')""",
                ("a" * 64,),
            )
            connection.execute(
                """INSERT INTO baseline_events
                   (event_id, resource_id, aip_id, source, completed_at, registered_at)
                   VALUES ('event', 'rid', 'aip-id', 'archivematica',
                           '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')"""
            )
            for name in ("digitalocean", "minio", "wasabi"):
                connection.execute(
                    """INSERT INTO replica_verifications
                       (event_id, replica_name, bucket, object_key, size_bytes,
                        checksum_verified, verified_at)
                       VALUES ('event', ?, 'private', 'private', 1, 1,
                               '2026-01-01T00:00:00+00:00')""", (name,),
                )
        config = self.root / "links.json"
        config.write_text(json.dumps({"links": [{
            "doi": "10.48331/scielodata.abc123", "aip_id": "aip-id",
        }]}), encoding="utf-8")
        output = self.root / "public"
        LandingPageGenerator(self.database, self.logger).generate(
            output=output, links_config=config, contact="data@scielo.org",
        )
        public = json.loads((output / "10.48331" / "scielodata.abc123" / "status.json").read_text())
        self.assertEqual("preserved_with_alerts", public["preservation"]["code"])
        self.assertNotIn("bucket", json.dumps(public))
        self.assertNotIn("checksum", json.dumps(public))

    def test_rejects_duplicate_or_invalid_links(self) -> None:
        path = self.root / "links.json"
        path.write_text('{"links":[{"doi":"invalid","aip_id":"aip"}]}')
        with self.assertRaises(LandingPageError):
            load_links(path)

    def test_rejects_doi_path_traversal(self) -> None:
        path = self.root / "links.json"
        path.write_text(
            '{"links":[{"doi":"10.48331/../outside","aip_id":"aip"}]}'
        )
        with self.assertRaises(LandingPageError):
            load_links(path)

    def test_refuses_to_publish_empty_dataset_inventory(self) -> None:
        empty_database = Database(self.root / "empty.db")
        with self.assertRaisesRegex(LandingPageError, "doi_audit_not_available"):
            LandingPageGenerator(empty_database, self.logger).generate(
                output=self.root / "empty-public", links_config=None,
                contact="data@scielo.org",
            )


if __name__ == "__main__":
    unittest.main()
