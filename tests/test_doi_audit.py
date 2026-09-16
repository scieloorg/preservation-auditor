from __future__ import annotations

import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from preservation_auditor.database import Database
from preservation_auditor.doi_audit import (
    DoiAuditor,
    LandingMetadataParser,
    audit_doi,
    iter_datacite_dois,
)
from preservation_auditor.metrics import render_metrics


def doi_record(doi: str = "10.48331/scielodata.abc123") -> dict:
    return {
        "id": doi,
        "attributes": {
            "doi": doi, "isActive": True, "state": "findable",
            "titles": [{"title": "Dataset"}],
            "creators": [{"name": "Author"}],
            "descriptions": [{"descriptionType": "Abstract", "description": "Summary"}],
            "rightsList": [{"rights": "CC BY 4.0"}],
            "contributors": [{"contributorType": "ContactPerson", "name": "Contact"}],
            "types": {"resourceTypeGeneral": "Dataset"},
        },
    }


def valid_landing(_doi: str) -> dict:
    return {
        "http_status": 200, "final_url": "https://data.scielo.org/dataset.xhtml",
        "redirects": [], "insecure_redirect": False, "title": True,
        "creators": 1, "abstract": True, "license": True, "doi": True,
        "contact": True, "status": True,
    }


class DoiAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_complete_doi_passes(self) -> None:
        result = audit_doi(doi_record(), valid_landing)
        self.assertEqual("PASS", result.status.value)
        self.assertEqual([], result.evidence["errors"])

    def test_missing_required_metadata_fails(self) -> None:
        record = doi_record()
        record["attributes"]["descriptions"] = []
        record["attributes"]["contributors"] = []
        result = audit_doi(record, valid_landing)
        self.assertEqual("FAIL", result.status.value)
        self.assertIn("abstract", result.evidence["missing_datacite_fields"])
        self.assertIn("contact", result.evidence["missing_datacite_fields"])

    def test_unavailable_landing_is_unknown(self) -> None:
        result = audit_doi(
            doi_record(), lambda _doi: {"error": "DOI_LANDING_UNAVAILABLE"}
        )
        self.assertEqual("UNKNOWN", result.status.value)

    def test_insecure_redirect_is_warning(self) -> None:
        landing = valid_landing("")
        landing["insecure_redirect"] = True
        result = audit_doi(doi_record(), lambda _doi: landing)
        self.assertEqual("WARNING", result.status.value)
        self.assertIn("DOI_INSECURE_REDIRECT", result.evidence["warnings"])

    def test_component_doi_inherits_parent_minimum_metadata(self) -> None:
        parent = doi_record()["attributes"]
        component = doi_record("10.48331/scielodata.abc123/file01")
        component["attributes"]["descriptions"] = []
        component["attributes"]["contributors"] = []
        component["attributes"]["relatedIdentifiers"] = [{
            "relationType": "IsPartOf", "relatedIdentifierType": "DOI",
            "relatedIdentifier": "10.48331/scielodata.abc123",
        }]
        landing = valid_landing("")
        landing.update({"creators": 0, "abstract": False, "license": False,
                        "contact": False})
        result = audit_doi(component, lambda _doi: landing, parent)
        self.assertEqual("PASS", result.status.value)
        self.assertEqual("parent", result.evidence["field_sources"]["abstract"])
        self.assertEqual("parent", result.evidence["field_sources"]["contact"])

    def test_html_metadata_parser(self) -> None:
        parser = LandingMetadataParser()
        parser.feed(
            '<title>Dataset landing</title>'
            '<meta name="DC.title" content="Dataset">'
            '<meta name="DC.creator" content="Author">'
            '<link rel="license" href="https://creativecommons.org/licenses/by/4.0">'
            '<body>Support Published</body>'
        )
        self.assertEqual(["Dataset"], parser.meta["dc.title"])
        self.assertEqual(1, len(parser.licenses))
        self.assertEqual(["Dataset landing"], parser.titles)
        self.assertIn("Support", " ".join(parser.text))

    def test_datacite_pagination_uses_all_pages(self) -> None:
        pages = [
            {"data": [{"id": "one"}], "meta": {"totalPages": 2}},
            {"data": [{"id": "two"}], "meta": {"totalPages": 2}},
        ]
        with patch("preservation_auditor.doi_audit._open_json", side_effect=pages) as fetch:
            records = list(iter_datacite_dois("10.48331", page_size=1000))
        self.assertEqual(["one", "two"], [item["id"] for item in records])
        self.assertIn("page%5Bsize%5D=1000", fetch.call_args_list[0].args[0])

    def test_audit_persists_and_exports_metrics(self) -> None:
        database = Database(self.root / "audit.db")
        logger = logging.getLogger("doi-test-{}".format(id(self)))
        logger.addHandler(logging.NullHandler())
        records = [doi_record("10.48331/scielodata.one"), doi_record("10.48331/scielodata.two")]
        _, results, complete = DoiAuditor(database, logger).check(
            prefix="10.48331", workers=2, source=records,
            landing_fetcher=valid_landing,
        )
        self.assertTrue(complete)
        self.assertEqual(2, len(results))
        metrics = render_metrics(database)
        self.assertIn("scielo_preservation_dois_total 2.0", metrics)
        self.assertIn("scielo_preservation_dois_valid 2.0", metrics)
        self.assertIn("scielo_preservation_dois_last_run_ok 1.0", metrics)


if __name__ == "__main__":
    unittest.main()
