from __future__ import annotations

import hashlib
import json
import logging
import tempfile
import unittest
from pathlib import Path

from preservation_auditor.database import Database
from preservation_auditor.integrity import resource_id
from preservation_auditor.metrics import render_metrics
from preservation_auditor.replica_audit import ReplicaAuditor
from preservation_auditor.replicas import ReplicaEvidence, ReplicaVerificationError
from test_auto_baseline import replicas_config


class ReplicaAuditorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = Database(self.root / "audit.db")
        self.config = self.root / "replicas.json"
        self.config.write_text(json.dumps(replicas_config()), encoding="utf-8")
        self.logger = logging.getLogger("replica-audit-{}".format(id(self)))
        self.logger.addHandler(logging.NullHandler())
        self.checksum = hashlib.sha256(b"aip").hexdigest()
        replicas = [
            ReplicaEvidence(
                name=name,
                bucket="preservation-{}".format(name),
                object_key="aips/{}/aip.7z".format(name),
                size_bytes=3,
                checksum_verified=True,
            )
            for name in ("digitalocean", "minio", "wasabi")
        ]
        self.database.add_automatic_baseline(
            resource_id=resource_id("aip.7z"),
            relative_path="aip.7z",
            checksum=self.checksum,
            size_bytes=3,
            event_id="archivematica-aip-001",
            aip_id="aip-001",
            completed_at="2026-09-14T00:00:00+00:00",
            replicas=replicas,
        )

    @staticmethod
    def valid_verifier(targets, **kwargs):
        target = targets[0]
        return [ReplicaEvidence(
            target.name,
            target.bucket,
            kwargs["object_key"],
            kwargs["expected_size"],
            True,
        )]

    def test_all_registered_replicas_are_checked_and_persisted(self) -> None:
        run_id, results, complete = ReplicaAuditor(
            self.database, self.logger, verifier=self.valid_verifier
        ).check(self.config)

        self.assertTrue(complete)
        self.assertEqual(3, len(results))
        self.assertEqual({"PASS"}, {item.status.value for item in results})
        with self.database.connect() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM audit_results WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
        self.assertEqual(3, count)
        metrics = render_metrics(self.database)
        self.assertIn("scielo_preservation_replicas_valid 3.0", metrics)
        self.assertIn(
            'scielo_preservation_replicas_valid{replica="wasabi"} 1.0', metrics
        )
        self.assertIn("scielo_preservation_replicas_last_run_ok 1.0", metrics)

    def test_missing_changed_and_unavailable_are_reported_independently(self) -> None:
        def verifier(targets, **kwargs):
            name = targets[0].name
            if name == "digitalocean":
                raise ReplicaVerificationError("replica_not_found")
            if name == "minio":
                raise ReplicaVerificationError("replica_checksum_mismatch:minio")
            raise ReplicaVerificationError("replica_head_failed:wasabi:TimeoutError")

        _, results, complete = ReplicaAuditor(
            self.database, self.logger, verifier=verifier
        ).check(self.config)

        self.assertFalse(complete)
        self.assertEqual(
            {
                "REPLICA_MISSING",
                "REPLICA_CHECKSUM_MISMATCH",
                "REPLICA_CHECK_INCONCLUSIVE",
            },
            {item.error_code for item in results},
        )
        metrics = render_metrics(self.database)
        self.assertIn("scielo_preservation_replicas_missing 1.0", metrics)
        self.assertIn("scielo_preservation_replicas_changed 1.0", metrics)
        self.assertIn("scielo_preservation_replicas_unknown 1.0", metrics)
        self.assertIn("scielo_preservation_replicas_scan_complete 0.0", metrics)

    def test_configuration_bucket_mismatch_does_not_contact_s3(self) -> None:
        config = replicas_config()
        config["replicas"][0]["bucket"] = "another-bucket"
        self.config.write_text(json.dumps(config), encoding="utf-8")

        contacted = []

        def verifier(targets, **kwargs):
            contacted.append(targets[0].name)
            return self.valid_verifier(targets, **kwargs)

        _, results, complete = ReplicaAuditor(
            self.database, self.logger, verifier=verifier
        ).check(self.config)

        self.assertFalse(complete)
        self.assertIn("REPLICA_CONFIG_MISMATCH", {item.error_code for item in results})
        self.assertEqual(["minio", "wasabi"], contacted)


if __name__ == "__main__":
    unittest.main()
