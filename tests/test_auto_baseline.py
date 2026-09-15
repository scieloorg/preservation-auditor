from __future__ import annotations

import hashlib
import hmac
import json
import logging
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import Mock, patch

from preservation_auditor.auto_baseline import (
    AutoBaselineError,
    AutoBaselineJob,
    load_signed_receipt,
)
from preservation_auditor.database import Database
from preservation_auditor.metrics import render_metrics
from preservation_auditor.replicas import (
    ReplicaEvidence,
    ReplicaVerificationError,
    S3HeadClient,
    load_replica_targets,
    verify_replicas,
)


SIGNING_KEY = b"x" * 32


def signed_receipt(**overrides) -> dict:
    receipt = {
        "schema_version": 1,
        "event_id": "event-001",
        "aip_id": "aip-001",
        "ingest_status": "COMPLETED",
        "relative_path": "aip-001.7z",
        "object_key": "aips/aip-001.7z",
        "algorithm": "sha256",
        "checksum": hashlib.sha256(b"aip-content").hexdigest(),
        "size_bytes": len(b"aip-content"),
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    receipt.update(overrides)
    canonical = json.dumps(
        receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    receipt["signature"] = hmac.new(
        SIGNING_KEY, canonical, hashlib.sha256
    ).hexdigest()
    return receipt


def replicas_config() -> dict:
    return {
        "replicas": [
            {
                "name": name,
                "endpoint_url": "https://{}.example.test".format(name),
                "bucket": "preservation-{}".format(name),
                "region": "us-east-1",
                "access_key_env": "TEST_ACCESS_KEY",
                "secret_key_env": "TEST_SECRET_KEY",
            }
            for name in ("digitalocean", "minio", "wasabi")
        ]
    }


class AutoBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "aips"
        self.root.mkdir()
        (self.root / "aip-001.7z").write_bytes(b"aip-content")
        self.receipt_path = self.base / "receipt.json"
        self.receipt_path.write_text(
            json.dumps(signed_receipt()), encoding="utf-8"
        )
        self.config_path = self.base / "replicas.json"
        self.config_path.write_text(json.dumps(replicas_config()), encoding="utf-8")
        self.database = Database(self.base / "state" / "audit.db")
        self.logger = logging.getLogger("auto-baseline-{}".format(id(self)))
        self.logger.addHandler(logging.NullHandler())

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def verifier(targets, *, object_key, expected_size, expected_checksum):
        return [
            ReplicaEvidence(
                target.name,
                target.bucket,
                object_key,
                expected_size,
                True,
            )
            for target in targets
        ]

    def run_job(self):
        with patch.dict(
            "os.environ", {"TEST_RECEIPT_KEY": SIGNING_KEY.decode("utf-8")}
        ):
            return AutoBaselineJob(
                self.database, self.logger, replica_verifier=self.verifier
            ).run(
                receipt_path=self.receipt_path,
                aip_root=self.root,
                replicas_config=self.config_path,
                signing_key_env="TEST_RECEIPT_KEY",
                max_receipt_age_seconds=86400,
            )

    def test_registers_only_after_all_validations_and_runs_integrity(self) -> None:
        result = self.run_job()

        self.assertTrue(result["baseline_created"])
        self.assertTrue(result["integrity_conforming"])
        self.assertEqual(
            ["digitalocean", "minio", "wasabi"], result["replicas_verified"]
        )
        with self.database.connect() as connection:
            event_count = connection.execute(
                "SELECT COUNT(*) FROM baseline_events"
            ).fetchone()[0]
            replica_count = connection.execute(
                "SELECT COUNT(*) FROM replica_verifications"
            ).fetchone()[0]
        self.assertEqual(1, event_count)
        self.assertEqual(3, replica_count)
        metrics = render_metrics(self.database)
        self.assertIn(
            "scielo_preservation_baseline_auto_automatic_baselines_total 1.0",
            metrics,
        )
        self.assertIn(
            "scielo_preservation_baseline_auto_replica_verifications_total 3.0",
            metrics,
        )
        self.assertIn("scielo_preservation_baseline_auto_last_run_ok 1.0", metrics)

    def test_replayed_receipt_is_idempotent_and_rechecks_integrity(self) -> None:
        self.run_job()
        result = self.run_job()

        self.assertFalse(result["baseline_created"])
        self.assertTrue(result["baseline_already_registered"])
        self.assertTrue(result["integrity_conforming"])
        with self.database.connect() as connection:
            self.assertEqual(
                1, connection.execute("SELECT COUNT(*) FROM baseline_events").fetchone()[0]
            )
            self.assertEqual(
                3,
                connection.execute(
                    "SELECT COUNT(*) FROM replica_verifications"
                ).fetchone()[0],
            )

    def test_invalid_signature_never_creates_baseline(self) -> None:
        receipt = signed_receipt()
        receipt["checksum"] = "0" * 64
        self.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

        with self.assertRaisesRegex(AutoBaselineError, "signature_mismatch"):
            self.run_job()
        self.assertEqual({}, self.database.baselines())

    def test_manual_job_rejects_expired_receipt(self) -> None:
        self.receipt_path.write_text(
            json.dumps(
                signed_receipt(completed_at="2020-01-01T00:00:00+00:00")
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(AutoBaselineError, "receipt_expired"):
            self.run_job()
        self.assertEqual({}, self.database.baselines())

    def test_replica_failure_never_creates_baseline(self) -> None:
        def fail_verification(*_args, **_kwargs):
            raise ReplicaVerificationError("replica_head_failed:minio")

        with patch.dict(
            "os.environ", {"TEST_RECEIPT_KEY": SIGNING_KEY.decode("utf-8")}
        ):
            with self.assertRaises(ReplicaVerificationError):
                AutoBaselineJob(
                    self.database,
                    self.logger,
                    replica_verifier=fail_verification,
                ).run(
                    receipt_path=self.receipt_path,
                    aip_root=self.root,
                    replicas_config=self.config_path,
                    signing_key_env="TEST_RECEIPT_KEY",
                    max_receipt_age_seconds=86400,
                )
        self.assertEqual({}, self.database.baselines())

    def test_rejects_symlink_even_when_target_is_inside_root(self) -> None:
        target = self.root / "target.7z"
        target.write_bytes(b"aip-content")
        link = self.root / "link.7z"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlinks unavailable")
        self.receipt_path.write_text(
            json.dumps(signed_receipt(relative_path="link.7z")), encoding="utf-8"
        )

        with self.assertRaisesRegex(AutoBaselineError, "symlink"):
            self.run_job()


class ReceiptAndReplicaTests(unittest.TestCase):
    def test_receipt_requires_completed_ingest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            path.write_text(
                json.dumps(signed_receipt(ingest_status="FAILED")), encoding="utf-8"
            )
            with self.assertRaisesRegex(AutoBaselineError, "ingest_not_completed"):
                load_signed_receipt(path, SIGNING_KEY)

    def test_receipt_rejects_unknown_fields(self) -> None:
        receipt = signed_receipt(unexpected="value")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(
                AutoBaselineError, "unsupported_receipt_schema"
            ):
                load_signed_receipt(path, SIGNING_KEY)

    def test_requires_exactly_the_three_replicas(self) -> None:
        config = replicas_config()
        config["replicas"].pop()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "replicas.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(
                ReplicaVerificationError, "required_replicas_not_configured"
            ):
                load_replica_targets(path)

    def test_remote_checksum_metadata_is_compared_when_present(self) -> None:
        class FakeClient:
            def head_object(self, **_kwargs):
                return {"ContentLength": 11, "Metadata": {"sha256": "0" * 64}}

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "replicas.json"
            path.write_text(json.dumps(replicas_config()), encoding="utf-8")
            targets = load_replica_targets(path)
        with self.assertRaisesRegex(
            ReplicaVerificationError, "replica_checksum_mismatch"
        ):
            verify_replicas(
                targets,
                object_key="aips/aip-001.7z",
                expected_size=11,
                expected_checksum="1" * 64,
                client_factory=lambda _target: FakeClient(),
            )

    def test_s3_head_uses_signature_v4_and_reads_metadata(self) -> None:
        class FakeResponse:
            headers = {
                "Content-Length": "11",
                "X-Amz-Meta-Sha256": "1" * 64,
            }

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "replicas.json"
            path.write_text(json.dumps(replicas_config()), encoding="utf-8")
            target = load_replica_targets(path)[0]
        with patch.dict(
            "os.environ",
            {"TEST_ACCESS_KEY": "access", "TEST_SECRET_KEY": "secret"},
        ):
            fake_opener = Mock()
            fake_opener.open.return_value = FakeResponse()
            with patch(
                "preservation_auditor.replicas.build_opener",
                return_value=fake_opener,
            ):
                response = S3HeadClient(target).head_object(
                    Bucket=target.bucket, Key="aips/aip-001.7z"
                )

        request = fake_opener.open.call_args.args[0]
        self.assertEqual("HEAD", request.method)
        self.assertTrue(
            request.get_header("Authorization").startswith("AWS4-HMAC-SHA256")
        )
        self.assertEqual(11, response["ContentLength"])
        self.assertEqual("1" * 64, response["Metadata"]["sha256"])

    def test_s3_head_reports_not_found_without_exposing_response(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "replicas.json"
            path.write_text(json.dumps(replicas_config()), encoding="utf-8")
            target = load_replica_targets(path)[0]
        with patch.dict(
            "os.environ",
            {"TEST_ACCESS_KEY": "access", "TEST_SECRET_KEY": "secret"},
        ):
            fake_opener = Mock()
            fake_opener.open.side_effect = HTTPError(
                target.endpoint_url, 404, "not found", {}, None
            )
            with patch(
                "preservation_auditor.replicas.build_opener",
                return_value=fake_opener,
            ):
                with self.assertRaisesRegex(
                    ReplicaVerificationError, "replica_not_found"
                ):
                    S3HeadClient(target).head_object(
                        Bucket=target.bucket, Key="aips/missing.7z"
                    )


if __name__ == "__main__":
    unittest.main()
