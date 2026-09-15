from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

from preservation_auditor.archivematica import package_receipt, publish_receipt, collect
from preservation_auditor.auto_baseline import AutoBaselineError, AutoBaselineJob, load_signed_receipt
from preservation_auditor.database import Database
import logging
from preservation_auditor.replicas import verify_replicas
from test_auto_baseline import replicas_config, SIGNING_KEY
from preservation_auditor.replicas import load_replica_targets


class ArchivematicaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        config = self.root / "replicas.json"
        config.write_text(json.dumps(replicas_config()))
        self.targets = load_replica_targets(config)
        self.now = datetime.now(timezone.utc)
        self.checksum = hashlib.sha256(b"aip").hexdigest()
        self.replicas = [NS(
            status="UPLOADED", size=3, checksum=self.checksum,
            checksum_algorithm="sha256", stored_date=self.now,
            current_path=t.name + "/replica.7z",
            current_location=NS(relative_path="aips", space=NS(
                access_protocol="S3", s3=NS(endpoint_url=t.endpoint_url,
                                            bucket_name=t.bucket))),
        ) for t in self.targets]
        self.package = NS(
            uuid="12345678-1234-1234-1234-123456789abc",
            status="UPLOADED", package_type="AIP", replicated_package_id=None,
            size=3, checksum=self.checksum, checksum_algorithm="sha256",
            stored_date=self.now, full_path=str(self.root / "original.7z"),
            current_location=NS(space=NS(access_protocol="FS")),
            replicas=NS(all=lambda: self.replicas),
        )

    def receipt(self):
        return package_receipt(self.package, self.targets, self.root, SIGNING_KEY)

    def test_signed_roundtrip_and_idempotent_publication(self):
        raw = self.receipt()
        path = publish_receipt(self.root, raw, SIGNING_KEY)
        receipt = load_signed_receipt(path, SIGNING_KEY)
        self.assertEqual(receipt.checksum, self.checksum)
        self.assertEqual(receipt.replica_object_keys["wasabi"], "aips/wasabi/replica.7z")
        self.assertEqual(publish_receipt(self.root, raw, SIGNING_KEY), path)

    def test_tampered_replica_path_rejected(self):
        raw = self.receipt()
        raw["replica_object_keys"]["wasabi"] = "wrong"
        with self.assertRaisesRegex(AutoBaselineError, "receipt_signature_mismatch"):
            publish_receipt(self.root, raw, SIGNING_KEY)

    def test_existing_event_never_overwritten(self):
        raw = self.receipt()
        path = publish_receipt(self.root, raw, SIGNING_KEY)
        original = path.read_bytes()
        self.package.size = 4
        for replica in self.replicas:
            replica.size = 4
        with self.assertRaisesRegex(AutoBaselineError, "receipt_event_conflict"):
            publish_receipt(self.root, self.receipt(), SIGNING_KEY)
        self.assertEqual(path.read_bytes(), original)

    def test_incomplete_replicas_rejected(self):
        self.replicas[0].status = "STAGING"
        with self.assertRaisesRegex(AutoBaselineError, "replica_not_uploaded"):
            self.receipt()

    def test_missing_replica_rejected(self):
        self.replicas.pop()
        with self.assertRaisesRegex(AutoBaselineError, "replicas_not_complete"):
            self.receipt()

    def test_wrong_bucket_rejected(self):
        self.replicas[0].current_location.space.s3.bucket_name = "other"
        with self.assertRaisesRegex(AutoBaselineError, "replicas_not_complete"):
            self.receipt()

    def test_wrong_storage_checksum_rejected(self):
        self.replicas[0].checksum = "0" * 64
        with self.assertRaisesRegex(AutoBaselineError, "replica_storage_checksum_mismatch"):
            self.receipt()

    def test_replica_cannot_be_treated_as_original(self):
        self.package.replicated_package_id = "parent"
        with self.assertRaisesRegex(AutoBaselineError, "aip_not_completed_local_original"):
            self.receipt()

    def test_path_outside_root_rejected(self):
        self.package.full_path = "/outside/package.7z"
        with self.assertRaises(ValueError):
            self.receipt()

    def test_each_head_uses_corresponding_signed_key(self):
        raw = self.receipt()
        clients = {t.name: Mock() for t in self.targets}
        for client in clients.values():
            client.head_object.return_value = {"ContentLength": 3, "Metadata": {}}
        evidence = verify_replicas(
            self.targets, object_key="unused", object_keys=raw["replica_object_keys"],
            expected_size=3, expected_checksum=self.checksum,
            client_factory=lambda target: clients[target.name],
        )
        for target, item in zip(self.targets, evidence):
            key = raw["replica_object_keys"][target.name]
            clients[target.name].head_object.assert_called_once_with(Bucket=target.bucket, Key=key)
            self.assertEqual(item.object_key, key)

    def test_collector_retries_then_registers_and_skips_existing_event(self):
        aip_root = self.root / "aips"
        aip_root.mkdir()
        local = aip_root / "original.7z"
        local.write_bytes(b"aip")
        self.package.full_path = str(local)
        state = self.root / "state"
        state.mkdir()
        (state / "inbox").mkdir()
        database = Database(state / "audit.db")
        clients = {t.name: Mock() for t in self.targets}
        for client in clients.values():
            client.head_object.return_value = {"ContentLength": 3, "Metadata": {}}
        def verifier(targets, **kwargs):
            return verify_replicas(targets, **kwargs,
                                   client_factory=lambda target: clients[target.name])
        def job(db, logger):
            return AutoBaselineJob(db, logger, replica_verifier=verifier)
        kwargs = dict(state=state, root=aip_root, targets=self.targets,
                      config=self.root / "replicas.json", database=database,
                      logger=logging.getLogger("collector-test"), max_age=86400)
        with patch.dict("os.environ", {"PRESERVATION_RECEIPT_HMAC_KEY": SIGNING_KEY.decode()}), \
                patch("preservation_auditor.archivematica.AutoBaselineJob", side_effect=job):
            self.replicas[0].status = "STAGING"
            self.assertEqual(collect([self.package], **kwargs)["failed"], 1)
            self.assertEqual(database.baselines(), {})
            self.assertEqual(list((state / "inbox").iterdir()), [])
            self.replicas[0].status = "UPLOADED"
            result = collect([self.package], **kwargs)
            self.assertEqual(result["registered"], 1)
            self.assertEqual(result["failed"], 0)
            self.assertEqual(collect([self.package], **kwargs)["skipped"], 1)
        with database.connect() as connection:
            rows = connection.execute("SELECT object_key FROM replica_verifications").fetchall()
        self.assertEqual({r[0] for r in rows}, set(self.receipt()["replica_object_keys"].values()))

    def test_v2_requires_all_replica_keys(self):
        raw = self.receipt()
        del raw["replica_object_keys"]["wasabi"]
        import hmac
        from preservation_auditor.auto_baseline import _canonical_payload
        raw["signature"] = hmac.new(SIGNING_KEY, _canonical_payload(raw), hashlib.sha256).hexdigest()
        with self.assertRaisesRegex(AutoBaselineError, "invalid_replica_object_keys"):
            publish_receipt(self.root, raw, SIGNING_KEY)
