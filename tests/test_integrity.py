from __future__ import annotations

import json
import logging
import os
import tempfile
import unittest
from pathlib import Path

from preservation_auditor.database import Database
from preservation_auditor.integrity import IntegrityAuditor
from preservation_auditor.metrics import render_metrics


class IntegrityAuditorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "aips"
        self.root.mkdir()
        self.data = Path(self.temp.name) / "state"
        self.database = Database(self.data / "audit.db")
        self.logger = logging.getLogger(f"test-{id(self)}")
        self.logger.addHandler(logging.NullHandler())
        self.auditor = IntegrityAuditor(self.database, self.logger)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, name: str, content: bytes) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_baseline_and_unchanged_file(self) -> None:
        self.write("one.7z", b"original")
        baseline = self.auditor.create_baseline(self.root)
        self.assertEqual({"created": 1, "existing": 0, "failed": 0}, baseline)

        _, results, complete = self.auditor.check(self.root)
        self.assertTrue(complete)
        self.assertEqual(["PASS"], [item.status.value for item in results])
        self.assertIn("scielo_preservation_aips_integrity_valid 1.0", render_metrics(self.database))

    def test_changed_file_does_not_replace_baseline(self) -> None:
        path = self.write("one.7z", b"original")
        self.auditor.create_baseline(self.root)
        path.write_bytes(b"changed")

        for _ in range(2):
            _, results, _ = self.auditor.check(self.root)
            self.assertEqual("CHECKSUM_MISMATCH", results[0].error_code)

        baseline = self.auditor.create_baseline(self.root)
        self.assertEqual(0, baseline["created"])
        self.assertEqual(1, baseline["existing"])

    def test_missing_and_untracked_files_are_distinct(self) -> None:
        path = self.write("known.7z", b"known")
        self.auditor.create_baseline(self.root)
        path.unlink()
        self.write("new.7z", b"new")

        _, results, complete = self.auditor.check(self.root)
        self.assertTrue(complete)
        self.assertEqual(
            {"FILE_MISSING", "NO_BASELINE"},
            {item.error_code for item in results},
        )

    def test_untracked_file_does_not_count_as_success(self) -> None:
        self.write("new.7z", b"new")

        run_id, results, complete = self.auditor.check(self.root)

        self.assertTrue(complete)
        self.assertEqual("NO_BASELINE", results[0].error_code)
        with self.database.connect() as connection:
            run = connection.execute(
                "SELECT status FROM audit_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        self.assertEqual("WARNING", run["status"])
        self.assertIn(
            "scielo_preservation_last_success_timestamp_seconds 0.0",
            render_metrics(self.database),
        )

    def test_failed_run_preserves_timestamp_of_last_success(self) -> None:
        path = self.write("one.7z", b"original")
        self.auditor.create_baseline(self.root)
        self.auditor.check(self.root)
        first_metrics = self.database.latest_integrity_metrics()
        path.write_bytes(b"changed")

        self.auditor.check(self.root)
        failed_metrics = self.database.latest_integrity_metrics()

        self.assertGreater(first_metrics["last_success_timestamp_seconds"], 0)
        self.assertEqual(
            first_metrics["last_success_timestamp_seconds"],
            failed_metrics["last_success_timestamp_seconds"],
        )

    def test_symlink_is_inconclusive_and_never_followed(self) -> None:
        outside = Path(self.temp.name) / "outside"
        outside.write_bytes(b"secret")
        link = self.root / "link"
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("symlinks unavailable")

        _, results, complete = self.auditor.check(self.root)
        self.assertFalse(complete)
        self.assertEqual("SYMLINK_SKIPPED", results[0].error_code)

    def test_database_permissions_are_private(self) -> None:
        mode = os.stat(self.database.path).st_mode & 0o777
        self.assertEqual(0o600, mode)


if __name__ == "__main__":
    unittest.main()
