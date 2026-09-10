from __future__ import annotations

import json
import logging
import tempfile
import unittest
from pathlib import Path

from preservation_auditor.audit_log import configure_audit_logging, log_event


class AuditLogTests(unittest.TestCase):
    def test_sensitive_fields_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.log"
            logger = configure_audit_logging(path)
            log_event(
                logger,
                action="job.test",
                result="success",
                resource="test",
                extra={"token": "do-not-log", "nested": {"password": "hidden"}},
            )
            for handler in logger.handlers:
                handler.flush()
            entry = json.loads(path.read_text(encoding="utf-8").strip())
            self.assertEqual("***", entry["extra"]["token"])
            self.assertEqual("***", entry["extra"]["nested"]["password"])


if __name__ == "__main__":
    unittest.main()
