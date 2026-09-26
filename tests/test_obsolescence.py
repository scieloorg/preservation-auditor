from __future__ import annotations

import json
import logging
import tempfile
import unittest
from pathlib import Path

from preservation_auditor.database import Database
from preservation_auditor.metrics import render_metrics
from preservation_auditor.obsolescence import (
    ObsolescenceError,
    ObsolescenceAuditor,
    classify_record,
    load_policy,
)


class ObsolescenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({
            "version": "test-1",
            "rules": [
                {"puid": "fmt/214", "extensions": ["xlsx"], "risk": "low",
                 "reason": "supported", "migration_target": "ODS"},
                {"puid": "fmt/39", "extensions": ["doc"], "risk": "medium",
                 "reason": "legacy", "migration_target": "ODT"},
                {"puid": "fmt/124", "extensions": ["swf"], "risk": "critical",
                 "reason": "obsolete", "migration_target": "HTML5"},
            ],
        }), encoding="utf-8")
        self.version, self.rules = load_policy(self.policy)

    def record(self, name: str, puid: str, warning: str = "") -> dict:
        return {
            "filename": str(self.root / "deposit.zip") + "#bag/data/" + name,
            "filesize": 10, "errors": "",
            "matches": [{"id": puid, "format": name, "version": "1",
                         "mime": "application/test", "warning": warning}],
        }

    def classify(self, record: dict):
        return classify_record(
            record, root=self.root, policy_version=self.version, rules=self.rules
        )

    def test_only_payload_files_are_classified(self) -> None:
        record = self.record("file.xlsx", "fmt/214")
        record["filename"] = str(self.root / "deposit.zip") + "#bag/metadata/file.xlsx"
        self.assertIsNone(self.classify(record))
        record["filename"] = "/outside/deposit.zip#bag/data/file.xlsx"
        self.assertIsNone(self.classify(record))

    def test_policy_maps_pass_warning_and_fail(self) -> None:
        self.assertEqual("PASS", self.classify(self.record("a.xlsx", "fmt/214")).status.value)
        self.assertEqual("WARNING", self.classify(self.record("a.doc", "fmt/39")).status.value)
        result = self.classify(self.record("a.swf", "fmt/124"))
        self.assertEqual("FAIL", result.status.value)
        self.assertEqual("critical", result.evidence["risk"])

    def test_unknown_and_unclassified_are_not_treated_as_safe(self) -> None:
        unknown = self.record("unknown.bin", "UNKNOWN")
        self.assertEqual("UNKNOWN", self.classify(unknown).status.value)
        unclassified = self.classify(self.record("data.xyz", "fmt/9999"))
        self.assertEqual("WARNING", unclassified.status.value)
        self.assertEqual("FORMAT_UNCLASSIFIED", unclassified.error_code)

    def test_extension_is_required_to_disambiguate_puid(self) -> None:
        result = self.classify(self.record("renamed.xml", "fmt/214"))
        self.assertEqual("WARNING", result.status.value)
        self.assertEqual("unclassified", result.evidence["risk"])

    def test_empty_file_is_warning_instead_of_unknown(self) -> None:
        record = self.record("empty.csv", "UNKNOWN")
        record["filesize"] = 0
        record["errors"] = "empty source"
        result = self.classify(record)
        self.assertEqual("WARNING", result.status.value)
        self.assertEqual("FORMAT_EMPTY_FILE", result.error_code)
        self.assertEqual("empty", result.evidence["risk"])

    def test_policy_rejects_duplicate_puid_extension_pair(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(json.dumps({
            "version": "duplicate",
            "rules": [
                {"puid": "fmt/12", "extensions": ["png"], "risk": "minimal",
                 "reason": "one", "migration_target": ""},
                {"puid": "fmt/12", "extensions": ["png"], "risk": "low",
                 "reason": "two", "migration_target": ""},
            ],
        }), encoding="utf-8")
        with self.assertRaisesRegex(ObsolescenceError, "duplicate_format_policy_rule"):
            load_policy(duplicate)

    def test_versioned_policy_covers_dominant_inventory_formats(self) -> None:
        policy = Path(__file__).resolve().parents[1] / "config" / "format-policy.json"
        version, rules = load_policy(policy)
        self.assertEqual("2026-09-25.1", version)
        for name, puid, expected in (
            ("image.jpg", "x-fmt/391", "PASS"),
            ("document.pdf", "fmt/276", "PASS"),
            ("dataset.shp", "x-fmt/235", "WARNING"),
            ("archive.zip", "x-fmt/263", "PASS"),
            ("image.png", "fmt/12", "PASS"),
        ):
            result = classify_record(
                self.record(name, puid), root=self.root,
                policy_version=version, rules=rules,
            )
            self.assertEqual(expected, result.status.value)
        suspicious = classify_record(
            self.record("misnamed.csv", "fmt/2023"), root=self.root,
            policy_version=version, rules=rules,
        )
        self.assertEqual("FORMAT_UNCLASSIFIED", suspicious.error_code)

    def test_audit_persists_results_and_exports_metrics(self) -> None:
        report = self.root / "report.json"
        report.write_text(json.dumps({"files": [
            self.record("safe.xlsx", "fmt/214"),
            self.record("legacy.doc", "fmt/39"),
            self.record("obsolete.swf", "fmt/124"),
            self.record("new.xyz", "fmt/9999"),
        ]}), encoding="utf-8")
        database = Database(self.root / "audit.db")
        logger = logging.getLogger("obsolescence-test-{}".format(id(self)))
        logger.addHandler(logging.NullHandler())
        _, results, complete = ObsolescenceAuditor(database, logger).check(
            root=self.root, policy_path=self.policy, report_path=report,
            siegfried_binary="sf",
        )
        self.assertTrue(complete)
        self.assertEqual(4, len(results))
        metrics = render_metrics(database)
        self.assertIn("scielo_preservation_formats_total 4.0", metrics)
        self.assertIn("scielo_preservation_formats_pass 1.0", metrics)
        self.assertIn("scielo_preservation_formats_warnings 2.0", metrics)
        self.assertIn("scielo_preservation_formats_medium_risk 1.0", metrics)
        self.assertIn("scielo_preservation_formats_empty 0.0", metrics)
        self.assertIn("scielo_preservation_formats_critical_risk 1.0", metrics)
        self.assertIn("scielo_preservation_formats_last_run_ok 0.0", metrics)


if __name__ == "__main__":
    unittest.main()
