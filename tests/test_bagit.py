from __future__ import annotations

import hashlib
import logging
import tempfile
import unittest
import zipfile
from pathlib import Path

from preservation_auditor.bagit import BagItAuditor, DirectoryBag, ZipBag, validate_bag
from preservation_auditor.database import Database
from preservation_auditor.metrics import render_metrics


def bag_files(
    payload: bytes = b"dataset", algorithm: str = "sha256", version: str = "1.0"
) -> dict[str, bytes]:
    digest = (
        hashlib.md5(payload, usedforsecurity=False).hexdigest()
        if algorithm == "md5"
        else hashlib.new(algorithm, payload).hexdigest()
    )
    return {
        "bagit.txt": (
            "BagIt-Version: {}\nTag-File-Character-Encoding: UTF-8\n".format(version)
            .encode("ascii")
        ),
        "bag-info.txt": b"Source-Organization: SciELO\n",
        "data/dataset.csv": payload,
        "manifest-{}.txt".format(algorithm): (
            "{}  data/dataset.csv\n".format(digest).encode("ascii")
        ),
    }


class BagItTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def make_directory_bag(self, name: str = "bag", **kwargs) -> Path:
        bag = self.root / name
        for relative, content in bag_files(**kwargs).items():
            path = bag / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        return bag

    def test_valid_directory_bag(self) -> None:
        bag = self.make_directory_bag()
        result = validate_bag(DirectoryBag(bag, "bag"))
        self.assertEqual("PASS", result.status.value)
        self.assertEqual("sha256", result.evidence["algorithm"])
        self.assertEqual(1, result.evidence["payload_files"])

    def test_valid_zip_bag_without_extraction(self) -> None:
        archive = self.root / "dataset.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
            for relative, content in bag_files(algorithm="sha512").items():
                output.writestr("deposit/" + relative, content)
        result = validate_bag(ZipBag(archive, "deposit/", "dataset.zip#deposit"))
        self.assertEqual("PASS", result.status.value)
        self.assertEqual("sha512", result.evidence["algorithm"])

    def test_md5_only_is_validated_and_reported_as_warning(self) -> None:
        bag = self.make_directory_bag(algorithm="md5")
        result = validate_bag(DirectoryBag(bag, "bag"))
        self.assertEqual("WARNING", result.status.value)
        self.assertEqual("md5", result.evidence["algorithm"])
        self.assertIn("BAG_WEAK_MANIFEST_ALGORITHM", result.evidence["warnings"])
        self.assertIn("BAG_STRONG_MANIFEST_MISSING", result.evidence["warnings"])

    def test_md5_mismatch_is_a_failure(self) -> None:
        bag = self.make_directory_bag(algorithm="md5")
        (bag / "data/dataset.csv").write_bytes(b"changed")
        result = validate_bag(DirectoryBag(bag, "bag"))
        self.assertEqual("FAIL", result.status.value)
        self.assertIn("BAG_CHECKSUM_MISMATCH", result.evidence["errors"])

    def test_nonstandard_bag_info_continuation_is_a_warning(self) -> None:
        bag = self.make_directory_bag()
        (bag / "bag-info.txt").write_text(
            "External-Description: first line\n\nsecond paragraph\n"
            "Bagging-Date: 2026-04-17\n",
            encoding="utf-8",
        )
        result = validate_bag(DirectoryBag(bag, "bag"))
        self.assertEqual("WARNING", result.status.value)
        self.assertIn(
            "BAG_NONSTANDARD_TAG_CONTINUATION", result.evidence["warnings"]
        )

    def test_double_slash_path_is_validated_with_warning(self) -> None:
        archive = self.root / "noncanonical.zip"
        payload = b"dataset"
        files = bag_files(payload=payload)
        del files["data/dataset.csv"]
        del files["manifest-sha256.txt"]
        files["data/folder//dataset.csv"] = payload
        files["manifest-sha256.txt"] = (
            hashlib.sha256(payload).hexdigest()
            + "  data/folder//dataset.csv\n"
        ).encode("ascii")
        with zipfile.ZipFile(archive, "w") as output:
            for relative, content in files.items():
                output.writestr("deposit/" + relative, content)
        result = validate_bag(ZipBag(archive, "deposit/", "noncanonical.zip"))
        self.assertEqual("WARNING", result.status.value)
        self.assertIn("BAG_NONCANONICAL_PATH", result.evidence["warnings"])

    def test_duplicate_zip_directories_are_tolerated_but_files_are_not(self) -> None:
        archive = self.root / "duplicate-directory.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("deposit/data/", b"")
            output.writestr("deposit/data/", b"")
            for relative, content in bag_files().items():
                output.writestr("deposit/" + relative, content)
        result = validate_bag(ZipBag(archive, "deposit/", "duplicate-directory.zip"))
        self.assertEqual("PASS", result.status.value)

        archive = self.root / "duplicate-file.zip"
        with zipfile.ZipFile(archive, "w") as output:
            for relative, content in bag_files().items():
                output.writestr("deposit/" + relative, content)
            output.writestr("deposit/data/dataset.csv", b"duplicate")
        result = validate_bag(ZipBag(archive, "deposit/", "duplicate-file.zip"))
        self.assertEqual("FAIL", result.status.value)
        self.assertIn("BAG_ZIP_DUPLICATE_ENTRY", result.evidence["errors"])

    def test_checksum_mismatch_and_unlisted_payload(self) -> None:
        bag = self.make_directory_bag()
        (bag / "data/dataset.csv").write_bytes(b"changed")
        (bag / "data/extra.txt").write_bytes(b"extra")
        result = validate_bag(DirectoryBag(bag, "bag"))
        self.assertIn("BAG_CHECKSUM_MISMATCH", result.evidence["errors"])
        self.assertIn("BAG_PAYLOAD_UNLISTED", result.evidence["errors"])

    def test_unsafe_zip_entry_is_rejected(self) -> None:
        archive = self.root / "unsafe.zip"
        with zipfile.ZipFile(archive, "w") as output:
            for relative, content in bag_files().items():
                output.writestr("deposit/" + relative, content)
            output.writestr("../outside", b"unsafe")
        result = validate_bag(ZipBag(archive, "deposit/", "unsafe.zip#deposit"))
        self.assertEqual("FAIL", result.status.value)
        self.assertIn("BAG_UNSAFE_PATH", result.evidence["errors"])

    def test_audit_persists_results_and_exports_metrics(self) -> None:
        self.make_directory_bag()
        database = Database(self.root / "audit.db")
        logger = logging.getLogger("bagit-test-{}".format(id(self)))
        logger.addHandler(logging.NullHandler())
        _, results, complete = BagItAuditor(database, logger).check(self.root)
        self.assertTrue(complete)
        self.assertEqual(1, len(results))
        metrics = render_metrics(database)
        self.assertIn("scielo_preservation_bagits_total 1.0", metrics)
        self.assertIn("scielo_preservation_bagits_valid 1.0", metrics)
        self.assertIn("scielo_preservation_bagits_last_run_ok 1.0", metrics)

    def test_warning_run_is_successful_and_exported_separately(self) -> None:
        self.make_directory_bag(algorithm="md5")
        database = Database(self.root / "audit.db")
        logger = logging.getLogger("bagit-warning-test-{}".format(id(self)))
        logger.addHandler(logging.NullHandler())
        _, results, complete = BagItAuditor(database, logger).check(self.root)
        self.assertTrue(complete)
        self.assertEqual("WARNING", results[0].status.value)
        metrics = render_metrics(database)
        self.assertIn("scielo_preservation_bagits_warnings 1.0", metrics)
        self.assertIn("scielo_preservation_bagits_invalid 0.0", metrics)
        self.assertIn("scielo_preservation_bagits_weak_algorithm 1.0", metrics)
        self.assertIn("scielo_preservation_bagits_last_run_ok 1.0", metrics)

    def test_empty_repository_is_not_reported_as_success(self) -> None:
        database = Database(self.root / "audit.db")
        logger = logging.getLogger("bagit-empty-test-{}".format(id(self)))
        logger.addHandler(logging.NullHandler())
        _, results, complete = BagItAuditor(database, logger).check(self.root)
        self.assertTrue(complete)
        self.assertEqual([], results)
        metrics = render_metrics(database)
        self.assertIn("scielo_preservation_bagits_total 0.0", metrics)
        self.assertIn("scielo_preservation_bagits_last_run_ok 0.0", metrics)


if __name__ == "__main__":
    unittest.main()
