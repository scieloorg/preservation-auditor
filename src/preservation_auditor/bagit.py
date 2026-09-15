from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, Iterator, Protocol

from .audit_log import log_event
from .database import Database
from .integrity import resource_id
from .models import AuditResult, Status


SUPPORTED_VERSIONS = {"0.96", "0.97"}
SUPPORTED_ALGORITHMS = {"sha256": 64, "sha512": 128}
MANIFEST_PATTERN = re.compile(r"^(tag)?manifest-([a-z0-9]+)\.txt$")
MAX_TEXT_FILE_BYTES = 16 * 1024 * 1024
MAX_ZIP_ENTRIES = 1_000_000
MAX_COMPRESSION_RATIO = 1_000


class BagReadError(RuntimeError):
    pass


class ZipMemberStream:
    def __init__(self, archive: zipfile.ZipFile, stream: BinaryIO):
        self.archive = archive
        self.stream = stream

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(size)

    def close(self) -> None:
        try:
            self.stream.close()
        finally:
            self.archive.close()

    def __enter__(self) -> ZipMemberStream:
        return self

    def __exit__(self, *_args) -> None:
        self.close()


class BagReader(Protocol):
    locator: str

    def files(self) -> set[str]: ...
    def open(self, relative: str) -> BinaryIO: ...
    def size(self, relative: str) -> int: ...


@dataclass
class DirectoryBag:
    root: Path
    locator: str

    def files(self) -> set[str]:
        result: set[str] = set()
        for current, directories, names in os.walk(self.root, followlinks=False):
            current_path = Path(current)
            safe_directories = []
            for name in directories:
                child = current_path / name
                if child.is_symlink():
                    raise BagReadError("BAG_SYMLINK")
                safe_directories.append(name)
            directories[:] = safe_directories
            for name in names:
                path = current_path / name
                if path.is_symlink() or not path.is_file():
                    raise BagReadError("BAG_SYMLINK")
                result.add(path.relative_to(self.root).as_posix())
        return result

    def open(self, relative: str) -> BinaryIO:
        candidate = self.root.joinpath(*PurePosixPath(relative).parts)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        return os.fdopen(os.open(candidate, flags), "rb")

    def size(self, relative: str) -> int:
        return self.root.joinpath(*PurePosixPath(relative).parts).stat().st_size


@dataclass
class ZipBag:
    archive: Path
    prefix: str
    locator: str

    def _name(self, relative: str) -> str:
        return self.prefix + relative

    def files(self) -> set[str]:
        with zipfile.ZipFile(self.archive) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise BagReadError("BAG_ZIP_TOO_MANY_ENTRIES")
            names: set[str] = set()
            seen: set[str] = set()
            for info in infos:
                if info.filename in seen:
                    raise BagReadError("BAG_ZIP_DUPLICATE_ENTRY")
                seen.add(info.filename)
                _validate_relative_path(info.filename.rstrip("/"))
                if info.flag_bits & 0x1:
                    raise BagReadError("BAG_ZIP_ENCRYPTED_ENTRY")
                compressed = max(info.compress_size, 1)
                if info.file_size > 100 * 1024 * 1024 and info.file_size / compressed > MAX_COMPRESSION_RATIO:
                    raise BagReadError("BAG_ZIP_SUSPICIOUS_COMPRESSION")
                if info.filename.startswith(self.prefix) and not info.is_dir():
                    names.add(info.filename[len(self.prefix):])
            return names

    def open(self, relative: str) -> BinaryIO:
        archive = zipfile.ZipFile(self.archive)
        try:
            stream = archive.open(self._name(relative), "r")
        except Exception:
            archive.close()
            raise
        return ZipMemberStream(archive, stream)  # type: ignore[return-value]

    def size(self, relative: str) -> int:
        with zipfile.ZipFile(self.archive) as archive:
            return archive.getinfo(self._name(relative)).file_size


def _validate_relative_path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith(("/", "\\"))
        or "\\" in value
        or ".." in path.parts
        or "." in path.parts
        or any(not part for part in value.split("/"))
    ):
        raise BagReadError("BAG_UNSAFE_PATH")


def _read_text(reader: BagReader, name: str, encoding: str = "utf-8") -> str:
    if reader.size(name) > MAX_TEXT_FILE_BYTES:
        raise BagReadError("BAG_METADATA_TOO_LARGE")
    try:
        with reader.open(name) as stream:
            return stream.read(MAX_TEXT_FILE_BYTES + 1).decode(encoding)
    except (OSError, KeyError, UnicodeError, zipfile.BadZipFile) as error:
        raise BagReadError("BAG_METADATA_READ_ERROR") from error


def _parse_tag_file(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        if raw_line.startswith((" ", "\t")) and current:
            fields[current][-1] += " " + raw_line.strip()
            continue
        if ":" not in raw_line:
            raise BagReadError("BAG_INVALID_TAG_FILE")
        name, value = raw_line.split(":", 1)
        name = name.strip()
        if not name or not value.strip():
            raise BagReadError("BAG_INVALID_TAG_FILE")
        fields.setdefault(name, []).append(value.strip())
        current = name
    return fields


def _parse_manifest(text: str, digest_length: int) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise BagReadError("BAG_INVALID_MANIFEST")
        digest, path_value = parts
        path_value = path_value[1:] if path_value.startswith("*") else path_value
        _validate_relative_path(path_value)
        if len(digest) != digest_length or any(c not in "0123456789abcdefABCDEF" for c in digest):
            raise BagReadError("BAG_INVALID_MANIFEST")
        if path_value in entries:
            raise BagReadError("BAG_DUPLICATE_MANIFEST_PATH")
        entries[path_value] = digest.lower()
    return entries


def _digest(reader: BagReader, name: str, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    try:
        with reader.open(name) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except (OSError, KeyError, RuntimeError, zipfile.BadZipFile) as error:
        raise BagReadError("BAG_FILE_READ_ERROR") from error
    return digest.hexdigest()


def validate_bag(reader: BagReader) -> AuditResult:
    errors: set[str] = set()
    evidence = {"bag": reader.locator, "payload_files": 0, "payload_bytes": 0}
    try:
        files = reader.files()
        required = {"bagit.txt", "bag-info.txt"}
        if not required <= files:
            errors.add("BAG_REQUIRED_TAG_MISSING")
        if "bagit.txt" in files:
            tags = _parse_tag_file(_read_text(reader, "bagit.txt", "ascii"))
            if tags.get("BagIt-Version", [None])[-1] not in SUPPORTED_VERSIONS:
                errors.add("BAG_UNSUPPORTED_VERSION")
            encoding = tags.get("Tag-File-Character-Encoding", [None])[-1]
            if not isinstance(encoding, str) or encoding.upper() != "UTF-8":
                errors.add("BAG_INVALID_ENCODING")
        if "bag-info.txt" in files:
            _parse_tag_file(_read_text(reader, "bag-info.txt"))

        payload_manifests: dict[str, str] = {}
        tag_manifests: dict[str, str] = {}
        weak_algorithms: set[str] = set()
        for name in files:
            match = MANIFEST_PATTERN.fullmatch(name)
            if not match:
                continue
            algorithm = match.group(2)
            if algorithm not in SUPPORTED_ALGORITHMS:
                weak_algorithms.add(algorithm)
                continue
            target = tag_manifests if match.group(1) else payload_manifests
            target[algorithm] = name
        if weak_algorithms:
            errors.add("BAG_WEAK_MANIFEST_ALGORITHM")
            evidence["weak_algorithms"] = sorted(weak_algorithms)
        if not payload_manifests:
            errors.add("BAG_STRONG_MANIFEST_MISSING")
        else:
            algorithm = "sha512" if "sha512" in payload_manifests else "sha256"
            entries = _parse_manifest(
                _read_text(reader, payload_manifests[algorithm]),
                SUPPORTED_ALGORITHMS[algorithm],
            )
            listed = set(entries)
            actual = {name for name in files if name.startswith("data/")}
            evidence["algorithm"] = algorithm
            evidence["payload_files"] = len(actual)
            evidence["payload_bytes"] = sum(reader.size(name) for name in actual)
            if listed - actual:
                errors.add("BAG_PAYLOAD_MISSING")
            if actual - listed:
                errors.add("BAG_PAYLOAD_UNLISTED")
            for name in sorted(listed & actual):
                if _digest(reader, name, algorithm) != entries[name]:
                    errors.add("BAG_CHECKSUM_MISMATCH")

        for algorithm, manifest_name in tag_manifests.items():
            entries = _parse_manifest(
                _read_text(reader, manifest_name), SUPPORTED_ALGORITHMS[algorithm]
            )
            for name, expected in entries.items():
                if name not in files:
                    errors.add("BAG_TAG_FILE_MISSING")
                elif _digest(reader, name, algorithm) != expected:
                    errors.add("BAG_TAG_CHECKSUM_MISMATCH")
    except BagReadError as error:
        errors.add(str(error))
    except (OSError, KeyError, zipfile.BadZipFile):
        return AuditResult(
            "bagit.structural_integrity", "bag", resource_id(reader.locator),
            Status.UNKNOWN, "HIGH", evidence, "BAG_READ_ERROR",
        )
    evidence["errors"] = sorted(errors)
    return AuditResult(
        "bagit.structural_integrity", "bag", resource_id(reader.locator),
        Status.PASS if not errors else Status.FAIL, "HIGH", evidence,
        None if not errors else sorted(errors)[0],
    )


def discover_bags(root: Path) -> Iterator[BagReader]:
    root = root.resolve(strict=True)
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = [name for name in directories if not (current_path / name).is_symlink()]
        if "bagit.txt" in names:
            yield DirectoryBag(current_path, current_path.relative_to(root).as_posix() or ".")
            directories[:] = []
            continue
        for name in sorted(names):
            if not name.lower().endswith(".zip"):
                continue
            archive_path = current_path / name
            locator = archive_path.relative_to(root).as_posix()
            try:
                with zipfile.ZipFile(archive_path) as archive:
                    bagit_names = sorted(
                        info.filename for info in archive.infolist()
                        if not info.is_dir() and PurePosixPath(info.filename).name == "bagit.txt"
                    )
            except (OSError, zipfile.BadZipFile):
                yield ZipBag(archive_path, "", locator)
                continue
            for bagit_name in bagit_names:
                prefix = bagit_name[:-len("bagit.txt")]
                yield ZipBag(archive_path, prefix, "{}#{}".format(locator, prefix.rstrip("/")))


class BagItAuditor:
    def __init__(self, database: Database, logger):
        self.database = database
        self.logger = logger

    def check(self, root: Path) -> tuple[str, list[AuditResult], bool]:
        run_id = str(uuid.uuid4())
        started_monotonic = time.monotonic()
        self.database.create_run(run_id, "bagit", datetime.now(timezone.utc).isoformat())
        log_event(self.logger, action="job.bagit_check", result="started",
                  resource="bagit_repository", run_id=run_id)
        try:
            results = [validate_bag(reader) for reader in discover_bags(root)]
            scan_complete = all(item.status != Status.UNKNOWN for item in results)
            self.database.save_results(run_id, results)
            status = "PASS" if results and scan_complete and all(
                item.status == Status.PASS for item in results
            ) else "FAIL"
            self.database.finish_run(
                run_id, status=status, scan_complete=scan_complete,
                duration_seconds=time.monotonic() - started_monotonic,
            )
            log_event(
                self.logger, action="job.bagit_check", result=status.lower(),
                resource="bagit_repository", run_id=run_id,
                extra={
                    "records_processed": len(results),
                    "valid": sum(item.status == Status.PASS for item in results),
                    "invalid": sum(item.status == Status.FAIL for item in results),
                    "unknown": sum(item.status == Status.UNKNOWN for item in results),
                    "scan_complete": scan_complete,
                },
            )
            return run_id, results, scan_complete
        except Exception as error:
            self.database.finish_run(
                run_id, status="FAIL", scan_complete=False,
                duration_seconds=time.monotonic() - started_monotonic,
            )
            log_event(
                self.logger, action="job.bagit_check", result="failure",
                resource="bagit_repository", run_id=run_id,
                extra={"error_type": type(error).__name__},
            )
            raise
