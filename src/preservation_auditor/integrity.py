from __future__ import annotations

import hashlib
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .audit_log import log_event
from .database import Database
from .models import AuditResult, Status


CHUNK_SIZE = 1024 * 1024


def resource_id(relative_path: str) -> str:
    return hashlib.sha256(relative_path.encode("utf-8")).hexdigest()


def hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    before = path.stat()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError("file_changed_during_hash")
    return digest.hexdigest(), after.st_size


def iter_files(root: Path, excluded: set[Path]) -> tuple[list[Path], list[AuditResult]]:
    files: list[Path] = []
    errors: list[AuditResult] = []
    try:
        for current, directories, names in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories[:] = [
                name for name in directories
                if (current_path / name).resolve() not in excluded
                and not (current_path / name).is_symlink()
            ]
            for name in names:
                path = current_path / name
                relative = path.relative_to(root).as_posix()
                rid = resource_id(relative)
                if path.is_symlink():
                    errors.append(AuditResult(
                        "aip.local_integrity", "file", rid, Status.UNKNOWN, "HIGH",
                        {"relative_path": relative}, "SYMLINK_SKIPPED",
                    ))
                elif path.is_file() and path.resolve() not in excluded:
                    files.append(path)
    except OSError as error:
        errors.append(AuditResult(
            "aip.local_integrity", "directory", resource_id(root.name),
            Status.UNKNOWN, "CRITICAL", {"error_type": type(error).__name__},
            "DIRECTORY_READ_ERROR",
        ))
    return files, errors


class IntegrityAuditor:
    def __init__(self, database: Database, logger):
        self.database = database
        self.logger = logger

    def create_baseline(self, root: Path) -> dict:
        root = root.resolve(strict=True)
        excluded = {self.database.path}
        files, errors = iter_files(root, excluded)
        created = existing = failed = 0
        for path in files:
            relative = path.relative_to(root).as_posix()
            rid = resource_id(relative)
            try:
                checksum, size = hash_file(path)
                if self.database.add_baseline(
                    resource_id=rid, relative_path=relative,
                    checksum=checksum, size_bytes=size,
                ):
                    created += 1
                else:
                    existing += 1
            except OSError:
                failed += 1
        failed += len(errors)
        log_event(
            self.logger, action="integrity.baseline_create",
            result="success" if failed == 0 else "failure",
            resource="integrity_baseline",
            extra={"created": created, "existing": existing, "failed": failed},
        )
        return {"created": created, "existing": existing, "failed": failed}

    def check(self, root: Path) -> tuple[str, list[AuditResult], bool]:
        run_id = str(uuid.uuid4())
        started = datetime.now(timezone.utc).isoformat()
        started_monotonic = time.monotonic()
        self.database.create_run(run_id, "integrity", started)
        log_event(
            self.logger, action="job.integrity_check", result="started",
            resource="integrity_scan", run_id=run_id,
        )

        results: list[AuditResult] = []
        scan_complete = True
        try:
            root = root.resolve(strict=True)
            files, traversal_errors = iter_files(root, {self.database.path})
            results.extend(traversal_errors)
            scan_complete = not traversal_errors
            observed: set[str] = set()
            baselines = self.database.baselines()

            for path in files:
                relative = path.relative_to(root).as_posix()
                observed.add(relative)
                rid = resource_id(relative)
                baseline = baselines.get(relative)
                if baseline is None:
                    results.append(AuditResult(
                        "aip.local_integrity", "file", rid, Status.WARNING, "HIGH",
                        {"relative_path": relative}, "NO_BASELINE",
                    ))
                    continue
                try:
                    checksum, size = hash_file(path)
                    matches = (
                        checksum == baseline["checksum"]
                        and size == baseline["size_bytes"]
                    )
                    results.append(AuditResult(
                        "aip.local_integrity", "file", rid,
                        Status.PASS if matches else Status.FAIL, "CRITICAL",
                        {
                            "relative_path": relative,
                            "algorithm": "sha256",
                            "size_bytes": size,
                        },
                        None if matches else "CHECKSUM_MISMATCH",
                    ))
                except (OSError, RuntimeError) as error:
                    scan_complete = False
                    results.append(AuditResult(
                        "aip.local_integrity", "file", rid, Status.UNKNOWN,
                        "CRITICAL", {"relative_path": relative,
                                     "error_type": type(error).__name__},
                        "FILE_READ_ERROR",
                    ))

            for relative, baseline in baselines.items():
                if relative not in observed:
                    results.append(AuditResult(
                        "aip.local_integrity", "file", baseline["resource_id"],
                        Status.FAIL, "CRITICAL", {"relative_path": relative},
                        "FILE_MISSING",
                    ))

            self.database.save_results(run_id, results)
            has_failure = any(item.status in {Status.FAIL, Status.UNKNOWN} for item in results)
            has_warning = any(item.status == Status.WARNING for item in results)
            if has_failure or not scan_complete:
                status = "FAIL"
            elif has_warning:
                status = "WARNING"
            else:
                status = "PASS"
            self.database.finish_run(
                run_id, status=status, scan_complete=scan_complete,
                duration_seconds=time.monotonic() - started_monotonic,
            )
            log_event(
                self.logger, action="job.integrity_check", result=status.lower(),
                resource="integrity_scan", run_id=run_id,
                extra={
                    "records_processed": len(results),
                    "scan_complete": scan_complete,
                    "failures": sum(item.status == Status.FAIL for item in results),
                    "unknown": sum(item.status == Status.UNKNOWN for item in results),
                },
            )
            return run_id, results, scan_complete
        except Exception as error:
            self.database.finish_run(
                run_id, status="FAIL", scan_complete=False,
                duration_seconds=time.monotonic() - started_monotonic,
            )
            log_event(
                self.logger, action="job.integrity_check", result="failure",
                resource="integrity_scan", run_id=run_id,
                extra={"error_type": type(error).__name__},
            )
            raise
