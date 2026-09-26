from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable

from .audit_log import log_event
from .database import Database
from .integrity import resource_id
from .models import AuditResult, Status


MAX_REPORT_BYTES = 512 * 1024 * 1024
RISK_STATUS = {
    "minimal": Status.PASS,
    "low": Status.PASS,
    "medium": Status.WARNING,
    "high": Status.FAIL,
    "critical": Status.FAIL,
}


class ObsolescenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class FormatRule:
    puid: str
    extensions: frozenset[str]
    risk: str
    reason: str
    migration_target: str


def load_policy(path: Path) -> tuple[str, list[FormatRule]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        version = str(raw["version"])
        rules_raw = raw["rules"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise ObsolescenceError("invalid_format_policy") from error
    if not isinstance(rules_raw, list) or not rules_raw:
        raise ObsolescenceError("invalid_format_policy")
    rules: list[FormatRule] = []
    seen_pairs: set[tuple[str, str]] = set()
    for item in rules_raw:
        try:
            risk = str(item["risk"]).lower()
            extensions = frozenset(str(value).lower() for value in item["extensions"])
            rule = FormatRule(
                puid=str(item["puid"]), extensions=extensions, risk=risk,
                reason=str(item["reason"]),
                migration_target=str(item.get("migration_target", "")),
            )
        except (KeyError, TypeError) as error:
            raise ObsolescenceError("invalid_format_policy") from error
        if (
            risk not in RISK_STATUS or not rule.puid or not extensions
            or any(not extension or extension.startswith(".") for extension in extensions)
        ):
            raise ObsolescenceError("invalid_format_policy")
        pairs = {(rule.puid, extension) for extension in extensions}
        if pairs & seen_pairs:
            raise ObsolescenceError("duplicate_format_policy_rule")
        seen_pairs.update(pairs)
        rules.append(rule)
    return version, rules


def _payload_path(filename: str, root: Path) -> str | None:
    value = filename
    root_values = {
        str(root.absolute()).rstrip("/") + "/",
        str(root.resolve()).rstrip("/") + "/",
    }
    matching_root = next(
        (root_value for root_value in root_values if value.startswith(root_value)), None
    )
    if matching_root:
        value = value[len(matching_root):]
    elif value.startswith("/"):
        return None
    if "#" not in value:
        return None
    archive, member = value.split("#", 1)
    parts = PurePosixPath(member).parts
    try:
        data_index = parts.index("data")
    except ValueError:
        return None
    relative_member = "/".join(parts[data_index:])
    return "{}#{}".format(archive, relative_member)


def _extension(path: str) -> str:
    name = PurePosixPath(path).name
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _matches(record: dict) -> list[dict]:
    matches = record.get("matches", [])
    if isinstance(matches, list):
        return [item for item in matches if isinstance(item, dict)]
    if record.get("id"):
        return [{
            "id": record.get("id"), "format": record.get("format", ""),
            "version": record.get("version", ""), "mime": record.get("mime", ""),
            "warning": record.get("warning", ""),
        }]
    return []


def classify_record(
    record: dict, *, root: Path, policy_version: str, rules: Iterable[FormatRule]
) -> AuditResult | None:
    filename = str(record.get("filename", ""))
    path = _payload_path(filename, root)
    if path is None:
        return None
    extension = _extension(path)
    matches = _matches(record)
    evidence: dict = {
        "path": path,
        "size_bytes": int(record.get("filesize") or 0),
        "extension": extension,
        "policy_version": policy_version,
    }
    if evidence["size_bytes"] == 0:
        evidence.update({"risk": "empty", "identification_warning": "empty_file"})
        return AuditResult(
            "format.obsolescence", "file", resource_id(path), Status.WARNING,
            "MEDIUM", evidence, "FORMAT_EMPTY_FILE",
        )
    if record.get("errors") or not matches or all(
        str(item.get("id", "")).upper() == "UNKNOWN" for item in matches
    ):
        evidence["identification_error"] = str(
            record.get("errors") or "format_not_identified"
        )
        return AuditResult(
            "format.obsolescence", "file", resource_id(path), Status.UNKNOWN,
            "MEDIUM", evidence, "FORMAT_NOT_IDENTIFIED",
        )

    selected = matches[0]
    puid = str(selected.get("id", ""))
    evidence.update({
        "puid": puid,
        "format": str(selected.get("format", "")),
        "format_version": str(selected.get("version", "")),
        "mime": str(selected.get("mime", "")),
        "identification_warning": str(selected.get("warning", "")),
    })
    rule = next(
        (item for item in rules if item.puid == puid and extension in item.extensions),
        None,
    )
    if rule is None:
        evidence["risk"] = "unclassified"
        return AuditResult(
            "format.obsolescence", "file", resource_id(path), Status.WARNING,
            "MEDIUM", evidence, "FORMAT_UNCLASSIFIED",
        )
    evidence.update({
        "risk": rule.risk,
        "risk_reason": rule.reason,
        "migration_target": rule.migration_target,
    })
    status = RISK_STATUS[rule.risk]
    error_code = None
    if status == Status.FAIL:
        error_code = "FORMAT_OBSOLESCENCE_RISK"
    elif status == Status.WARNING:
        error_code = "FORMAT_OBSOLESCENCE_WARNING"
    if selected.get("warning") and status == Status.PASS:
        status = Status.WARNING
        error_code = "FORMAT_IDENTIFICATION_WEAK"
    return AuditResult(
        "format.obsolescence", "file", resource_id(path), status,
        "HIGH" if status == Status.FAIL else "MEDIUM" if status == Status.WARNING else "LOW",
        evidence, error_code,
    )


def load_siegfried_report(path: Path) -> list[dict]:
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ObsolescenceError("siegfried_report_too_large")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ObsolescenceError("invalid_siegfried_report") from error
    files = raw.get("files") if isinstance(raw, dict) else None
    if not isinstance(files, list):
        raise ObsolescenceError("invalid_siegfried_report")
    return [item for item in files if isinstance(item, dict)]


def generate_siegfried_report(root: Path, binary: str, output_directory: Path) -> Path:
    executable = shutil.which(binary) if os.sep not in binary else binary
    if not executable or not Path(executable).is_file():
        raise ObsolescenceError("siegfried_not_found")
    output_directory.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix="siegfried-", suffix=".json", dir=output_directory
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            process = subprocess.run(
                [executable, "-json", "-z", str(root.resolve(strict=True))],
                stdout=output, stderr=subprocess.DEVNULL, check=False, timeout=86400,
            )
        if process.returncode != 0:
            raise ObsolescenceError("siegfried_failed")
        return Path(name)
    except Exception:
        Path(name).unlink(missing_ok=True)
        raise


class ObsolescenceAuditor:
    def __init__(self, database: Database, logger):
        self.database = database
        self.logger = logger

    def check(
        self, *, root: Path, policy_path: Path, report_path: Path | None,
        siegfried_binary: str,
    ) -> tuple[str, list[AuditResult], bool]:
        run_id = str(uuid.uuid4())
        started = time.monotonic()
        self.database.create_run(run_id, "obsolescence", datetime.now(timezone.utc).isoformat())
        log_event(self.logger, action="job.obsolescence_check", result="started",
                  resource="dataverse_payloads", run_id=run_id)
        generated: Path | None = None
        try:
            version, rules = load_policy(policy_path)
            if report_path is None:
                generated = generate_siegfried_report(
                    root, siegfried_binary, self.database.path.parent
                )
                report_path = generated
            results = [
                result for record in load_siegfried_report(report_path)
                if (result := classify_record(
                    record, root=root, policy_version=version, rules=rules
                )) is not None
            ]
            complete = bool(results) and all(item.status != Status.UNKNOWN for item in results)
            self.database.save_results(run_id, results)
            if not results or not complete or any(item.status == Status.FAIL for item in results):
                status = "FAIL"
            elif any(item.status == Status.WARNING for item in results):
                status = "WARNING"
            else:
                status = "PASS"
            self.database.finish_run(
                run_id, status=status, scan_complete=complete,
                duration_seconds=time.monotonic() - started,
            )
            log_event(
                self.logger, action="job.obsolescence_check", result=status.lower(),
                resource="dataverse_payloads", run_id=run_id,
                extra={
                    "records_processed": len(results),
                    "pass": sum(item.status == Status.PASS for item in results),
                    "warnings": sum(item.status == Status.WARNING for item in results),
                    "fail": sum(item.status == Status.FAIL for item in results),
                    "unknown": sum(item.status == Status.UNKNOWN for item in results),
                    "empty": sum(item.error_code == "FORMAT_EMPTY_FILE" for item in results),
                    "scan_complete": complete,
                },
            )
            return run_id, results, complete
        except Exception as error:
            self.database.finish_run(
                run_id, status="FAIL", scan_complete=False,
                duration_seconds=time.monotonic() - started,
            )
            log_event(
                self.logger, action="job.obsolescence_check", result="failure",
                resource="dataverse_payloads", run_id=run_id,
                extra={"error_type": type(error).__name__},
            )
            raise
        finally:
            if generated is not None:
                generated.unlink(missing_ok=True)
