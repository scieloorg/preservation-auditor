from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .audit_log import log_event
from .database import Database
from .integrity import IntegrityAuditor, hash_file, resource_id
from .replicas import (
    REQUIRED_REPLICAS,
    ReplicaEvidence,
    ReplicaVerificationError,
    load_replica_targets,
    verify_replicas,
)


IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CHECKSUM_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
RECEIPT_FIELDS = {
    "schema_version",
    "event_id",
    "aip_id",
    "ingest_status",
    "relative_path",
    "object_key",
    "algorithm",
    "checksum",
    "size_bytes",
    "completed_at",
    "signature",
}


class AutoBaselineError(RuntimeError):
    pass


def safe_error_code(error: BaseException) -> str:
    if isinstance(error, (AutoBaselineError, ReplicaVerificationError)):
        return str(error).split(":", 1)[0]
    return type(error).__name__


@dataclass(frozen=True)
class ArchivematicaReceipt:
    event_id: str
    aip_id: str
    ingest_status: str
    relative_path: str
    object_key: str
    algorithm: str
    checksum: str
    size_bytes: int
    completed_at: str
    replica_object_keys: Optional[Dict[str, str]] = None


def _canonical_payload(raw: Dict[str, Any]) -> bytes:
    payload = {key: value for key, value in raw.items() if key != "signature"}
    return json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def load_signed_receipt(path: Path, signing_key: bytes) -> ArchivematicaReceipt:
    if len(signing_key) < 32:
        raise AutoBaselineError("receipt_signing_key_too_short")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AutoBaselineError("invalid_receipt") from error
    if not isinstance(raw, dict):
        raise AutoBaselineError("invalid_receipt")
    version = raw.get("schema_version")
    fields = RECEIPT_FIELDS | ({"replica_object_keys"} if version == 2 else set())
    if type(version) is not int or version not in (1, 2) or set(raw) != fields:
        raise AutoBaselineError("unsupported_receipt_schema")
    string_fields = RECEIPT_FIELDS - {"schema_version", "size_bytes"}
    if any(not isinstance(raw.get(field), str) for field in string_fields):
        raise AutoBaselineError("invalid_receipt_fields")
    if type(raw.get("size_bytes")) is not int:
        raise AutoBaselineError("invalid_receipt_fields")

    signature = raw.get("signature")
    if not isinstance(signature, str) or not CHECKSUM_PATTERN.fullmatch(signature):
        raise AutoBaselineError("invalid_receipt_signature")
    expected = hmac.new(signing_key, _canonical_payload(raw), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature.lower(), expected):
        raise AutoBaselineError("receipt_signature_mismatch")

    try:
        receipt = ArchivematicaReceipt(
            event_id=str(raw["event_id"]),
            aip_id=str(raw["aip_id"]),
            ingest_status=str(raw["ingest_status"]),
            relative_path=str(raw["relative_path"]),
            object_key=str(raw["object_key"]),
            algorithm=str(raw["algorithm"]).lower(),
            checksum=str(raw["checksum"]).lower(),
            size_bytes=raw["size_bytes"],
            completed_at=str(raw["completed_at"]),
            replica_object_keys=raw.get("replica_object_keys"),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise AutoBaselineError("invalid_receipt_fields") from error
    if version == 2:
        keys = receipt.replica_object_keys
        if not isinstance(keys, dict) or set(keys) != REQUIRED_REPLICAS:
            raise AutoBaselineError("invalid_replica_object_keys")
        if any(not isinstance(key, str) or not key or len(key.encode("utf-8")) > 1024
               or any(ord(c) < 32 for c in key) for key in keys.values()):
            raise AutoBaselineError("invalid_replica_object_keys")
    _validate_receipt(receipt)
    return receipt


def _validate_receipt(receipt: ArchivematicaReceipt) -> None:
    if not IDENTIFIER_PATTERN.fullmatch(receipt.event_id):
        raise AutoBaselineError("invalid_event_id")
    if not IDENTIFIER_PATTERN.fullmatch(receipt.aip_id):
        raise AutoBaselineError("invalid_aip_id")
    if receipt.ingest_status != "COMPLETED":
        raise AutoBaselineError("ingest_not_completed")
    if receipt.algorithm != "sha256" or not CHECKSUM_PATTERN.fullmatch(
        receipt.checksum
    ):
        raise AutoBaselineError("invalid_checksum")
    if receipt.size_bytes < 0:
        raise AutoBaselineError("invalid_size")
    relative = Path(receipt.relative_path)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise AutoBaselineError("invalid_relative_path")
    if (
        not receipt.object_key
        or len(receipt.object_key.encode("utf-8")) > 1024
        or any(ord(character) < 32 for character in receipt.object_key)
    ):
        raise AutoBaselineError("invalid_object_key")
    try:
        completed_at = datetime.fromisoformat(receipt.completed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise AutoBaselineError("invalid_completed_at") from error
    if completed_at.tzinfo is None:
        raise AutoBaselineError("completed_at_without_timezone")


def signing_key_from_environment(name: str) -> bytes:
    value = os.environ.get(name)
    if value is None:
        raise AutoBaselineError("missing_receipt_signing_key")
    return value.encode("utf-8")


class AutoBaselineJob:
    def __init__(
        self,
        database: Database,
        logger,
        *,
        replica_verifier: Callable[..., List[ReplicaEvidence]] = verify_replicas,
    ):
        self.database = database
        self.logger = logger
        self.replica_verifier = replica_verifier

    def run(
        self,
        *,
        receipt_path: Path,
        aip_root: Path,
        replicas_config: Path,
        signing_key_env: str,
        max_receipt_age_seconds: int,
        enforce_receipt_age: bool = True,
    ) -> Dict[str, Any]:
        run_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        started_monotonic = time.monotonic()
        self.database.create_run(run_id, "baseline_auto", started_at)
        log_event(
            self.logger,
            action="job.baseline_auto",
            result="started",
            resource="integrity_baseline",
            run_id=run_id,
        )
        receipt: Optional[ArchivematicaReceipt] = None
        try:
            receipt = load_signed_receipt(
                receipt_path, signing_key_from_environment(signing_key_env)
            )
            completed_at = datetime.fromisoformat(
                receipt.completed_at.replace("Z", "+00:00")
            )
            age_seconds = (datetime.now(timezone.utc) - completed_at).total_seconds()
            if age_seconds < -300:
                raise AutoBaselineError("receipt_completed_at_in_future")
            if enforce_receipt_age and age_seconds > max_receipt_age_seconds:
                raise AutoBaselineError("receipt_expired")
            already_registered = self.database.baseline_event_exists(receipt.event_id)

            root = aip_root.resolve(strict=True)
            relative_path = Path(receipt.relative_path)
            candidate = root
            for part in relative_path.parts:
                candidate = candidate / part
                if candidate.is_symlink():
                    raise AutoBaselineError("aip_symlink_not_allowed")
            local_path = candidate.resolve(strict=True)
            try:
                local_path.relative_to(root)
            except ValueError as error:
                raise AutoBaselineError("aip_outside_root") from error
            if local_path.is_symlink() or not local_path.is_file():
                raise AutoBaselineError("invalid_aip_file")

            checksum, size_bytes = hash_file(local_path)
            if checksum != receipt.checksum:
                raise AutoBaselineError("local_checksum_mismatch")
            if size_bytes != receipt.size_bytes:
                raise AutoBaselineError("local_size_mismatch")

            targets = load_replica_targets(replicas_config)
            replica_evidence = self.replica_verifier(
                targets,
                object_key=receipt.object_key,
                expected_size=receipt.size_bytes,
                expected_checksum=receipt.checksum,
                **({"object_keys": receipt.replica_object_keys}
                   if receipt.replica_object_keys is not None else {}),
            )
            rid = resource_id(receipt.relative_path)
            if already_registered:
                if not self.database.automatic_baseline_matches(
                    event_id=receipt.event_id,
                    aip_id=receipt.aip_id,
                    relative_path=receipt.relative_path,
                    checksum=receipt.checksum,
                    size_bytes=receipt.size_bytes,
                ):
                    raise AutoBaselineError("receipt_event_conflict")
                created = False
            else:
                created = self.database.add_automatic_baseline(
                    resource_id=rid,
                    relative_path=receipt.relative_path,
                    checksum=receipt.checksum,
                    size_bytes=receipt.size_bytes,
                    event_id=receipt.event_id,
                    aip_id=receipt.aip_id,
                    completed_at=receipt.completed_at,
                    replicas=replica_evidence,
                )
                if not created:
                    raise AutoBaselineError("baseline_already_exists")

            integrity = IntegrityAuditor(self.database, self.logger)
            check_run_id, check_results, scan_complete = integrity.check(root)
            conforming = scan_complete and all(
                item.status.value == "PASS" for item in check_results
            )
            self.database.finish_run(
                run_id,
                status="PASS" if conforming else "WARNING",
                scan_complete=scan_complete,
                duration_seconds=time.monotonic() - started_monotonic,
            )
            log_event(
                self.logger,
                action="job.baseline_auto",
                result="success" if conforming else "warning",
                resource="integrity_baseline",
                resource_id=rid,
                run_id=run_id,
                extra={
                    "aip_id": receipt.aip_id,
                    "event_id": receipt.event_id,
                    "replicas_verified": len(replica_evidence),
                    "baseline_created": created,
                    "baseline_already_registered": already_registered,
                    "integrity_run_id": check_run_id,
                    "scan_complete": scan_complete,
                },
            )
            return {
                "run_id": run_id,
                "integrity_run_id": check_run_id,
                "aip_id": receipt.aip_id,
                "baseline_created": created,
                "baseline_already_registered": already_registered,
                "replicas_verified": [item.name for item in replica_evidence],
                "integrity_conforming": conforming,
            }
        except (AutoBaselineError, ReplicaVerificationError, OSError, RuntimeError) as error:
            self.database.finish_run(
                run_id,
                status="FAIL",
                scan_complete=False,
                duration_seconds=time.monotonic() - started_monotonic,
            )
            log_event(
                self.logger,
                action="job.baseline_auto",
                result="failure",
                resource="integrity_baseline",
                resource_id=(resource_id(receipt.relative_path) if receipt else None),
                run_id=run_id,
                extra={"error_code": safe_error_code(error)},
            )
            raise
