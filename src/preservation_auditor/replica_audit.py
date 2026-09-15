from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .audit_log import log_event
from .database import Database
from .models import AuditResult, Status
from .replicas import (
    ReplicaTarget,
    ReplicaVerificationError,
    load_replica_targets,
    verify_replicas,
)


Verifier = Callable[..., Any]


def _error_code(error: ReplicaVerificationError) -> tuple[Status, str]:
    code = str(error).split(":", 1)[0]
    if code == "replica_not_found":
        return Status.FAIL, "REPLICA_MISSING"
    if code == "replica_size_mismatch":
        return Status.FAIL, "REPLICA_SIZE_MISMATCH"
    if code == "replica_checksum_mismatch":
        return Status.FAIL, "REPLICA_CHECKSUM_MISMATCH"
    return Status.UNKNOWN, "REPLICA_CHECK_INCONCLUSIVE"


class ReplicaAuditor:
    def __init__(
        self,
        database: Database,
        logger,
        *,
        verifier: Verifier = verify_replicas,
    ):
        self.database = database
        self.logger = logger
        self.verifier = verifier

    def check(self, replicas_config: Path) -> tuple[str, list[AuditResult], bool]:
        run_id = str(uuid.uuid4())
        started = datetime.now(timezone.utc).isoformat()
        started_monotonic = time.monotonic()
        self.database.create_run(run_id, "replica_integrity", started)
        log_event(
            self.logger,
            action="job.replica_integrity_check",
            result="started",
            resource="preservation_replica",
            run_id=run_id,
        )
        results: list[AuditResult] = []
        try:
            targets = {item.name: item for item in load_replica_targets(replicas_config)}
            for replica in self.database.registered_replicas():
                name = replica["replica_name"]
                evidence = {
                    "aip_id": replica["aip_id"],
                    "event_id": replica["event_id"],
                    "replica_name": name,
                    "bucket": replica["bucket"],
                    "object_key": replica["object_key"],
                    "expected_size_bytes": replica["size_bytes"],
                    "algorithm": "sha256",
                }
                target: ReplicaTarget | None = targets.get(name)
                if target is None or target.bucket != replica["bucket"]:
                    results.append(AuditResult(
                        "aip.replica_integrity", "replica",
                        "{}:{}".format(replica["event_id"], name),
                        Status.UNKNOWN, "CRITICAL", evidence,
                        "REPLICA_CONFIG_MISMATCH",
                    ))
                    continue
                try:
                    verified = self.verifier(
                        [target],
                        object_key=replica["object_key"],
                        expected_size=replica["size_bytes"],
                        expected_checksum=replica["checksum"],
                    )[0]
                    evidence["observed_size_bytes"] = verified.size_bytes
                    evidence["checksum_verified"] = verified.checksum_verified
                    results.append(AuditResult(
                        "aip.replica_integrity", "replica",
                        "{}:{}".format(replica["event_id"], name),
                        Status.PASS, "CRITICAL", evidence,
                    ))
                except ReplicaVerificationError as error:
                    status, error_code = _error_code(error)
                    results.append(AuditResult(
                        "aip.replica_integrity", "replica",
                        "{}:{}".format(replica["event_id"], name),
                        status, "CRITICAL", evidence, error_code,
                    ))

            scan_complete = all(item.status != Status.UNKNOWN for item in results)
            self.database.save_results(run_id, results)
            status = "PASS" if all(item.status == Status.PASS for item in results) else "FAIL"
            self.database.finish_run(
                run_id,
                status=status,
                scan_complete=scan_complete,
                duration_seconds=time.monotonic() - started_monotonic,
            )
            log_event(
                self.logger,
                action="job.replica_integrity_check",
                result=status.lower(),
                resource="preservation_replica",
                run_id=run_id,
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
                run_id,
                status="FAIL",
                scan_complete=False,
                duration_seconds=time.monotonic() - started_monotonic,
            )
            log_event(
                self.logger,
                action="job.replica_integrity_check",
                result="failure",
                resource="preservation_replica",
                run_id=run_id,
                extra={"error_type": type(error).__name__},
            )
            raise
