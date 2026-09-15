from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .models import AuditResult
from .replicas import ReplicaEvidence


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS integrity_baselines (
    resource_id TEXT PRIMARY KEY,
    relative_path TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL CHECK (algorithm IN ('sha256')),
    checksum TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_runs (
    run_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    scan_complete INTEGER NOT NULL DEFAULT 0,
    duration_seconds REAL
);
CREATE TABLE IF NOT EXISTS audit_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
    control TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    error_code TEXT,
    checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_results_run_idx ON audit_results(run_id);
CREATE INDEX IF NOT EXISTS audit_results_status_idx ON audit_results(status);
CREATE TABLE IF NOT EXISTS baseline_events (
    event_id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL UNIQUE REFERENCES integrity_baselines(resource_id),
    aip_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('archivematica')),
    completed_at TEXT NOT NULL,
    registered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS replica_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL REFERENCES baseline_events(event_id),
    replica_name TEXT NOT NULL,
    bucket TEXT NOT NULL,
    object_key TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    checksum_verified INTEGER NOT NULL CHECK (checksum_verified IN (0, 1)),
    verified_at TEXT NOT NULL,
    UNIQUE(event_id, replica_name)
);
CREATE INDEX IF NOT EXISTS replica_verifications_event_idx
    ON replica_verifications(event_id);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch(mode=0o600)
        os.chmod(self.path, 0o600)
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
            connection.commit()
        finally:
            connection.close()

    def create_run(self, run_id: str, kind: str, started_at: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO audit_runs(run_id, kind, started_at, status) VALUES (?, ?, ?, ?)",
                (run_id, kind, started_at, "RUNNING"),
            )

    def finish_run(
        self, run_id: str, *, status: str, scan_complete: bool, duration_seconds: float
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """UPDATE audit_runs
                   SET finished_at = ?, status = ?, scan_complete = ?, duration_seconds = ?
                   WHERE run_id = ?""",
                (
                    datetime.now(timezone.utc).isoformat(), status, int(scan_complete),
                    duration_seconds, run_id,
                ),
            )

    def add_baseline(
        self, *, resource_id: str, relative_path: str, checksum: str, size_bytes: int
    ) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO integrity_baselines
                   (resource_id, relative_path, algorithm, checksum, size_bytes, created_at)
                   VALUES (?, ?, 'sha256', ?, ?, ?)""",
                (
                    resource_id, relative_path, checksum, size_bytes,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            return cursor.rowcount == 1

    def baselines(self) -> dict[str, sqlite3.Row]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM integrity_baselines").fetchall()
        return {row["relative_path"]: row for row in rows}

    def registered_replicas(self) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                """SELECT r.event_id, r.replica_name, r.bucket, r.object_key,
                          r.size_bytes, b.checksum, e.aip_id
                   FROM replica_verifications AS r
                   JOIN baseline_events AS e ON e.event_id = r.event_id
                   JOIN integrity_baselines AS b ON b.resource_id = e.resource_id
                   ORDER BY r.event_id, r.replica_name"""
            ).fetchall()

    def baseline_event_exists(self, event_id: str) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM baseline_events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return row is not None

    def automatic_baseline_matches(
        self,
        *,
        event_id: str,
        aip_id: str,
        relative_path: str,
        checksum: str,
        size_bytes: int,
    ) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT e.aip_id, b.relative_path, b.checksum, b.size_bytes
                   FROM baseline_events AS e
                   JOIN integrity_baselines AS b ON b.resource_id = e.resource_id
                   WHERE e.event_id = ?""",
                (event_id,),
            ).fetchone()
        return row is not None and (
            row["aip_id"], row["relative_path"], row["checksum"], row["size_bytes"]
        ) == (aip_id, relative_path, checksum, size_bytes)

    def add_automatic_baseline(
        self,
        *,
        resource_id: str,
        relative_path: str,
        checksum: str,
        size_bytes: int,
        event_id: str,
        aip_id: str,
        completed_at: str,
        replicas: list[ReplicaEvidence],
    ) -> bool:
        registered_at = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO integrity_baselines
                   (resource_id, relative_path, algorithm, checksum, size_bytes, created_at)
                   VALUES (?, ?, 'sha256', ?, ?, ?)""",
                (resource_id, relative_path, checksum, size_bytes, registered_at),
            )
            if cursor.rowcount != 1:
                return False
            connection.execute(
                """INSERT INTO baseline_events
                   (event_id, resource_id, aip_id, source, completed_at, registered_at)
                   VALUES (?, ?, ?, 'archivematica', ?, ?)""",
                (event_id, resource_id, aip_id, completed_at, registered_at),
            )
            connection.executemany(
                """INSERT INTO replica_verifications
                   (event_id, replica_name, bucket, object_key, size_bytes,
                    checksum_verified, verified_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        event_id,
                        item.name,
                        item.bucket,
                        item.object_key,
                        item.size_bytes,
                        int(item.checksum_verified),
                        registered_at,
                    )
                    for item in replicas
                ],
            )
        return True

    def save_results(self, run_id: str, results: list[AuditResult]) -> None:
        checked_at = datetime.now(timezone.utc).isoformat()
        values = [
            (
                run_id, item.control, item.resource_type, item.resource_id,
                item.status.value, item.severity,
                json.dumps(item.evidence, ensure_ascii=True, sort_keys=True),
                item.error_code, checked_at,
            )
            for item in results
        ]
        with self.connect() as connection:
            connection.executemany(
                """INSERT INTO audit_results
                   (run_id, control, resource_type, resource_id, status, severity,
                    evidence_json, error_code, checked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values,
            )

    def latest_integrity_metrics(self) -> dict[str, float]:
        with self.connect() as connection:
            run = connection.execute(
                """SELECT * FROM audit_runs
                   WHERE kind = 'integrity' AND finished_at IS NOT NULL
                   ORDER BY finished_at DESC LIMIT 1"""
            ).fetchone()
            baseline_count = connection.execute(
                "SELECT COUNT(*) AS value FROM integrity_baselines"
            ).fetchone()["value"]
            last_success = connection.execute(
                """SELECT finished_at FROM audit_runs
                   WHERE kind = 'integrity' AND status = 'PASS'
                     AND finished_at IS NOT NULL
                   ORDER BY finished_at DESC LIMIT 1"""
            ).fetchone()
            if run is None:
                return {"baselines_total": float(baseline_count)}
            counts = connection.execute(
                """SELECT status, error_code, COUNT(*) AS value
                   FROM audit_results WHERE run_id = ? GROUP BY status, error_code""",
                (run["run_id"],),
            ).fetchall()

        metrics: dict[str, float] = {
            "baselines_total": float(baseline_count),
            "valid": 0.0,
            "changed": 0.0,
            "missing": 0.0,
            "without_baseline": 0.0,
            "errors": 0.0,
            "scan_complete": float(run["scan_complete"]),
            "last_run_duration_seconds": float(run["duration_seconds"] or 0),
            "last_success_timestamp_seconds": 0.0,
        }
        if last_success is not None:
            metrics["last_success_timestamp_seconds"] = datetime.fromisoformat(
                last_success["finished_at"]
            ).timestamp()
        for row in counts:
            error_code = row["error_code"]
            value = float(row["value"])
            if row["status"] == "PASS":
                metrics["valid"] += value
            elif error_code == "CHECKSUM_MISMATCH":
                metrics["changed"] += value
            elif error_code == "FILE_MISSING":
                metrics["missing"] += value
            elif error_code == "NO_BASELINE":
                metrics["without_baseline"] += value
            else:
                metrics["errors"] += value
        return metrics

    def latest_auto_baseline_metrics(self) -> dict[str, float]:
        with self.connect() as connection:
            run = connection.execute(
                """SELECT status, finished_at, duration_seconds FROM audit_runs
                   WHERE kind = 'baseline_auto' AND finished_at IS NOT NULL
                   ORDER BY finished_at DESC LIMIT 1"""
            ).fetchone()
            last_success = connection.execute(
                """SELECT finished_at FROM audit_runs
                   WHERE kind = 'baseline_auto' AND status IN ('PASS', 'WARNING')
                     AND finished_at IS NOT NULL
                   ORDER BY finished_at DESC LIMIT 1"""
            ).fetchone()
            baseline_count = connection.execute(
                "SELECT COUNT(*) FROM baseline_events"
            ).fetchone()[0]
            replica_count = connection.execute(
                "SELECT COUNT(*) FROM replica_verifications"
            ).fetchone()[0]

        metrics = {
            "automatic_baselines_total": float(baseline_count),
            "replica_verifications_total": float(replica_count),
            "last_run_ok": 0.0,
            "last_run_timestamp_seconds": 0.0,
            "last_run_duration_seconds": 0.0,
            "last_success_timestamp_seconds": 0.0,
        }
        if run is not None:
            metrics["last_run_ok"] = float(run["status"] in {"PASS", "WARNING"})
            metrics["last_run_timestamp_seconds"] = datetime.fromisoformat(
                run["finished_at"]
            ).timestamp()
            metrics["last_run_duration_seconds"] = float(
                run["duration_seconds"] or 0
            )
        if last_success is not None:
            metrics["last_success_timestamp_seconds"] = datetime.fromisoformat(
                last_success["finished_at"]
            ).timestamp()
        return metrics

    def latest_replica_metrics(self) -> tuple[dict[str, float], dict[str, dict[str, float]]]:
        with self.connect() as connection:
            run = connection.execute(
                """SELECT run_id, status, scan_complete, finished_at, duration_seconds
                   FROM audit_runs
                   WHERE kind = 'replica_integrity' AND finished_at IS NOT NULL
                   ORDER BY finished_at DESC LIMIT 1"""
            ).fetchone()
            last_success = connection.execute(
                """SELECT finished_at FROM audit_runs
                   WHERE kind = 'replica_integrity' AND status = 'PASS'
                     AND finished_at IS NOT NULL
                   ORDER BY finished_at DESC LIMIT 1"""
            ).fetchone()
            rows = [] if run is None else connection.execute(
                """SELECT status, error_code, evidence_json
                   FROM audit_results
                   WHERE run_id = ? AND control = 'aip.replica_integrity'""",
                (run["run_id"],),
            ).fetchall()

        metrics = {
            "valid": 0.0,
            "missing": 0.0,
            "changed": 0.0,
            "unknown": 0.0,
            "scan_complete": float(run["scan_complete"]) if run else 0.0,
            "last_run_ok": float(run["status"] == "PASS") if run else 0.0,
            "last_run_timestamp_seconds": (
                datetime.fromisoformat(run["finished_at"]).timestamp() if run else 0.0
            ),
            "last_run_duration_seconds": float(run["duration_seconds"] or 0) if run else 0.0,
            "last_success_timestamp_seconds": (
                datetime.fromisoformat(last_success["finished_at"]).timestamp()
                if last_success else 0.0
            ),
        }
        providers: dict[str, dict[str, float]] = {}
        for row in rows:
            evidence = json.loads(row["evidence_json"])
            provider = str(evidence["replica_name"])
            provider_metrics = providers.setdefault(
                provider,
                {"valid": 0.0, "missing": 0.0, "changed": 0.0, "unknown": 0.0},
            )
            if row["status"] == "PASS":
                key = "valid"
            elif row["error_code"] == "REPLICA_MISSING":
                key = "missing"
            elif row["status"] == "FAIL":
                key = "changed"
            else:
                key = "unknown"
            metrics[key] += 1.0
            provider_metrics[key] += 1.0
        return metrics, providers
