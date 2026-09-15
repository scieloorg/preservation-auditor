"""Read completed Storage Service packages using its installed Django models.

Run with the Storage Service Python and environment. No source database writes.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import posixpath
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .auto_baseline import (
    AutoBaselineError, AutoBaselineJob, _canonical_payload,
    load_signed_receipt, safe_error_code, signing_key_from_environment,
)
from .audit_log import configure_audit_logging
from .database import Database
from .replicas import load_replica_targets


def package_receipt(package, targets, root: Path, signing_key: bytes) -> dict:
    if len(signing_key) < 32:
        raise AutoBaselineError("receipt_signing_key_too_short")
    if (package.package_type != "AIP" or package.status != "UPLOADED"
            or package.replicated_package_id is not None
            or package.current_location.space.access_protocol != "FS"):
        raise AutoBaselineError("aip_not_completed_local_original")
    if package.checksum_algorithm != "sha256" or not package.checksum:
        raise AutoBaselineError("storage_checksum_unavailable")
    # Keep the stored checksum as the authority: baseline-auto compares disk to it.
    path = Path(package.full_path)
    relative = path.relative_to(root).as_posix()
    if ".." in Path(relative).parts:
        raise AutoBaselineError("aip_outside_root")
    keys = {}
    completed_dates = [package.stored_date]
    for replica in package.replicas.all():
        space = replica.current_location.space
        if space.access_protocol != "S3":
            continue
        s3 = space.s3
        # Archivematica uses the Space UUID as the physical bucket name when
        # the optional S3 bucket field is empty.
        storage_bucket = s3.bucket_name or str(space.uuid)
        matches = [t for t in targets
                   if t.endpoint_url.rstrip("/") == s3.endpoint_url.rstrip("/")
                   and t.bucket == storage_bucket]
        if not matches:
            continue
        if replica.status != "UPLOADED":
            raise AutoBaselineError("replica_not_uploaded")
        if (replica.size != package.size or replica.checksum != package.checksum
                or replica.checksum_algorithm != "sha256"):
            raise AutoBaselineError("replica_storage_checksum_mismatch")
        name = matches[0].name
        if name in keys:
            raise AutoBaselineError("ambiguous_replica")
        keys[name] = posixpath.join(replica.current_location.relative_path,
                                   replica.current_path)
        completed_dates.append(replica.stored_date)
    if set(keys) != {t.name for t in targets}:
        raise AutoBaselineError("replicas_not_complete")
    if any(d is None or d.tzinfo is None for d in completed_dates):
        raise AutoBaselineError("storage_completion_date_unavailable")
    receipt = {
        "schema_version": 2,
        "event_id": "archivematica-" + str(package.uuid),
        "aip_id": str(package.uuid), "ingest_status": "COMPLETED",
        "relative_path": relative, "object_key": relative,
        "replica_object_keys": keys, "algorithm": "sha256",
        "checksum": package.checksum, "size_bytes": package.size,
        "completed_at": max(completed_dates).astimezone(timezone.utc).isoformat(),
    }
    receipt["signature"] = hmac.new(
        signing_key, _canonical_payload(receipt), hashlib.sha256
    ).hexdigest()
    return receipt


def publish_receipt(inbox: Path, raw: dict, key: bytes) -> Path:
    """Publish without overwriting an existing signed event, even on a race."""
    destination = inbox / (raw["event_id"] + ".json")
    fd, name = tempfile.mkstemp(prefix=".receipt-", dir=inbox)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(raw, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        load_signed_receipt(temporary, key)
        try:
            os.link(temporary, destination)
            directory = os.open(inbox, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except FileExistsError:
            load_signed_receipt(destination, key)
            if json.loads(destination.read_text()) != raw:
                raise AutoBaselineError("receipt_event_conflict")
        return destination
    finally:
        temporary.unlink()


def collect(packages, *, state: Path, root: Path, targets, config: Path,
            database: Database, logger, max_age: int, dry_run: bool = False) -> dict:
    key = signing_key_from_environment("PRESERVATION_RECEIPT_HMAC_KEY")
    if len(key) < 32:
        raise AutoBaselineError("receipt_signing_key_too_short")
    if not 60 <= max_age <= 604800:
        raise AutoBaselineError("invalid_max_receipt_age")
    summary = {"candidates": 0, "registered": 0, "skipped": 0, "failed": 0}
    for package in packages:
        summary["candidates"] += 1
        event = "archivematica-" + str(package.uuid)
        if database.baseline_event_exists(event):
            summary["skipped"] += 1
            continue
        try:
            raw = package_receipt(package, targets, root, key)
            if dry_run:
                print(json.dumps({"event_id": event, "status": "ready"}))
                continue
            receipt_path = publish_receipt(state / "inbox", raw, key)
            result = AutoBaselineJob(database, logger).run(
                receipt_path=receipt_path, aip_root=root, replicas_config=config,
                signing_key_env="PRESERVATION_RECEIPT_HMAC_KEY",
                max_receipt_age_seconds=max_age,
                enforce_receipt_age=False,
            )
            summary["registered"] += int(result["baseline_created"])
            if not result["integrity_conforming"]:
                summary["failed"] += 1
            print(json.dumps({"event_id": event, "result": result}))
        except Exception as error:
            summary["failed"] += 1
            print(json.dumps({"event_id": event, "status": "pending",
                              "error_code": safe_error_code(error)}), flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    since = datetime.fromisoformat(os.environ["PRESERVATION_ARCHIVEMATICA_SINCE"])
    if since.tzinfo is None:
        raise SystemExit("PRESERVATION_ARCHIVEMATICA_SINCE precisa de fuso horario")
    state = Path(os.environ.get("PRESERVATION_STATE_DIR", "/var/lib/preservation-auditor"))
    with (state / "archivematica.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("archivematica_collector_already_running")
        import django
        from django.db.backends.signals import connection_created

        def read_only_connection(sender, connection, **kwargs):
            with connection.cursor() as cursor:
                if connection.vendor == "mysql":
                    cursor.execute("SET SESSION TRANSACTION READ ONLY")
                elif connection.vendor == "sqlite":
                    cursor.execute("PRAGMA query_only = ON")
                else:
                    raise RuntimeError("unsupported_storage_database")

        connection_created.connect(read_only_connection, weak=False)
        django.setup()
        from archivematica.storage_service.locations.models import Package

        packages = Package.objects.filter(
            package_type="AIP", status="UPLOADED", replicated_package__isnull=True,
            stored_date__gte=since, current_location__space__access_protocol="FS",
        ).select_related("current_location__space").prefetch_related(
            "replicas__current_location__space__s3"
        ).order_by("stored_date", "uuid").iterator(chunk_size=100)
        config = Path(os.environ["PRESERVATION_REPLICAS_CONFIG"])
        summary = collect(
            packages, state=state, root=Path(os.environ["PRESERVATION_AIP_ROOT"]),
            targets=load_replica_targets(config), config=config,
            database=Database(Path(os.environ["PRESERVATION_DB_PATH"])),
            logger=configure_audit_logging(Path(os.environ["PRESERVATION_AUDIT_LOG"])),
            max_age=int(os.environ.get("PRESERVATION_MAX_RECEIPT_AGE", "86400")),
            dry_run=args.dry_run,
        )
        print(json.dumps(summary), flush=True)
        raise SystemExit(2 if summary["failed"] else 0)


if __name__ == "__main__":
    main()
