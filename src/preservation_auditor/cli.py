from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .auto_baseline import AutoBaselineError, AutoBaselineJob, safe_error_code
from .audit_log import configure_audit_logging
from .bagit import BagItAuditor
from .database import Database
from .integrity import IntegrityAuditor
from .metrics import render_metrics, serve
from .models import Status
from .replicas import ReplicaVerificationError
from .replica_audit import ReplicaAuditor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="preservation-auditor")
    parser.add_argument(
        "--database",
        default=os.environ.get("PRESERVATION_DB_PATH", "./data/audit.db"),
    )
    parser.add_argument(
        "--audit-log",
        default=os.environ.get("PRESERVATION_AUDIT_LOG", "./data/audit.log"),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    baseline = commands.add_parser("baseline", help="Registra apenas arquivos novos")
    baseline.add_argument("directory", type=Path)

    baseline_auto = commands.add_parser(
        "baseline-auto",
        help="Registra um AIP validado pelo Archivematica e pelas tres replicas",
    )
    baseline_auto.add_argument("--receipt", required=True, type=Path)
    baseline_auto.add_argument(
        "--aip-root",
        type=Path,
        default=os.environ.get("PRESERVATION_AIP_ROOT"),
    )
    baseline_auto.add_argument(
        "--replicas-config",
        type=Path,
        default=os.environ.get("PRESERVATION_REPLICAS_CONFIG"),
    )
    baseline_auto.add_argument(
        "--signing-key-env",
        default="PRESERVATION_RECEIPT_HMAC_KEY",
    )
    baseline_auto.add_argument(
        "--max-receipt-age-seconds",
        type=int,
        default=int(os.environ.get("PRESERVATION_MAX_RECEIPT_AGE", "86400")),
    )

    check = commands.add_parser("check", help="Compara arquivos com o baseline")
    check.add_argument("directory", type=Path)

    check_replicas = commands.add_parser(
        "check-replicas", help="Verifica novamente as replicas registradas"
    )
    check_replicas.add_argument(
        "--replicas-config",
        type=Path,
        default=os.environ.get("PRESERVATION_REPLICAS_CONFIG"),
    )

    check_bagits = commands.add_parser(
        "check-bagits", help="Valida pacotes BagIt do Dataverse"
    )
    check_bagits.add_argument(
        "directory",
        type=Path,
        nargs="?",
        default=os.environ.get("PRESERVATION_BAGIT_ROOT"),
    )

    commands.add_parser("metrics", help="Imprime metricas Prometheus")

    server = commands.add_parser("serve", help="Expoe /metrics, /health e /ready")
    server.add_argument(
        "--host", default=os.environ.get("PRESERVATION_LISTEN_HOST", "127.0.0.1")
    )
    server.add_argument(
        "--port", type=int,
        default=int(os.environ.get("PRESERVATION_LISTEN_PORT", "9877")),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    database = Database(Path(args.database))
    logger = configure_audit_logging(Path(args.audit_log))
    auditor = IntegrityAuditor(database, logger)

    if args.command == "baseline":
        result = auditor.create_baseline(args.directory)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        raise SystemExit(0 if result["failed"] == 0 else 2)
    if args.command == "baseline-auto":
        if args.aip_root is None or args.replicas_config is None:
            raise SystemExit("aip-root e replicas-config sao obrigatorios")
        if not 60 <= args.max_receipt_age_seconds <= 604800:
            raise SystemExit("max-receipt-age-seconds deve estar entre 60 e 604800")
        try:
            result = AutoBaselineJob(database, logger).run(
                receipt_path=args.receipt,
                aip_root=args.aip_root,
                replicas_config=args.replicas_config,
                signing_key_env=args.signing_key_env,
                max_receipt_age_seconds=args.max_receipt_age_seconds,
            )
        except (AutoBaselineError, ReplicaVerificationError, OSError, RuntimeError) as error:
            print(
                json.dumps(
                    {"status": "failure", "error_code": safe_error_code(error)},
                    ensure_ascii=True,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            raise SystemExit(2)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        raise SystemExit(0 if result["integrity_conforming"] else 2)
    if args.command == "check":
        run_id, results, complete = auditor.check(args.directory)
        summary = {
            "run_id": run_id,
            "scan_complete": complete,
            "total": len(results),
            "pass": sum(item.status == Status.PASS for item in results),
            "fail": sum(item.status == Status.FAIL for item in results),
            "warning": sum(item.status == Status.WARNING for item in results),
            "unknown": sum(item.status == Status.UNKNOWN for item in results),
        }
        print(json.dumps(summary, ensure_ascii=True, sort_keys=True))
        conforming = complete and all(
            summary[key] == 0 for key in ("fail", "warning", "unknown")
        )
        raise SystemExit(0 if conforming else 2)
    if args.command == "check-replicas":
        if args.replicas_config is None:
            raise SystemExit("replicas-config e obrigatorio")
        try:
            run_id, results, complete = ReplicaAuditor(database, logger).check(
                args.replicas_config
            )
        except (ReplicaVerificationError, OSError, RuntimeError) as error:
            print(
                json.dumps(
                    {"status": "failure", "error_code": type(error).__name__},
                    ensure_ascii=True,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            raise SystemExit(2)
        summary = {
            "run_id": run_id,
            "scan_complete": complete,
            "total": len(results),
            "valid": sum(item.status == Status.PASS for item in results),
            "failed": sum(item.status == Status.FAIL for item in results),
            "unknown": sum(item.status == Status.UNKNOWN for item in results),
        }
        print(json.dumps(summary, ensure_ascii=True, sort_keys=True))
        raise SystemExit(0 if complete and summary["failed"] == 0 else 2)
    if args.command == "check-bagits":
        if args.directory is None:
            raise SystemExit("directory ou PRESERVATION_BAGIT_ROOT e obrigatorio")
        run_id, results, complete = BagItAuditor(database, logger).check(args.directory)
        summary = {
            "run_id": run_id,
            "scan_complete": complete,
            "total": len(results),
            "valid": sum(item.status == Status.PASS for item in results),
            "invalid": sum(item.status == Status.FAIL for item in results),
            "unknown": sum(item.status == Status.UNKNOWN for item in results),
        }
        print(json.dumps(summary, ensure_ascii=True, sort_keys=True))
        raise SystemExit(
            0 if results and complete and summary["invalid"] == 0 else 2
        )
    if args.command == "metrics":
        print(render_metrics(database), end="")
        return
    if args.command == "serve":
        if not 1 <= args.port <= 65535:
            raise SystemExit("porta invalida")
        serve(database, args.host, args.port)


if __name__ == "__main__":
    main()
