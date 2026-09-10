from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .audit_log import configure_audit_logging
from .database import Database
from .integrity import IntegrityAuditor
from .metrics import render_metrics, serve
from .models import Status


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

    check = commands.add_parser("check", help="Compara arquivos com o baseline")
    check.add_argument("directory", type=Path)

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
    if args.command == "metrics":
        print(render_metrics(database), end="")
        return
    if args.command == "serve":
        if not 1 <= args.port <= 65535:
            raise SystemExit("porta invalida")
        serve(database, args.host, args.port)


if __name__ == "__main__":
    main()
