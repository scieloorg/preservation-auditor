from __future__ import annotations

import json
import logging
import logging.handlers
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


SENSITIVE_FIELDS = {
    "password", "senha", "pwd", "token", "secret", "api_key", "authorization"
}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "***" if key.lower() in SENSITIVE_FIELDS else _sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


def configure_audit_logging(path: Path) -> logging.Logger:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600, exist_ok=True)
    os.chmod(path, 0o600)

    logger = logging.getLogger("preservation_audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.handlers.TimedRotatingFileHandler(
            path, when="midnight", backupCount=90, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


def log_event(
    logger: logging.Logger,
    *,
    action: str,
    result: str,
    resource: str,
    resource_id: Optional[str] = None,
    run_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": None,
        "ip_address": None,
        "session_id": None,
        "action": action,
        "resource": resource,
        "resource_id": resource_id,
        "run_id": run_id,
        "result": result,
        "before": None,
        "after": None,
        "extra": _sanitize(extra or {}),
    }
    logger.info(json.dumps(entry, ensure_ascii=True, sort_keys=True))
