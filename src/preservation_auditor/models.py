from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class AuditResult:
    control: str
    resource_type: str
    resource_id: str
    status: Status
    severity: str
    evidence: dict[str, Any]
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        return result
