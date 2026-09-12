from __future__ import annotations

import json
from pathlib import Path

from .models import ClosureEvidence

_REQUIRED = {
    "finding_id", "owner", "change_reference", "control_change",
    "destination_validated", "identity_reviewed", "detection_retested", "validation_passed"
}
_BOOL_FIELDS = {"destination_validated", "identity_reviewed", "detection_retested", "validation_passed"}


def load_closure_evidence(path: str | Path) -> list[ClosureEvidence]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("closure evidence must be a list")
    output: list[ClosureEvidence] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != _REQUIRED:
            raise ValueError(f"closure {index}: schema mismatch")
        if item["finding_id"] in seen:
            raise ValueError(f"duplicate closure finding_id: {item['finding_id']}")
        seen.add(item["finding_id"])
        if any(type(item[field]) is not bool for field in _BOOL_FIELDS):
            raise ValueError(f"closure {index}: boolean field type invalid")
        output.append(ClosureEvidence(**item))
    return output


def validate_closure(evidence: ClosureEvidence) -> tuple[str, list[str]]:
    gaps: list[str] = []
    for field in ("owner", "change_reference", "control_change"):
        if not getattr(evidence, field).strip():
            gaps.append(f"missing {field}")
    if not evidence.destination_validated:
        gaps.append("destination control state not validated")
    if not evidence.identity_reviewed:
        gaps.append("identity review incomplete")
    if not evidence.detection_retested:
        gaps.append("detection was not retested")
    if evidence.detection_retested and not evidence.validation_passed:
        return "invalid_closure", gaps + ["post-change validation failed"]
    if gaps:
        return "needs_evidence", gaps
    return "validated", []
