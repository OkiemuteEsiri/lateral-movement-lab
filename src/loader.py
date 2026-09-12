from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .models import AuthEvent

_ALLOWED_PROTOCOLS = {"RDP", "SMB", "WINRM", "SSH"}
_ALLOWED_CRITICALITY = {"low", "medium", "high", "critical"}
_REQUIRED = {
    "event_id", "timestamp", "source_host", "destination_host", "user", "protocol",
    "success", "privileged_user", "source_managed", "destination_criticality",
    "interactive_logon", "admin_share_access", "remote_service_created",
    "detection_control_present"
}
_BOOL_FIELDS = {
    "success", "privileged_user", "source_managed", "interactive_logon",
    "admin_share_access", "remote_service_created", "detection_control_present"
}


def load_events(path: str | Path) -> list[AuthEvent]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("top-level telemetry must be a list")
    events: list[AuthEvent] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != _REQUIRED:
            raise ValueError(f"event {index}: schema mismatch")
        if item["event_id"] in seen:
            raise ValueError(f"duplicate event_id: {item['event_id']}")
        seen.add(item["event_id"])
        if item["protocol"] not in _ALLOWED_PROTOCOLS:
            raise ValueError(f"event {index}: unsupported protocol")
        if item["destination_criticality"] not in _ALLOWED_CRITICALITY:
            raise ValueError(f"event {index}: unsupported criticality")
        if any(type(item[field]) is not bool for field in _BOOL_FIELDS):
            raise ValueError(f"event {index}: boolean field type invalid")
        if any(not isinstance(item[field], str) or not item[field].strip() for field in
               ("event_id", "source_host", "destination_host", "user", "protocol")):
            raise ValueError(f"event {index}: required string is empty")
        try:
            ts = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"event {index}: invalid timestamp") from exc
        events.append(AuthEvent(timestamp=ts, **{k: v for k, v in item.items() if k != "timestamp"}))
    return events
