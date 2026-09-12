from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Tuple


@dataclass(frozen=True)
class AuthEvent:
    event_id: str
    timestamp: datetime
    source_host: str
    destination_host: str
    user: str
    protocol: str
    success: bool
    privileged_user: bool
    source_managed: bool
    destination_criticality: str
    interactive_logon: bool
    admin_share_access: bool
    remote_service_created: bool
    detection_control_present: bool


@dataclass(frozen=True)
class Finding:
    finding_id: str
    event_id: str
    title: str
    risk_score: int
    severity: str
    rationale: Tuple[str, ...]
    attack_techniques: Tuple[str, ...]
    source_host: str
    destination_host: str
    user: str
    protocol: str


@dataclass(frozen=True)
class ClosureEvidence:
    finding_id: str
    owner: str
    change_reference: str
    control_change: str
    destination_validated: bool
    identity_reviewed: bool
    detection_retested: bool
    validation_passed: bool
