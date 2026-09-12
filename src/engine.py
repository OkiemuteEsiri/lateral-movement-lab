from __future__ import annotations

import hashlib
from collections import Counter

from .models import AuthEvent, Finding

_ATTACK = {
    "RDP": ("T1021.001 - Remote Services: Remote Desktop Protocol",),
    "SMB": ("T1021.002 - Remote Services: SMB/Windows Admin Shares",),
    "WINRM": ("T1021.006 - Remote Services: Windows Remote Management",),
    "SSH": ("T1021.004 - Remote Services: SSH",),
}
_CRIT = {"low": 0, "medium": 6, "high": 12, "critical": 18}


def _finding_id(event: AuthEvent) -> str:
    material = f"{event.event_id}|{event.source_host}|{event.destination_host}|{event.user}|{event.protocol}"
    return "LM-" + hashlib.sha256(material.encode()).hexdigest()[:12].upper()


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def assess_event(event: AuthEvent) -> Finding | None:
    signals: list[str] = []
    score = 0
    if event.success:
        score += 20; signals.append("remote authentication succeeded")
    if event.privileged_user:
        score += 20; signals.append("privileged identity involved")
    if not event.source_managed:
        score += 16; signals.append("source host is unmanaged")
    if event.interactive_logon:
        score += 8; signals.append("interactive remote logon observed")
    if event.admin_share_access:
        score += 14; signals.append("administrative share access observed")
    if event.remote_service_created:
        score += 18; signals.append("remote service creation telemetry observed")
    score += _CRIT[event.destination_criticality]
    if event.destination_criticality in {"high", "critical"}:
        signals.append(f"destination criticality is {event.destination_criticality}")
    if event.detection_control_present:
        score -= 10; signals.append("detective control coverage present")
    score = max(0, min(100, score))
    if score < 20:
        return None
    return Finding(
        finding_id=_finding_id(event), event_id=event.event_id,
        title=f"Suspicious {event.protocol} lateral movement context",
        risk_score=score, severity=_severity(score), rationale=tuple(signals),
        attack_techniques=_ATTACK[event.protocol], source_host=event.source_host,
        destination_host=event.destination_host, user=event.user, protocol=event.protocol,
    )


def assess(events: list[AuthEvent]) -> list[Finding]:
    findings = [finding for event in events if (finding := assess_event(event)) is not None]
    return sorted(findings, key=lambda f: (-f.risk_score, f.finding_id))


def metrics(findings: list[Finding]) -> dict[str, object]:
    severities = Counter(f.severity for f in findings)
    protocols = Counter(f.protocol for f in findings)
    return {
        "total_findings": len(findings),
        "critical": severities["critical"], "high": severities["high"],
        "medium": severities["medium"], "low": severities["low"],
        "protocols": dict(sorted(protocols.items())),
        "unique_destination_hosts": len({f.destination_host for f in findings}),
        "unique_users": len({f.user for f in findings}),
    }
