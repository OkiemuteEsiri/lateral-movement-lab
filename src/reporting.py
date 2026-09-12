from __future__ import annotations

from .engine import metrics
from .models import Finding


def render_markdown(findings: list[Finding]) -> str:
    m = metrics(findings)
    lines = [
        "# Lateral Movement Assessment",
        "",
        "> Synthetic defensive telemetry only. No live targeting or offensive execution is performed.",
        "",
        "## Executive Summary",
        "",
        f"- Total findings: **{m['total_findings']}**",
        f"- Critical: **{m['critical']}** | High: **{m['high']}** | Medium: **{m['medium']}** | Low: **{m['low']}**",
        f"- Unique destination hosts: **{m['unique_destination_hosts']}**",
        f"- Unique users: **{m['unique_users']}**",
        f"- Protocol coverage: **{m['protocols']}**",
        "",
        "## Prioritized Findings",
        "",
    ]
    for finding in findings:
        lines.extend([
            f"### {finding.finding_id} — {finding.title}",
            "",
            f"**Risk:** {finding.risk_score}/100 ({finding.severity.upper()})  ",
            f"**Path:** `{finding.source_host}` → `{finding.destination_host}`  ",
            f"**Identity:** `{finding.user}`  ",
            f"**Protocol:** `{finding.protocol}`",
            "",
            "**Risk rationale**",
            *[f"- {reason}" for reason in finding.rationale],
            "",
            "**MITRE ATT&CK context**",
            *[f"- {technique}" for technique in finding.attack_techniques],
            "",
            "**Recommended validation/remediation**",
            "- Confirm the remote access was expected and attributable to an approved workflow.",
            "- Restrict unnecessary remote-management reachability and administrative shares.",
            "- Review the identity's privilege and authentication context.",
            "- Validate destination hardening and endpoint/network detection coverage.",
            "- Retest telemetry after the control change before closing the finding.",
            "",
        ])
    return "\n".join(lines)
