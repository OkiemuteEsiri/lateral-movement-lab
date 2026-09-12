# Methodology and Architecture

## Objective
This project demonstrates defensive analysis of lateral-movement telemetry using entirely synthetic data. It does not authenticate to hosts, enumerate networks, execute remote commands, create services, or deliver payloads.

## Processing flow
1. **Ingest** synthetic authentication and remote-management telemetry.
2. **Validate** exact schemas, controlled enumerations, timestamps, booleans, and duplicate identifiers.
3. **Assess** contextual risk using identity privilege, source trust, destination criticality, access behavior, and detective-control coverage.
4. **Map** relevant observations to MITRE ATT&CK Remote Services sub-techniques.
5. **Prioritize** deterministically by bounded risk score.
6. **Report** analyst-readable rationale and remediation guidance.
7. **Validate closure** only when accountable ownership, change evidence, security review, detection retest, and a passing validation result exist.

## Trust boundaries
Input telemetry is untrusted until it passes strict validation. Risk scoring is deterministic and transparent; no external reputation service or production data source is required. Generated reports are evidence summaries, not proof of compromise.

## Risk model
The 0–100 score increases for successful remote access, privileged identities, unmanaged source hosts, interactive sessions, administrative-share access, remote-service creation, and high-value destinations. Existing detective controls reduce contextual exposure modestly but never erase underlying technical risk.

## ATT&CK mappings
- T1021.001 — Remote Desktop Protocol
- T1021.002 — SMB/Windows Admin Shares
- T1021.004 — SSH
- T1021.006 — Windows Remote Management

ATT&CK mapping provides defensive threat-model context. A mapped event is not automatically malicious.

## Remediation workflow
Typical response actions include restricting remote-management paths, reducing privilege, enforcing managed jump hosts, hardening administrative shares, improving endpoint/network telemetry, and retesting the control. Closure requires evidence, not an analyst status change alone.

## Limitations
This lab does not implement graph-wide sequence correlation, identity-provider enrichment, EDR API integration, network-flow baselining, or real-time streaming. Those capabilities are appropriate roadmap items for a production implementation.
