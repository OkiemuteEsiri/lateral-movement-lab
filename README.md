# Lateral Movement Detection & Validation Lab

A defensive security-engineering project for analyzing synthetic remote-access telemetry, prioritizing suspicious lateral-movement paths, mapping relevant observations to MITRE ATT&CK, and validating remediation evidence before closure.

> **Safety scope:** This repository does not authenticate to hosts, scan networks, execute remote commands, create services, deliver payloads, collect credentials, or target production systems. All telemetry and identities are fictional.

## Problem statement

Remote administration protocols are legitimate business tools and common lateral-movement mechanisms. The engineering challenge is therefore contextual: identify combinations of identity privilege, endpoint trust, destination criticality, access behavior, and detective-control coverage that deserve investigation without treating every remote session as malicious.

This project demonstrates that workflow with deterministic, explainable Python rather than offensive execution.

## Architecture

```text
Synthetic JSON telemetry
        |
        v
Strict schema validation
        |
        v
Contextual risk engine -----> MITRE ATT&CK mapping
        |
        v
Deterministic prioritization
        |
        +-----> Markdown analyst report
        |
        +-----> Portfolio metrics
        |
        v
Remediation evidence validation
```

### Project structure

```text
.github/workflows/security-quality.yml
 data/synthetic_events.json
 docs/methodology.md
 reports/example-assessment.md
 src/
   __init__.py
   cli.py
   engine.py
   loader.py
   models.py
   remediation.py
   reporting.py
 tests/test_engine.py
```

## Detection context

The engine evaluates synthetic RDP, SMB, WinRM, and SSH activity using signals such as:

- successful versus failed remote authentication;
- privileged identity use;
- managed versus unmanaged source hosts;
- destination business criticality;
- interactive remote logon;
- administrative-share access;
- remote-service creation telemetry;
- existing detective-control coverage.

The result is a bounded **0–100 contextual risk score** with Critical, High, Medium, and Low classification. Existing detection coverage can reduce contextual risk modestly, but it never erases the underlying technical exposure.

## MITRE ATT&CK context

| Technique | Defensive use in this project |
|---|---|
| T1021.001 — Remote Desktop Protocol | Contextualize suspicious RDP paths |
| T1021.002 — SMB/Windows Admin Shares | Contextualize SMB administrative access |
| T1021.004 — SSH | Contextualize remote shell administration |
| T1021.006 — Windows Remote Management | Contextualize WinRM activity |

ATT&CK mappings are threat-model context only. A mapped event is not asserted to be malicious or evidence of compromise.

## Usage

Requires Python 3.11+ and no third-party packages.

```bash
python -m unittest discover -s tests -v
python -m src.cli --events data/synthetic_events.json --output reports/generated-assessment.md
```

The CLI performs no network activity. It reads local synthetic JSON and generates a local Markdown assessment.

## Input validation

Telemetry is treated as untrusted until validation succeeds. The loader rejects:

- unexpected or missing fields;
- duplicate event identifiers;
- unsupported remote-access protocols;
- unsupported criticality values;
- malformed timestamps;
- string values masquerading as booleans;
- empty required identifiers.

This fail-closed behavior keeps the scoring pipeline deterministic and auditable.

## Risk design

The scoring model intentionally favors explainability over opaque weighting. Material risk increases include successful access, privileged identity context, unmanaged source hosts, administrative-share access, remote-service creation, and high-value destinations. Scores are capped at 100, converted to explicit severity bands, and sorted deterministically.

Stable SHA-256-derived finding identifiers make repeated synthetic assessments easier to compare without exposing sensitive data.

## Remediation and validation workflow

A finding should not be closed solely because a remediation ticket says work is complete. `src/remediation.py` requires evidence for:

1. accountable ownership;
2. a change/reference identifier;
3. the implemented control change;
4. destination control-state validation;
5. identity/privilege review;
6. detection retesting;
7. a passing post-change validation result.

Possible closure states are `validated`, `needs_evidence`, and `invalid_closure`.

Typical defensive actions include restricting remote-management reachability, requiring managed jump hosts, reducing standing administrative privilege, hardening administrative shares, and improving endpoint/network telemetry.

## Testing

The unit suite covers:

- prioritized risk ordering;
- score bounds;
- deterministic finding IDs;
- MITRE ATT&CK mappings;
- portfolio metrics;
- report generation;
- duplicate event rejection;
- invalid boolean rejection;
- successful remediation closure;
- failed retest handling;
- incomplete closure evidence.

GitHub Actions is configured with least-privilege `contents: read` permissions and performs Python compilation, unit-test discovery, synthetic report generation, and defensive-content smoke checks.

## Example assessment

`reports/example-assessment.md` explains three representative fictional scenarios: unmanaged SMB access to a critical file server, WinRM with remote-service telemetry to a high-value application server, and managed jump-host RDP to a critical database. Each scenario includes rationale, ATT&CK context, remediation, and validation expectations.

## Design decisions

- **Defensive telemetry, not exploitation:** the repository models observable behaviors without reproducing attacker tooling.
- **Synthetic evidence only:** hostnames, identities, timestamps, and business context are fictional.
- **Risk is contextual:** remote administration is not assumed malicious merely because it uses a technique associated with lateral movement.
- **Detection is not remediation:** detective coverage is useful but does not remove the need to constrain excessive remote-access paths.
- **Closure requires evidence:** remediation status and validated remediation are deliberately separate concepts.

## Skills demonstrated

- Detection engineering
- Windows/Linux remote-access security
- Identity and privilege-risk analysis
- Security data validation
- MITRE ATT&CK mapping
- Risk scoring and prioritization
- Remediation governance
- Python engineering
- Unit testing
- CI/CD security-quality controls
- Technical reporting and risk communication

## Limitations

This portfolio lab does not implement real-time streaming, graph-wide attack-path reconstruction, EDR/SIEM API integration, identity-provider enrichment, UEBA, packet capture, or automated enforcement. It should not be used as proof that a particular event is malicious without additional evidence.

## Roadmap

- add multi-event sequence correlation across source/destination chains;
- add synthetic identity-group and PAM context;
- model approved administration windows and jump-host policy;
- add Sigma-style detection-rule representations;
- export structured JSON findings alongside Markdown;
- add owner/team aggregation and trend comparison;
- add optional graph visualization from synthetic data;
- add remediation regression fixtures for before/after control validation.

## License and ethics

Use only for defensive engineering, authorized testing, education, and portfolio demonstration. Do not use this project to target systems without explicit authorization.
