# Lateral Movement Assessment — Example

> Synthetic defensive example. No production systems or real identities are represented.

## Executive Summary

The sample dataset contains six fictional remote-access events spanning SMB, WinRM, RDP, and SSH. The highest-risk paths combine privileged identities, unmanaged source systems, sensitive destinations, administrative-share access, or remote-service creation. Existing detection coverage is treated as a mitigating signal, not a substitute for reducing the underlying exposure.

## Priority observations

### 1. Unmanaged source → critical file server over SMB
- Privileged service identity involved.
- Authentication succeeded.
- Administrative-share access observed.
- Destination classified as critical.
- No detective-control coverage represented.
- ATT&CK context: **T1021.002 — SMB/Windows Admin Shares**.

**Recommended action:** restrict SMB administration to approved management paths, validate the service identity's privilege, review the source-host trust state, and retest the resulting telemetry before closure.

### 2. Unmanaged source → high-value application server over WinRM
- Privileged identity involved.
- Remote service creation telemetry represented.
- Destination classified as high criticality.
- Detective coverage exists but does not remove technical exposure.
- ATT&CK context: **T1021.006 — Windows Remote Management**.

**Recommended action:** constrain WinRM reachability, require managed administration endpoints, validate identity scope, and confirm endpoint/network detections still fire after hardening.

### 3. Managed jump host → critical database over RDP
- Privileged identity and interactive remote logon represented.
- Managed jump-host source and detection coverage reduce contextual risk.
- ATT&CK context: **T1021.001 — Remote Desktop Protocol**.

**Recommended action:** confirm business justification, privileged-access controls, session logging, MFA/PAM policy, and destination hardening.

## Closure criteria
A finding is not considered validated merely because remediation is declared complete. Closure evidence must include an accountable owner, a change reference, implemented control details, destination validation, identity review, detection retest, and a passing post-change validation result.
