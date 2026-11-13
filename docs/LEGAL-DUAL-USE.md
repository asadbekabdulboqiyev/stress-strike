# Sift — Dual-Use and Legal Notice

**Status:** Draft  
**Version:** 1.0  
**Date:** 2026-11-05

**Abstract:** Sift is designed for authorized security assessments and controlled load testing. Like many security and performance tools, it is dual-use: it can support legitimate testing and resilience work, but it can also be misused for unauthorized or harmful activity. This document outlines acceptable use boundaries, responsible disclosure, abuse monitoring considerations, and data-handling expectations.

---

## 1. Acceptable Use Policy

### 1.1 Permitted use
- Load testing and security scanning against systems you **own** or have **explicit written authorization** to test.
- Authorized penetration testing performed under a defined scope and applicable laws/policies.
- Educational and research use in lab/test environments where all targets are authorized.

### 1.2 Prohibited use
- Unauthorized attacks (including DDoS, brute-force, injection, or exploitation attempts against systems without permission).
- Attempts to access, disrupt, or damage third-party systems or data without authorization.
- Use for fraud, harassment, sabotage, or other unlawful purposes.

> Note: Security and load-testing operations may be logged and subject to authorization/audit controls depending on deployment configuration.

---

## 2. Responsible Disclosure

If you discover a security vulnerability in Sift:

1. **Do not disclose publicly before coordination.**
2. **Report privately:** send details to `security@techcorp.example`.
3. **Include:** vulnerability type, affected component/location, reproduction steps, and impact assessment.
4. **Response target:** acknowledgment within 5 business days; remediation plan or fix timeline typically within 30 business days (severity-dependent).
5. **Credit:** researchers may be credited after remediation if desired.

Please allow a reasonable embargo period (commonly up to 90 days, adjusted based on risk and fix status) before public disclosure.

---

## 3. Abuse Monitoring and Safeguards

Sift includes or supports controls that can help reduce misuse risk in authorized environments:

| Control | Purpose | Example location/component |
|---|---|---|
| Authorization/scope controls | Restrict targets/actions to approved scope | `internal/authz`, scanner guard/scope checks |
| Audit logging | Record security-relevant/state-changing operations | audit/logging components |
| Dashboard/API auth controls | Limit access to control surfaces | dashboard/auth configuration |
| Rate limiting / safeguards | Reduce accidental or abusive request patterns | dashboard/rate limiting, runtime controls |
| Distributed worker controls | Restrict/verify worker participation (where configured) | distributed coordinator/worker components |

If abuse is suspected in a deployment:
- Revoke access/credentials and stop affected runs.
- Preserve audit logs and relevant artifacts for investigation.
- Report incidents through the appropriate security/contact channel.

---

## 4. Data Processing (DPA / Operational Notes)

Depending on configuration and usage, Sift may process the following data:

| Data type | Source | Typical retention (deployment-dependent) |
|---|---|---|
| Target URLs/hosts | User/operator input | Configurable / policy-dependent |
| Worker identifiers/keys | Worker registration/configuration | Configurable / policy-dependent |
| Telemetry (RPS, errors, latency, etc.) | Test execution | Configurable / policy-dependent |
| Findings/vulnerability results | Scanner outputs | Configurable / policy-dependent |
| Audit log entries | CLI/dashboard/control operations | Configurable / policy-dependent |

### 4.1 Operator responsibilities
- **Data sharing:** Do not send data to third parties unless authorized and permitted by policy/law.
- **Transport security:** Use TLS and secure deployment practices for remote access.
- **Deletion/retention:** Define and enforce retention/deletion policies appropriate to your environment.
- **Legal compliance:** Ensure testing activities and data handling comply with applicable laws and contracts.

### 4.2 Disclaimer
Sift is provided **"as is"**, without warranties. Operators are responsible for obtaining authorization, defining scope, and using the software lawfully and safely.

---

## 5. Contacts

| Purpose | Contact |
|---|---|
| General questions | `maintainers@techcorp.example` |
| Security reports | `security@techcorp.example` |
| Legal / DPA inquiries | `legal@techcorp.example` |
| Enterprise / sales inquiries | `sales@techcorp.example` |
