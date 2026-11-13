# Sift Enterprise (Planning Draft)

**Status:** Planning/mapping only (no SOC 2 / ISO 27001 certification claims)  
**Version:** 1.0  
**Date:** 2026-11-05

This document outlines a potential enterprise/support tier around the open-core Sift project. It does **not** claim certifications, guarantees, or commercial availability unless explicitly stated elsewhere.

## 1. Open-core boundary (illustrative)

| Capability | Open Core (Apache-2.0) | Potential Enterprise Tier |
|---|---:|---:|
| HTTP load testing | ✅ | ✅ |
| Security scanning (TLS/WAF/HTTP/security checks) | ✅ | ✅ |
| Distributed mode + worker controls | ✅ | ✅ |
| Dashboard (web UI) | ✅ | ✅ |
| OIDC / RBAC support (project capabilities) | ✅ | ✅ |
| HTTP/3/QUIC-related capabilities (as implemented) | ✅ | ✅ |
| Browser-based testing (as implemented) | ✅ | ✅ |
| SLA commitments | ❌ | Possible (contractual) |
| Priority support (24/7) | ❌ | Possible (contractual) |
| SOC 2 Type II / ISO 27001 certification | ❌ | Not currently claimed |
| Dedicated account management | ❌ | Possible (contractual) |
| Custom deployment/support packages | ❌ | Possible (contractual) |
| Advanced audit/export/compliance workflows | Partial/roadmap-dependent | Possible (contractual/roadmap) |

## 2. Potential enterprise offerings (non-binding)

### 2.1 Support and SLA
- Response-time targets by severity (contract-defined)
- Prioritized bug triage/fixes (scope-defined)
- Operational support guidance for self-hosted deployments

### 2.2 Compliance and governance (roadmap-dependent)
- Audit log export and retention guidance
- Security/compliance documentation support
- Formal certifications would require separate audits and are **not** claimed by this document

### 2.3 Deployment assistance
- Docker/Helm/Kubernetes deployment guidance
- On-prem/self-hosted rollout assistance
- Architecture review for distributed deployments

## 3. Example pricing tiers (placeholder)

> Pricing below is illustrative only and not a published offer.

| Plan | Example Price | Users/Admins | Support |
|---|---:|---:|---|
| Startup | $499/mo | 5 admins | Business-hours / defined SLA |
| Business | $1,499/mo | 25 admins | Priority support / defined SLA |
| Enterprise | Custom | Custom | Custom SLA/support package |

## 4. When an enterprise/support tier may be relevant

- Organizations requiring contractual support/SLA commitments
- Teams needing deployment assistance for production/self-hosted environments
- Customers with governance/audit workflow requirements (subject to implemented capabilities)

The open-core project remains focused on providing core technical capabilities; any commercial tier would primarily cover support, services, and contractual commitments.

## 5. Open items

- [ ] Define actual commercial packaging and support boundaries (if pursued)
- [ ] Validate compliance roadmap separately (no certification claims until audited)
- [ ] Establish billing/licensing/support processes (if commercialized)
- [ ] Publish official support/contact channels for enterprise inquiries
