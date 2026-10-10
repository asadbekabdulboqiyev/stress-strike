# Compliance Notes (HIPAA/FedRAMP/GDPR)

## Overview
This document outlines minimal, factual considerations. It does not constitute legal advice.

## HIPAA
- stress-strike is a test tool; do not run against production PHI-containing systems without explicit authorization
- No PHI is collected by default; logs redact/avoid PII
- Authorization gate + immutable audit trail support access accountability

## FedRAMP
- Air-gapped/local deployment supported (no cloud SaaS)
- Secrets via env/${VAR}; audit trail hash-chained and tamper-evident
- K8s manifests provided for controlled deployment

## GDPR
- No personal data collection by default
- Authorization/audit record minimal fields; data minimization
- Users control config/retention of local artifacts

## Data boundaries
- CLI stores: reports/, ~/.stress-strike/audit.jsonl, policy files
- Control-plane (Postgres): only metadata (tenants/users/roles/keys/events) — no request bodies with PII
