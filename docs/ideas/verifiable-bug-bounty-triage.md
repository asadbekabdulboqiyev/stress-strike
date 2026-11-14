# Verifiable Bug Bounty / Triage Workflow (Staged, Evidence-First)

**Status:** Idea / design proposal (production-minded, staged)  
**Audience:** Sift maintainers, security program operators, platform engineers, triage leads  
**Last updated:** 2026-11-14  
**Related components:** `internal/attest`, `internal/evidence`, distributed coordinator attestation (`internal/dist/coordinator/attest.go`), `docs/VPMP-RFC.md`, `docs/AUTHORIZATION.md`, report/pentest outputs, `sift verify`, `sift certificate`, dashboard attestation flows

---

## 1. Problem and value

Bug bounty and vulnerability intake programs routinely struggle with three compounding issues:

1. **Evidence ambiguity.** Reports often contain screenshots, prose, or partial logs that are hard to reproduce, easy to misinterpret, and difficult to bind to a specific test run, target state, and tool configuration.
2. **Trust and dispute overhead.** Submitters and triage teams spend cycles arguing over "did this really happen?", "was it in scope?", "is this the same run you claim?", and "what exactly was observed?".
3. **Operational and legal risk.** Security testing must remain explicitly authorized. Intake systems that reward submissions without strong scope/authorization context can incentivize out-of-scope or abusive behavior.

Sift already has unusually strong primitives for **verifiable, evidence-honest measurement artifacts** (VPMP v1 bundles, Ed25519 signatures, Merkle commitments, recomputable aggregates, sidecars, independent verification). This proposal applies those strengths to a **staged bug-bounty/triage workflow** where evidence quality, reproducibility, and authorization context are first-class — without promising a fully automatic, trustless payout oracle.

### Value proposition

- **For triagers/program owners:** higher-quality submissions with machine-checkable integrity, clearer provenance, faster reproduce/validate loops, and better auditability.
- **For researchers/testers:** a portable way to prove what was executed and observed (within documented limits), reduce "cannot reproduce" friction, and preserve submission integrity over time.
- **For Sift:** a natural extension of existing attestation/reporting posture into security operations workflows while staying aligned with authorized, evidence-honest principles.

---

## 2. Goals and non-goals

### Goals

- Define a **staged, verifiable triage workflow** built on existing Sift attestation and evidence capabilities.
- Standardize a **submission evidence package** that is portable, integrity-checkable, and review-friendly.
- Make **reproducibility, scope/authorization, and provenance** explicit parts of intake and triage state transitions.
- Support **human-in-the-loop triage and dispute handling** with auditable decisions.
- Preserve Sift's **fail-closed, evidence-honest** posture: what is verified is stated precisely; what is not verified is labeled as such.
- Allow an **optional, later, cautious escrow/reward integration** as an extension that depends on verified evidence + human adjudication signals, not as an automatic payout guarantee.

### Non-goals (explicit exclusions)

- **Not a fully automated "finding -> smart contract auto-pays with no human" system.** This document explicitly does **not** promise or design for trustless automatic payout solely from tool output.
- **Not a claim that a bundle proves exploitability, impact, business risk, or root cause by itself.** Sift evidence can prove measurement/report integrity and committed observations under defined assumptions; human/security analysis remains required.
- **Not a bypass of authorization controls.** No workflow step should weaken `docs/AUTHORIZATION.md` policy, audit, or "authorized testing only" posture.
- **Not legal adjudication automation.** Triage outcomes do not substitute for contractual, legal, or disclosure-process decisions.
- **Not immediate on-chain settlement in MVP.** Ledger/escrow integration is a later, opt-in, cautious extension with additional controls.

---

## 3. Alignment with existing Sift capabilities (how this builds on what exists)

This design is intentionally additive and reuses Sift primitives rather than inventing a parallel trust system.

### 3.1 Existing foundations to leverage

| Existing capability | Location / reference | How it is used in this workflow |
|---|---|---|
| **VPMP v1 evidence bundles (canonical, signed, recomputable)** | `internal/attest/bundle.go`, `docs/VPMP-RFC.md` | Core integrity envelope for run/scan evidence and submission manifests; canonical digesting and Ed25519 signatures establish tamper-evident artifacts. |
| **Commit + Merkle + sidecar verification model** | `internal/attest` (`Commit`, records, proofs, `verify.go`) | Proves committed sample/report-record integrity when sidecars are present; supports bounded verification and explicit "samples absent" semantics. |
| **Evidence sealing helpers** | `internal/evidence` (`BuildBundle`, `WriteBundle`, `SidecarPath`) | Reused patterns for fail-closed sealing, sidecar-first writes, and recomputation-from-records (not copying telemetry claims). |
| **Distributed worker attestation primitives** | `internal/dist/coordinator/attest.go`, VPMP distributed flow | Optional provenance strengthening for distributed scan/load workers (signed telemetry/final reports, allowlisted keys) where applicable. |
| **Authorization and consent enforcement** | `docs/AUTHORIZATION.md`, `sift authorize`, audit chain | Mandatory scope/authorization context for submissions; policy decisions and ticket references become part of triage evidence. |
| **Pentest/report outputs and scan artifacts** | `sift pentest`, `sift scan`, report generation paths | Primary human-readable and machine-readable findings artifacts included in evidence packages (with clear limits, "NOT TESTED" semantics preserved). |
| **Certificate / attestation UX** | `sift certificate`, dashboard attestation flows, `docs/VERIFIER.html` | User-facing verification and portable proof artifacts; submission receipts and triage verification reports can follow similar patterns. |
| **Independent verification tooling** | `sift verify`, verifier assets | Intake and triage services should verify submitted packages using existing verification semantics before trusting claims. |

### 3.2 Design principle: evidence-honest composition

The workflow must distinguish and preserve:

- **Signed/verified facts** (e.g., bundle digest matches, signature verifies, Merkle/root and recomputed aggregates match committed records).
- **Operator-asserted context** (e.g., target ownership claim, ticket/authorization references, environment notes).
- **Analyst judgments** (e.g., severity, impact, exploitability, duplicate status, remediation priority).
- **Unknowns / not tested / unavailable** (must remain visible, never upgraded to "pass" or "verified").

---

## 4. Architecture

### 4.1 High-level components

1. **Evidence Producer (Sift CLI / dashboard / CI job)**
   - Runs authorized scans/tests/pentest workflows.
   - Emits reports/artifacts and seals one or more verifiable evidence bundles + sidecars.
   - Produces a **Submission Manifest** binding artifacts, authorization context, and metadata.

2. **Submission Packager**
   - Assembles a deterministic (or content-addressed) package layout: manifest, bundles, sidecars, reports, logs/summaries allowed by policy, and optional reproduction recipe.
   - Computes package-level checksums/index for transport integrity.

3. **Intake & Verification Service (program side)**
   - Receives package, validates schema/size/policy constraints.
   - Runs cryptographic and structural verification (`sift verify` semantics / library calls) and records a **Verification Result**.
   - Performs scope/authorization checks (ticket/policy linkage, target matching rules, expiry, approver context where available).

4. **Triage Workflow Engine (human-in-the-loop)**
   - Tracks submission state, assignments, SLA timers, comments, and decisions.
   - Requires human review for validation, severity, bounty eligibility, and dispute outcomes.

5. **Evidence Store / Audit Log**
   - Stores immutable (append-only or content-addressed) submission artifacts and verification results.
   - Maintains hash-chained or tamper-evident audit records of state transitions and actor actions (aligned with Sift audit posture).

6. **Optional Later: Cautious Escrow / Reward Adapter (staged extension)**
   - Integrates with an external ledger/payment/escrow system **only after** required human approvals and policy checks.
   - Consumes signed triage decisions/attestations; does not auto-pay from raw findings.

### 4.2 Evidence packaging model

A submission is a **verifiable evidence package** (directory or archive) with explicit boundaries between machine-verified and human-asserted content.

**Recommended package contents (MVP+):**

- `submission.manifest.json` — canonical manifest (see Data Model) binding all files, hashes, target/scope claims, and references.
- `evidence/` — one or more VPMP v1 bundle files (`*.json`) and corresponding sidecars (`*.samples.jsonl`) where applicable.
- `reports/` — Sift-generated reports (e.g. pentest/scan/load reports, JSON/TXT/CSV as produced) with stable filenames referenced by the manifest.
- `repro/` — reproduction recipe: sanitized command invocation template, scenario/config references, environment assumptions, timing notes, prerequisites.
- `authz/` (optional, policy-controlled) — references or excerpts proving authorization context (ticket ID, policy decision record hash/id, approval metadata) **without leaking secrets**.
- `notes/researcher_statement.md` (optional) — human narrative, impact hypothesis, and suggested remediation (explicitly non-verified claim content).
- `verification/intake_verification.json` (program-generated, post-intake) — results of automated verification checks.

**Packaging rules (production-minded):**
- Content hashes (SHA-256) recorded in manifest for every file.
- Strict size/count limits and media-type allowlist at intake.
- No secrets/credentials in reports or manifests (consistent with Sift security posture; request bodies/headers with credentials must not be embedded).
- Deterministic canonicalization for manifest signing (if/when signed manifests are introduced).

### 4.3 Submission and verification flow

1. **Authorized execution**
   - Operator/researcher runs Sift against an in-scope, authorized target (`--authorized <ticket>` / policy-compliant path as required).
   - Authorization decision is recorded in Sift audit logs as usual.

2. **Evidence sealing**
   - Sift produces reports and seals evidence bundle(s) + sidecars (where supported for the run type).
   - A submission manifest is generated referencing outputs and authorization context.

3. **Local preflight (recommended)**
   - Submitter runs verification locally (`sift verify` / future `sift submission verify`) to catch broken packages before upload.

4. **Intake validation (program side, fail-closed on integrity checks)**
   - Schema validation, hash verification, and signature/Merkle/recompute checks.
   - Scope checks: target identity normalization, allowlist/ticket linkage, time window/expiry, policy constraints.
   - Classification of result: `verified`, `verified_with_warnings`, `invalid`, `unverifiable` (e.g., missing sidecar when required by policy).

5. **Triage**
   - Human reviewer assesses reproducibility, validity, severity, and impact using verified artifacts plus narrative.
   - Program may request additional evidence or reproduction steps.

6. **Disposition and (optional later) reward workflow**
   - Human-approved outcome recorded and signed/attested by program-side authority.
   - Any escrow/payout action (future extension) is triggered only from approved disposition artifacts, never directly from raw scan findings.

### 4.4 Triage states (proposed)

| State | Meaning | Entry conditions | Exit conditions |
|---|---|---|---|
| `draft` | Local/incomplete submission being assembled | Package not yet submitted | Submitted or abandoned |
| `submitted` | Received by intake, pending automated checks | Package uploaded | Verification completes |
| `intake_rejected` | Rejected before triage (format/integrity/policy gate) | Hash/signature/schema/scope gate fails per policy | Terminal (resubmission creates new submission) |
| `verified` | Integrity checks passed; ready for human triage | Automated verification succeeded | Assigned/triaged |
| `verified_with_warnings` | Verified but with caveats (e.g., sidecar absent, partial artifacts) | Verification passed with documented warnings | Assigned/triaged or more info requested |
| `needs_info` | Additional evidence/repro/context requested | Triage/program action | Resubmitted/supplemented or closed |
| `triaging` | Under active human analysis | Assigned reviewer/program owner | Validated/rejected/duplicate/etc. |
| `reproduced` | Program reproduced issue (with or without original package replay) | Reviewer confirmation + evidence | Severity/impact assessment |
| `accepted` | Valid issue accepted (severity/impact tracked separately) | Human adjudication complete | Remediation/reward workflow |
| `duplicate` | Duplicate of known issue | Human adjudication | Closed/linked |
| `informative` | Valid observation but not actionable/security issue per policy | Human adjudication | Closed |
| `out_of_scope` | Not in authorized scope/program policy | Scope/policy adjudication | Closed (with reason) |
| `not_reproducible` | Could not be reproduced with available evidence | Human adjudication | Closed or needs info |
| `disputed` | Submitter disputes triage outcome/evidence interpretation | Submitter/program action | Re-triage/resolved |
| `resolved` | Final outcome recorded (accepted/rejected/duplicate/etc. + remediation/reward metadata as applicable) | Human/program sign-off | Terminal (immutable record) |

State transitions must be append-only audited events with actor, timestamp, reason, and references to evidence/verification artifacts.

### 4.5 Roles and responsibilities

- **Researcher / Tester (submitter):** runs authorized tests, packages evidence honestly, provides reproduction narrative and impact hypothesis.
- **Approver / Scope owner:** grants authorization tickets/policy entries (`sift authorize` model), defines windows and constraints.
- **Intake verifier (automated):** validates integrity, schema, and policy gates; produces verification reports (no vulnerability adjudication).
- **Triage analyst:** reproduces/assesses findings, sets severity/validity, requests more info, documents rationale.
- **Program owner:** final disposition authority, bounty eligibility decisions, disclosure/remediation coordination.
- **Auditor/compliance reviewer (optional):** reviews audit trails, authorization linkage, and process adherence.

### 4.6 Optional/later: cautious escrow integration (staged extension)

**Purpose:** improve payout transparency/timeliness *after* human adjudication, not replace adjudication.

**Constraints (if ever implemented):**
- Trigger inputs must be **program-signed disposition attestations** (e.g., accepted + severity + reward amount + submission digest), not raw scanner output.
- Support **time-delayed settlement**, dispute windows, and manual holds.
- Multi-party controls for high-value payouts (e.g., program owner + finance/security approver).
- Explicit handling of reversals/adjustments via off-chain adjudication records; on-chain state (if used) reflects decisions, not proof of bug truth.
- Jurisdictional/compliance review required before deployment.

This is intentionally deferred beyond MVP and should be treated as a separate security/compliance project.

---

## 5. Data model (proposed)

The model separates immutable evidence artifacts from mutable workflow metadata.

### 5.1 Core entities

#### `SubmissionManifest` (researcher/program-generated, canonical JSON)
- `manifest_version` (string)
- `submission_id` (program-assigned or content-derived identifier)
- `created_at` (RFC3339)
- `producer` (tool name/version, host/runtime metadata as policy allows)
- `subject` (target(s), normalized identifiers, environment label)
- `authorization` (ticket IDs, policy reference/hash, declared scope statements, test window)
- `artifacts[]` (path, media type, size, `sha256`, role: `bundle|sidecar|report|repro|notes|other`)
- `evidence_bundles[]` (bundle digest, coordinator key, worker IDs, sample presence, verification hints)
- `claims` (researcher-provided summary, alleged impact class, reproduction summary) — **non-verified**
- `extensions` (forward-compatible namespaced fields)

#### `VerificationResult` (intake-generated)
- `submission_id`, `verified_at`, verifier version
- `overall_status` (`verified|verified_with_warnings|invalid|unverifiable`)
- `file_integrity_checks[]` (hash matches/mismatches)
- `bundle_results[]` (per-bundle: `sift verify`-equivalent result summary, errors, warnings, digest, samples_absent)
- `authorization_checks[]` (ticket/policy linkage, expiry/window, target-in-scope evaluation, reason codes)
- `policy_findings[]` (size limits, disallowed content, missing required artifacts)
- `review_required` (bool) and reasons

#### `TriageCase`
- `case_id`, `submission_id`, current state
- `program_id`, `assignment`, SLA timestamps
- `severity`, `impact_assessment`, `cvss_or_internal_score` (optional), `component/asset`
- `repro_status` (not attempted / reproduced / not reproducible / partial)
- `links` (duplicates, remediation ticket, advisory/disclosure refs)
- `resolution` (accepted/duplicate/informative/out_of_scope/rejected/etc.) and rationale

#### `TriageEvent` (append-only audit record)
- `event_id`, `case_id`, `timestamp`, `actor`, `actor_role`
- `from_state`, `to_state`
- `reason_code`, `comment`
- `evidence_refs` (artifact hashes/digests, verification result IDs)
- `prev_hash`, `hash` (optional hash-chain for tamper-evident workflow history)

#### `DispositionAttestation` (program-signed, optional but recommended for later escrow extension)
- `submission_id`, `case_id`, final outcome, severity/reward decision metadata
- `artifact_digests` covered (manifest digest, verification result digest, key report digests)
- `approver identity/key`, signature, timestamp, policy/version references

### 5.2 Integrity and identity considerations

- Prefer **content-addressed artifact IDs** (SHA-256) internally to prevent ambiguity.
- Normalize target identifiers (URL host, port, scheme, canonicalized forms) before scope comparisons.
- Treat researcher-provided narratives as untrusted input; render safely in UIs.
- Keep cryptographic verification outputs separate from human judgments in storage and UI.

---

## 6. MVP scope (staged, practical)

The MVP should prove verifiable intake and human triage value without requiring protocol changes or payment rails.

### MVP capabilities

- **Submission manifest format (v0 draft)** and local packager conventions.
- **CLI-assisted packaging workflow** (scriptable): collect selected Sift outputs, generate manifest with hashes, bundle references, and authorization metadata fields.
- **Intake verifier job/service** that:
  - validates manifest schema and file hashes,
  - runs `sift verify` semantics on included bundles/sidecars,
  - emits a machine-readable `VerificationResult`.
- **Basic triage UI/API** (can be minimal/internal): submission list, verification status, artifact viewer/download, state transitions, comments, and audit trail.
- **Scope/authorization checks (manual + automated helpers):** ticket presence/format, target consistency checks, expiry/policy signals where available.
- **Dispute/needs-info loop:** request more evidence and accept supplemental packages linked to the same case.
- **Documentation and operator playbooks:** how to prepare evidence, what is verified vs not, and legal/ethical expectations.

### MVP out of scope

- Automatic bounty pricing or payout decisions.
- On-chain escrow/smart-contract settlement.
- Full autonomous reproduction in sandboxed exploit environments.
- Cross-program reputation scoring.
- Advanced deduplication ML (beyond basic linking/manual workflows).

---

## 7. Phased roadmap

### Phase 0 — Design hardening (now / pre-implementation)
- Validate manifest schema requirements against real `sift pentest`/`scan` outputs and VPMP bundle variants.
- Define policy profiles for required artifacts (e.g., sidecar required vs optional by run type).
- Security/legal review of data handling, retention, and disclosure boundaries.

### Phase 1 — Verifiable intake MVP
- Implement manifest generator/validator and packaging conventions.
- Integrate automated verification pipeline and verification report storage.
- Deliver human triage workflow with audited state transitions.

### Phase 2 — Reproducibility and program operations
- Add reproducibility templates (sanitized replay instructions, environment fingerprint fields).
- Add duplicate linking, SLA metrics, and structured reason codes.
- Improve program-side dashboards and evidence diffing across resubmissions.

### Phase 3 — Stronger provenance and attestations
- Support signed manifests and/or program-side countersignatures.
- Bind authorization decision artifacts more directly (e.g., signed audit excerpts or verifiable policy references) where feasible.
- Explore standardized export formats for disclosure/remediation systems.

### Phase 4 — Optional cautious escrow integration (separate, gated)
- Pilot only with explicit human approval gates and signed disposition attestations.
- Add dispute windows, hold/release controls, and compliance logging.
- Conduct independent security and legal review before any production use.

---

## 8. Trust boundaries and threat model

### 8.1 Trust boundaries

1. **Tester environment (untrusted to semi-trusted):** may be misconfigured, malicious, or attempting forgery.
2. **Submitted package boundary:** all inputs are untrusted until hash/schema/crypto verification passes.
3. **Verification/triage infrastructure (trusted computing base for workflow):** must protect keys, logs, and policy enforcement.
4. **Authorization/policy source of truth:** policy files, approver records, and ticket systems define scope; integrity of this source is critical.
5. **Optional settlement systems (future):** external trust and failure modes; must not be fed unadjudicated claims.

### 8.2 What the system can and cannot prove

**Can help prove (when verification passes):**
- Specific artifacts have not changed since hashing/manifesting (integrity).
- A VPMP bundle/signature corresponds to the canonical content and named keys (as implemented/verified).
- Committed records and recomputed aggregates/roots match the provided sidecar evidence (subject to verifier checks/limits).
- A submission was processed under recorded policy/verification/triage decisions.

**Cannot prove by itself:**
- That the target was owned/authorized unless authorization artifacts are independently trustworthy and correctly scoped.
- That a reported issue is exploitable, impactful, novel, or in reward scope.
- That all relevant system behavior was captured (coverage limits, untested areas, environment drift).
- Human intent or absence of abuse outside captured evidence.

### 8.3 Threats and mitigations

| Threat | Example | Mitigations |
|---|---|---|
| **Evidence tampering** | Modified report/bundle/sidecar after signing | Manifest hashes, canonical bundle digests, Ed25519 signature verification, Merkle/root recomputation, fail-closed intake |
| **Replay/miscontexting** | Valid evidence from another target/time presented as current in-scope finding | Bind target, time window, auth ticket/policy refs in manifest; require analyst validation; store verification timestamps and environment context |
| **Scope laundering** | Out-of-scope testing claimed as authorized | Mandatory authorization context checks, normalized target matching, approver/ticket validation, audited decisions; preserve Sift default-deny posture for risky classes |
| **Malformed/hostile packages** | Parser bombs, oversized sidecars, path traversal archives | Strict size/entry limits, safe archive extraction, schema validation, sandboxed verification workers, timeouts |
| **Sensitive data leakage** | Secrets in reports, PII in captures, credential-bearing logs | Secret redaction policies, artifact allowlists, report sanitization guidance, restricted storage/access controls |
| **Verifier confusion / policy bypass** | "Samples absent" mistaken as fully verified reproduction | Explicit verification statuses/warnings; policy-configurable requirements (e.g., sidecar required for certain claims) |
| **Triage process abuse** | Spam submissions, fraudulent disputes, collusion | Rate limits, identity controls, authenticated actors, audit trails, separation of duties for approvals/payout decisions |
| **Escrow misuse (future)** | Premature or fraudulent payouts | Human-gated disposition attestations, delay/hold/dispute windows, multisig/dual-control, compliance reviews (deferred) |

---

## 9. Legal, ethical, and abuse considerations

### 9.1 Authorized-use and policy alignment

- The workflow must reinforce Sift's **authorized testing only** stance and integrate with existing authorization/audit mechanisms (`docs/AUTHORIZATION.md`).
- Submissions without adequate scope/authorization evidence should be rejected or quarantined per program policy, not rewarded.
- "Verified evidence" must never be presented as authorization.

### 9.2 Data handling and privacy

- Evidence packages may contain sensitive operational data. Programs need retention limits, access controls, encryption at rest/in transit, and secure deletion procedures.
- Follow least-privilege access for triage roles; separate duties for verification, adjudication, and any future payout approval.
- Disclosure workflows (coordinated vulnerability disclosure) should be supported by auditable exports, but legal review is required for jurisdiction-specific obligations.

### 9.3 Abuse resistance and fairness

- Rate-limit intake and enforce per-identity/per-target quotas where appropriate.
- Preserve transparent reason codes for rejection/dispute outcomes to reduce ambiguity.
- Do not use automated severity scoring alone as a basis for rewards or punitive actions.

### 9.4 Claims and communications

User-facing language must be precise:
- "Cryptographically verified bundle/report integrity" is acceptable when checks pass.
- "Guaranteed vulnerability" or "automatic entitlement to payout" is not acceptable.
- "NOT TESTED" and verification warnings must remain visible in downstream triage views.

---

## 10. Risks and limitations

- **Coverage gaps remain:** Sift reports may mark areas as not tested; a verifiable package does not expand scanner coverage.
- **Environment drift:** a valid reproduction package may not reproduce later if the target changes; triage must capture timestamps and target state context.
- **Artifact incompleteness:** some run types may lack sidecars or may be policy-limited; verification status must reflect this honestly.
- **Operational complexity:** secure storage, key management, and verification infrastructure add program overhead.
- **False confidence risk:** polished cryptographic verification can be mistaken for proof of impact/severity; UI/process must counter this.
- **Interoperability/versioning:** manifest and bundle schema evolution must be versioned and backward-compatible where possible.
- **Future escrow risk:** integrating payments introduces regulatory, fraud, and irreversible-transfer risks; therefore deferred and gated.

---

## 11. Fit with v0.15

Sift v0.15 already presents the core ingredients this workflow needs:

- **Evidence and trust primitives:** VPMP v1 concepts, `internal/attest` bundle/signature/verification logic, evidence sealing patterns, `sift verify`/certificate flows.
- **Authorized, auditable operations:** policy-driven authorization and hash-chained audit posture (`docs/AUTHORIZATION.md`) aligned with enterprise-grade accountability.
- **Security assessment outputs:** `scan`/`pentest` workflows and reporting surfaces that can be packaged as submission artifacts.
- **Operational direction:** roadmap themes around worker trust/attestation hardening, OIDC/RBAC integration depth, and compliance-oriented documentation all support a staged triage platform.

**Practical fit assessment:** this proposal is a **natural v0.15-adjacent extension path** (design + MVP conventions + verification integration) that leverages existing strengths without requiring Sift to become a payout oracle or to weaken its evidence-honest/security posture. Near-term implementation should prioritize manifest/verification ergonomics and human triage auditability; any ledger/escrow work should remain a separately governed later phase.

---

## 12. Open questions (for follow-up design/implementation)

- Which Sift commands/run types must emit sidecars for a submission to be considered `verified` vs `verified_with_warnings` in program policy?
- Should the submission manifest be signed by the researcher key, coordinator key, or both (and how are keys distributed/trusted)?
- How should authorization evidence be referenced portably without exposing sensitive policy/audit internals?
- What minimal normalized target identity fields are required to prevent scope ambiguity across URLs, IPs, ports, and environments?
- Which verification checks should run in a hardened sandbox (e.g., large sidecar recomputation) and what resource quotas are required?
- What export format best supports downstream vulnerability management/remediation systems while preserving verification metadata?

---

## 13. Summary of intent

This proposal defines a **verifiable, human-adjudicated bug-bounty/triage workflow** that turns Sift's existing attestation and evidence capabilities into higher-trust submission and review operations. It explicitly rejects fully automated finding-to-payout promises, centers authorization and reproducibility, and stages any escrow integration as a cautious, later extension governed by human decisions and additional controls.