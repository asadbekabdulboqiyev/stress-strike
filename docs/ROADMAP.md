# Roadmap — Known Limitations and Planned Improvements

This roadmap is based on current project review findings. Items are grouped by category and should be tracked with measurable outcomes.

## Category 1 — Current limitations (honest constraints)

### 1.1 Scanner is not a full oracle
- **Current state:** `docs/OWASP-SCANNER.md` documents coverage boundaries clearly (e.g. JS-rendered SPA behavior, deep business logic, and some authenticated/authorization flows may be out of scope or heuristic).
- **Planned improvements:** headless browser support (Chromium/CDP), SPA rendering/crawl support, deeper authenticated flows (login → crawl → scan), and improved business-logic rule coverage.
- **Estimate:** ~3 weeks (1 senior + 1 part-time).

### 1.2 Bus factor = 1
- **Current state:** project maintenance is concentrated on a single primary maintainer.
- **Planned improvements:** grow maintainer/contributor base, improve contribution docs/processes, and keep ownership/review paths explicit (`MAINTAINERS.md`, `CODEOWNERS`, `CONTRIBUTING.md`).
- **Estimate:** ~2 months (ongoing).

### 1.3 Benchmarks are mostly loopback/local
- **Current state:** limited independent cross-tool/system benchmarking; published comparison matrix is incomplete.
- **Planned improvements:** reproducible benchmark harness (e.g. comparisons with k6/wrk2 where appropriate), multi-platform runs (macOS/Linux/Windows), and independently verifiable results.
- **Estimate:** ~4 weeks.

### 1.4 Distributed worker trust/attestation depth
- **Current state:** distributed execution exists, but trust and attestation hardening can be improved further.
- **Planned improvements:** stronger worker identity/attestation controls, signed telemetry/snapshots, key rotation, and stricter allowlist verification paths.
- **Estimate:** ~3 weeks (1 senior).

### 1.5 Dual-use / legal responsibility boundaries
- **Current state:** authorization/audit controls exist, but legal/compliance responsibility ultimately remains with operators and organizations.
- **Planned improvements:** compliance-oriented documentation/mapping, approval workflow guidance, and clearer operator responsibility boundaries.
- **Estimate:** ~1 month (documentation/process work).

## Category 2 — Engineering improvements (in code)

### 2.1 Scanner modularization/refactor
- **Current state:** scanner subsystem is large and complex; coverage/maintainability can be improved by clearer module boundaries.
- **Planned improvements:** split/refactor into focused modules (passive/intrusive/cve/owasp/auth/jwt/fuzz/dirbust/graph/websocket/crawl/portscan/sslscan/subdomain/guard/verify/nvd, etc.) while preserving CLI behavior and test parity.
- **Estimate:** ~6–8 weeks (2 senior engineers). Prioritize incremental refactors with test coverage.

### 2.2 Dashboard OIDC/RBAC integration depth
- **Current state:** dashboard auth controls exist; OIDC/RBAC integration can be deepened and standardized.
- **Planned improvements:** stronger OIDC broker integration hooks, consistent RBAC policy enforcement, and clearer admin/operator role flows.
- **Estimate:** ~2 weeks (1 senior + 1 part-time).

### 2.3 HTTP/3 (QUIC) support
- **Current state:** HTTP/1.1/HTTP/2 paths exist; HTTP/3 support is limited/not complete.
- **Planned improvements:** QUIC transport support for relevant load/probe paths and validation across environments.
- **Estimate:** ~4 weeks (2 senior engineers).

### 2.4 Browser-based load testing
- **Current state:** protocol-level load testing is strong; full browser-driven load testing is not the primary mode.
- **Planned improvements:** CDP/Chromium-based browser execution path for JS-heavy app scenarios (targeted use cases).
- **Estimate:** ~6 weeks (2 senior engineers).

## Category 2.5 — Planning & Evidence Insights (integrated)

- **Digital Twin capacity simulation (`sift simulate`):** evidence-based what-if simulation from completed Sift reports with confidence, uncertainty bounds, and explicit assumptions.
- **Host X-Ray observability (`sift xray`):** opt-in, cgo-free aggregate host snapshots and correlation helpers (Linux `/proc` + portable runtime fallback) with time-correlated indicators for investigation.
- **Verifiable bug-bounty/triage workflow (`sift bounty`):** verifiable evidence packaging, integrity/attestation verification, and a complete staged triage workflow built on attest/VPMP artifacts.

Dashboard integration: **Insights** view and APIs for fit/simulate, capability detection/correlation, manifest validation, full artifact verification uploads, and triage replay. CLI provides end-to-end file-based packaging and replay workflows.

## Category 3 — Adoption and ecosystem

- **VPMP standardization:** VPMP v1 exists in-project; broader external review/adoption and spec evolution may be needed.
- **Release cadence:** maintain predictable minor/patch releases and keep release automation healthy.
- **Independent security review:** pursue third-party security review/red-team assessment for additional assurance.
- **Open-core boundaries:** keep core capabilities open while defining any future commercial/support tier clearly.

## Suggested planning timeline (illustrative)

| Window | Focus |
|---|---|
| Weeks 45–46 | Stabilize flaky tests, improve coverage baseline/docs (completed baseline recorded in `docs/COVERAGE.md`) |
| Weeks 47–49 | Worker trust/attestation hardening (distributed mode) |
| Weeks 50–52 | Dashboard OIDC/RBAC integration improvements |
| Weeks 53–55 | Scanner depth improvements (headless/authenticated flows) |
| Weeks 56–57 | HTTP/3 (QUIC) investigation/implementation |
| Weeks 58–60 | Independent benchmark harness, VPMP spec refinement, maintainer growth |

> This is a planning guide, not a commitment. Each milestone should be scoped, measured, and adjusted based on results.
