# Security Guide

This document describes the security posture of **stress-strike**, a Go load
testing / network simulator. It covers the threat model, the controls already
in place, findings from the security audit, and recommendations for safe use.

> This file is maintained as part of a security audit. Version it together with
> the code; treat every security-relevant change as an update to this document.

---

## 1. Project description & security objective

`stress-strike` generates high volumes of concurrent HTTP requests against a
target server to measure breaking points, latency distribution, and error
behavior. It is controlled entirely by an operator through CLI flags or a
YAML/JSON scenario file, and runs on the operator's own machine.

**Security objective:** run heavy load generation without exposing the operator
or third parties to harm. Concretely:

- bound resource consumption of the test machine and the target;
- never leak secrets configured in scenario files into output;
- never send traffic the operator did not intend (only allow-listed same-host
  redirects);
- use secure transport (TLS ≥ 1.2, no certificate verification bypass);
- protect generated report files from other local users.

---

## 2. Trust model & threat model

**Trusted input:** the CLI, the scenario file, and environment variables are
provided by the operator who owns/authorizes the target system. They are
trusted **by design** (there is no multi-tenant or remote input surface).

**Trusted components:** Go standard library, `gopkg.in/yaml.v3`.

### Attack vectors considered

| # | Vector | Description | Relevant component |
|---|--------|-------------|--------------------|
| 1 | **SSRF** | A scenario or a malicious redirect could make the tool fetch internal/cloud-metadata/private resources. Since the operator controls config, the main residual risk is *unattended CI* or *third-party-supplied scenario files* that point at unexpected hosts. | `internal/engine/client.go` |
| 2 | **Resource exhaustion (self-DoS)** | Absurd `users`, `duration`, `timeout`, or `rps` values could exhaust sockets, memory, or CPU on the test machine. | `internal/config/scenario.go`, `internal/engine/engine.go` |
| 3 | **Path traversal** | A scenario `name` with `../`, `/`, NUL, etc. could escape the report directory or overwrite arbitrary files. | `internal/report/report.go` |
| 4 | **Secret leakage** | Tokens, passwords, headers, and request bodies may exist in scenario files; they must never appear in reports. | `internal/report/report.go`, `internal/engine/engine.go` |
| 5 | **Transport downgrade / MITM** | Redirect to a plaintext or different host, or disabling certificate verification, would weaken TLS protection. | `internal/engine/client.go` |
| 6 | **Denial of service (target side)** | The tool is, by definition, a load generator. Misuse against third-party systems is illegal (DDoS) and is mitigated by operator warnings, not technical controls. | `cmd/stress-strike/main.go` |
| 7 | **Malicious config parsing** | `yaml.v3` alias/entity expansion ("billion laughs", alias bombs) on untrusted scenario files. | `internal/config/scenario.go` |

---

## 3. Existing security controls (verified)

Verified against the codebase during the audit:

- **TLS floor:** `http.Transport` uses `TLSClientConfig{MinVersion: tls.VersionTLS12}`.
  `InsecureSkipVerify` is **not** set anywhere.
  (`internal/engine/client.go`)
- **Connection bounds:** `MaxConnsPerHost`, `MaxIdleConnsPerHost` clamped to
  `[256, 20 000]`; `DisableKeepAlives` configurable.
  (`internal/engine/client.go`)
- **Redirect policy:** at most **10** hops; **cross-host redirects are rejected**
  (`req.URL.Host != via[0].URL.Host` → `http.ErrUseLastResponse`), preventing
  SSRF-style redirect chains to other origins.
  (`internal/engine/client.go`)
- **Concurrency cap:** `users` and `spike_users` are capped at **100,000**.
  (`internal/config/scenario.go`)
- **Duration/timeout caps (added in this audit):** profile `duration` ≤ **7 days**;
  profile and per-step `timeout` ≤ **5 minutes**; spike `warmup+hold` ≤ **7 days**.
  (`internal/config/scenario.go`)
- **Response body cap:** responses are read through `io.LimitReader(..., 8 MiB)`.
  (`internal/engine/engine.go`)
- **Per-request timeout:** default 5 s; applied to the whole request lifecycle.
  (`internal/engine/client.go`, `internal/engine/engine.go`)
- **Report file permissions:** report files are created with mode **0600**;
  directories with **0755**. (`internal/report/report.go`)
- **Filename sanitization:** scenario names are sanitized (`..`, `/`, `\`, `:`,
  NUL, control chars, etc. removed), truncated to 64 chars, so a malicious name
  cannot escape the report directory. Verified by tests.
  (`internal/report/report.go`)
- **No secrets in reports:** reports contain only metric aggregates — step name,
  request/error counts, status-code and error-class distributions, latency
  percentiles (min/avg/max/p50/p95/p99). Scenario `variables`, request headers,
  bodies, and extracted values (e.g. auth tokens) are **never** serialized.
  (`internal/report/report.go`, `internal/metrics/metrics.go`)
- **Operator guardrails:** a legal (DDoS) warning is printed on every run, and a
  warning is shown when the open-file limit (`ulimit -n`) is too low for the
  planned concurrency. (`cmd/stress-strike/main.go`)
- **Graceful shutdown:** `SIGINT`/`SIGTERM` drain in-flight requests; a second
  signal exits immediately. (`cmd/stress-strike/main.go`)

---

## 4. Audit findings

Findings from the review, ordered by risk.

### 4.1 Fixed during this audit

- **[Medium] Unbounded `duration` / `timeout` (resource exhaustion).**
  Only `users` was capped; a typo like `duration: 999999999` would run an
  effectively endless test, and `timeout` of hours would pin worker goroutines
  open. **Fixed** by adding hard caps in `scenario.go`:
  `maxDuration = 7 days`, `maxTimeout = 5 minutes` (profile level and per-step
  `timeout`), spike `warmup+hold` total ≤ 7 days. Out-of-range values now fail
  fast with a descriptive error instead of misbehaving.
- **[Low] `.env` / `*.env` not ignored by git.** A scenario or helper script
  with credentials could have been committed accidentally. **Fixed** — added
  `*.env` / `.env` to `.gitignore` (and to `.dockerignore`, so secrets cannot
  leak into a Docker build context).
- **[Info] `dist/` build output not git-ignored.** Added `dist/` to
  `.gitignore` so cross-compiled release binaries are not committed.

### 4.2 Confirmed safe (no change needed)

- Cross-host redirects are blocked (SSRF redirect chains covered).
- `InsecureSkipVerify` absent; TLS ≥ 1.2 enforced.
- Filename sanitization prevents path traversal from scenario `name`.
- Reports never contain variables/headers/bodies/tokens.
- `maxUsers` concurrency cap present.
- 8 MiB response body cap present.
- Report files written 0600.
- Secret-keyword scan of the Go sources found **only test/demo** references
  (`password`, `token`, etc.) — no hardcoded API keys, no secrets in the
  repository.

### 4.3 Accepted residual risks (documented, not "fixed" by design)

- **[Info] Private/local targets intentionally allowed.** `stress-strike` is
  built to test the operator's own servers, including `http://localhost`,
  `127.0.0.1`, and other private addresses (the included demo server listens on
  `127.0.0.1:8080`). Blocking private IP by default would break the primary use
  case, so the default behavior is unchanged and this is documented. Do **not**
  run this tool from an environment where untrusted scenario files are
  accepted.
- **[Info] Network reachability is the operator's responsibility.** The tool
  will send traffic wherever the scenario points. There is no allowlist for the
  *initial* target (only redirects are restricted). Keep the tool confined to
  the network where the target lives.
- **[Info] Same-host scheme downgrade.** A redirect from `https://host` to
  `http://host` (same host) is currently allowed. The host is operator-owned,
  but if hardening is desired later, reject redirects that change scheme from
  HTTPS to HTTP.
- **[Info] Proxy environment variables.** `http.Transport` honors
  `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`. Confirm your proxy configuration before
  running tests that involve sensitive data.
- **[Info] `report-dir` is arbitrary by design.** The `--report-dir` flag
  accepts any path (tests write into it intentionally). This is operator-
  controlled; files inside are still created 0600.

---

## 5. Safe usage recommendations

1. **Only test systems you own or have explicit written permission to test.**
   Unsanctioned load floods against third parties are illegal (DDoS).
2. **Do not commit scenario files containing real credentials.** Consider
   per-secret references and keep real tokens/passwords out of the repository.
   `.env`-style files are git-ignored; treat scenario YAML the same way.
3. **Review scenario files before use**, and prefer running in CI only against
   dedicated test environments, not production.
4. **Pin limits in every profile** (`duration`, `timeout`, `rps`) — the tool now
   rejects unreasonable values, but explicit small values avoid accidents.
5. **Raise `ulimit -n`** before large concurrency runs (e.g. `ulimit -n 65535`);
   the tool warns when the limit looks too low.
6. **If you must inject secrets at runtime** (tokens returned by the target):
   they live only in memory (`vars` extraction) and never reach reports. Do not
   enable verbose logging of request content in wrappers around this tool.
7. **Treat reports as potentially sensitive** — they are written 0600, but the
   directory itself is 0755. Keep the reports directory private if the target
   URL reveals internal hostnames.
8. **Air-gapped CI or restricted network:** run from a host with network access
   limited to the target, so a malicious redirect already can't reach internal
   services even if a future regression disables the redirect guard.

---

## 6. YAML parser security (`gopkg.in/yaml.v3`)

Scenario files are parsed with `gopkg.in/yaml.v3 v3.x`.

- The Go YAML package has **no built-in depth/alias expansion budget**. A
  crafted file with deeply or exponentially nested anchors and aliases (e.g.
  `&a`/`*a` references) can cause CPU and memory spikes during `Unmarshal` — a
  classic **alias bomb**.
- Scenario files are an **explicitly trusted input** (they are written by the
  operator running the tool). This makes exploitation unlikely. But:
  - **Do not load scenario files from untrusted sources** (e.g. URLs, user
    uploads, multi-tenant systems). If you must, pre-validate or sandbox the
    parsing step.
  - Keep the binary and its config channel private; do not expose scenario
    parsing as a remotely reachable service.
- If unauthenticated input ever becomes a use case, mitigate at the parser
  level (e.g. enforce a node-depth limit or pre-scan the document). The current
  design intentionally keeps parsing simple and trusted.

---

## 7. Reporting a vulnerability

This is an internal tool. If you find a security issue in this repository,
report it to the project maintainers **before** publishing details. Include:

- a description of the issue and its impact;
- the affected component and version (`./bin/stress-strike --version`);
- a minimal reproduction (scenario file or command line) if possible.

Do not include real credentials in the report.