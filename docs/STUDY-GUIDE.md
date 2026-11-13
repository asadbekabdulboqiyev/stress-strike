# Sift — Study Guide

> This document is a learning guide for understanding the Sift codebase.
> The goal is not to memorize every line of code, but to understand the **big picture**, the purpose of each major component, and how data flows through the system.
>
> **How to use this guide:** Level 1 (fundamentals) → Level 2 (map) → Level 3 (flows) → Level 4 (deep dive). Move to the next level when you can explain the current level in your own words.

---

## Level 0: Project in one paragraph

**Sift** is a Go-based toolkit with two primary goals:

1. **Load testing** — simulate many virtual users sending concurrent HTTP/gRPC/WebSocket/TCP/UDP requests to measure performance, reliability, and scalability.
2. **Security scanning and assessment** — run TLS/WAF/HTTP/security checks, scanners, and pentest workflows to identify issues and produce reports/evidence.

It also includes **traffic replay** (PCAP/HAR), **distributed mode** (master/worker), a **real-time dashboard**, and interactive CLI workflows.

**Why Go?** Strong concurrency primitives (goroutines/channels), efficient compiled binaries, and straightforward deployment.

---

## Level 1: Core concepts

If you can explain these concepts clearly, you have the foundation:

1. **Virtual User (VU)** — a simulated client; typically runs in its own concurrent execution context.
2. **Load profile** — how load changes over time (steady, ramp-up, spike, wave, constant RPS, etc.).
3. **RPS (Requests Per Second)** — request throughput.
4. **Latency** — time from request start to response completion.
5. **Percentiles (P50/P95/P99)** — latency distribution markers (e.g. P99 means 99% of requests were faster than that value).
6. **SLA gate** — pass/fail criteria evaluated against test results (often used in CI).
7. **Assertion** — validation rule applied to responses (status code, body/path checks, etc.).
8. **Scenario** — the test definition/configuration (CLI flags and/or YAML/JSON config).

---

## Level 2: Repository map

### High-level structure

```text
sift/
├── api/                     # Reusable high-level API
├── cmd/                     # Executable entrypoints (binaries)
│   ├── sift/                # Main CLI
│   ├── sift-dashboard/      # Dashboard binary
│   ├── sift-replay/         # Replay binary
│   ├── sift-scan/           # Scan binary
│   ├── sift-master/         # Distributed master/coordinator
│   └── sift-worker/         # Distributed worker
├── examples/                # Example scenarios, demo server/store
├── internal/                # Internal packages (not public API)
│   ├── config/              # Scenario loading/normalization/validation
│   ├── engine/              # Load execution engine
│   ├── metrics/             # Metrics collection, histograms, telemetry, timeline
│   ├── report/              # Terminal/JSON/HTML/PDF reporting
│   ├── replay/              # PCAP/HAR replay
│   ├── scanner/             # Security scanning modules
│   ├── dashboard/           # Web dashboard server and UI assets
│   ├── dist/                # Distributed mode (gRPC, coordinator/worker)
│   ├── authz/               # Authorization and audit controls
│   ├── certificate/         # Certificate issuance/verification
│   └── ...                  # Other supporting packages
├── scripts/                 # Build/install/release/demo scripts
├── docs/                    # Documentation
├── deploy/                  # Docker/K8s/systemd deployment assets
├── packaging/               # Packaging manifests (Homebrew/Scoop/Winget etc.)
├── Makefile                 # Build/test/lint/release targets
├── Dockerfile*              # Container build definitions
└── go.mod                   # Go module definition
```

> Note: Command directory names in the repo are lowercase (e.g. `cmd/sift`), while produced binaries may use canonical names and/or lowercase aliases depending on build/install scripts.

### One-line purpose per major package

| Package | Purpose |
|---|---|
| `cmd/sift` | Main CLI entrypoint and command dispatch |
| `internal/config` | Load and validate scenario/configuration inputs |
| `internal/engine` | Execute load tests (workers, profiles, request dispatch) |
| `internal/metrics` | Collect and aggregate runtime/test metrics |
| `internal/report` | Render/export test and assessment results |
| `internal/replay` | Replay captured traffic (PCAP/HAR) |
| `internal/scanner` | Security scanning and assessment checks |
| `internal/dashboard` | Real-time dashboard server/API/UI |
| `internal/dist` | Distributed master/worker coordination |
| `internal/authz` | Authorization, policy, and audit-related controls |
| `internal/certificate` | Signed assessment certificate creation/verification |
| `api` | Programmatic API for embedding/running Sift workflows |

---

## Level 3: Core execution flows

### Flow A: CLI startup and command dispatch

```text
sift <command>
  └─ cmd/sift main()
       ├─ version/help
       ├─ run            -> load test execution
       ├─ replay         -> replay workflow / subcommand/binary
       ├─ scan/pentest   -> scanning/assessment workflows
       ├─ dashboard      -> dashboard server
       ├─ master/worker  -> distributed mode
       └─ other commands -> authz/audit/certificate/admin/etc.
```

The main CLI parses flags/subcommands, prepares configuration/context, and dispatches to the appropriate command implementation.

### Flow B: Load test (`run`)

```text
cmdRun()
  ├─ Parse flags / load scenario (YAML/JSON or quick scenario from flags)
  ├─ Normalize and validate config
  ├─ Initialize engine and metrics/reporting components
  ├─ engine.Run(ctx, options)
  ├─ Build report/results (terminal/JSON/HTML/PDF as configured)
  ├─ Evaluate gates (SLA/regression/baseline) if configured
  └─ Persist outputs and exit with appropriate status
```

### Flow C: Engine execution (core)

```text
Engine.Run(...)
  ├─ Build load profile/scheduler (steady/ramp/spike/wave/constant-rps, etc.)
  ├─ Start workers/virtual users (goroutines)
  ├─ For each step/request:
  │    ├─ Send request via protocol-specific client
  │    ├─ Capture timing/status/errors
  │    ├─ Apply assertions/extraction (if configured)
  │    └─ Record metrics/telemetry/timeline samples
  ├─ Handle cancellation, timeouts, and graceful shutdown
  └─ Return aggregated results for reporting
```

Key implementation concerns in the engine include concurrency control, connection reuse, rate limiting, coordinated timing behavior (where enabled), and accurate measurement.

### Flow D: Metrics → report

```text
Engine events/results
  └─ metrics/telemetry aggregation (histograms, counters, timelines)
       └─ report.Build(...)
            ├─ terminal summary/output
            ├─ JSON/HTML/PDF artifacts (as configured)
            └─ SLA/baseline comparison evaluation
```

---

## Level 4: Deeper package notes

### `internal/config`
- Defines scenario/config structures (targets, steps, profiles, assertions, SLA, variables, etc.).
- Loads YAML/JSON and applies validation/normalization.
- Enforces bounds and safe defaults where appropriate.

### `internal/engine`
- Core runtime for executing load profiles and request workflows.
- Contains protocol clients and execution helpers (HTTP/gRPC/WebSocket/TCP/UDP paths as implemented).
- Integrates with metrics, assertions, capture, rate limiting, and shutdown handling.

### `internal/metrics`
- Aggregates counters, histograms, latency percentiles, error/status distributions, and timelines.
- Provides data structures consumed by reporting and dashboard views.

### `internal/report`
- Converts aggregated results into human-readable and machine-readable outputs.
- Supports console output and report artifacts (format support depends on feature/path).
- Handles SLA evaluation and baseline/regression comparison where configured.

### `internal/replay`
- Parses and replays captured traffic (e.g. PCAP/HAR) with pacing/concurrency/filtering options.
- Useful for reproducing realistic traffic patterns in test environments.

### `internal/scanner`
- Implements scanning/assessment modules (TLS, HTTP/WAF checks, crawling, fuzzing, JWT/GraphQL/WebSocket checks, etc., depending on command/module).
- Applies scope/authorization/audit controls where required.
- Produces findings and supporting evidence for reports.

### `internal/dashboard`
- Serves the web UI and APIs for run control, live telemetry, scanners, history, and certificate workflows.
- Bridges runtime state/results to browser clients (including real-time updates where implemented).

### `internal/dist`
- Implements distributed master/worker coordination over gRPC.
- Handles worker registration, command/event flow, telemetry aggregation, and fleet execution controls.

### `internal/certificate` and `internal/attest`
- Issue and verify signed evidence/certificates (e.g. assessment certificates, VPMP/attestation-related flows where applicable).
- Focus on integrity, verification, and reproducible evidence handling.

### `api`
- Provides a programmatic entrypoint for running Sift workflows from Go code (API surface depends on package exports).

---

## Suggested Go topics to learn alongside this codebase

1. Goroutines and channels (concurrency)
2. `sync` primitives (`Mutex`, `WaitGroup`, atomics where used)
3. Pointers, methods, and interfaces
4. Error handling (`errors.Is/As`, wrapping)
5. `context.Context` and cancellation/timeouts
6. `net/http` (client/server behavior)
7. JSON/YAML encoding/decoding
8. gRPC/protobuf basics (for distributed mode)
9. WebSockets and streaming protocols (where relevant)
10. Testing (`testing`, table-driven tests, race detector)
11. Performance profiling and resource management
12. CLI design with `flag` and command routing

---

## Discussion prompts (interview / self-review)

1. How does `sift run` flow from CLI parsing to final report output?
2. How does the engine model virtual users and apply load profiles?
3. What metrics are collected, and how are percentiles calculated?
4. How do SLA/regression gates affect exit behavior?
5. How are replay, scanning, dashboard, and distributed modes separated in the codebase?
6. Where are concurrency and synchronization used, and why?
7. What safety controls exist for scanning/authorization/audit flows?
8. How does the project produce verifiable evidence (attestations/certificates)?

---

## Summary

- **Levels 1–2:** enough for a high-level understanding and portfolio/interview discussion.
- **Level 3:** understand the main runtime flows and component interactions.
- **Level 4:** dive into package internals as needed for contributions or debugging.

You do not need to memorize the entire codebase. Focus on the architecture, execution flows, and how to locate relevant code when solving a specific problem.
