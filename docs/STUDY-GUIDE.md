# stress-strike — Complete Study Guide

> This document is designed to help you **understand** the `stress-strike` project.
> The goal is not to memorize the entire codebase but to grasp the **big picture**
> and the responsibility of every component.
>
> **How to read it:** Level 1 (basics) → Level 2 (map) → Level 3
> (flows) → Level 4 (deep dive, optional). If you can explain a level in your
> own words — move on to the next one.

---

## Level 0: The project in one paragraph

**stress-strike** is a dual-purpose tool written in Go:

1. **Load testing** — many virtual users simultaneously send HTTP/gRPC/WebSocket
   requests and measure how much load a site/API can handle.
2. **Security scanning** — checks for TLS/WAF/vulnerability weaknesses and
   produces a pentest report.

Additionally, it includes: **traffic replay** (replaying real traffic from PCAP/HAR),
**distributed mode** (load generation across many machines via master/worker),
**real-time dashboard**, and an **interactive wizard**.

**Why Go?** — high concurrency for sending many requests at once
(goroutines), a compiled binary (fast), and simple deployment.

---

## Level 1: Core concepts (enough to discuss it in a portfolio interview)

If you can articulate this in your own words — the foundation is ready:

1. **Virtual user (VU)** — a simulation of a single "user" in the test; each one
   sends requests from its own goroutine.
2. **Load profile** — how the number of users changes over time
   (steady / ramp-up / spike / wave).
3. **RPS (Requests Per Second)** — the number of requests sent per second
   (the primary "throughput" metric).
4. **Latency** — the time between sending a request and receiving a response.
5. **Percentile (P50/P95/P99)** — a measure that expresses a percentage of requests:
   P99 means 99% of requests were faster than this value.
6. **SLA gate** — a check at the end of the test: "did the result meet the target?"
   (fails with exit code 2 in CI/CD).
7. **Assertion** — verifies an expected condition in the response body (for example
   `status == 200`).
8. **Scenario** — the set of settings that describes the test (YAML file or flags).

---

## Level 2: Directory structure — the "map"

The main parts of the repository:

```
stress-strike/
├── api/                     # Reusable high-level API
├── cmd/                     # All executables (binary entry points)
│   ├── stress-strike/       # Main CLI (run, replay, scan, pentest, ...)
│   ├── stress-strike-dashboard/
│   ├── stress-strike-replay/
│   ├── stress-strike-scan/
│   ├── stress-strike-master/
│   └── stress-strike-worker/
├── examples/                # Sample YAML scenarios + demo server
├── internal/                # Internal packages (not exported to other projects)
│   ├── config/              # Scenario loading/validation
│   ├── engine/              # The main load machine (core)
│   ├── metrics/             # Result measurement (histogram, telemetry, timeline)
│   ├── report/              # Report generation (terminal, JSON, HTML, PDF)
│   ├── replay/              # PCAP/HAR traffic replay
│   ├── scanner/             # Security scanner (TLS, WAF, CVE, OWASP, auth)
│   ├── dashboard/           # Real-time web dashboard server
│   └── dist/                # Distributed (master/worker) gRPC protocol
├── scripts/                 # install.sh, build-all.sh, release.sh
├── docs/                    # Documentation (this document)
├── Makefile                 # Build/test/lint/release commands
├── Dockerfile
└── go.mod                   # Module: github.com/asadbekabdulboqiyev/stress-strike
```

### Every package in one sentence

| Package | Responsibility |
|---|---|
| `cmd/stress-strike` | Main CLI — flags, subcommand selection, invoking commands |
| `internal/config` | Loads a YAML/JSON scenario, normalizes it, and validates it |
| `internal/engine` | Actually **executes** the test — users, profile, sending requests |
| `internal/metrics` | Collects all measurements: histogram, percentile, telemetry, timeline |
| `internal/report` | Turns results into a nicely formatted report (terminal/JSON/HTML/PDF) |
| `internal/replay` | Reads real PCAP/HAR traffic and replays it as load |
| `internal/scanner` | Security checks: TLS, WAF, HTTP server info, CVE, OWASP |
| `internal/dashboard` | Web server that displays results in real time in the browser |
| `internal/dist` | Master/worker multi-machine protocol (gRPC) |
| `api` | Simple, reusable `Run(ctx, cfg)` API |

---

## Level 3: Main flows (how the actual work happens)

This is the most important part of the project. Set aside some time and trace
through each flow on your own.

### Flow A: CLI startup

```
go run ./cmd/stress-strike <command>
        │
        ▼
main.go main() ── look at os.Args[1]
        │  "version"/"help"  → print and exit
        │  "run"             → cmdRun()
        │  "replay"          → cmdReplay()  → runSubCommand("stress-strike-replay")
        │  "scan"            → cmdScan()
        │  "dashboard"       → cmdDashboard()
        │  "master"/"worker" → distributed
        │  "pentest"         → cmdPentest()
        │
        └── otherwise: if TTY → interactivePicker(), else cmdRun()
```

**Important:** `run` is the primary command. `replay/scan/dashboard/master/worker`
invoke separate binaries (under `cmd/`) via `runSubCommand()`.

### Flow B: `cmdRun` — the load-test flow

```
cmdRun()
  ├── flags declared (--url, --users, --duration, --profile, ...)
  ├── Scenario created:
  │     if configPath given → config.Load(path)   (YAML file)
  │     if --url given      → quickScenario(...)  (quick scenario from flags)
  ├── SLA/AQL? read scenario.SLA
  ├── engine.New(scenario)            → Engine object
  ├── eng.Run(ctx, RunOptions{...})   → <--- the test RUNS HERE
  ├── result converted to a Report via report.Build(...)
  ├── terminal report printed (display)
  ├── SLA evaluated → exit code
  └── JSON/TXT files saved
```

### Flow C: `engine.Run` — the core work (the most important flow!)

Inside, the following happens:

```
Engine.Run(ctx, opts)
  ├── LoadProfile created (steady/ramp/spike/wave/constant-rps)
  ├── pre-warm (if requested): TCP connections opened in advance
  ├── goroutine launched for each virtual user
  │      └── each user executes its "steps" (config.Step):
  │            sends HTTP/gRPC/WebSocket/raw TCP requests
  ├── result of each request measured → metrics.Telemetry
  ├── progress tracker ran (----% live)
  ├── capture (if requested): failed responses saved
  ├── pooling (if requested): data taken from a payload pool
  ├── gate (if requested): race-shot "simultaneous" test
  └── at the end the result returned → report package
```

**Sending requests** is handled in `internal/engine` by the following "client" files:
`client.go` (HTTP), `grpc_client.go`, `ws_client.go` (WebSocket),
`raw_client.go` (TCP), `streaming.go`.

### Flow D: Measurement → report

```
engine     → metrics.Telemetry
                 ├── Histogram (latency distribution)
                 ├── status code counts
                 ├── error type counts
                 └── timeline (per-second samples)
                 ▼
report.Build(t, scenario)  → Report struct
                 ├── report.Compare (compare against baseline)
                 ├── report.EvaluateSLA
                 └── display (nice terminal panel)
```

---

## Level 4: Per-package deep dive (when needed)

### `internal/config` — scenario hub

Key types:
- `Scenario` — the project's "passport": `Name`, `BaseURL`, `Profile`, `Steps`,
  `Variables`, `SLA`, `PreWarm`.
- `Profile` — load shape: `Type`, `Users`, `Duration`, `Warmup`, `RampUp`,
  `Spike*`, `WavePeriod`, `RPS`, `TargetRPS`, `Gate`, `RateLimit`.
- `Step` — a single request step: `Name`, `Method`, `URL`, `Body`, `Headers`,
  `Assertions`, `Extract`.
- `SLA` — targets: max P99, max error rate, min RPS.
- `Assertion` — response-body check.
- `RateLimitConfig` — global rate limit (token bucket).

Functions:
- `Load(path)` — reads YAML/JSON
- `LoadJSON(data)` — from JSON data
- internal `normalize*` — assigns default values to fields, prepends `http://`
  and validates.

### `internal/engine` — the core

Key types:
- `Engine` — the main object; created with `New(scenario)`, run via `Run(ctx, opts)`.
- `LoadProfile` (interface) — `ConcurrencyAt(t)`, `MaxConcurrency()`, `Duration()`.
  Implementations: `steady`, `ramp`, `spike`, `wave`, `constant-rps`
  (`profile.go`).
- `RunOptions` — `Out`, `Quiet`, `Capture`, `Pool`, `Progress`.
- `ProgressTracker` — live progress bar.

Important additional files:
- `client.go` — HTTP request sending (connection pooling, keep-alive)
- `grpc_client.go` — gRPC
- `ws_client.go` — WebSocket
- `raw_client.go` — raw TCP + `classifyNetError` (error classification)
- `streaming.go` — streaming responses, large payloads
- `buffer_pool.go` — buffer reuse (for performance)
- `token_bucket.go` — RPS limiting
- `capture.go` — capturing failed responses
- `assert.go` — assertion checking
- `vars.go` — scenario variables
- `broadcast.go` — broadcasting requests/gate
- `progress.go` — progress bar

### `internal/metrics`

- `Telemetry` — aggregate of the entire test result (`StartSampling` real-time).
- `StepStats` — per-step statistics.
- `Histogram` — latency distribution, `Percentile()` function.
- `Timeline` + `TimelineSample` — captures per-second samples.

### `internal/report`

- `Report` — the standard result structure (for JSON serialization).
- `StepReport` — a single-step report.
- `SLAResult` / `EvaluateSLA` — SLA verification.
- `Compare(current, baseline)` — regression detection.
- `GenerateHTML` / `GenerateMarkdown` / `GeneratePDF` — pentest reports.
- `LoadReport` / `SaveReport` — load/save to a file.
- `pdf_writer.go` / `pdf.go` — PDF generation (a Go-based reportlab analogue).
- `display.go` — attractive terminal panel (with ANSI colors).
- `compliance.go` — PCI-DSS / SOC2 / ISO27001 compliance assessment.

### `internal/replay`

- `PCAPParser` — reads PCAP files and organizes TCP sessions.
- `ReplayEngine` / `ReplayWorker` — replays real traffic.
- `ParseHAR` — HAR (HTTP Archive) files.
- `Capture` — a packet/traffic collection for replay.
- `types.go` — persisted data types.
- **TLS security:** `MinVersion TLS1.2`, warns on `--skip-tls-verify`.

### `internal/scanner` — security

- `NewScanner` top-level structure + submodules:
  - `vuln_scanner.go` / `cve.go` — vulnerabilities/CVEs
  - `nvd.go` — NVD database
  - `owasp.go` — OWASP Top 10
  - `crawler.go` — crawling through site pages
  - `auth.go` — authenticated scanning (AuthSession)
  - `verify.go` — confirming (verifying) a found vulnerability
- Result types: `TLSInfo`, `WAFInfo`, `HTTPInfo`, `ScanResult`,
  `CVEDetector`, `OWASPChecker`.

### `internal/dashboard`

- `Server` — HTTP server; `NewServer()`, `ServeHTTP`.
- `EngineBridge` — forwards engine results to the web.
- API: `/api/snapshot`, `/api/run`, `/api/history`, real-time WebSocket.
- `index.html` — browser side (interface).

### `internal/dist` (distributed)

- `proto/` — gRPC definition (`.pb.go` generated from `coordinator.proto`).
- `MasterWorker` — `Coordinate` bidi-streaming gRPC.
- The master splits and distributes the load, workers execute it, and results are
  collected.
- Flow: `WorkerCommand → WorkerEvent` (RunProgress, RunStarted, Report, ...).

### `api`

- `Config` / `Result` types.
- `Run(ctx, cfg)` — a complete test through a single function; for use in other
  projects as a Go library.

---

## Topics to study independently (Go fundamentals)

To deeply understand this project you need to know these Go/Golang concepts —
they are used heavily in the code:

1. **Goroutine** — `go func(){...}()`; the basis of parallel execution.
2. **Channel** — communication between goroutines.
3. **`sync`** — `Mutex`, `WaitGroup`, `sync.Once` (concurrency safety).
4. **Pointer / value receiver** — `*T` vs `T` in methods.
5. **Interface** — like `LoadProfile`, `ResponseCapture`; polymorphism.
6. **Error handling** — `errors.Is`, `errors.As`, `fmt.Errorf` (%w wrap).
7. **Context** — `context.Context`, `signal.NotifyContext` (cancellation).
8. **`net/http`** — HTTP server & client.
9. **JSON** — `encoding/json`, `Marshal/Unmarshal`, `omitempty`.
10. **YAML** — `gopkg.in/yaml.v3` (scenario loading).
11. **gRPC** — `google.golang.org/grpc`, code generation from `.proto`.
12. **WebSocket** — `gorilla/websocket`.
13. **`flag`** — CLI argument parsing.
14. **Histogram / percentile** — measurement distribution statistics.
15. **CI/CD** — GitHub Actions (`.github/workflows/ci.yml`, `release.yml`).
16. **Docker** — `Dockerfile`, multistage build.
17. **Performance** — buffer pool, connection reuse.

---

## Sample talking points (for interviews)

These are real examples that show you deeply know the project:

1. **"Connection pooling / keep-alive"** — reusing TCP connections in `client.go`,
   reaching 66k+ RPS.
2. **"Race condition (gate mode)"** — a feature from upstream; sending many
   requests at once to detect race conditions.
3. **"Histogram percentile"** — `metrics/histogram.go` for computing P99.
4. **"PCAP replay"** — replaying real traffic; a private key for TLS decryption.
5. **"Security compliance"** — PCI-DSS/SOC2/ISO27001 assessment —
   `report/compliance.go`.
6. **"Distributed"** — scaling across many machines via master/worker gRPC.
7. **"Fail-fast"** — the program fails quickly (12s) on dead targets — `probe`
   during an `abi` step.

---

## Self-assessment questions

If you can answer each in your own words — you are ready:

1. What does `main()` do? What subcommands exist?
2. How is the `Scenario` created in `cmdRun` (file vs --url)?
3. What happens inside `engine.Run` (the flow)?
4. What is `LoadProfile` and what types exist?
5. Why are `Telemetry` and `Histogram` needed?
6. What does `report.Build` return and how is it used?
7. Replay, scanner, dashboard, dist — what is the purpose of each?
8. Where is concurrency used? What safety measures exist (mutex)?
9. How does the SLA gate work and why is the exit code used?
10. Which tests run in CI/CD?

---

## Conclusion

- **Levels 1-2** — enough for a portfolio/interview (a few days).
- **Level 3** — tracing the main flows (about a week).
- **Level 4** — deep learning (optional, can continue for months).

**Remember:** you don't need to memorize the entire codebase. Knowing the **big
picture** and searching the files when needed — that's how a real developer works.