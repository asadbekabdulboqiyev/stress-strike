# ⚡ stress-strike

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/asadbekabdulboqiyev/stress-strike/actions/workflows/ci.yml/badge.svg)](https://github.com/asadbekabdulboqiyev/stress-strike/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/asadbekabdulboqiyev/stress-strike)](https://goreportcard.com/report/github.com/asadbekabdulboqiyev/stress-strike)

**stress-strike** is a professional-grade, multi-protocol **load testing &
network simulator** written in Go. It drives high volumes of realistic
concurrent traffic at a target system to discover its breaking point, latency
distribution, and error behavior — an open alternative to Apache JMeter and
Locust, built on pure Go concurrency.

```
This is a load generator. Use it ONLY against systems you own or have
explicit written permission to test. An unsanctioned load flood against
someone else's server is illegal (DDoS).
```

---

## ✨ Features

- **Multi-protocol** — stress HTTP/HTTPS, WebSocket (`ws://`/`wss://`),
  gRPC (`grpc://` plaintext / `grpcs://` TLS), raw TCP, and UDP targets from
  a single scenario file.
- **Scenario constructor** — YAML/JSON files define multi-step chains with
  variable extraction between steps (`POST /login` → extract token →
  `GET /profile` → `POST /cart` → `POST /checkout`).
- **5 load profiles** — `steady`, `soak`, `linear-ramp`, `spike`, and `wave`
  (sinusoidal load oscillation).
- **Assertions** — per-step pass/fail checks on status families (`2xx`), JSON
  paths, or regex matches; failures surface as `assert_failed` errors.
- **Cookie sessions** — per-virtual-user cookie jars replay `Set-Cookie` across
  scenario steps, enabling realistic multi-step authenticated flows.
- **SLA gate (CI/CD)** — declare latency/error/throughput thresholds in the
  scenario (`sla:`) or via `--expect-*` flags; violations exit with code 2 so
  pipelines fail automatically on performance regressions.
- **Baseline comparison** — `--compare baseline.json` prints a delta table
  (RPS, p50/p95/p99, errors) and flags regressions beyond `--regress-pct`.
- **Timeline export** — `--timeline` writes a per-second CSV (requests, errors,
  active users) for spreadsheets, notebooks, or Grafana.
- **Go library API** — `import "stress-strike/api"` to embed load tests in
  your own programs, test suites, and CI tooling.
- **Connection pooling** — keep-alive + tuned `http.Transport`
  (`MaxIdleConnsPerHost`, idle timeouts) so each request reuses a TCP socket.
- **Global pacing** — optional `rps` cap via a thread-safe token bucket.
- **Real-time telemetry** — live multi-line panel (progress bar, RPS sparkline,
  request/error counters, p50/p95/p99, active users) and a color-coded final
  report with per-step latency percentiles, a latency-distribution chart and
  status/error distributions.
- **Graceful drain** — in-flight requests at the end of a run are drained
  instead of being spuriously counted as errors.
- **Reports** — timestamped JSON and TXT files in `./reports/`, written with
  private (`0600`) permissions.
- **Safety rails** — concurrency caps, OS limit guard, sane defaults, and a
  legal notice on every run.

---

## 📦 Installation

### From source

Requires Go 1.26+:

```sh
go install github.com/asadbekabdulboqiyev/stress-strike/cmd/stress-strike@latest
```

### Build locally

```sh
git clone https://github.com/asadbekabdulboqiyev/stress-strike.git
cd stress-strike
make build          # produces bin/stress-strike + bin/demo-server
```

### Docker

```sh
docker build -t stress-strike .
docker run --rm --cpus=2 --memory=512m \
  stress-strike --url http://host.docker.internal:8080/health \
  --users 100 --duration 5
```

---

## 🚀 Quick start

```sh
# 200 concurrent users hammering /health for 5 seconds
./bin/stress-strike --url http://localhost:8080/health --users 200 --duration 5

# Ramp up to 1000 users over 30s, hold for 60s, capped at 2000 rps
./bin/stress-strike --url https://api.example.com --profile linear-ramp \
  --users 1000 --duration 90 --ramp-up 30 --rps 2000

# Spike: 5s baseline at 100 users, instant burst to 50,000 for 15s
./bin/stress-strike --url https://api.example.com --profile spike \
  --users 100 --spike-users 50000 --spike-warmup 5 --spike-hold 15

# Soak: 1 hour of constant load at 500 users (endurance/capacity testing)
./bin/stress-strike --url https://api.example.com --profile soak \
  --users 500 --duration 3600

# Wave: load oscillating with a 60s period (traffic-pattern simulation)
./bin/stress-strike --url https://api.example.com --profile wave \
  --users 1000 --duration 180 --wave-period 60
```

---

## 📄 Scenario files

Run a scripted multi-step scenario:

```sh
./bin/stress-strike --config examples/scenario.yaml
```

Scenario steps run **sequentially** per virtual user. Built-in per-user
template variables: `{{user}}`, `{{pass}}`, `{{email}}`, `{{item}}`, `{{id}}`,
plus any keys under `variables:`. Use `{{name}}` placeholders inside URLs,
headers, and bodies. `extract` pulls values from a step response and feeds
them into later steps:

```yaml
name: ecommerce-checkout
base_url: http://localhost:8080
load_profile:
  type: linear-ramp
  users: 1000
  duration: 120
  ramp_up: 30
  timeout: 5
  keep_alive: true

steps:
  - name: login
    method: POST
    url: /api/login
    body: '{"username":"{{user}}","password":"{{pass}}"}'
    extract:
      - name: token
        from: json        # json (dot path) | header | body (regex)
        path: data.token

  - name: profile
    method: GET
    url: /api/profile
    headers:
      Authorization: "Bearer {{token}}"
```

See `examples/scenario.yaml` (full chain) and `examples/spike.yaml`.

### Multi-protocol steps

Set `type` on a step to target a non-HTTP protocol (default is `http`):

```yaml
steps:
  - name: ws_chat          # WebSocket: dial → send body → read first frame
    type: ws
    url: wss://echo.websocket.events
    body: '{"user":"{{user}}"}'
    frame_type: text       # text (default) | binary
    session: true          # keep one persistent socket per virtual user
                           # (each iteration = one message round trip)
    assertions:
      - type: status
        value: "101"

  - name: grpc_method      # Generic unary invoke of any method
    type: grpc
    url: grpcs://api.example.com:443   # grpc:// plaintext / grpcs:// TLS
    grpc_method: /pkg.Service/Method   # omit to use standard health check
    headers:                           # sent as gRPC metadata
      authorization: "Bearer {{token}}"
    body: '{"id": "{{id}}"}'           # raw request payload

  - name: redis_ping        # Raw TCP: write bytes, read response
    type: tcp
    url: localhost:6379
    body: "PING\r\n"
    session: true           # reuse one persistent connection per user
    assertions:
      - type: regex
        value: "PONG"

  - name: stats_datagram    # UDP: fire-and-forget datagram
    type: udp
    url: localhost:8125
    body: 'stress.test:1|c'

  - name: dns_probe         # UDP request-response mode
    type: udp
    url: 1.1.1.1:53
    body: '{{dns_query}}'
    await_response: true    # wait for a reply and measure the RTT
    assertions:
      - type: regex
        value: ".+"
```

Protocol upgrades at a glance:

| Protocol | Default behavior | Enhanced options |
| --- | --- | --- |
| HTTP/HTTPS | Connection pooling + HTTP/2 | TLS session resumption, tuned buffers |
| WebSocket | Fresh dial per iteration | `session: true` — persistent sockets with ping/pong liveness, clean close handshake, binary frames |
| gRPC | Health check per call | Shared HTTP/2 conn pool, keepalive probes, custom methods via `grpc_method`, metadata headers |
| TCP | Fresh dial per iteration | `session: true` — persistent connections, self-healing on drop |
| UDP | Fire-and-forget | `await_response: true` — measure real RTT with assertions |

### Assertions

Each step may carry `assertions` — if any fail, the step is recorded as an
`assert_failed` error and the iteration stops:

```yaml
assertions:
  - type: status            # exact code or family: 200 | 2xx | 5xx
    value: "2xx"
  - type: json_path         # the dotted path must exist in the JSON body
    value: data.token
  - type: regex             # regex must match the response body
    value: "OK"
```

---

## 🔌 Go library API

Embed load tests directly in your own Go programs and CI tooling:

```go
import (
    "context"
    "time"

    "github.com/asadbekabdulboqiyev/stress-strike/api"
)

result, err := api.Run(ctx, api.Config{
    URL:      "http://localhost:8080/health",
    Users:    500,
    Duration: 10 * time.Second,
    Profile:  "wave",
})
if err != nil {
    // handle setup error
}
if result.ErrorRatePct > 2 {
    // fail the build / deployment gate
}
```

With an SLA gate:

```go
res, _ := api.Run(ctx, api.Config{
    URL:      "http://localhost:8080/health",
    Users:    300,
    Duration: 30 * time.Second,
    SLA:      &config.SLA{MaxP99Ms: 250, MaxErrorRatePct: 1},
})
if !res.SLAPassed {
    log.Fatalf("SLA violated: %+v", res.SLAResults)
}
```

`Result` exposes `TotalRequests`, `RPS`, `ErrorRatePct`, `P50/P95/P99`
latency, and full `StatusCodes` / `Errors` maps.

---

## 🏛️ Architecture

```
[ CLI / API ] --> [ Engine (scheduler + workers) ] --> [ Target ]
                        |                              (HTTP/WS/gRPC/TCP/UDP)
                        v
                  [ Telemetry --> Report (JSON/TXT) ]
```

- `cmd/stress-strike` — CLI entry point and flag parsing.
- `api` — stable, public Go library API.
- `internal/engine` — concurrency, load profiles, protocol clients,
  assertions, token-bucket pacing.
- `internal/config` — scenario model and validation.
- `internal/metrics` — lock-free histogram and telemetry.
- `internal/report` — live progress bar and JSON/TXT reporting.

The `internal/engine` package is designed to later split into standalone
**Worker Nodes**; `internal/report` + CLI logic maps to a future **Master
Controller**.

---

## ⚙️ CLI reference

| Flag | Description |
| --- | --- |
| `--config/-c FILE` | YAML/JSON scenario file (takes precedence over quick flags) |
| `--url URL` | target URL (quick mode) |
| `--method M` | HTTP method (quick mode, default `GET`) |
| `--data BODY` | request body (quick mode) |
| `--header K=V` | request header, repeatable |
| `--users N` | concurrent virtual users |
| `--duration S` | test duration in seconds |
| `--profile P` | `steady` \| `soak` \| `linear-ramp` \| `spike` \| `wave` |
| `--ramp-up S` | ramp-up duration (linear-ramp) |
| `--spike-users N` | burst target (spike) |
| `--spike-warmup S` | baseline warmup (spike) |
| `--spike-hold S` | burst hold (spike) |
| `--wave-period S` | oscillation period (wave, default duration/3) |
| `--rps N` | global pacing cap, `0` = unlimited |
| `--timeout S` | per-request timeout (default `5`) |
| `--keep-alive` | connection pooling on (default) |
| `--expect-p99-ms N` | SLA gate: fail the run if p99 exceeds this (exit code 2) |
| `--expect-avg-ms N` | SLA gate: avg latency ceiling in ms |
| `--expect-error-rate N` | SLA gate: max error rate in % |
| `--expect-min-rps N` | SLA gate: minimum throughput |
| `--compare FILE` | compare against a baseline JSON report (regression detection) |
| `--regress-pct N` | degradation % that counts as a regression (default 20) |
| `--timeline` | also write a per-second CSV timeline for analysis |
| `--quiet` | hide the live progress bar |
| `--report-dir DIR` | report output directory (default `./reports`) |
| `--version` | print version and exit |

**Exit codes:** `0` success · `1` setup error · `2` SLA/regression gate failed — perfect for CI/CD gates.

---

## 🧠 Engineering notes

- **Coordinated omission** — workers keep firing on the profile schedule
  rather than waiting for responses before the next request; in-flight
  requests at test end are drained gracefully (up to the per-request timeout).
- **OS limits** — run `ulimit -n` before large concurrency tests
  (e.g. `ulimit -n 65535`). The tool warns when the open-file limit looks low.
- **Latency reporting** — percentiles come from a fixed histogram with 1 ms
  resolution capped at 60 s (constant memory for millions of samples). Values
  at or above the cap are tracked exactly in min/max/avg and counted in a
  `clamped` counter in the JSON report.
- **Scenario templates** — `{{var}}` placeholders are substituted raw in URLs
  and headers; inside JSON bodies, values within quotes are JSON-escaped so
  extracted server data cannot corrupt the payload.
- **Error classes** — `timeout`, `connection_error`, `status_4xx`,
  `status_5xx`, `extract_error`, `redirect_limit`, `assert_failed`,
  `canceled`.

### Safety & boundaries

- Concurrency is capped (`users`/`spike_users` ≤ 100,000).
- Per-host connections are bounded (256–20,000) to prevent resource
  exhaustion of the test machine.
- Redirects are followed only within the same host (cross-host redirects are
  not followed) and limited to 10 hops.
- Per-request timeout bounds slow servers; response bodies are capped at
  8 MiB.
- Report files are written private (`0600`); filenames are sanitized.
- A legal notice is printed on every run; `Ctrl+C` stops gracefully, a second
  `Ctrl+C` exits immediately.

---

## 🎓 Cybersecurity Lab Playbook

This section is the instruction manual for students and engineers using
stress-strike in security & reliability coursework: what the tool is for,
what you may and may not do, and hands-on labs that build real skills.

### ⚖️ The rules (read first)

```
1. Load test ONLY systems you own or have explicit WRITTEN permission to test.
2. An unsanctioned load flood against someone else's server is a crime (DDoS).
3. University lab? Test ONLY lab targets (localhost, lab VMs, provided ranges).
4. Never use this tool to disrupt, extort, or "test" third parties "for fun".
5. Document every engagement: target, scope, time window, permission.
```

Breaking these rules turns an educational tool into an attack — and you into
a defendant. Every professional pentester signs scope agreements first.

### 🧪 What stress-strike is FOR (legitimate uses)

| Skill | How stress-strike trains it |
| --- | --- |
| **Capacity planning** | Find the breaking point: ramp users until p99 explodes (`linear-ramp`) |
| **DoS mitigation validation** | Prove YOUR rate limiter / WAF / autoscaler holds under load (see `rate_limit` config) |
| **Resilience engineering** | `spike` + `wave` profiles simulate traffic bursts; verify graceful degradation, not collapse |
| **Endurance / memory leaks** | 1-hour `soak` runs expose connection leaks, GC death spirals, log disk exhaustion |
| **CI/CD performance gates** | SLA thresholds fail the pipeline when latency/error budgets are violated (exit code 2) |
| **Regression detection** | `--compare` against yesterday's baseline catches silent slowdowns before users do |
| **Protocol mastery** | Multi-protocol scenarios teach HTTP/2, WebSocket lifecycle, gRPC streaming, raw sockets |

### 🥋 Lab drills (run against ./bin/demo-server)

**Lab 0 — Baseline (5 min)**
```sh
make build && ./bin/demo-server &
./bin/stress-strike --url http://localhost:8080/health --users 50 --duration 10 \
  --expect-p99-ms 100 --expect-error-rate 0
# Study the report: RPS, percentiles, status codes.
```

**Lab 1 — Find the breaking point (15 min)**
```sh
for n in 500 2000 8000; do
  ./bin/stress-strike --url http://localhost:8080/health \
    --users $n --duration 15 --name "capacity-$n" --quiet
done
# Compare reports/ capacity-* files: where does p99 bend? Where do errors start?
```

**Lab 2 — Spike resilience (10 min)**
```sh
./bin/stress-strike --url http://localhost:8080/health --profile spike \
  --users 100 --spike-users 5000 --spike-warmup 5 --spike-hold 20
# Question: does the server recover after the spike, or does error rate stay high?
```

**Lab 3 — Regression gate (10 min)** *(the DevSecOps workflow)*
```sh
# Day 1: save a healthy baseline.
./bin/stress-strike --url http://localhost:8080/health --users 200 --duration 10 \
  --name baseline-v1
# Day 2: after a code change, gate the deployment on it.
./bin/stress-strike --url http://localhost:8080/health --users 200 --duration 10 \
  --name release-candidate --compare "$(ls -t reports/baseline-v1_*.json | head -1)" \
  --regress-pct 25   # exit code 2 if p99/errors degrade >25%
```

**Lab 4 — Timeline forensics (10 min)**
```sh
./bin/stress-strike --url http://localhost:8080/health --profile wave \
  --users 1000 --duration 60 --timeline
python3 - <<'EOF'
import csv, glob
path = sorted(glob.glob('reports/*.csv'))[-1]
rows = list(csv.DictReader(open(path)))
peak = max(int(r['requests_delta']) for r in rows)
print(f"peak second throughput: {peak} req/s")
EOF
# Plot requests_delta over time — correlate dips with GC pauses or errors.
```

### 🔐 CI/CD integration example

```yaml
# .github/workflows/perf-gate.yml
jobs:
  perf-gate:
    runs-on: ubuntu-latest
    steps:
      - run: go install github.com/asadbekabdulboqiyev/stress-strike/cmd/stress-strike@latest
      # Start your service here, then:
      - run: |
          stress-strike --url http://localhost:8080/health \
            --users 300 --duration 30 \
            --expect-p99-ms 250 --expect-error-rate 1 --expect-min-rps 800
      # Exit code 2 fails the job automatically when the SLA is violated.
```

Scenario files support the same gates declaratively:

```yaml
name: api-slo-check
sla:                      # evaluated after the run; failure => exit code 2
  max_p99_ms: 250
  max_error_rate_pct: 1
  min_rps: 800
load_profile: { type: steady, users: 300, duration: 30 }
steps:
  - { name: health, url: /health }
```

---

## 🛡️ Security

See [SECURITY.md](SECURITY.md) for the full threat model and audit report.

Highlights: TLS ≥ 1.2 enforced (no `InsecureSkipVerify`), cross-host redirects
blocked, concurrency and duration limits enforced, response bodies capped at
8 MiB, private (`0600`) report files with sanitized filenames — scenario
variables, headers, bodies, and tokens never appear in report output.

---

## 🧪 Testing

The suite is race-safe and covers unit, integration, and benchmark tests:

```sh
make test        # go test -race ./...
make coverage    # coverage report (≈85–98% per core package)
make bench       # benchmarks (histogram, telemetry)
```

---

## 🛠️ Development & DevOps

The repo ships with a Makefile, a multi-platform build script, a Dockerfile,
and GitHub Actions workflows, so local development, CI, and releases share
the same quality gates.

### Makefile

```sh
make build      # build bin/stress-strike and bin/demo-server
make test       # go test -race ./...
make vet        # go vet ./...
make lint       # go vet + gofmt enforcement
make coverage   # run tests, write coverage.out, print coverage
make bench      # run benchmarks
make clean      # remove build artifacts
make install    # go install ./cmd/stress-strike (into PATH)
make release    # cross-compile all platforms into dist/
```

Release version defaults to `0.2.0`; override with `make release VERSION=1.2.3`.

### Multi-platform builds

`make release` (or `scripts/build-all.sh`) produces static binaries
(`CGO_ENABLED=0`) into `dist/` for:

```
darwin/arm64, darwin/amd64, linux/arm64, linux/amd64, windows/amd64
```

### CI/CD

- **ci.yml** — on push to `main` and pull requests: `lint` (vet + gofmt),
  `test` (race detector + coverage artifact), `build` (multi-platform matrix),
  and a `docker` job building `linux/amd64` + `linux/arm64` images. Images are
  pushed only on push events **and** when `secrets.DOCKER_USERNAME` /
  `secrets.DOCKER_TOKEN` are configured — no credentials are hardcoded.
- **release.yml** — on `v*` tags: runs the test suite, cross-compiles all
  five platforms, and attaches the binaries to a GitHub Release.

---

## 🗺️ Roadmap

1. **Distributed mode** — gRPC control plane between a master controller and
   standalone worker nodes for load generation from multiple machines.
2. **Web dashboard** — live charts over WebSockets (React) for real-time
   telemetry.
3. **Advanced coordinated omission** — pre-scheduled start slots to further
   reduce measurement bias.

---

## 📄 License

[MIT](LICENSE) © Asadbek Abdulboqiyev

---

## 🤝 Contributing

Contributions are welcome. Please open an issue or pull request and keep the
quality gates green: `make lint && make test`.
