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
- **Go library API** — `import "stress-strike/api"` to embed load tests in
  your own programs, test suites, and CI tooling.
- **Connection pooling** — keep-alive + tuned `http.Transport`
  (`MaxIdleConnsPerHost`, idle timeouts) so each request reuses a TCP socket.
- **Global pacing** — optional `rps` cap via a thread-safe token bucket.
- **Real-time telemetry** — live progress bar (RPS, active users, errors,
  p50/p95/p99) and a color-coded final report with per-step latency
  percentiles and status/error distributions.
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
    assertions:
      - type: status
        value: "101"

  - name: grpc_health       # gRPC Health/Check (grpcs:// enables TLS)
    type: grpc
    url: grpc://localhost:50051

  - name: redis_ping        # Raw TCP: write bytes, read response
    type: tcp
    url: localhost:6379
    body: "PING\r\n"
    assertions:
      - type: regex
        value: "PONG"

  - name: stats_datagram    # UDP: fire-and-forget datagram
    type: udp
    url: localhost:8125
    body: 'stress.test:1|c'
```

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
| `--quiet` | hide the live progress bar |
| `--report-dir DIR` | report output directory (default `./reports`) |
| `--version` | print version and exit |

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
