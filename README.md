# stress-strike

A professional-grade **load testing & network simulator** written in Go. It
sends high volumes of realistic concurrent requests to a target server to
discover its breaking point, latency distribution, and error behavior — an
analog of Apache JMeter / Locust, built with pure Go concurrency (no AI).

> **WARNING**: Only run stress tests against systems you own or have explicit
> permission to test. An unsanctioned load flood against someone else's
> server is illegal (DDoS). This tool is intended for QA, capacity planning,
> and performance engineering of your own infrastructure.

## Features

- **Scenario constructor** — YAML/JSON files define multi-step chains with
  variable extraction between steps (e.g. `POST /login` → extract token →
  `GET /profile` → `POST /cart` → `POST /checkout`).
- **Load profiles**
  - `steady` — fixed concurrent virtual users.
  - `linear-ramp` — users rise from 0 to `users` over `ramp_up`, then hold.
  - `spike` — baseline warmup, then an instant burst to `spike_users`.
- **Connection pooling** — keep-alive + tuned `http.Transport`
  (`MaxIdleConnsPerHost`, idle timeouts) so each request does not open a new
  TCP socket.
- **Global pacing** — optional `rps` cap via a thread-safe token bucket.
- **Real-time telemetry** — live progress line (RPS, active users, errors,
  p50/p95/p99) plus final report with per-step latency percentiles and status
  code / error distributions.
- **Graceful drain** — requests in flight when the test window ends are given
  time to finish instead of being spuriously counted as errors.
- **Reports** — timestamped JSON and TXT files in `./reports/`.
- **OS limit guard** — warns when the open-file (`ulimit -n`) limit may be too
  low for the planned concurrency.

## Build

```sh
go build -o bin/stress-strike ./cmd/stress-strike
```

## Quick usage

```sh
# 200 concurrent users hammering /health for 5s
./bin/stress-strike --url http://localhost:8080/health --users 200 --duration 5

# Ramp up to 1000 users over 30s, hold for 60s, cap at 2000 rps
./bin/stress-strike --url https://api.example.com --profile linear-ramp \
  --users 1000 --duration 90 --ramp-up 30 --rps 2000

# Spike: 5s baseline at 100 users, then instant burst to 50,000 for 15s
./bin/stress-strike --url https://api.example.com --profile spike \
  --users 100 --spike-users 50000 --spike-warmup 5 --spike-hold 15
```

## Scenario file

```sh
./bin/stress-strike --config examples/scenario.yaml
```

Scenario steps run sequentially per virtual user. Built-in per-user template
variables: `{{user}}`, `{{pass}}`, `{{email}}`, `{{item}}`, `{{id}}`, plus any
keys under `variables:`. Use `{{name}}` placeholders inside URLs, headers, and
bodies. `extract` pulls values from a step response and feeds them into later
steps:

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

## Local demo target

A small reference server matching the example scenario is included:

```sh
go build -o bin/demo-server ./examples/demo_server.go
./bin/demo-server            # listens on :8080 (or pass a port)
./bin/stress-strike --config examples/scenario.yaml
```

## Load profiles & flags

| Flag | Meaning |
| --- | --- |
| `--config/-c FILE` | YAML/JSON scenario file (takes precedence over quick flags) |
| `--url URL` | target URL (quick mode) |
| `--method M` | HTTP method (quick mode, default GET) |
| `--data BODY` | request body (quick mode) |
| `--header K=V` | request header, repeatable |
| `--users N` | concurrent virtual users |
| `--duration S` | test duration (seconds) |
| `--profile P` | `steady` \| `linear-ramp` \| `spike` |
| `--ramp-up S` | ramp-up duration (linear-ramp) |
| `--spike-users N` | burst target (spike) |
| `--spike-warmup S` | baseline warmup (spike) |
| `--spike-hold S` | burst hold (spike) |
| `--rps N` | global pacing cap, 0 = unlimited |
| `--timeout S` | per-request timeout (default 5) |
| `--keep-alive` | connection pooling on (default) |
| `--quiet` | hide live progress line |
| `--report-dir DIR` | report output dir (default `./reports`) |

## Architecture

```
[ CLI ] --> [ Engine (master scheduling + workers) ] --> [ Target ]
                  |                                       (HTTP/WS)
                  v
            [ Telemetry --> Report (JSON/TXT) ]
```

The `internal/engine` package is designed to later split into standalone
**Worker Nodes**; `internal/report` + CLI logic maps to a future **Master
Controller**. Planned roadmap:

1. gRPC control plane between Master and Workers (distributed load generation).
2. Web dashboard with live charts (React + WebSockets) for real-time telemetry.
3. Advanced coordinated-omission handling via pre-scheduled start slots.

## Engineering notes

- **Coordinated omission**: workers keep firing on the profile schedule rather
  than waiting for responses before the next request; in-flight requests at
  test end are drained gracefully (up to the per-request timeout).
- **OS limits**: run `ulimit -n` before large concurrency tests
  (e.g. `ulimit -n 65535`). The tool warns when the open-file limit looks low.
- **Safety & boundaries**
  - Concurrency is capped (`users`/`spike_users` ≤ 100,000).
  - Per-host connections are bounded (256–20,000) to prevent resource
    exhaustion of the test machine.
  - Redirects are followed only within the same host (cross-host redirects are
    not followed) and limited to 10 hops.
  - Per-request timeout bounds slow servers; response bodies are capped at
    8 MiB.
  - Report files are written private (0600); filenames are sanitized.
  - A legal notice is printed on every run; `Ctrl+C` stops gracefully, a second
    `Ctrl+C` exits immediately.
- **Error classes**: `timeout`, `connection_error`, `status_4xx`,
  `status_5xx`, `extract_error`, `redirect_limit`, `canceled`.
- **Latency reporting**: percentiles come from a fixed histogram with 1 ms
  resolution capped at 60 s (constant memory for millions of samples). Values
  at or above the cap are tracked exactly in min/max/avg and counted in a
  `clamped` counter in the JSON report.
- **Scenario templates**: `{{var}}` placeholders are substituted raw in URLs
  and headers; inside JSON bodies, values placed within quotes are JSON-escaped
  so extracted server data cannot corrupt the payload.

## Tests

```sh
go test -race ./...
```
