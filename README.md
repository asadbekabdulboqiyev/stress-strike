```
                  _____ _               _____       _             __
                 / ____| |             |_   _|     | |           / _|
                | (___ | |_ __ _ _ __   | |  _ __ | | _____  __| |_ ___  ___
                 \___ \| __/ _` | '__|  | | | '_ \| |/ / _ \/ __|  _/ _ \/ __|
                 ____) | || (_| | |     _| |_| | | |   <  __/ (__| ||  __/ (__
                |_____/ \__\__,_|_|    |_____|_| |_|_|\_\___|\___|_| \___|\___|
```

[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Version](https://img.shields.io/badge/Version-0.12.0-green.svg)]()

Ultra-fast multi-protocol load testing, traffic replay, and security audit suite — written in Go.

---

## Features

- **Multi-protocol** — HTTP/HTTPS, WebSocket (`ws://`/`wss://`), gRPC (`grpc://` plaintext / `grpcs://` TLS), TCP, and UDP from a single scenario file
- **Scenario constructor** — YAML/JSON multi-step chains with variable extraction between steps (`POST /login` → extract token → `GET /profile` → `POST /cart`)
- **5 load profiles** — `steady`, `soak`, `linear-ramp`, `spike`, `wave` (sinusoidal load oscillation)
- **Assertions** — per-step pass/fail checks on status families (`2xx`), JSON paths, or regex matches; failures surface as `assert_failed` errors
- **1-click pentest** — full security assessment: recon, vuln scan, CVE detection, OWASP Top 10, client-ready PDF report
- **PCAP/HAR replay** — replay real captured traffic at 1x–100x speed
- **TLS/WAF scanner** — deep cipher suite analysis, WAF fingerprinting, security headers audit
- **Real-time web dashboard** — live RPS, latency, error charts via WebSocket
- **Distributed mode** — master/worker architecture over gRPC for multi-machine load
- **SLA gate** — CI/CD performance gate with exit code 2 on regression
- **Baseline comparison** — delta reports against a previous run (RPS, p50/p95/p99, errors)
- **Go library API** — `import "stress-strike/api"` for embedding in programs and test suites
- **Timeline CSV** — per-second export for Grafana, Jupyter, or spreadsheet analysis
- **Global pacing** — optional `rps` cap via a thread-safe token bucket
- **Real-time telemetry** — live progress bar (RPS, active users, errors, p50/p95/p99, top error types) and color-coded final report with per-step latency percentiles
- **Connection pooling** — keep-alive + tuned `http.Transport` (`MaxIdleConnsPerHost`, idle timeouts) and graceful drain
- **Race-condition strikes** — `--gate` parks every virtual user on a start barrier and fires ONE request per user the instant it opens, maximizing the chance of exploiting check-then-act windows (double-spend, coupon reuse, OTP races). For authorized bug-bounty targets only
- **BEAST preset** — `--beast` (or wizard mode 3): 100k-user linear ramp with unlimited RPS over 300s, auto-tuned to find breaking points on systems you own or have written permission to test
- **Warmup period** — `--warmup S` sends load for S seconds without counting it toward metrics, so percentiles reflect the warmed-up steady state
- **JSON stdout** — `--json` prints the full machine-readable report for jq, CI gates, and dashboards
- **Debug capture** — opt-in `--capture N` saves the first N raw responses (≤100, bodies ≤2KB each) to a private capture file for diagnosing what the target actually returns. Request credentials are never captured; off by default
- **Payload pools** — `--pool FILE` loads one payload per line; `{{pool}}` gets a unique value per request
- **Reports** — timestamped JSON and TXT files in `./reports/`, written with private (`0600`) permissions
- **Safety rails** — concurrency caps, OS limit guard, sane defaults, and a legal notice on every run

---

## Quick Start

Ranjit (one command) is inside the repo and runnable on this machine the way
the website says. From a terminal:

```sh
./start.sh
```

It builds the binaries **once** (first run only), boots a safe local demo
site, serves the real-time **web dashboard** on http://localhost:8888, opens
your browser automatically, and hands you a URL field + a **Start** button.
No Docker. No SSH. No servers. No cloud account. Ctrl+C stops everything
when you&rsquo;re done and cleans up the demo site.

> Give it a real target whenever you like:
> `URL=https://api.example.com USERS=100 DURATION=60 ./start.sh`

### Install (one command)

> By default `stress-strike` installs from the module proxy. Requires **Go 1.26+**.
> The whole suite is pure Go — no CGO, no libpcap, no system dependencies.

```sh
# Latest release (installs all binaries: run, replay, scan, dashboard, master, worker)
go install github.com/asadbekabdulboqiyev/stress-strike/cmd/stress-strike@latest

# Or use the convenience installer (installs every binary, pin with ./scripts/install.sh v0.12.0)
curl -fsSL https://raw.githubusercontent.com/asadbekabdulboqiyev/stress-strike/main/scripts/install.sh | bash
```

If `stress-strike` isn't found after installing, add Go's bin directory to your `PATH`:

```sh
export PATH="$PATH:$(go env GOPATH)/bin"
```

> **Pure-Go:** PCAP/HAR replay uses in-tree `pcapgo` — nothing to install,
> no `brew install libpcap`, works on macOS/Linux/Windows out of the box.
> Upgrade an old install anytime:
> ```sh
> go install github.com/asadbekabdulboqiyev/stress-strike/cmd/stress-strike@latest
> ./scripts/install.sh   # or: ./scripts/install.sh v0.12.0
> ```

### Your first test in 60 seconds

Use the bundled demo server so you never have to point a generator at a real
service to try it out — there is nothing to break:

```sh
# Terminal 1 — start a local demo target (health, auth, slow, and failing endpoints)
go run github.com/asadbekabdulboqiyev/stress-strike/examples/demo_server.go

# Terminal 2 — 200 concurrent users hitting /health for 30 seconds
stress-strike run --url http://localhost:8080/health --users 200 --duration 30
```

You get a live progress bar, then a terminal report with RPS, latency
distribution, and error counts. Want a prettier view? Press `Ctrl+C` and run
again with `--mode dashboard`, then open http://localhost:8888 and hit **Start**.

### Load profiles that matter

```sh
# Ramp to 1000 users over 30s, hold for 60s, capped at 2000 rps
stress-strike run --url https://api.example.com --profile linear-ramp \
  --users 1000 --duration 90 --ramp-up 30 --rps 2000

# Instant spike: 100 users baseline, burst to 50K for 15s
stress-strike run --url https://api.example.com --profile spike \
  --users 100 --spike-users 50000 --spike-warmup 5 --spike-hold 15

# 1-hour soak test at 500 users
stress-strike run --url https://api.example.com --profile soak \
  --users 500 --duration 3600

# Sinusoidal wave with 60s oscillation period
stress-strike run --url https://api.example.com --profile wave \
  --users 1000 --duration 180 --wave-period 60

# CI/CD gate — fail (exit 2) if P99 > 200ms or error rate > 1%
stress-strike run --url https://api.example.com --users 50 --duration 30 \
  --expect-p99-ms 200 --expect-error-rate 1
```

### Build from source

```sh
git clone https://github.com/asadbekabdulboqiyev/stress-strike.git
cd stress-strike
make build          # produces bin/stress-strike + all sibling binaries
make test           # run the full suite with the race detector
```

When working from the clone (e.g. before a version is published), start the
demo target locally and run a test against it:

```sh
go run ./examples/demo_server.go          # terminal 1 — local demo target
go run ./cmd/stress-strike run --url http://localhost:8080/health --users 100 --duration 20
```

---

## Commands Reference

```
stress-strike <command> [flags]
```

| Command | Description |
|---------|-------------|
| `run` | HTTP/gRPC/WebSocket/TCP/UDP load test (default) |
| `pentest` | 1-click professional security assessment |
| `replay` | Replay real traffic from PCAP/HAR captures |
| `scan` | TLS/WAF deep scanner + fingerprinting |
| `dashboard` | Real-time web dashboard with WebSocket |
| `master` | Distributed mode — master coordinator |
| `worker` | Distributed mode — worker node |

### `stress-strike pentest`

Full security assessment in one command — 14 automated phases:

```bash
# Standard assessment (crawl + NVD + compliance, all report formats)
stress-strike pentest --target https://example.com

# Authenticated scan behind login (where 80% of vulnerabilities live)
stress-strike pentest --target https://app.example.com \
  --auth-form https://app.example.com/login \
  --auth-user admin --auth-pass 'S3cret'

# Session cookie / API token auth
stress-strike pentest --target https://app.example.com --auth-cookie 'session=abc123'
stress-strike pentest --target https://api.example.com --auth-header 'Authorization: Bearer eyJ...'

# Deep scan, verbose, PDF only, PCI DSS only
stress-strike pentest --target example.com --depth 3 --verbose --format pdf --compliance pci-dss

# Web-only scope, no crawling, skip load test
stress-strike pentest --target https://example.com --crawl=false --skip-load-test
```

Phases: technology fingerprint → port scan → subdomain discovery →
**authentication** → **attack-surface crawl** (endpoints + forms) → security
headers → TLS → WAF detection → **deep vulnerability scan** (SQLi, XSS,
traversal, open redirect, default credentials, CORS, API security, cookies,
info disclosure — across crawled endpoints, with **confidence verification**:
`[VERIFIED]` / `[PROBABLE]` / `[UNVERIFIED]`) → **CVE detection** (90+
signatures + **live NVD**, 240K+ CVEs, cached) → OWASP Top 10 →
**compliance mapping** (PCI DSS v4.0, SOC 2, ISO 27001:2022) → load probe →
reports.

Output (default `--format all`) in `reports/pentest-{target}-{ts}/`:
`pentest.html`, `pentest.json`, `pentest.md` plus client-ready
`pentest-professional.pdf` (cover page, executive summary, risk gauge,
detailed findings, OWASP matrix, **compliance impact**, timeline,
disclaimer). Exit codes: `2` critical/high findings, `1` medium, `0` clean —
CI/CD friendly.

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | | Target URL or domain (required) |
| `--depth` | `2` | Scan depth: 1=quick, 2=standard, 3=deep |
| `--format` | `all` | `html`, `json`, `markdown`, `pdf`, `professional`, `all` |
| `--scope` | `full` | `full`, `web`, `network` |
| `--threads` | `10` | Parallel threads |
| `--timeout` | `10` | Request timeout (seconds) |
| `--skip-load-test` | `false` | Skip the load probe phase |
| `--crawl` | `true` | Discover endpoints/forms by crawling |
| `--max-pages` | `50` | Crawl page limit |
| `--auth-form` | | Login URL for authenticated scanning |
| `--auth-user` / `--auth-pass` | | Credentials for form login |
| `--auth-cookie` | | Raw cookie header (session auth) |
| `--auth-header` | | Static header, e.g. `Authorization: Bearer x` |
| `--nvd` | `true` | Live NVD lookup (240K+ CVEs; `NVD_API_KEY` env raises rate limit) |
| `--compliance` | all three | `pci-dss,soc2,iso27001` or `none` |
| `--output` | auto | Output directory |
| `--verbose` | `false` | Detailed findings in terminal |

> **Ethical use:** only run against systems you own or have written
> authorization to test.

### `stress-strike run`

Core load testing command. Run with `--url` for quick mode or `--config` for YAML scenarios.

| Flag | Default | Description |
|------|---------|-------------|
| `--config, -c` | | YAML/JSON scenario file |
| `--url` | | Target URL (quick mode) |
| `--method` | `GET` | HTTP method |
| `--data` | | Request body |
| `--header` | | Header in `Key=Value` form (repeatable) |
| `--name` | `quick-test` | Report/test name |
| `--users` | `10` | Concurrent virtual users |
| `--duration` | `30` | Duration in seconds |
| `--profile` | `steady` | `steady` \| `soak` \| `linear-ramp` \| `spike` \| `wave` |
| `--ramp-up` | half of duration | Ramp-up duration (seconds) |
| `--spike-users` | 10x users | Burst target for spike profile |
| `--spike-warmup` | `5` | Baseline warmup before spike |
| `--spike-hold` | `10` | Spike burst hold duration |
| `--wave-period` | duration/3 | Oscillation period for wave |
| `--rps` | `0` (unlimited) | Global pacing cap |
| `--timeout` | `5` | Per-request timeout (seconds) |
| `--keep-alive` | `true` | Reuse TCP connections |
| `--tls-fingerprint` | | Present a browser/mobile TLS ClientHello (chrome, firefox, safari, edge, ios, android_okhttp, randomized, golang, ...) — beats JA3-based blocking |
| `--expect-p99-ms` | | SLA: max p99 latency (ms) |
| `--expect-avg-ms` | | SLA: max avg latency (ms) |
| `--expect-error-rate` | | SLA: max error rate (%) |
| `--expect-min-rps` | | SLA: minimum throughput |
| `--compare` | | Baseline JSON for regression detection |
| `--regress-pct` | `20` | Regression threshold (%) |
| `--timeline` | | Write per-second CSV timeline |
| `--quiet` | | Disable live progress bar |
| `--report-dir` | `./reports` | Report output directory |

**Exit codes:** `0` success · `1` setup error · `2` SLA/regression gate failed

### `stress-strike replay`

Replay captured production traffic at configurable speed. Supports PCAP and HAR formats.

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | | PCAP or HAR file (required) |
| `--rate` | `1x` | Replay speed multiplier (1x–100x) |
| `--concurrency` | `10` | Concurrent replay workers |
| `--duration` | | Max replay duration (e.g. `30s`, `5m`) |
| `--base-url` | | Override target base URL |
| `--methods` | | Filter by HTTP methods (e.g. `GET,POST`) |
| `--url-pattern` | | Filter by URL glob pattern |
| `--status` | | Filter by response status codes |
| `--validate` | | Run response assertions |
| `--assert-status` | | Assert response status code |
| `--assert-regex` | | Assert response body matches regex |
| `--tls-key` | | TLS private key for decryption |
| `--tls-cert` | | TLS certificate for decryption |
| `--output-json` | | Export results to JSON |
| `--output-csv` | | Export latency data to CSV |

```sh
# Replay HAR at 10x speed
stress-strike replay --input traffic.har --rate 10x

# Replay PCAP at 50x with 50 workers, only GET requests
stress-strike replay --input capture.pcap --rate 50x --concurrency 50 --methods GET

# Replay with response validation
stress-strike replay --input traffic.har --rate 5x --validate --assert-status 200

# Replay to staging server
stress-strike replay --input traffic.har --base-url https://staging.example.com --rate 5x
```

### `stress-strike scan`

TLS/WAF deep scanner with vulnerability detection and risk scoring.

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | | Target host (required, e.g. `example.com`) |
| `--port` | `443` | Target port |
| `--all` | (default if no filter) | Run all scans |
| `--tls` | | TLS scan only |
| `--http` | | HTTP fingerprint only |
| `--waf` | | WAF detection only |
| `--security` | | Security headers audit only |
| `--output-json` | | Export results to JSON file |

Scans include:
- **TLS** — cipher suites, certificate chain, version vulnerabilities, forward secrecy
- **HTTP** — server fingerprinting, technology detection, CORS analysis
- **WAF** — Cloudflare, Akamai, AWS WAF, and 30+ providers detected
- **Security** — HSTS, CSP, CORS, X-Frame-Options, and 15+ headers audited
- **Vulnerabilities** — risk-scored findings with remediation guidance

```sh
# Full scan
stress-strike scan --target example.com --all

# TLS scan only
stress-strike scan --target example.com --tls

# Export scan to JSON
stress-strike scan --target example.com --all --output-json scan.json
```

### `stress-strike dashboard`

Start a real-time web dashboard with live telemetry over WebSocket.

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8888` | Dashboard listen address |

Features:
- Live RPS sparkline graph
- Latency percentiles (p50/p95/p99) in real-time
- Error rate tracking with history
- Worker node monitoring in distributed mode
- Start/stop runs directly from the browser

```sh
stress-strike dashboard --listen :9090
# Open http://localhost:9090
```

### `stress-strike master`

Distributed load testing coordinator. Distributes users across worker nodes.

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:50051` | Master listen address |
| `--workers` | | Comma-separated worker addresses (static fleet) |
| `--wait-workers` | `0` | Auto-discovery: wait for N self-registering workers |
| `--wait-timeout` | `30` | Auto-discovery registration timeout (seconds) |
| `--token` | | Shared control-plane token (empty = disabled) |
| `--run-timeout` | `0` | Overall run deadline (0 = duration + 60s) |
| `--config` | | YAML scenario file |
| `--url` | | Target URL (quick mode) |
| `--users` | `100` | Total virtual users (split across workers) |
| `--duration` | `30` | Duration in seconds |
| `--profile` | `steady` | Load profile |
| `--expect-p99-ms` | | SLA: max p99 latency |
| `--expect-error-rate` | | SLA: max error rate (%) |
| `--expect-min-rps` | | SLA: minimum throughput |
| `--compare` | | Baseline for regression detection |
| `--regress-pct` | `20` | Regression threshold (%) |
| `--timeline` | | Export CSV timeline |
| `--quiet` | `false` | Suppress the live aggregate progress line |

### `stress-strike worker`

Distributed load testing worker node. Receives commands from master over gRPC.

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:0` (random) | Worker listen address |
| `--advertise` | listen addr | Address advertised to the master |
| `--master` | | Master address for self-registration |
| `--id` | auto-generated | Worker identifier |
| `--max-users` | `100000` | Max virtual users this worker supports |
| `--max-runs` | `4` | Max concurrent runs |
| `--token` | | Shared control-plane token (must match master) |

The master aggregates live telemetry from every worker (200 ms cadence), keeps
running if a worker dies, and merges the final per-worker reports. Every
load-shaping field (`users`, `spike_users`, `rps`) is split across the fleet.
See [docs/DISTRIBUTED.md](docs/DISTRIBUTED.md) for the full guide, including
fault tolerance, security, Docker and systemd deployment, and the Linux worker
cross-compile script:

```sh
./scripts/build-worker-linux.sh 0.12.0   # or: make worker-linux
```

---

## YAML Scenario Files

Scenarios define multi-step flows that run sequentially per virtual user. Variables extracted from earlier steps are available in later steps via `{{name}}` placeholders.

### Template Variables

Built-in per-virtual-user variables: `{{user}}`, `{{pass}}`, `{{email}}`, `{{item}}`, `{{id}}`
Custom variables: defined under the `variables:` key

### E-commerce Checkout Flow

```yaml
name: ecommerce-checkout
base_url: http://localhost:8080

variables:
  tenant: demo

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
    headers:
      Content-Type: application/json
    body: '{"username":"{{user}}","password":"{{pass}}","tenant":"{{tenant}}"}'
    extract:
      - name: token
        from: json
        path: data.token

  - name: profile
    method: GET
    url: /api/profile
    headers:
      Authorization: "Bearer {{token}}"

  - name: add_to_cart
    method: POST
    url: /api/cart
    headers:
      Authorization: "Bearer {{token}}"
      Content-Type: application/json
    body: '{"item":"{{item}}","qty":1}'
    extract:
      - name: cart_id
        from: json
        path: data.cart_id

  - name: checkout
    method: POST
    url: /api/checkout
    headers:
      Authorization: "Bearer {{token}}"
      Content-Type: application/json
    body: '{"cart_id":"{{cart_id}}"}'
```

### Multi-Protocol Steps

Set `type` on a step to target non-HTTP protocols:

```yaml
steps:
  - name: ws_chat
    type: ws
    url: wss://echo.websocket.events
    body: '{"user":"{{user}}"}'
    frame_type: text          # text (default) | binary
    session: true             # persistent socket per virtual user
    assertions:
      - type: status
        value: "101"

  - name: grpc_method
    type: grpc
    url: grpcs://api.example.com:443
    grpc_method: /pkg.Service/Method
    headers:
      authorization: "Bearer {{token}}"
    body: '{"id": "{{id}}"}'

  - name: redis_ping
    type: tcp
    url: localhost:6379
    body: "PING\r\n"
    session: true             # persistent connection per user
    assertions:
      - type: regex
        value: "PONG"

  - name: stats_datagram
    type: udp
    url: localhost:8125
    body: 'stress.test:1|c'

  - name: dns_probe
    type: udp
    url: 1.1.1.1:53
    body: '{{dns_query}}'
    await_response: true      # measure real RTT
    assertions:
      - type: regex
        value: ".+"
```

| Protocol | `session: true` | Notes |
|----------|-----------------|-------|
| HTTP/HTTPS | N/A (always pooled) | HTTP/2, TLS session resumption |
| WebSocket | Persistent socket | Ping/pong liveness, binary frames |
| gRPC | Shared HTTP/2 pool | Keepalive probes, custom methods |
| TCP | Persistent connection | Self-healing on drop |
| UDP | N/A | `await_response: true` for RTT |

### Assertions

Each step supports pass/fail assertions. Failed assertions record `assert_error` and stop the iteration.

```yaml
assertions:
  - type: status            # exact code or family: 200 | 2xx | 5xx
    value: "2xx"
  - type: json_path         # dotted path must exist in JSON body
    value: data.token
  - type: regex             # regex must match response body
    value: "OK"
```

### Authentication Flow with SLA Gate

```yaml
name: login-flow
base_url: http://localhost:8080

variables:
  username: testuser@example.com
  password: s3cretP@ss

load_profile:
  type: linear-ramp
  users: 200
  duration: 120
  ramp_up: 60
  timeout: 10

steps:
  - name: login
    type: http
    method: POST
    url: /api/auth/login
    headers:
      Content-Type: application/json
    body: '{"email": "{{username}}", "password": "{{password}}"}'
    extract:
      - name: auth_token
        from: json
        path: token
      - name: refresh_token
        from: json
        path: refresh_token
    assertions:
      - type: status
        value: "200"
      - type: json_path
        value: token

  - name: get-profile
    type: http
    method: GET
    url: /api/users/me
    headers:
      Authorization: Bearer {{auth_token}}
    assertions:
      - type: status
        value: "200"

  - name: logout
    type: http
    method: POST
    url: /api/auth/logout
    headers:
      Authorization: Bearer {{auth_token}}
      Content-Type: application/json
    body: '{"refresh_token": "{{refresh_token}}"}'

sla:
  max_p99_ms: 500
  max_avg_ms: 250
  max_error_rate_pct: 2
  min_rps: 50
```

---

## Distributed Mode

Run load tests across multiple machines using the master/worker architecture over gRPC.

### Setup

```sh
# On machine A (worker)
stress-strike-worker -listen :50052 -id worker-a -max-users 200000

# On machine B (worker)
stress-strike-worker -listen :50052 -id worker-b -max-users 200000

# On machine C (master) — distributes 3000 users across 2 workers
stress-strike-master \
  -workers host-a:50052,host-b:50052 \
  -url https://api.example.com \
  -users 3000 \
  -duration 60 \
  -profile linear-ramp
```

### With scenario file

```sh
stress-strike-master \
  -workers host-a:50052,host-b:50052,host-c:50052 \
  -config scenario.yaml
```

The master splits every load-shaping field (`users`, `spike_users`, `rps`)
across workers, streams and aggregates live telemetry every 200 ms, keeps
running if a worker dies, and produces a unified report with recomputed SLA
verdicts.

### Auto-discovery

Start the master with `-wait-workers N`, then launch workers that register
themselves — no static address list needed:

```sh
stress-strike-master -listen :50051 -wait-workers 3 -url https://api.example.com -users 30000 -duration 120

stress-strike-worker -listen 0.0.0.0:50052 -id worker-a \
  -master master-host:50051 -advertise host-a:50052
```

### Securing the control plane

Pass the same `-token` to the master and every worker; calls without it are
rejected with `Unauthenticated`:

```sh
stress-strike-master -workers host-a:50052 -token "$STRESS_TOKEN" ...
stress-strike-worker -listen :50052 -token "$STRESS_TOKEN" ...
```

### Deploying to real Linux load hosts

```sh
./scripts/build-worker-linux.sh 0.12.0   # or: make worker-linux
```

Each archive (amd64/arm64) ships the worker, the master, a hardened systemd
unit and an `worker.env` template. See
[docs/DISTRIBUTED.md](docs/DISTRIBUTED.md) for systemd, Docker, sysctl tuning
and the full CLI reference.

For a ready-to-run VPS fleet straight from your SSH keys, two helpers ship in
the repo:

```sh
# one host manually
scp dist/linux-worker/stress-strike-worker-v0.12.0-linux-amd64.tar.gz deploy/fleet/bootstrap-worker.sh root@HOST:/tmp/
ssh root@HOST 'cd /tmp && \
  SS_MASTER=10.0.0.5:50051 SS_TOKEN=secret \
  bash bootstrap-worker.sh stress-strike-worker-v0.12.0-linux-amd64.tar.gz'

# a whole fleet (builds packages, scp + installs, prints the master command)
./scripts/deploy-fleet.sh --master 10.0.0.5:50051 --token secret -- root@10.0.0.11 root@10.0.0.12
```

Single-host container option:
[`deploy/docker-compose.yml`](deploy/docker-compose.yml) (master + 2 workers).
Full checklist in [docs/DEPLOY-REMOTE.md](docs/DEPLOY-REMOTE.md).

---

## TLS Fingerprinting (JA3 masking)

Many CDNs and WAFs fingerprint clients by their TLS ClientHello (JA3/JA4).
Go's own hello is distinctive, so pure-Go load generators get blocked or
challenged the instant a fingerprinting rule goes live.

`stress-strike` can impersonate a real browser or mobile client at the TLS
layer with `-tls-fingerprint` (or `tls_fingerprint:` in a scenario):

```sh
stress-strike run --url https://api.example.com \
  --users 500 --duration 120 \
  --tls-fingerprint chrome      # or: firefox, safari, edge, ios, android_okhttp
```

```yaml
name: mobile-like
base_url: https://api.example.com
profile:
  users: 500
  duration: 120
  tls_fingerprint: ios
```

Fingerprint presets (from `github.com/refraction-networking/utls`):

| Preset | ClientHello mimics |
|--------|--------------------|
| `chrome` | Chrome 133 (`chrome_120`, `chrome_133`) |
| `firefox` | Firefox 120 (`firefox_102`) |
| `safari` | Safari 16.0 |
| `edge` | Edge 85 |
| `ios` | iOS 14 |
| `android_okhttp` | Android 11 OkHttp (real mobile traffic) |
| `golang` | plain Go hello (baseline, useful for comparisons) |
| `randomized*` | random walk over extension sets |

JA3 is the fingerprint most gateways check, and the masked ClientHello keeps
that value: ciphers, extension ordering, curves and point formats all match the
mimicked browser. ALPN is pinned to `http/1.1` so the Go transport never
misreads the negotiated protocol (HTTP/2 is available in the fingerprint-off
path). The engine has been exercised end-to-end against live TLS hosts, where a
`chrome` masked run returns full 200s while unmasked Go hellos get marked.

In distributed mode, pass the same flag on the master and every worker receives
it in the scenario: `stress-strike-master -tls-fingerprint chrome -wait-workers 4 ...`.

---

## SLA Gate / CI/CD Integration

Define performance thresholds that fail the run with exit code 2 when violated.

### CLI flags

```sh
stress-strike run --url http://localhost:8080/health \
  --users 300 --duration 30 \
  --expect-p99-ms 250 \
  --expect-error-rate 1 \
  --expect-min-rps 800
```

### Scenario-level SLA

```yaml
name: api-slo-check
load_profile:
  type: steady
  users: 300
  duration: 30

sla:
  max_p99_ms: 250
  max_avg_ms: 100
  max_error_rate_pct: 1
  min_rps: 800

steps:
  - name: health
    method: GET
    url: /health
```

### GitHub Actions

```yaml
# .github/workflows/perf-gate.yml
jobs:
  perf-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      - run: go install github.com/asadbekabdulboqiyev/stress-strike/cmd/stress-strike@latest

      - name: Start service
        run: ./your-service &

      - name: Performance gate
        run: |
          stress-strike run \
            --url http://localhost:8080/health \
            --users 300 --duration 30 \
            --expect-p99-ms 250 \
            --expect-error-rate 1 \
            --expect-min-rps 800
        # Exit code 2 fails the job when SLA is violated
```

### Baseline Comparison

```sh
# Day 1: save a healthy baseline
stress-strike run --url http://localhost:8080/health \
  --users 200 --duration 10 --name baseline-v1

# Day 2: gate on regression detection
stress-strike run --url http://localhost:8080/health \
  --users 200 --duration 10 --name release-candidate \
  --compare "$(ls -t reports/baseline-v1_*.json | head -1)" \
  --regress-pct 25
# Exit code 2 if p99 or errors degrade > 25%
```

---

## Library API

Embed load tests directly in your Go programs:

```go
package main

import (
    "context"
    "log"
    "time"

    "stress-strike/api"
)

func main() {
    result, err := api.Run(context.Background(), api.Config{
        URL:      "http://localhost:8080/health",
        Users:    500,
        Duration: 10 * time.Second,
        Profile:  "wave",
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("RPS: %.0f, p99: %s, errors: %.2f%%",
        result.RPS, result.P99, result.ErrorRatePct)

    if result.ErrorRatePct > 2 {
        log.Fatal("error rate too high")
    }
}
```

### With SLA gate

```go
res, err := api.Run(ctx, api.Config{
    URL:      "http://localhost:8080/health",
    Users:    300,
    Duration: 30 * time.Second,
    SLA: &config.SLA{
        MaxP99Ms:        250,
        MaxErrorRatePct: 1,
    },
})
if err != nil {
    log.Fatal(err)
}
if !res.SLAPassed {
    log.Fatalf("SLA violated: %+v", res.SLAResults)
}
```

`Result` fields: `TotalRequests`, `RPS`, `ErrorRatePct`, `P50`, `P95`, `P99`, `StatusCodes`, `Errors`, `SLAResults`, `SLAPassed`.

---

## Build from Source

Requires Go 1.26+.

```
[ CLI / API ] --> [ Engine (scheduler + workers) ] --> [ Target ]
                        |                              (HTTP/WS/gRPC/TCP/UDP)
                        v
                  [ Telemetry --> Report (JSON/TXT) ]
```

- `cmd/stress-strike` — CLI entry point and flag parsing
- `api` — stable, public Go library API
- `internal/engine` — concurrency, load profiles, protocol clients, assertions, token-bucket pacing
- `internal/config` — scenario model and validation
- `internal/metrics` — lock-free histogram and telemetry
- `internal/report` — live progress bar and JSON/TXT reporting

The `internal/engine` package is designed to later split into standalone **Worker Nodes**; `internal/report` + CLI logic maps to a future **Master Controller**.

```sh
git clone https://github.com/asadbekabdulboqiyev/stress-strike.git
cd stress-strike
```

### Makefile targets

| Target | Description |
|--------|-------------|
| `make build` | Build `stress-strike` + `demo-server` into `./bin` |
| `make test` | Run tests with race detector |
| `make vet` | Run `go vet` |
| `make lint` | `go vet` + `gofmt` enforcement |
| `make coverage` | Test coverage report |
| `make bench` | Run benchmarks |
| `make clean` | Remove build artifacts |
| `make install` | Install into `PATH` |
| `make release VERSION=0.12.0` | Cross-compile all platforms into `./dist` |

### Cross-compilation

`make release` produces static binaries (`CGO_ENABLED=0`) for:

```
darwin/arm64    darwin/amd64    linux/arm64
linux/amd64     windows/amd64
```

### Docker

```sh
docker build -t stress-strike .
docker run --rm --cpus=2 --memory=512m \
  stress-strike run --url http://host.docker.internal:8080/health \
  --users 100 --duration 5
```

---

## Engineering Notes

- **Coordinated omission** — workers fire on schedule, not waiting for responses; in-flight requests drain gracefully at test end
- **OS limits** — run `ulimit -n 65535` before large concurrency tests; the tool warns when the file descriptor limit is low
- **Latency histogram** — fixed 1 ms resolution capped at 60 s; constant memory for millions of samples
- **Template escaping** — `{{var}}` placeholders in JSON bodies are JSON-escaped automatically
- **Error classes** — `timeout`, `connection_error`, `status_4xx`, `status_5xx`, `extract_error`, `redirect_limit`, `assert_failed`, `canceled`
- **Safety limits** — max 100K users, 256–20K per-host connections, 10 redirect hops, 8 MiB response cap, `0600` report permissions

---

## License

[GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE) -- Asadbek Abdulboqiyev

AGPL-3.0 is a strong copyleft license: if you run a modified/stripped version
of stress-strike as a network service, you must make your modifications'
source code available to its users. See [LICENSE](LICENSE) for full terms.

---

## WARNING: Authorized Testing Only

```
stress-strike is a load testing tool. Only use it against systems you own
or have explicit written permission to test. Unauthorized load floods are
illegal and constitute a denial-of-service attack (DDoS).
```

This tool is provided for legitimate performance testing, security auditing of your own infrastructure, and educational purposes. Every run prints a legal notice. The authors assume no liability for misuse.
