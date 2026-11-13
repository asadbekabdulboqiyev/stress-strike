# Sift

[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Version](https://img.shields.io/badge/Version-0.14.14-green.svg)]()

**Sift** is a Go-based toolkit for multi-protocol load testing, traffic replay, security scanning, and verifiable test evidence.

> **Authorized testing only.** Use Sift only on systems you own or have explicit written permission to test. Unauthorized load generation or scanning may be illegal.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Interactive Mode](#interactive-mode)
- [Commands](#commands)
- [Load Testing (`run`) and YAML Scenarios](#load-testing-run-and-yaml-scenarios)
- [Security Scanning and Pentest](#security-scanning-and-pentest)
- [Replay and Scan](#replay-and-scan)
- [Web Dashboard](#web-dashboard)
- [Distributed Mode (Master/Worker)](#distributed-mode-masterworker)
- [Authorization, Audit, Certificates, and Evidence](#authorization-audit-certificates-and-evidence)
- [VPMP Evidence and Verification](#vpmp-evidence-and-verification)
- [VeriGate and Demo Store](#verigate-and-demo-store)
- [Go Library API](#go-library-api)
- [Reports, SLA Gates, and Exit Codes](#reports-sla-gates-and-exit-codes)
- [Project Structure and Documentation](#project-structure-and-documentation)
- [Build, Test, and Development](#build-test-and-development)
- [License and Maintainers](#license-and-maintainers)

## Overview

Sift provides an integrated workflow for performance and security assessment:

- Generate and shape load across multiple protocols
- Replay captured production-like traffic (PCAP/HAR)
- Run TLS/WAF/security scans and offensive test workflows
- Control execution via CLI or real-time web dashboard
- Scale tests across distributed workers
- Produce reports and cryptographically verifiable evidence bundles

## Features

### Load Testing and Traffic
- **Protocols:** HTTP/HTTPS, WebSocket (`ws`/`wss`), gRPC (`grpc`/`grpcs`), TCP, and UDP (via scenario step `type`).
- **Load profiles:** `steady`, `soak`, `linear-ramp`, `spike`, `wave`, and `constant-rps`.
- **Scenarios:** YAML/JSON multi-step flows with `{{variable}}` templating, value extraction (`extract`), and assertions (`status`, `json_path`, `regex`).
- **Execution controls:** virtual users, duration, ramp-up, timeout, keep-alive, global RPS, pre-warm, and TLS client fingerprint presets (`chrome`, `firefox`, `safari`, `edge`, `ios`, `android_okhttp`, `randomized`, `golang`).
- **Measurement and analysis:** coordinated omission correction (`--coordinated-omission` for supported paced profiles), debug capture, payload pools, timeline CSV export, baseline comparison, and regression thresholds.
- **Replay:** Re-run captured traffic from PCAP/HAR with configurable rate, concurrency, filters, and validation.

### Security Testing
- **`pentest`:** One-command assessment workflow (recon/fingerprinting, ports/subdomains, authentication, crawling, headers/TLS/WAF checks, deep vulnerability scanning, CVE/NVD lookups, OWASP Top 10 mapping, compliance mapping, and reporting). Supports `--dry-run`.
- **Individual scanners (scope-gated):** `fuzz`, `dirbust`, `jwt` (offline analysis), `graphql`, `websocket`, `crawl`, `subdomain`, `portscan`, `sslscan`.
- **`scan`:** TLS/WAF/HTTP fingerprinting and security-header analysis.
- **Safety model:** authorization/audit policy, allowlists, rate/budget limits, dry-run, and explicit reporting of untested categories as `NOT TESTED` (never silently treated as `PASS`).

### Dashboard, Distribution, and Trust
- **Web dashboard:** Real-time metrics (RPS/latency/errors), run control, history, scanner panels, and operational endpoints (`/healthz`, `/readyz`, `/metrics`).
- **Distributed execution:** `master`/`worker` architecture over gRPC with static fleets or auto-discovery, plus token/TLS/attestation options.
- **Evidence and certificates:** `keygen`, `verify` (VPMP/v1 bundles), and `certificate` issuance/verification. Runs can emit verifiable evidence artifacts.
- **VeriGate:** Built-in protection gate (rate limiting, proof-of-work challenge, IP blocking) with a bundled VoltStore demo for live behavior and SLA demonstrations.

### Developer Integration
- **Go API:** `github.com/asadbekabdulboqiyev/sift/api`
- **Outputs:** Terminal summaries, JSON/TXT reports, timeline CSV, and scan/pentest exports.
- **CI/CD:** SLA and regression gates with non-zero exit codes on violations.

## Quick Start

```bash
# From the repository (builds on first run)
./start.sh
# Opens the dashboard at http://127.0.0.1:8888

# Or with an installed CLI
Sift
Sift run --url http://127.0.0.1:8080/health --users 100 --duration 30
Sift dashboard
```

Run against the bundled local demo server:

```bash
# Terminal 1
go run ./examples/demo_server.go

# Terminal 2
Sift run --url http://localhost:8080/health --users 200 --duration 30
```

## Installation

**Requirements:** Go 1.26+ (pure Go; no CGO/libpcap required).

```bash
# Install the main CLI (and related commands provided by the module)
go install github.com/asadbekabdulboqiyev/sift/cmd/sift@latest

# Or build from source
git clone https://github.com/asadbekabdulboqiyev/sift.git
cd sift
make build   # builds binaries into ./bin
```

If `Sift` is not found, add Go's bin directory to your `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

Optional convenience installer (review before running):

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/asadbekabdulboqiyev/sift/v0.14.14/scripts/install.sh
less install.sh
./install.sh v0.14.14
```

Local source builds are also available via:

```bash
./scripts/build-all.sh 0.14.14
./scripts/install-local.sh 0.14.14
```

## Interactive Mode

Running `Sift` with no arguments in a terminal opens an interactive menu:

1. **CLI** — Run a load test and print the report in the terminal
2. **WEB** — Open the real-time dashboard in your browser
3. **AUTH** — Certificate, authorize, audit, and verify workflows
4. **TOOLS** — GitOps reporting, AI fuzzing gateway (Ollama), and SIEM/Telegram alerts
0. **Quit**

In **WEB** mode, Sift opens the dashboard immediately using default or last-used settings; target and run parameters can be adjusted in the browser.

## Commands

```bash
Sift <command> [flags]
```

| Group | Command | Purpose |
|---|---|---|
| Load / Replay / Scan | `run` | HTTP/gRPC/WebSocket/TCP/UDP load testing |
|  | `replay` | Replay traffic from PCAP/HAR captures |
|  | `scan` | TLS/WAF/HTTP/security scanning |
|  | `pentest` | One-command professional security assessment |
| Dashboard / Distributed | `dashboard` | Real-time web dashboard |
|  | `master` | Distributed load-test coordinator |
|  | `worker` | Distributed load-test worker |
| Individual scanners | `fuzz`, `dirbust`, `jwt`, `graphql`, `websocket`, `crawl`, `subdomain`, `portscan`, `sslscan` | Targeted security checks |
| Trust / Evidence | `authorize`, `audit`, `keygen`, `verify`, `certificate` | Authorization, audit trail, keys, and evidence/certificate workflows |
| Other | `demo-store`, `admin`, `help`, `version` | Demo environment, local admin controls, help, and version info |

Use `Sift --help` for global usage and `Sift <command> --help` for command-specific flags.

## Load Testing (`run`) and YAML Scenarios

### Common Examples

```bash
# Basic load test
Sift run --url https://api.example.com --users 100 --duration 60

# Constant RPS
Sift run --url https://api.example.com --profile constant-rps --target-rps 1000 --duration 30

# Ramp-up with SLA gate
Sift run --url https://api.example.com --profile linear-ramp --users 1000 --ramp-up 30 --duration 90 \
  --expect-p99-ms 200 --expect-error-rate 1

# Baseline comparison (regression gate)
Sift run --url https://api.example.com --users 50 --duration 30 \
  --compare reports/baseline.json --regress-pct 20

# Start with dashboard mode
Sift run --url https://api.example.com --users 50 --duration 60 --mode dashboard --listen 127.0.0.1:8888
```

### Key `run` Flags
- **Target/config:** `--url`, `--config`, `--name`
- **Load shape:** `--users`, `--duration`, `--ramp-up`, `--profile`, `--target-rps`, `--spike-users`, `--spike-warmup`, `--spike-hold`, `--wave-period`
- **Request behavior:** `--method`, `--data`, `--header "Key: Value"` (repeatable), `--timeout`, `--keep-alive`
- **Quality/output:** `--coordinated-omission`, `--expect-p99-ms`, `--expect-error-rate`, `--expect-min-rps`, `--compare`, `--regress-pct`, `--timeline`, `--report-dir`, `--quiet`
- **Mode:** `--mode cli|dashboard`, `--listen`

For the complete and current flag list, use `Sift --help` and `Sift run --help`.

### YAML Scenario Example

```yaml
name: login-flow
base_url: http://localhost:8080

variables:
  username: user1
  password: pass1

load_profile:
  type: linear-ramp
  users: 100
  duration: 60
  ramp_up: 20
  timeout: 10

steps:
  - name: login
    method: POST
    url: /api/login
    headers:
      Content-Type: application/json
    body: '{"username":"{{username}}","password":"{{password}}"}'
    extract:
      - name: token
        from: json
        path: data.token
    assertions:
      - type: status
        value: "200"
      - type: json_path
        value: data.token

  - name: profile
    method: GET
    url: /api/profile
    headers:
      Authorization: "Bearer {{token}}"

sla:
  max_p99_ms: 300
  max_error_rate_pct: 1
```

Scenario steps can target HTTP by default and other protocols (e.g. WebSocket, gRPC, TCP, UDP) depending on step configuration. See `examples/*.yaml` for additional patterns.

## Security Scanning and Pentest

### `pentest`

```bash
Sift pentest --target https://example.com
Sift pentest --target https://example.com --depth 3 --format all --verbose
Sift pentest --target https://example.com --dry-run
```

`pentest` supports a multi-phase assessment workflow (including discovery, authentication options, crawling, headers/TLS/WAF checks, vulnerability scanning, CVE/NVD enrichment, OWASP and compliance mapping, and report generation). Output formats include HTML/JSON/Markdown/PDF/professional variants depending on flags.

### Individual Scanners

- `fuzz` — HTTP fuzzing
- `dirbust` — Directory/file brute forcing
- `jwt` — Offline JWT weakness analysis
- `graphql` — GraphQL introspection checks
- `websocket` — WebSocket security checks
- `crawl` — Endpoint/form/link discovery
- `subdomain` — Passive subdomain enumeration
- `portscan` — TCP port and service scanning
- `sslscan` — TLS certificate/configuration analysis

Common gate/output flags (command-dependent): `--authorized`, `--policy`, `--audit-log`, `--notify-webhook`, `--allow`, `--allow-all`, `--dry-run`, `--rate`, `--budget`, `--json`, `--output-json`.

## Replay and Scan

### `replay`

```bash
Sift replay -input traffic.har -rate 10x
Sift replay -input capture.pcap -rate 50x -concurrency 50 -methods GET
Sift replay -input traffic.har -base-url https://staging.example.com -validate -assert-status 200
```

Key flags include `-input`, `-rate`, `-concurrency`, `-duration`, `-base-url`, filtering options, validation/assertion flags, TLS key/cert options, and output/report flags.

### `scan`

```bash
Sift scan -target example.com -all
Sift scan -target example.com -tls
Sift scan -target example.com -all -output-json scan.json
```

`scan` performs TLS/WAF/HTTP/security-header checks and produces structured findings (including risk-oriented results).

## Web Dashboard

```bash
Sift dashboard
Sift dashboard -listen 127.0.0.1:8888
Sift run --mode dashboard --listen 127.0.0.1:8888 --url https://api.example.com --users 50 --duration 60
```

Dashboard capabilities include:
- Live telemetry (RPS, latency percentiles, errors/status distribution)
- Run control and history
- Security/scanner panels (OWASP, pentest, crawl, fuzz, subdomain, portscan, dirbust, TLS, JWT, GraphQL, WebSocket)
- Operational endpoints: `/healthz`, `/readyz`, `/metrics`
- Attestation metadata and bundle download/verification for runs (UI/API)

Security note: exposing the dashboard beyond loopback requires appropriate authentication/insecure acknowledgement depending on configuration. See `Sift dashboard --help` and related docs.

## Distributed Mode (Master/Worker)

```bash
# Workers
Sift worker --listen :50052 --id worker-a
Sift worker --listen :50052 --id worker-b

# Master (static fleet)
Sift master --workers host-a:50052,host-b:50052 --url https://api.example.com --users 3000 --duration 60
```

Distributed mode supports load splitting, live aggregation, and fleet-based execution. Depending on configuration, it can also use discovery, tokens/TLS, and attestation-related controls.

References: `docs/DISTRIBUTED.md`, `docs/DEPLOY-REMOTE.md`, `docs/K8S.md`, `deploy/`, `scripts/deploy-fleet.sh`.

## Authorization, Audit, Certificates, and Evidence

```bash
# Record authorization
Sift authorize add --pattern example.com --approver ciso@corp --ticket SEC-77 --until 2026-12-01T00:00:00Z --reason "approved test"

# Run with authorization ticket
Sift run --url https://example.com --users 100 --duration 30 --authorized SEC-77
Sift pentest --target https://example.com --authorized SEC-77

# Audit trail
Sift audit show --limit 20
Sift audit verify

# Keys, certificates, and verification
Sift keygen --help
Sift certificate --help
Sift verify --help
```

Sift includes policy-based authorization controls and audit logging for sensitive operations. See `docs/AUTHORIZATION.md` for policy details and workflows.

## VPMP Evidence and Verification

Sift can emit and verify cryptographic evidence bundles (VPMP/v1) for test runs.

```bash
# Generate key
Sift keygen --out operator.key

# Run with evidence bundle
Sift run --url http://localhost:8080/health --profile steady --target-rps 100 --users 20 --duration 30 \
  --coordinated-omission --emit-bundle run.bundle.json --bundle-key operator.key

# Verify
Sift verify --bundle run.bundle.json --samples run.bundle.json.samples.jsonl
```

The web dashboard can also produce and expose run attestations/bundles for verification. For independent browser-based verification, see `docs/VERIFIER.html`; for CLI verification via Node, see `web/verifier/verify-cli.mjs` (when Node.js is available).

References: `docs/VPMP-RFC.md`, `docs/EXPLAINER.md`.

## VeriGate and Demo Store

```bash
Sift demo-store
Sift demo-store status
Sift demo-store stop
```

The bundled VoltStore demo (`examples/demo_store`) is designed to exercise VeriGate protections (rate limiting, proof-of-work challenge, and IP blocking) and can be used to demonstrate behavior changes under load.

Additional materials: `docs/VERIGATE.md`, `make demo-store-protect` (from source repo).

## Go Library API

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/asadbekabdulboqiyev/sift/api"
)

func main() {
	res, err := api.Run(context.Background(), api.Config{
		URL:      "http://localhost:8080/health",
		Users:    100,
		Duration: 30 * time.Second,
		Profile:  "steady",
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("RPS=%.2f P99=%s Errors=%.2f%%", res.RPS, res.P99, res.ErrorRatePct)
}
```

See the `api` package for available configuration and result fields.

## Reports, SLA Gates, and Exit Codes

- **Reports:** Runs typically produce JSON/TXT outputs in `reports/` (and optional timeline/capture artifacts). Pentest and scan commands provide structured exports in supported formats.
- **SLA gates:** `--expect-p99-ms`, `--expect-error-rate`, `--expect-min-rps` (and scenario `sla` settings) fail the run when thresholds are violated.
- **Regression checks:** `--compare <baseline.json>` with `--regress-pct`.
- **Common exit codes:** `0` success, `1` runtime/setup error, `2` SLA/regression failure; some commands may return additional command-specific codes (e.g. authorization denial).

## Project Structure and Documentation

### Repository Layout (high-level)
- `cmd/` — CLI entrypoints and binaries (`sift`, `sift-dashboard`, `sift-master`, `sift-worker`, `sift-replay`, `sift-scan`)
- `api/` — Public Go API
- `internal/` — Core implementation (engine, config, metrics, report, scanner, dashboard, distributed, authz, attest, etc.)
- `examples/` — Example scenarios and demo applications
- `web/`, `website/` — Web assets and verifier/site materials
- `docs/` — Detailed documentation
- `deploy/`, `packaging/`, `scripts/` — Deployment, packaging, and helper scripts

### Key Documentation
- `docs/AUTHORIZATION.md` — Authorization and audit model
- `docs/DISTRIBUTED.md` — Distributed execution guide
- `docs/DEPLOY-REMOTE.md`, `docs/K8S.md` — Deployment guides
- `docs/OWASP-SCANNER.md` — Scanner behavior and coverage notes
- `docs/VERIGATE.md` — VeriGate and demo details
- `docs/VPMP-RFC.md`, `docs/EXPLAINER.md`, `docs/VERIFIER.html` — Evidence format and verification
- `SECURITY.md` — Security reporting
- `CONTRIBUTING.md` — Contribution guidelines
- `LICENSING.md`, `NOTICE` — Licensing details and third-party notices

## Build, Test, and Development

```bash
# Build
make build
./scripts/build-all.sh 0.14.14

# Test and checks
go build ./...
go test ./...
make test
make lint

# Run from source
go run ./cmd/sift --help
```

Local binaries can be installed with `./scripts/install-local.sh 0.14.14` or copied from `./bin/`.

## License and Maintainers

- **License:** Apache-2.0 (see `LICENSE`). Additional licensing information: `LICENSING.md`. Third-party attributions: `NOTICE`.
- **Maintainers:** See `MAINTAINERS.md` for current maintainer information.
- **Security:** Please follow the responsible disclosure process described in `SECURITY.md`.

---

Sift is intended for authorized performance and security testing workflows where reproducible results and verifiable evidence matter.
