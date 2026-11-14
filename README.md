# Sift

[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Version](https://img.shields.io/badge/Version-0.15.2-green.svg)](https://github.com/asadbekabdulboqiyev/sift/releases/tag/v0.15.2)

**Sift** is a professional, self-hostable toolkit written in Go for **multi-protocol load testing**, **traffic replay**, **security scanning/pentest workflows**, **verifiable (cryptographically attestable) evidence**, and **planning/triage insights**.

It is designed for engineers, QA teams, and security practitioners who need a unified CLI/dashboard workflow for performance validation, authorized security assessment, CI quality gates, reproducible evidence, capacity what-if analysis, and evidence-oriented bounty triage.

> **Authorized testing only.** Use Sift only against systems you own or have explicit written permission to test. Unauthorized load generation, scanning, or exploitation attempts may be illegal and harmful.

---

## Table of Contents

- [Overview](#overview)
- [Key Capabilities](#key-capabilities)
- [What's Included in 0.15.2](#whats-included-in-0151)
- [Comparison with Paid Alternatives](#comparison-with-paid-alternatives)
- [System Requirements](#system-requirements)
- [Installation](#installation)
  - [macOS](#macos)
  - [Linux](#linux)
  - [Windows](#windows)
  - [Install from Source](#install-from-source)
  - [Install with Go](#install-with-go)
  - [Release Binaries and Verification](#release-binaries-and-verification)
  - [Docker](#docker)
  - [Docker Compose (Fleet/Dashboard)](#docker-compose-fleetdashboard)
  - [Kubernetes / Helm](#kubernetes--helm)
  - [systemd (Distributed Worker)](#systemd-distributed-worker)
  - [Package Manifests](#package-manifests)
  - [Verify Installation and Update on macOS](#verify-installation-and-update-on-macos)
- [Quick Start](#quick-start)
- [Interactive Mode](#interactive-mode)
- [Command Reference](#command-reference)
  - [Core Commands](#core-commands)
  - [Individual Security Scanners](#individual-security-scanners)
  - [Trust, Authorization, and Evidence Commands](#trust-authorization-and-evidence-commands)
  - [Other Commands](#other-commands)
- [Load Testing (`run`)](#load-testing-run)
- [YAML/JSON Scenarios](#yamljson-scenarios)
- [Replay (`replay`)](#replay-replay)
- [Scan (`scan`) and Pentest (`pentest`)](#scan-scan-and-pentest-pentest)
- [Web Dashboard](#web-dashboard)
- [Capacity Digital Twin (`simulate`)](#capacity-digital-twin-simulate)
- [Host X-Ray (`xray`)](#host-x-ray-xray)
- [Bounty & Triage (`bounty`)](#bounty--triage-bounty)
- [Distributed Mode (Master/Worker)](#distributed-mode-masterworker)
- [Authorization, Audit, Certificates, and Admin Controls](#authorization-audit-certificates-and-admin-controls)
- [Verifiable Evidence (VPMP v1)](#verifiable-evidence-vpmp-v1)
- [VeriGate and Demo Store](#verigate-and-demo-store)
- [Go Library API](#go-library-api)
- [Reports, Artifacts, SLA Gates, and Exit Codes](#reports-artifacts-sla-gates-and-exit-codes)
- [Configuration and Environment Variables](#configuration-and-environment-variables)
- [Deployment and Infrastructure Hardening](#deployment-and-infrastructure-hardening)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Build, Test, and Development](#build-test-and-development)
- [Troubleshooting](#troubleshooting)
- [Security Policy](#security-policy)
- [Contributing](#contributing)
- [License and Maintainers](#license-and-maintainers)

---

## Overview

Sift unifies multiple testing, assessment, and evidence workflows in one toolchain:

- **Performance/load testing:** HTTP/HTTPS, WebSocket, gRPC, TCP, and UDP workloads with configurable profiles and scenarios
- **Traffic replay:** Re-run captured PCAP/HAR traffic with rate control, filtering, and validation
- **Security assessment:** TLS/WAF/HTTP scanning, individual scanners, and a multi-phase `pentest` workflow
- **Capacity planning:** Evidence-based digital-twin fitting and what-if simulation from completed reports
- **Host observability correlation:** Opt-in, aggregate host/runtime snapshots correlated with workload signals (no eBPF loading, no privilege escalation)
- **Bounty/triage evidence:** Verifiable package integrity, attestation replay helpers, and staged human triage workflow
- **Operational visibility:** Real-time web dashboard, metrics endpoints, structured reports, and dashboard **Insights**/**Report** views
- **Distributed execution:** Master/worker architecture for scaling test generation
- **Trust and evidence:** Authorization/audit controls and cryptographically verifiable evidence bundles (VPMP v1)

---

## Key Capabilities

### Load & Performance
- Protocols: HTTP/HTTPS, WebSocket (`ws`/`wss`), gRPC (`grpc`/`grpcs`), TCP, UDP
- Profiles: `steady`, `soak`, `linear-ramp`, `spike`, `wave`, `constant-rps`
- Scenario engine: YAML/JSON multi-step flows, variables (`{{var}}`), extraction, assertions
- Controls: users, duration, ramp-up, timeout, keep-alive, global RPS, pre-warm
- TLS fingerprint presets (where applicable): `chrome`, `firefox`, `safari`, `edge`, `ios`, `android_okhttp`, `randomized`, `golang`
- Analysis: coordinated omission correction (supported paced runs), baseline comparison, regression thresholds, SLA gates, timeline CSV
- Debug/utility: payload pools, response capture options, quiet mode

### Security Testing
- `pentest`: one-command assessment workflow (recon/fingerprint, ports/subdomains, auth options, crawl, headers/TLS/WAF, deep checks, CVE/NVD enrichment, OWASP/compliance mapping, reports)
- Individual scanners (scope-gated): `fuzz`, `dirbust`, `jwt` (offline), `graphql`, `websocket`, `crawl`, `subdomain`, `portscan`, `sslscan`
- `scan`: TLS/WAF/HTTP fingerprinting and security-header analysis
- Safety controls: authorization tickets/policy, allowlists, dry-run, rate/budget controls, audit logging; untested categories are reported as `NOT TESTED` (not `PASS`)

### Planning, Observability & Bounty Triage
- **Digital Twin (`simulate`)**: fit capacity models from completed Sift reports and run best/likely/worst or custom what-if scenarios with quantified confidence and uncertainty bounds (**estimates, not guarantees**)
- **Host X-Ray (`xray`)**: opt-in, cgo-free, aggregate-only collection (Linux `/proc` counters where available, otherwise Go runtime metrics of the Sift process), capability detection, and correlation with workload signals (**correlated indicators, not causal findings**)
- **Bounty/Triage (`bounty`)**: package artifacts with digests, verify integrity/scope and replay attestation evidence where provided, and maintain an append-only validated triage state log (**human review determines validity; `rewarded` is an audit state, not a payment**)

### Dashboard & Distribution
- Real-time dashboard with run control, scanner panels, **Report** view (latest completed run rendered inline), and **Insights** view
- **Insights**: X-Ray capability/correlation helpers, Twin fit/simulate helpers, Bounty manifest validation, full verify-upload, and triage status replay
- Operational endpoints: `/healthz`, `/readyz`, `/metrics`
- Distributed `master`/`worker` over gRPC (static fleet or auto-discovery, depending on setup)
- Deployment assets for Docker, Docker Compose, Kubernetes/Helm, and systemd

### Evidence & Trust
- VPMP v1 evidence bundles with Ed25519 signatures and Merkle-based verification
- `keygen`, `verify`, and `certificate` workflows
- Dashboard-generated attestations/bundles for run verification
- Independent verifier assets (`docs/VERIFIER.html`, `web/verifier/*`)

### Developer & CI Integration
- Go API: `github.com/asadbekabdulboqiyev/sift/api`
- CLI-first automation for CI pipelines
- Structured outputs (JSON/TXT/CSV and report artifacts)
- Exit-code-based gates for SLA/regression, authorization/policy outcomes, and selected command results

---

## What's Included in 0.15.2

- **5th dashboard section — Insights (New Features)**: visible sidebar section (`Insights`, shortcut `5`) bringing Digital Twin, Host X-Ray, and Bounty workflows into one place
- **Digital Twin (`simulate`)**: `fit`, `run`, and `compare` workflows for evidence-based capacity estimates with uncertainty/confidence and optional breach gates
- **Host X-Ray (`xray`)**: `capabilities`, `collect --allow`, and `report` for opt-in, aggregate observability and signal correlation
- **Bounty/Triage (`bounty`)**: `package`, `verify`, `triage`, and `status` for verifiable evidence packaging and staged, auditable triage
- **Dashboard UI/API updates**: **Insights** view (Twin/X-Ray/Bounty), **Report** view (latest run rendered inline), and hardened insights endpoints/handling
- **Deployment hardening assets**: reverse-proxy TLS configs, secure Compose overlays, Helm ingress template/values, and `docs/DEPLOYMENT-HARDENING.md`
- **Stability/polish**: English-only project text, rebuilt/verified release artifacts, and continued test/vet/build/security checks

> Results from `simulate` and `xray` are for planning/investigation support (estimates/correlations), not guarantees or causal proof. Bounty workflows support evidence integrity and auditable triage decisions, not automatic payouts.

---

## Comparison with Paid Alternatives

Sift is an open-core, self-hostable toolkit that combines load testing, replay, scanning, verifiable evidence, and planning/triage workflows. Paid/commercial products may provide managed infrastructure, enterprise governance, vendor support, and broader hosted ecosystems. Features and pricing vary by vendor and plan.

| Area | Sift (this project) | Typical paid alternatives (examples) | Practical difference |
|---|---|---|---|
| **Licensing / cost** | Apache-2.0 core in this repository; optional commercial tier for specific enterprise capabilities | Commercial licenses / SaaS subscriptions (e.g. Grafana Cloud k6, BlazeMeter, Tricentis NeoLoad, OpenText LoadRunner, Gatling Enterprise, Burp Suite Professional/Enterprise, Invicti, Acunetix, Qualys WAS) | Sift can be self-hosted for core workflows without per-seat SaaS pricing; paid tools may include managed services/support. |
| **Load testing** | Multi-protocol load generation, profiles, scenarios, SLA/regression gates, local/CI/self-managed distributed runs | Managed global load generation, hosted analytics, collaboration features (vendor-dependent) | Paid SaaS can simplify very large geographically distributed tests; Sift offers strong control and local/CI integration. |
| **Replay** | Built-in PCAP/HAR replay with pacing, filters, validation | Often part of broader APM/performance platforms or separate tooling | Sift includes replay as a first-class CLI workflow. |
| **Security scanning** | Integrated scan/pentest/scanner commands with authorization and audit controls | Commercial DAST platforms with larger managed vuln intelligence, enterprise workflows, vendor SLAs/support | Sift is strong for integrated engineering workflows; commercial platforms may offer broader managed coverage/governance. |
| **Evidence & verification** | VPMP v1 attestations, signatures, Merkle proofs, CLI/browser verification, bounty evidence packaging/triage | Not always a primary feature in load-testing products; audit features vary in security products | Sift emphasizes reproducible, tamper-evident run/evidence workflows. |
| **Planning/observability insights** | Digital twin what-if simulation and opt-in host correlation helpers | Capacity planning/observability often provided by separate APM/SRE platforms | Sift provides lightweight, report/evidence-oriented analysis close to test workflows. |
| **Operations** | Self-hosted dashboard, metrics endpoints, deploy assets (Docker/K8s/systemd) | Hosted dashboards, team management, SSO/RBAC/governance (plan-dependent) | Paid platforms may reduce ops overhead; Sift provides operator control and portability. |
| **Extensibility** | Open codebase (core), Go API, YAML scenarios, scripts | Vendor SDKs/plugins/integrations vary | Sift is customizable in-repo; paid ecosystems vary in openness and flexibility. |

> **Note:** This is a high-level comparison. Evaluate against your exact requirements (scale, compliance, integrations, support, and budget).

---

## System Requirements

### Runtime / Usage
- **Supported OS (source/binaries):** Linux, macOS, Windows (per project tooling and release targets)
- **Go (for source builds / `go install`):** Go **1.26+**
- **Network testing permissions:** Explicit authorization for target systems
- **File descriptor limits:** High-concurrency tests may require raising OS limits (e.g. `ulimit -n` on Unix-like systems)

### Optional Dependencies (feature-specific)
- **Node.js:** For verifier tooling/scripts in `web/verifier` and related checks (if you use those workflows)
- **Docker / Docker Compose:** For containerized runs and compose-based deployments
- **kubectl / Helm / Kubernetes cluster:** For Kubernetes/Helm deployments
- **Chrome/Chromium:** For browser-based pentest/crawl/auth features (`--use-browser`, browser auth flows)
- **Caddy/nginx/ingress controller/cert-manager:** For TLS termination and hardened external exposure (deployment-dependent)
- **Ollama (local):** For AI fuzzing gateway features exposed in interactive tools (if used)

---

## Installation

Sift can be installed in multiple ways depending on your environment and operational needs.

### macOS

#### Option A: Build from source (recommended for latest local state)
```bash
git clone https://github.com/asadbekabdulboqiyev/sift.git
cd sift
./scripts/install-local.sh 0.15.2
# or: make install
```
This builds all binaries, installs them to `$(go env GOBIN)` (or `$SIFT_INSTALL_DIR`), and performs macOS signing/launch checks.

#### Option B: Go install
```bash
go install github.com/asadbekabdulboqiyev/sift/cmd/sift@latest
export PATH="$PATH:$(go env GOPATH)/bin"
sift version
```

#### Option C: Release installer script (review before running)
```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/asadbekabdulboqiyev/sift/v0.15.2/scripts/install.sh
less install.sh
./install.sh v0.15.2
```
Notes:
- The script downloads release archives, verifies checksums (and can verify signatures if `cosign` is installed), installs binaries, and performs macOS signature/launch validation.
- Use `SIFT_INSTALL_DIR` to control install location.

#### Option D: Build all binaries manually
```bash
git clone https://github.com/asadbekabdulboqiyev/sift.git
cd sift
./scripts/build-all.sh 0.15.2
# binaries in ./bin
```

### Linux

#### Option A: Build from source
```bash
git clone https://github.com/asadbekabdulboqiyev/sift.git
cd sift
./scripts/install-local.sh 0.15.2
# or: make build && copy ./bin/* to a PATH directory
```

#### Option B: Go install
```bash
go install github.com/asadbekabdulboqiyev/sift/cmd/sift@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

#### Option C: Release installer script
```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/asadbekabdulboqiyev/sift/v0.15.2/scripts/install.sh
less install.sh
./install.sh v0.15.2
```

#### Option D: Release archives (manual)
1. Download the appropriate archive for your OS/architecture from [GitHub Releases](https://github.com/asadbekabdulboqiyev/sift/releases).
2. Verify checksums (`checksums.txt`) and signatures if provided (`cosign`).
3. Extract the archive and place binaries in a directory on your `PATH` (e.g. `/usr/local/bin` or `~/.local/bin`).

### Windows

#### Option A: Go install
```powershell
go install github.com/asadbekabdulboqiyev/sift/cmd/sift@latest
# Ensure %GOPATH%\bin or Go bin path is in PATH
sift version
```

#### Option B: Release archives (manual)
1. Download the Windows archive for your architecture from [GitHub Releases](https://github.com/asadbekabdulboqiyev/sift/releases).
2. Verify checksums/signatures if available.
3. Extract (ZIP) and add the extracted directory to your `PATH`.
4. Run `sift.exe version` (or `sift version` if extension resolution is configured).

#### Option C: Build from source
```powershell
git clone https://github.com/asadbekabdulboqiyev/sift.git
cd sift
go build ./cmd/sift
# Build additional binaries as needed (sift-dashboard, sift-master, etc.)
```

### Install from Source

```bash
git clone https://github.com/asadbekabdulboqiyev/sift.git
cd sift

# Build all binaries for current platform
./scripts/build-all.sh 0.15.2
# or
make build

# Optional: install locally (with macOS signing/launch checks on Darwin)
./scripts/install-local.sh 0.15.2
```

Produced binaries (local build): `Sift`, `Sift-dashboard`, `Sift-master`, `Sift-worker`, `Sift-replay`, `Sift-scan` (canonical names). Build/install scripts also create lowercase aliases: `sift`, `sift-dashboard`, `sift-master`, `sift-worker`, `sift-replay`, `sift-scan` for cross-platform CLI usage.

### Install with Go

```bash
go install github.com/asadbekabdulboqiyev/sift/cmd/sift@latest
```

This installs the main CLI package via the Go toolchain/module proxy. For multi-binary local workflows (dashboard/master/worker/replay/scan as separate executables), prefer source builds or release archives.

### Release Binaries and Verification

Release packaging is configured in `.goreleaser.yaml` and may include:
- Platform archives for multiple binaries and OS/arch targets
- `checksums.txt` (SHA-256)
- SBOM artifacts and signatures (when release pipeline runs with configured tooling)

General verification workflow:
```bash
# Example (adjust artifact names)
sha256sum -c checksums.txt --ignore-missing

# If cosign signatures/certificates are present
cosign verify-blob \
  --certificate <artifact>.pem \
  --signature <artifact>.sig \
  <artifact>
```

Always download from the official repository release page and verify integrity before installation.

### Docker

#### Build images from source
```bash
# Main/all-in-one image (per Dockerfile)
docker build -t sift:0.15.2 .

# Distributed images
docker build -f Dockerfile.master -t sift-master:0.15.2 .
docker build -f Dockerfile.worker -t sift-worker:0.15.2 .
```

#### Run examples
```bash
# CLI help
docker run --rm sift:0.15.2 sift --help

# Dashboard (bind to localhost on host)
docker run --rm -p 127.0.0.1:8888:8888 sift:0.15.2 sift dashboard -listen 0.0.0.0:8888 --insecure
```

> Container defaults, entrypoints, and exposed ports may differ by image. Review the corresponding `Dockerfile`/compose configuration before production use.

### Docker Compose (Fleet/Dashboard)

A sample compose file is provided at `deploy/docker-compose.yml`.

```bash
docker compose -f deploy/docker-compose.yml build
docker compose -f deploy/docker-compose.yml up -d
```

A hardened overlay is also provided for TLS-terminating reverse-proxy exposure patterns:
```bash
# Public-style secure overlay (configure domain/TLS first)
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.secure.yml up -d

# Local validation overlay (no public DNS/ACME)
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.secure.yml -f deploy/docker-compose.secure.local.yml up -d
```

Important notes:
- Review networking, auth, token, and security settings before use.
- Secure overlays require proxy/TLS configuration (see `deploy/reverse-proxy/` and `docs/DEPLOYMENT-HARDENING.md`).
- Some master/worker healthcheck/flag behaviors depend on binary capabilities; validate against your built image/version.

### Kubernetes / Helm

Kubernetes assets are provided under `deploy/`:
- Helm chart: `deploy/charts/sift/`
- Ingress template: `deploy/charts/sift/templates/ingress.yaml` (`ingress.*` values)
- CRD/operator assets: `deploy/crds/`, `deploy/operator/`
- HPA example: `deploy/hpa/worker-hpa.yaml`

Typical workflow (adapt to your cluster and image registry):
```bash
# Example Helm install (local chart)
helm upgrade --install sift deploy/charts/sift \
  --namespace sift --create-namespace
```

Before deploying:
- Review chart values (`deploy/charts/sift/values.yaml`)
- Configure images, resources, security context, networking, and ingress/TLS as needed
- Validate RBAC/CRD/operator requirements for your environment
- Consult `docs/K8S.md`, `docs/DISTRIBUTED.md`, and `docs/DEPLOYMENT-HARDENING.md`

### systemd (Distributed Worker)

A systemd unit and env template are provided for worker nodes:
- `deploy/systemd/sift-worker.service`
- `deploy/systemd/worker.env.example`

High-level setup:
```bash
# Install binary (example path used by unit)
sudo install -m 0755 ./bin/Sift-worker /usr/local/bin/Sift-worker

# Create config directory and env file
sudo mkdir -p /etc/Sift /var/lib/Sift
sudo cp deploy/systemd/worker.env.example /etc/Sift/worker.env
sudoedit /etc/Sift/worker.env

# Install and start service
sudo cp deploy/systemd/sift-worker.service /etc/systemd/system/sift-worker.service
sudo systemctl daemon-reload
sudo systemctl enable --now sift-worker
sudo systemctl status sift-worker
```

Review and harden user/group creation, file permissions, `NOFILE` limits, and network exposure according to your environment.

### Package Manifests

Repository includes packaging manifests/templates under `packaging/`:
- Homebrew formula: `packaging/homebrew/sift.rb`
- Scoop manifest: `packaging/scoop/Sift.json`
- WinGet manifests: `packaging/winget/Sift.yaml`, `packaging/winget/Sift.installer.yaml`

These files are useful for packaging/distribution workflows, but availability in upstream package registries may depend on publication status. Check the repository/release documentation for current distribution channels.

### Verify Installation and Update on macOS

If you do not see new commands (`simulate`, `xray`, `bounty`) or new dashboard views (**Insights**, **Report**), verify the installed binary and running process:

```bash
# 1) Confirm which binary and version you are running
which -a sift
sift version
sift --help | rg "simulate|xray|bounty"

# 2) Rebuild and install latest local build (from repo root)
cd /path/to/sift
git pull
./scripts/build-all.sh 0.15.2
SIFT_INSTALL_DIR="$HOME/.local/bin" ./scripts/install-local.sh 0.15.2
./scripts/install-local.sh 0.15.2

# 3) Verify again
sift version
```

If the dashboard UI looks outdated:
```bash
# Restart dashboard with the updated binary
pkill -f "sift dashboard" || true
pkill -f "Sift-dashboard" || true
sift dashboard -listen 127.0.0.1:8888
# or: Sift-dashboard -listen 127.0.0.1:8888
```
Then open `http://127.0.0.1:8888` and **hard refresh** (`Cmd+Shift+R`) to clear cached UI assets.

---

## Quick Start

```bash
# Interactive launcher (from source repository)
./start.sh

# CLI
sift
sift run --url http://127.0.0.1:8080/health --users 100 --duration 30
sift dashboard
```

Local demo target:
```bash
# Terminal 1: demo server
go run ./examples/demo_server.go

# Terminal 2: run a test
sift run --url http://localhost:8080/health --users 200 --duration 30
```

Web dashboard mode:
```bash
sift run --url http://localhost:8080/health --users 50 --duration 60 --mode dashboard -listen 127.0.0.1:8888
# Open http://127.0.0.1:8888
```

New workflows (0.15.2, also available in Insights dashboard section):
```bash
# Digital twin (from a completed report)
sift simulate fit --report reports/run.json --out reports/twin
sift simulate run --model reports/twin/twin-model.json --scenario likely

# Opt-in host x-ray
sift xray capabilities
sift xray collect --allow --interval 2s --duration 30s --out reports/xray.jsonl

# Bounty evidence package
sift bounty package --report report.md --scope scope.txt --claim claim.json --program "Acme" --out ./pkg
sift bounty verify --package ./pkg/bounty-package.json --dir ./pkg
```

---

## Interactive Mode

Run `sift` without arguments in a terminal to open the interactive menu:

1. **CLI** — Guided/run load test and view report in terminal
2. **WEB** — Open real-time dashboard in browser
3. **AUTH** — Certificate, authorization, audit, and verification workflows
4. **TOOLS** — GitOps reporting, AI fuzzing gateway (Ollama), SIEM/Telegram alerts
0. **Quit**

Notes:
- **WEB** mode opens the dashboard immediately using default or previously saved settings.
- **TOOLS** options may require external services/credentials (e.g. GitHub token, local Ollama, Telegram bot/chat IDs).

---

## Command Reference

```bash
sift <command> [flags]
sift --help
sift <command> --help
```

### Core Commands

| Command | Description |
|---|---|
| `run` | Load testing (HTTP/gRPC/WebSocket/TCP/UDP via config/scenario support) |
| `replay` | Replay captured traffic from PCAP/HAR |
| `scan` | TLS/WAF/HTTP/security scanning |
| `pentest` | One-command professional security assessment workflow |
| `dashboard` | Real-time web dashboard |
| `master` | Distributed coordinator |
| `worker` | Distributed worker node |
| `simulate` | Capacity digital-twin / what-if simulation from Sift reports (**estimates**) |
| `xray` | Opt-in host observability snapshots and correlation (aggregate, no eBPF loading) |
| `bounty` | Verifiable bug-bounty/triage evidence package workflow |

### Individual Security Scanners

| Command | Description |
|---|---|
| `fuzz` | HTTP fuzzing (scope-gated) |
| `dirbust` | Directory/file brute forcing (scope-gated) |
| `jwt` | Offline JWT weakness analysis |
| `graphql` | GraphQL introspection/security checks |
| `websocket` | WebSocket security checks |
| `crawl` | Site crawling and endpoint/form discovery |
| `subdomain` | Passive subdomain enumeration |
| `portscan` | TCP port/service scanning |
| `sslscan` | TLS certificate/configuration analysis |

> Scanner commands share common gate/output flags (command-dependent), such as authorization/policy/audit flags, allowlists, dry-run, rate/budget controls, and JSON output options.

### Trust, Authorization, and Evidence Commands

| Command | Description |
|---|---|
| `authorize` | Manage target authorization policy/approvals |
| `audit` | Show or verify authorization audit trail |
| `keygen` | Generate coordinator/operator key material (Ed25519 PEM) |
| `verify` | Verify VPMP evidence bundles |
| `certificate` | Issue/verify signed assessment certificates |

### Other Commands

| Command | Description |
|---|---|
| `demo-store` | Launch/manage bundled VoltStore demo (subcommands may include `status`, `stop`) |
| `admin` | Local admin controls (code/status/unlock/lock, depending on configuration) |
| `help` | Show help |
| `version` | Show version |

---

## Load Testing (`run`)

### Examples

```bash
# Basic HTTP load test
sift run --url https://api.example.com --users 100 --duration 60

# Constant RPS mode
sift run --url https://api.example.com --profile constant-rps --target-rps 1000 --duration 30

# Ramp-up with SLA gate
sift run --url https://api.example.com --profile linear-ramp --users 1000 --ramp-up 30 --duration 90 \
  --expect-p99-ms 200 --expect-error-rate 1

# Baseline comparison (regression gate)
sift run --url https://api.example.com --users 50 --duration 30 \
  --compare reports/baseline.json --regress-pct 20

# Run using a scenario file
sift run --config examples/login-flow.yaml

# Dashboard-backed run
sift run --url https://api.example.com --users 50 --duration 60 --mode dashboard -listen 127.0.0.1:8888
```

### Common `run` Flags (high-level)

- **Target/config:** `--url`, `--config`, `--name`
- **Load shape:** `--users`, `--duration`, `--ramp-up`, `--profile`, `--target-rps`, `--spike-users`, `--spike-warmup`, `--spike-hold`, `--wave-period`
- **Request:** `--method`, `--data`, `--header "Key: Value"` (repeatable), `--timeout`, `--keep-alive`
- **Accuracy/quality:** `--coordinated-omission`
- **Gates:** `--expect-p99-ms`, `--expect-error-rate`, `--expect-min-rps`, `--compare`, `--regress-pct`
- **Output:** `--report-dir`, `--timeline`, `--quiet`
- **Mode/UI:** `--mode cli|dashboard`, `-listen` / dashboard listen flags as supported

> Use `sift --help` and `sift run --help` for the authoritative, version-specific flag list.

---

## YAML/JSON Scenarios

Sift supports scenario-based execution for repeatable multi-step workflows and complex load shapes.

### Example Scenario

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

### Scenario Features (typical)
- Multi-step request chains per virtual user
- Variable substitution (`{{...}}`)
- Response extraction for later steps
- Assertions (`status`, `json_path`, `regex`, depending on step/context)
- Profile/SLA configuration
- Protocol-specific steps (e.g. HTTP, WebSocket, gRPC, TCP, UDP) depending on scenario schema

See `examples/` for real scenario files (`basic-get.yaml`, `login-flow.yaml`, `spike.yaml`, `grpc-test.yaml`, `websocket-test.yaml`, etc.).

---

## Replay (`replay`)

Replay captured traffic (PCAP/HAR) to reproduce realistic request patterns.

```bash
# Replay HAR at 10x speed
sift replay -input traffic.har -rate 10x

# Replay PCAP with higher concurrency and method filter
sift replay -input capture.pcap -rate 50x -concurrency 50 -filter-methods GET

# Replay against a different target with validation
sift replay -input traffic.har -base-url https://staging.example.com -validate -assert-status 200
```

Common capabilities/flags (see `sift --help`): input file, rate, concurrency, filters, base URL override, assertions/validation, TLS options, output/report options.

---

## Scan (`scan`) and Pentest (`pentest`)

### `scan`
```bash
sift scan -target example.com -all
sift scan -target example.com -tls
sift scan -target example.com -all -json scan.json
```

`scan` focuses on TLS/WAF/HTTP/security-header analysis and fingerprinting-oriented checks.

### `pentest`
```bash
sift pentest --target https://example.com
sift pentest --target https://example.com --depth 3 --format all --verbose
sift pentest --target https://example.com --dry-run
```

`pentest` provides a broader multi-phase workflow (discovery, auth/crawl options, deep checks, enrichment/mapping, and reporting). Depth, output format, scope, and authenticated/browser options are command-specific; consult `sift pentest --help`.

> **Important:** Always run scans/pentests only with proper authorization and within approved scope.

---

## Web Dashboard

Start the dashboard:
```bash
sift dashboard
# default: http://127.0.0.1:8888
```

Run a test and control/view it in dashboard mode:
```bash
sift run --url https://api.example.com --users 50 --duration 60 --mode dashboard -listen 127.0.0.1:8888
```

### Capabilities
- Live telemetry: RPS, latency percentiles, status/error trends
- Run control and history
- **Report** view: latest completed run rendered inline (dashboard history)
- **Insights** view:
  - Digital Twin: load latest run data, fit model, run/simulate scenarios
  - X-Ray: capability detection and correlation helpers
  - Bounty: manifest validation, full verify-upload (artifact re-hash/replay), and triage status replay
- Scanner/security panels (OWASP, pentest, crawl, fuzz, subdomains, ports, TLS, JWT, GraphQL, WebSocket, etc.)
- Operational endpoints: `/healthz`, `/readyz`, `/metrics`
- Attestation/evidence views and bundle download/verification (where available)

### UI Tips
- After upgrading binaries, restart the dashboard process and hard refresh the browser (`Cmd+Shift+R` on macOS).
- Common shortcuts: **Report** (`4`), **Insights** (`5`, 5th section — new features) in the dashboard UI.

### Security Notes
- Binding beyond loopback may require explicit credentials or `--insecure` acknowledgement depending on flags/configuration.
- Review `sift dashboard --help` and deployment settings before exposing the dashboard on a network.
- Insights and control endpoints include request validation/size limits and origin/method checks where applicable; still deploy behind proper auth/network controls.

---

## Capacity Digital Twin (`simulate`)

`sift simulate` builds an evidence-based capacity model from a completed Sift run report and answers what-if questions **without touching the target service**.

### Commands
- `fit` — fit a model from a report JSON
- `run` — simulate one scenario/preset (`best`, `likely`, `worst`, or custom inputs)
- `compare` — compare presets side by side

### Examples
```bash
# Fit model from a completed run report
sift simulate fit --report reports/run.json --out reports/twin

# Run a scenario
sift simulate run --model reports/twin/twin-model.json --scenario likely --rps 500

# Compare presets
sift simulate compare --model reports/twin/twin-model.json --out reports/twin/compare
```

### Notes
- Requires usable, positive latency percentile evidence in the source report.
- Outputs are **model-based estimates with uncertainty/confidence bounds**, not guarantees.
- Optional breach-probability gates can be used for planning/CI-style decisions.

---

## Host X-Ray (`xray`)

`sift xray` provides opt-in, aggregate-only host/runtime observability to correlate external Sift signals with host evidence.

### Commands
- `capabilities` — show available evidence sources and platform capability facts
- `collect` — sample metrics to JSONL (**requires `--allow`**)
- `report` — correlate samples with external signals and generate Markdown report

### Examples
```bash
sift xray capabilities
sift xray collect --allow --interval 2s --duration 30s --out reports/xray.jsonl
sift xray report --input reports/xray.jsonl --signals signals.json --window 5s --out reports/xray-report.md
```

### Safety/Scope Notes
- Opt-in only (`collect` refuses without `--allow`)
- cgo-free; no eBPF programs loaded; no privilege escalation requested
- Aggregate counters/runtime metrics only (no process command lines, payloads, secrets)
- Correlations are **indicators for investigation, not causal findings**

---

## Bounty & Triage (`bounty`)

`sift bounty` implements a verifiable, staged bug-bounty/triage evidence workflow.

### Commands
- `package` — build `bounty-package.json` by hashing referenced artifacts
- `verify` — re-hash package artifacts, check scope, and replay attestation evidence when provided
- `triage` — append a validated state transition
- `status` — replay and display current triage state

### Example Workflow
```bash
# Create package
sift bounty package \
  --report report.md \
  --scope scope.txt \
  --claim claim.json \
  --program "Acme Web" \
  --out ./pkg

# Verify integrity/scope (attestation replay optional)
sift bounty verify --package ./pkg/bounty-package.json --dir ./pkg --target https://example.com/search

# Triage state transitions
sift bounty triage --package ./pkg/bounty-package.json --log triage.jsonl --to submitted --actor alice --role reporter --reason "submitted"
sift bounty triage --package ./pkg/bounty-package.json --log triage.jsonl --to triaged --actor bob --role triager --reason "confirmed"
sift bounty status --log triage.jsonl
```

### Important Semantics
- Evidence integrity does **not** prove finding validity.
- `rewarded` is an **audit/workflow state**, not an automatic payment or smart-contract action.
- Human triage and program policy decisions remain required.

---

## Distributed Mode (Master/Worker)

Sift supports distributed load generation using a master/worker model over gRPC.

### Basic Example

```bash
# Start workers
sift worker -listen :50052 -id worker-a
sift worker -listen :50052 -id worker-b

# Start master (static fleet)
sift master -workers host-a:50052,host-b:50052 -url https://api.example.com -users 3000 -duration 60
```

### Deployment Options
- **Manual / bare metal / VMs:** run binaries directly or via systemd
- **Docker / Docker Compose:** sample compose in `deploy/docker-compose.yml`
- **Kubernetes / Helm:** assets in `deploy/charts/sift`, `deploy/crds`, `deploy/operator`
- **Fleet scripts:** `scripts/deploy-fleet.sh`, `deploy/fleet/*`

### Important
- Open required ports securely (gRPC/control/metrics as applicable)
- Use tokens/TLS and approved network policies where supported
- Tune OS limits (`nofile`, networking) for high connection counts

See `docs/DISTRIBUTED.md`, `docs/DEPLOY-REMOTE.md`, `docs/K8S.md`, and `docs/DEPLOYMENT-HARDENING.md`.

---

## Authorization, Audit, Certificates, and Admin Controls

Sift includes controls for approved testing workflows and traceability.

### Authorization and Audit
```bash
# Record an authorization
sift authorize add --pattern example.com --approver ciso@corp --ticket SEC-77 --until 2026-12-01T00:00:00Z --reason "approved test"

# Use authorization ticket
sift run --url https://example.com --users 100 --duration 30 --authorized SEC-77
sift pentest --target https://example.com --authorized SEC-77

# Audit trail
sift audit show --limit 20
sift audit verify
```

### Certificates and Keys
```bash
sift keygen --help
sift certificate --help
sift verify --help
```

### Local Admin Controls
```bash
sift admin --help
```
Use for local admin-related workflows (e.g. status/code/unlock/lock behavior, as implemented by the command).

See `docs/AUTHORIZATION.md` for policy details.

---

## Verifiable Evidence (VPMP v1)

Sift can emit cryptographically verifiable evidence bundles for runs.

### Example Workflow
```bash
# Generate key material
sift keygen --out operator.key

# Run with bundle emission
sift run --url http://localhost:8080/health --profile steady --target-rps 100 --users 20 --duration 30 \
  --coordinated-omission --emit-bundle run.bundle.json --bundle-key operator.key

# Verify bundle
sift verify --bundle run.bundle.json --samples run.bundle.json.samples.jsonl
```

### Verification Options
- **CLI:** `sift verify`
- **Dashboard:** bundle metadata/download/verification workflows (where available)
- **Independent browser verifier:** `docs/VERIFIER.html` (offline-capable asset)
- **Node-based verifier tooling:** `web/verifier/verify-cli.mjs` and related scripts (if Node.js is installed)

References: `docs/VPMP-RFC.md`, `docs/EXPLAINER.md`, `docs/VERIFIER.html`.

---

## VeriGate and Demo Store

Sift includes a bundled demo application (**VoltStore**) and **VeriGate** protection features for demonstration and testing.

```bash
sift demo-store
sift demo-store status
sift demo-store stop
```

VeriGate demonstrates protective controls such as:
- Rate limiting
- Proof-of-work challenge flows
- IP blocking / enforcement behavior (implementation-dependent)

Useful references:
- `docs/VERIGATE.md`
- `examples/demo_store/`
- `make demo-store`, `make demo-store-protect`, `make demo-sla` (from source repo)

---

## Go Library API

Sift exposes a public Go API for embedding runs in Go programs.

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

Refer to the `api` package for supported config/result fields and behavior.

---

## Reports, Artifacts, SLA Gates, and Exit Codes

### Reports and Artifacts
- CLI run reports (terminal)
- JSON/TXT report files (commonly under `reports/`)
- Optional timeline CSV and debug/capture artifacts (feature/flag dependent)
- Scan/pentest exports in supported formats (command/flag dependent)
- Evidence bundles and sidecars (VPMP workflows)
- Twin model/simulation outputs (`reports/twin/` by default)
- X-Ray sample/report artifacts
- Bounty package manifests, verification outputs, and triage logs

### SLA and Regression Gates
- SLA thresholds (examples): `--expect-p99-ms`, `--expect-error-rate`, `--expect-min-rps`
- Baseline comparison: `--compare <baseline.json>` with `--regress-pct`
- Scenario-level SLA settings are supported in scenario configs
- `simulate run/compare` supports breach-probability gating for planning workflows (see command help)

### Exit Codes (common)
- `0` — Success
- `1` — Runtime/setup/configuration error
- `2` — SLA or regression gate failure (command-dependent)
- Other command-specific non-zero codes may apply (e.g. authorization/policy denial, simulation breach gate, bounty verification states)

Always check command help/output for exact behavior in your workflow.

---

## Configuration and Environment Variables

Sift is primarily CLI/config-file driven. Some scripts and deployment assets also use environment variables.

### Common Examples

| Variable | Used by | Purpose |
|---|---|---|
| `SIFT_INSTALL_DIR` | `scripts/install.sh`, `scripts/install-local.sh` | Override installation directory |
| `VERSION` | build/release scripts, Make targets | Set build/version string |
| `RELEASE` / `DIST_DIR` | `scripts/build-all.sh` | Control release/cross-build output behavior |
| `SIFT_TOKEN` | compose/deploy examples (if wired in your environment) | Shared token/secret for control-plane auth patterns (deployment-specific) |
| `URL`, `USERS`, `DURATION` | `./start.sh` (convenience launcher) | Quick local launcher overrides |

### Notes
- Command-line flags take precedence in most CLI workflows.
- Deployment manifests (compose/helm/systemd) may define additional variables or config files (e.g. `worker.env`).
- Review scripts/manifests before use in production-like environments.

---

## Deployment and Infrastructure Hardening

Sift is self-hosted; operators are responsible for secure deployment, network exposure, TLS termination, and compliance controls.

### Provided Assets
- **Reverse-proxy/TLS configs:** `deploy/reverse-proxy/Caddyfile`, `deploy/reverse-proxy/Caddyfile.local`, `deploy/reverse-proxy/nginx.conf`
- **Secure Compose overlays:** `deploy/docker-compose.secure.yml`, `deploy/docker-compose.secure.local.yml`
- **Kubernetes ingress template:** `deploy/charts/sift/templates/ingress.yaml` with `ingress.*` values in `deploy/charts/sift/values.yaml`
- **Guide:** `docs/DEPLOYMENT-HARDENING.md`

### Hardening Guidance (high level)
- Terminate TLS at a trusted reverse proxy/ingress/load balancer; enforce HTTPS
- Keep dashboard/master/worker/data services on private networks where possible
- Protect control surfaces with strong auth, origin controls, IP allowlists/VPN, and least-privilege networking
- Harden containers/services (non-root, read-only FS where possible, dropped capabilities, resource limits, probes)
- Harden databases (TLS, private access, least-privilege roles, secret rotation, backups/PITR)
- Run authorized re-scans/validation after deployment changes

See `docs/DEPLOYMENT-HARDENING.md` for detailed checklists and examples.

---

## Project Structure

```text
.
├── api/                  # Public Go API
├── cmd/                  # CLI entrypoints and binaries
│   ├── sift/
│   ├── sift-dashboard/
│   ├── sift-master/
│   ├── sift-worker/
│   ├── sift-replay/
│   └── sift-scan/
├── internal/             # Core implementation packages
├── examples/             # Scenarios and demo applications
├── docs/                 # Documentation
├── web/                  # Web/verifier assets
├── website/              # Website/static materials
├── deploy/               # Docker Compose, Helm chart, reverse proxy, systemd, operator/CRD assets
├── packaging/            # Homebrew/Scoop/WinGet manifests
├── scripts/              # Build/install/deploy/helper scripts
├── Dockerfile*           # Container build definitions
├── Makefile              # Build/test/dev targets
└── .goreleaser.yaml      # Release packaging/signing/SBOM configuration
```

---

## Documentation

### Core Docs
- `docs/AUTHORIZATION.md` — Authorization and audit model
- `docs/DISTRIBUTED.md` — Distributed architecture and usage
- `docs/DEPLOY-REMOTE.md` — Remote deployment guidance
- `docs/DEPLOYMENT-HARDENING.md` — TLS/proxy/CDN, DB, deployment, and re-scan hardening guidance
- `docs/K8S.md` — Kubernetes deployment guidance
- `docs/OWASP-SCANNER.md` — Scanner behavior and coverage notes
- `docs/VERIGATE.md` — VeriGate/demo behavior
- `docs/VPMP-RFC.md` — VPMP evidence format/specification
- `docs/EXPLAINER.md`, `docs/EXPLAINER.html` — Conceptual explanation
- `docs/VERIFIER.html` — Independent browser-based verifier

### Additional Docs
- `docs/COMPLIANCE.md`, `docs/SECRETS-OBSERVABILITY.md`, `docs/POWER-FEATURES.md`, `docs/STUDY-GUIDE.md`, `docs/ROADMAP.md`, and others in `docs/`

### Repository Policies
- `SECURITY.md` — Security reporting and policy
- `CONTRIBUTING.md` — Contribution process
- `MAINTAINERS.md` — Maintainers
- `LICENSING.md`, `LICENSE`, `NOTICE` — Licensing and attributions

---

## Build, Test, and Development

### Build
```bash
make build
./scripts/build-all.sh 0.15.2
```

### Test and Validation
```bash
go build ./...
go test ./...
make test
make vet
make lint
make verify
```

`make verify` (when available in your checkout/toolchain) runs the full local gate (build/vet/format/tests/Linux build/security checks as configured).

### Local Run from Source
```bash
go run ./cmd/sift --help
go run ./examples/demo_server.go
```

### Useful Targets
```bash
make help
make version
make demo-verified
make verifier
```

> Some targets/scripts require additional tools (e.g. Node.js, `gosec`, Docker). See the `Makefile` and `scripts/` for details.

---

## Troubleshooting

### `sift: command not found`
- Ensure the install directory is on your `PATH` (e.g. `$(go env GOPATH)/bin` or `$SIFT_INSTALL_DIR`).
- Re-run installation or verify binary names/locations.

### Latest version or new features not visible (macOS/CLI/dashboard)
- Check installed binaries and version: `which -a sift && sift version`.
- Rebuild/reinstall: `./scripts/build-all.sh 0.15.2 && ./scripts/install-local.sh 0.15.2`.
- If another copy is earlier in `PATH` (e.g. `~/go/bin` vs `~/.local/bin`), update/remove the stale one or adjust `PATH`.
- For dashboard UI, restart the dashboard process and hard refresh the browser (`Cmd+Shift+R`).
- Confirm the running dashboard serves latest APIs: `curl -sS http://127.0.0.1:8888/api/version`.

### macOS reports “killed” / code signature issues
- Use `./scripts/install-local.sh` or `make sign` (source repo) to re-sign installed binaries.
- Avoid copying binaries in ways that break executable validation; prefer the provided install scripts.

### Dashboard not reachable
- Confirm listen address/port (`-listen` / flags, default `127.0.0.1:8888`).
- If binding to non-loopback addresses, ensure required auth flags or explicit insecure mode are set as intended.
- Check firewall/container/proxy port mappings.

### Digital Twin fit fails (latency percentiles / unusable data)
- `simulate fit` (and dashboard Twin "Load latest run") requires a report with usable, positive latency percentile evidence (`p50/p95/p99`).
- Runs with no measurable successful latency samples or incompatible/old report data cannot be modeled; use a completed run report with valid latency statistics.
- Current Sift versions record request timing even for failed attempts; if a target is unreachable, latency may still be present but error rate will be high and the run may not be suitable for capacity modeling.

### High load tests produce errors or instability
- Increase OS file descriptor limits (`ulimit -n`).
- Reduce concurrency/rate or increase target capacity.
- Use warmup/pre-warm options and validate target/network constraints.

### Scan/pentest blocked by policy
- Register/verify authorization (`sift authorize`, `sift audit`) and pass the correct ticket/flags.
- Check allowlists/scope/rate/budget/dry-run settings.

### Distributed workers do not connect
- Verify master/worker addresses, ports, and firewall rules.
- Check tokens/TLS settings and advertised addresses.
- Review `docs/DISTRIBUTED.md` and deployment manifests.

---

## Security Policy

- Use Sift only for authorized testing and approved environments.
- Review `SECURITY.md` for vulnerability reporting guidance.
- Follow responsible disclosure and legal/organizational policies.

---

## Contributing

Contributions are welcome. Please read:
- `CONTRIBUTING.md`
- `MAINTAINERS.md`
- Relevant docs/tests for the area you are changing

Before submitting changes, run applicable build/test/lint checks.

---

## License and Maintainers

- **License:** Apache-2.0 (`LICENSE`)
- **Additional licensing information:** `LICENSING.md`
- **Third-party notices:** `NOTICE`
- **Maintainers:** `MAINTAINERS.md`

---

Sift is built for teams that need **performance testing, security assessment, and verifiable evidence** in one consistent, scriptable, and self-hostable workflow.
