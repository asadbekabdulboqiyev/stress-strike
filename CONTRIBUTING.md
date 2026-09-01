# Contributing to stress-strike

Thank you for your interest in contributing to stress-strike! This guide will
help you get started with development, testing, and submitting changes.

## Code of Conduct

Be respectful, constructive, and inclusive. This project welcomes contributors
of all experience levels. Harassment or abusive behavior is not tolerated.

## Project Overview

stress-strike is a Go module that compiles into several CLI binaries:

| Binary | Purpose | Source |
|--------|---------|--------|
| `stress-strike` | Unified CLI (run/replay/scan/dashboard/master/worker/pentest) | `cmd/stress-strike/` |
| `stress-strike-dashboard` | Standalone WebSocket dashboard host | `cmd/stress-strike-dashboard/` |
| `stress-strike-master` | Distributed coordinator | `cmd/stress-strike-master/` |
| `stress-strike-worker` | Distributed worker node | `cmd/stress-strike-worker/` |
| `stress-strike-replay` | PCAP/HAR traffic replay | `cmd/stress-strike-replay/` |
| `stress-strike-scan` | TLS/WAF deep scanner | `cmd/stress-strike-scan/` |

The core logic lives in `internal/`:

- `internal/engine/` — concurrency scheduler, protocol clients, assertions
- `internal/metrics/` — lock-free atomic histogram, telemetry, timeline
- `internal/config/` — YAML scenario model, load profiles, SLA, validation
- `internal/report/` — terminal/JSON/TXT/CSV reports, baseline compare, compliance, PDF
- `internal/scanner/` — pentest engine, CVE, OWASP Top 10, crawler, verification
- `internal/replay/` — PCAP/HAR parsing and replay
- `internal/dashboard/` — WebSocket real-time telemetry server + embedded UI
- `internal/dist/proto/` — gRPC master/worker protocol

The public reusable library is exposed via `api/` (`api.Run(ctx, api.Config)`).

## Development Environment

- **Go 1.26+** (see `go.mod`)
- **`gopacket` / `libpcap`** only required for the replay binary (CGO).
  Run `brew install libpcap` (macOS) or `apt install libpcap-dev` (Debian)
  if you work on `internal/replay/`.
- No other system dependencies. Everything else is pure Go.

## Getting Started

```sh
# Clone and build
git clone https://github.com/asadbekabdulboqiyev/stress-strike.git
cd stress-strike
make build         # builds all binaries into ./bin

# Run the test suite (with race detector)
make test

# Lint (go vet + gofmt enforcement)
make lint
```

## Project Conventions

### Code style
- Run `gofmt` on every file you touch — `make lint` fails otherwise.
- Run `go vet ./...` before submitting.
- One file = one responsibility. Do not create "god files."
- Use idiomatic Go: table-driven tests, `sync/atomic` for hot paths, and
  `sync.Mutex` for shared mutable state.
- Errors should be wrapped with context: `fmt.Errorf("load config: %w", err)`.

### Performance-sensitive code
The engine runs millions of operations per second. When you touch hot paths:
- Prefer lock-free atomics over mutexes where correct.
- Avoid per-request allocations in loops.
- Reuse buffers via `internal/engine` buffer pools.
- Add a benchmark (see `internal/metrics/benchmark_test.go`) for any hot-path change.

### Security
See [SECURITY.md](SECURITY.md) for the full threat model. Highlights:
- Never hardcode secrets or credentials.
- Never write passwords/tokens to logs.
- TLS connections must enforce `MinVersion: tls.VersionTLS12`.
- Follow the principle of least privilege in all new code.
- If your change touches HTTP handling, keep response-body size caps and
  timeout enforcement intact.

## Testing

- Unit tests live next to the code they test, e.g. `internal/engine/engine_test.go`.
- Integration tests that spin up real protocol servers live in
  `internal/engine/integration_test.go`.
- The `api/` package has end-to-end tests via `httptest`.
- Every bug fix should include a regression test.

```sh
# Run everything (with race detector)
make test

# Get a coverage report
make coverage
```

**All tests must pass with the race detector enabled before a pull request is merged.**

## Adding a New Feature

1. Open an issue describing the problem and proposed solution first.
2. Fork the repo and create a feature branch:
   `git checkout -b feat/my-feature`
3. Implement the change with tests.
4. Run `make lint` and `make test`.
5. Update `README.md` and add an example scenario under `examples/` if the
   feature is user-facing.
6. Open a pull request with a clear description.

## Adding or Changing a CLI Flag

- Add the flag in `cmd/stress-strike/main.go` (unified CLI help) **and** the
  relevant standalone `cmd/stress-strike-*/` binary if it exists.
- Update the `printFullHelp` block and the README "Quick Examples" section.

## Generated Code

- The gRPC protocol files under `internal/dist/proto/` are generated from
  `coordinator.proto`. Do not edit the `*.pb.go` files by hand — regenerate
  with `protoc` if you change the protocol:
  ```sh
  protoc --go_out=. --go-grpc_out=. internal/dist/proto/coordinator.proto
  ```

## Versioning

- Version strings live in `cmd/stress-strike/main.go` (`var version`), the
  `Makefile` (`VERSION ?=`), and `Dockerfile` (`ARG VERSION`). Keep them in
  sync with the latest release tag.
- Runtime binaries can override the version at build time:
  `go build -ldflags "-X main.version=X.Y.Z"`.

## Commit Message Style

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add HTTP/2 support to the replay engine
fix: enforce TLS min-version on replay connections
docs: document the distributed mode architecture
test: add regression test for RPS cap
ci: bump Go builder to 1.26
```

## Pull Request Checklist

- [ ] `make lint` passes
- [ ] `make test` passes with the race detector
- [ ] `make coverage` shows new code is covered
- [ ] No secrets or `.env` files committed
- [ ] README / CLI help updated for user-facing changes
- [ ] Commit messages follow Conventional Commits

Thank you for contributing!
