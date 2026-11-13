# Coverage — Baseline and Policy

This document tracks test coverage status and policy for Sift.

## Baseline (2026-11-05)

| Metric | Value | Notes |
|---|---:|---|
| Aggregate suite (`go test ./... -covermode=atomic -coverpkg=./...`) | **58.7%** | Measured with `-coverpkg=./...`; `-cover` alone only counts the target package |
| Higher-coverage packages (examples) | `attest` 81.9%, `otel` 80.2%, `otel/exporter` 98.0%, `probe` 97.1%, `honor` 94.0%, `rbac` 100.0%, `demostore` 79.1%, `metrics/exporter` 98.0% | Cryptographic/governance-related packages are relatively strong |
| Lower-coverage real packages (examples) | `store/postgres` 78.6%, `siem` 89.0%, `report` 88.8%, `secrets` 91.7%, `legal` 74.6%, `metrics` 81.5% | Varies by subsystem |
| Uncovered/low-covered areas (real code) | `store/memstore` 0%, `tenant` 0%, `version` 0%, `auditdb` 0%, parts of `replay/pcap`, engine internals | Requires targeted tests |
| CLI entrypoints (`cmd/*/main.go`) | 0.0% | Expected; `main()` is typically not exercised by unit tests |

## Local coverage commands

```bash
# Full test run with race detector and aggregate coverage profile
go test -race -timeout 20m -covermode=atomic -coverprofile=coverage.out -coverpkg=./... ./...

# Show aggregate coverage percentage
go tool cover -func=coverage.out | tail -1

# List uncovered functions/files hotspots
go tool cover -func=coverage.out | grep '0.0%'
```

## CI policy

The `coverage` job in `.github/workflows/ci.yml`:

1. Collects `coverage-*.out` artifacts produced by the `test` job (`-coverpkg=./...`).
2. Computes aggregate coverage using `go tool cover -func`.
3. Fails if coverage is below the configured floor (**45%**).

The `test` job runs `go test -race -covermode=atomic -coverpkg=./... ./...`, so coverage artifacts and aggregate checks are based on the same measurement mode.

## Follow-up goals

- Maintain and improve the baseline (58.7%) over time; document meaningful floor changes in this file.
- Add unit/integration tests for currently uncovered real-code packages (e.g. `store/memstore`, `tenant`, `version`, `auditdb`) where practical.
- Treat `main()` coverage gaps as expected unless an integration test strategy is added.
- Monitor flaky behavior in race/coverage runs (especially `internal/engine`) and stabilize tests as needed.

## Notes

- `-coverpkg=./...` measures coverage across packages, not just the package under test.
- `-covermode=atomic` is used for race-safe coverage accounting; compare results consistently using the same mode/settings.
