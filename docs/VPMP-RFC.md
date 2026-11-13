# VPMP v1 — Verified Payload Measurement Protocol

**Status:** RFC (Request for Comments)  
**Version:** 1.0  
**Author:** TechCorp / Sift project  
**Date:** 2026-11-05  
**Abstract:** VPMP (Verified Payload Measurement Protocol) is a lightweight, encrypted,
attested protocol for distributed load testing and security scanning. It lets a
coordinator orchestrate workers, collect telemetry, and verify that every
telemetry snapshot and final report is cryptographically signed by the worker
that produced it (fail-closed). VPMP is transport-agnostic but ships with a
gRPC reference implementation.

---

## 1. Goals

- **Attestation:** Every worker signs its telemetry snapshots and final reports
  with an Ed25519 key. The coordinator verifies signatures before accepting
  data (fail-closed: unsigned or forged telemetry is rejected).
- **Authorization:** Workers join only via a fail-closed allowlist of public
  keys (`AuthorizedWorkers`).
- **Observability:** Telemetry includes live progress, error rates, latency
  percentiles, and per-target findings.
- **Extensibility:** New check families (TLS, WAF, HTTP, security, browser,
  HTTP/3) can be added without changing the wire protocol.
- **Simplicity:** stdlib-plus-one-dependency (gRPC + protobuf) implementation.

---

## 2. Architecture

```
+----------------+      gRPC/VPMP      +----------------+
|   Coordinator  | <==================> |    Worker A    |
| (control plane)|  signed telemetry   | (Ed25519 key)  |
+----------------+                      +----------------+
        |
        | +----------------+  +----------------+
        +--->|    Worker B  |  |    Worker C    |
             +----------------+  +----------------+
```

- **Coordinator:** issues run requests, aggregates telemetry, verifies
  signatures, emits final reports.
- **Worker:** connects to coordinator, receives tasks, runs load/scan checks,
  signs every telemetry snapshot and final report, streams results back.

---

## 3. Wire Protocol (protobuf)

The canonical definition lives in `internal/dist/proto/coordinator.proto`.

### 3.1 Messages

| Field | Type | Description |
|-------|------|-------------|
| `RunRequest.target` | string | Target host/URL |
| `RunRequest.users` | int32 | Concurrent users |
| `RunRequest.duration` | string | Duration (e.g. "60s") |
| `RunRequest.intrusive` | bool | Allow intrusive probes |
| `RunProgress.worker_id` | string | Worker identity |
| `RunProgress.signature` | bytes | Ed25519 signature over the snapshot |
| `RunProgress.rps` | double | Current requests/sec |
| `RunProgress.errors` | int64 | Error count |
| `RunProgress.latency_p50/p95/p99` | double | Latency percentiles (ms) |
| `RunCompleted.worker_id` | string | Worker identity |
| `RunCompleted.signature` | bytes | Ed25519 signature over the final report |
| `RunCompleted.total_requests` | int64 | Total requests sent |
| `RunCompleted.total_errors` | int64 | Total errors |
| `RunCompleted.findings[]` | Vuln | Findings from scan |

### 3.2 Signature format

Each signed message is canonicalized as length-prefixed UTF-8:

```
<len>:<field1>\n<len>:<field2>\n...
```

Then signed with Ed25519 (`crypto/ed25519`). The coordinator verifies using
the worker's registered public key. Verification failure → worker marked
`failed`, telemetry dropped (fail-closed).

---

## 4. CLI flags (coordinator)

| Flag | Meaning |
|------|---------|
| `-authorized-keys` | Comma-separated hex Ed25519 public keys allowed to join |
| `-require-attestation` | Enforce signature verification on all telemetry |
| `-attest-key` | Worker's Ed25519 private key (hex or file) |

---

## 5. Security properties

- **Fail-closed:** No allowlist entry → worker cannot register. No valid
  signature → telemetry rejected.
- **No key material on wire:** Only public keys are enrolled; signatures never
  reveal private keys.
- **Replay resistance:** Each snapshot includes a monotonically increasing
  sequence number; the coordinator rejects out-of-order or duplicate snapshots.

---

## 6. Implementation status

| Component | Location | Status |
|-----------|----------|--------|
| Proto definition | `internal/dist/proto/coordinator.proto` | Implemented |
| Attestation core | `internal/dist/coordinator/attest.go` | Implemented |
| Worker signing | `internal/dist/coordinator/worker.go` | Implemented |
| Master verification | `internal/dist/coordinator/master.go` | Implemented |
| Aggregator storage | `internal/dist/coordinator/aggregator.go` | Implemented |
| E2E tests | `internal/dist/coordinator/worker_attestation_test.go` | Implemented |

---

## 7. Open items (post-v1)

- [ ] Third-party adoption / independent implementations
- [ ] IANA registration of a VPMP service name (if TCP transport is added)
- [ ] Formal security review of the attestation construction
- [ ] VPMP v1.1: optional mTLS transport layer

---

## 8. References

- [Sift repository](https://github.com/asadbekabdulboqiyev/sift)
- [coordinator.proto](internal/dist/proto/coordinator.proto)
- [attest.go](internal/dist/coordinator/attest.go)
- [DISTRIBUTED.md](docs/DISTRIBUTED.md)
