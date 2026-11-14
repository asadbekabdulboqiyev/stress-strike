# eBPF Kernel-Level X-Ray (Opt-in Host Observability Agent)

**Status:** Design proposal (idea)  
**Target product:** Sift v0.15+  
**Scope:** Linux hosts, opt-in, authorized, defensive/diagnostic observability  
**Audience:** Sift maintainers, platform/SRE/security engineers, enterprise operators

---

## 1. Problem and Value

Sift already provides strong external and workflow-level visibility: multi-protocol load/replay execution, scanner/pentest workflows, distributed orchestration, dashboard telemetry, OpenTelemetry-aware tracing hooks, and verifiable evidence (VPMP). However, Sift primarily observes systems from the outside (client/request perspective, probe results, service responses, and exported traces/metrics).

When a run shows latency spikes, error bursts, handshake failures, connection resets, or unexplained throughput collapse, operators often cannot determine **why** from external signals alone:

- Was the bottleneck in the application, kernel networking stack, DNS resolution path, TLS handshakes, disk I/O, CPU scheduling, cgroup throttling, or socket queue pressure?
- Did request time increase because of syscall stalls (`read`, `write`, `epoll_wait`, `connect`, `fsync`) or lock/contention effects inside the host?
- Were errors caused by retransmits, SYN backlog drops, conntrack pressure, OOM kills, or noisy-neighbor resource contention on shared workers/targets?
- How should operators correlate a Sift scenario step, trace span, or distributed worker action with host-side evidence in a reproducible, auditable way?

**Value proposition:** an opt-in "Kernel-Level X-Ray" agent augments Sift with low-level, host-local evidence to improve diagnosis and confidence during authorized testing and operations. It does **not** replace application profiling or external measurements; it correlates them.

### Expected outcomes

- Faster root-cause triage for performance regressions and intermittent failures observed during Sift runs.
- Better explainability in reports/dashboard: "external symptom" + "host/kernel corroborating signals" with confidence and caveats.
- Early-warning and anomaly/risk signals (e.g. rising retransmits, accept queue saturation, excessive syscall latency tails) before hard failure thresholds are crossed.
- Stronger evidence packages for reproducible internal investigations when combined with existing Sift artifacts and VPMP workflows.

---

## 2. Goals and Non-Goals

### 2.1 Goals

1. **Correlate external Sift signals with in-host evidence**  
   Link Sift run/step/request/worker identifiers (and OTel trace/span context where available) to syscall/network/scheduling/resource observations on the relevant Linux host(s).

2. **Provide opt-in, defensive diagnostics**  
   Enable collection only when explicitly configured and authorized for a host/scope/duration, with clear operator intent and auditability.

3. **Minimize overhead and preserve safety**  
   Use bounded, event/sample-driven eBPF collectors with backpressure, rate limits, and safe defaults to avoid destabilizing test hosts or skewing results excessively.

4. **Support production-minded deployment**  
   Define a deployable agent/sidecar model for bare metal, VMs, containers, and Kubernetes nodes, with privilege and compatibility constraints documented.

5. **Integrate with Sift v0.15 architecture**  
   Fit naturally with existing CLI/dashboard/distributed workflows, `internal/otel` tracing, metrics endpoints, report artifacts, and evidence concepts without requiring invasive rewrites.

6. **Explainable outputs**  
   Produce anomaly/risk indicators with confidence levels, supporting measurements, and explicit limitations (not deterministic "doom predictions").

### 2.2 Non-Goals

- **Not offensive tooling:** no exploitation, privilege escalation, credential theft, covert surveillance, persistence, or bypass of host security controls.
- **Not a general-purpose EDR/HIDS:** no continuous enterprise threat hunting product surface in MVP; focus is run-correlated diagnostics.
- **Not full packet capture/storage:** avoid raw payload capture by default; prefer metadata/aggregates and redacted summaries.
- **Not kernel module development:** prefer eBPF/CO-RE-based user-space agents (libbpf/cilium-ebpf ecosystem) over custom LKM distribution.
- **Not guaranteed root-cause attribution:** signals are probabilistic/corroborative and must be presented with uncertainty.
- **Not universal OS support:** Linux-focused only (kernel/eBPF/BTF dependent). macOS/Windows are out of scope except as future research.
- **Not mandatory for core Sift:** feature must be fully optional and degrade gracefully when unavailable.

---

## 3. Design Principles

- **Opt-in by default off:** no eBPF programs loaded unless explicitly enabled.
- **Least privilege:** request only required BPF/capabilities and attach only required probes.
- **Data minimization:** collect the minimum fields needed for correlation and diagnosis; aggregate early where possible.
- **Bounded impact:** strict limits on event rates, memory, CPU, map sizes, and export volume.
- **Explainability over certainty:** every derived signal includes evidence, confidence, and known blind spots.
- **Portability with honesty:** support modern BTF-enabled kernels first; document fallbacks/unsupported cases clearly.
- **Auditability:** record who enabled collection, where, for what run/scope, and with which collectors.

---

## 4. Architecture Overview

The capability is implemented as an **opt-in host observability agent** (`sift-ebpf-agent`, name TBD) that runs on Linux hosts participating in or affected by Sift workloads (target hosts, worker hosts, or co-located test infrastructure), plus a Sift-side correlation/integration layer.

```text
+--------------------+         run/trace IDs, control        +----------------------+
| Sift CLI / Master  | ------------------------------------> | Sift Correlation/API |
| Dashboard / Worker | <------------------------------------ | (dashboard/report)   |
+--------------------+         summaries, alerts, evidence   +----------+-----------+
                                                                           ^
                                                                           | OTLP/gRPC/HTTP (batched)
                                                                           |
                                                              +------------+-------------+
                                                              | sift-ebpf-agent (Linux)  |
                                                              | - collector manager      |
                                                              | - eBPF loader/maps       |
                                                              | - enricher/redactor      |
                                                              | - exporter/backpressure  |
                                                              +------------+-------------+
                                                                           |
                                                                           | bpf() / ringbuf / maps
                                                                           v
                                                              +--------------------------+
                                                              | Linux kernel (BTF/trace) |
                                                              | tracepoints/kprobes/...  |
                                                              +--------------------------+
```

### 4.1 Components

#### A. Host Agent (`sift-ebpf-agent`)
A privileged (but capability-scoped) user-space daemon responsible for:
- Validating runtime compatibility (kernel version, BTF availability, enabled features).
- Loading/verifying/managing eBPF programs and maps for selected collectors.
- Reading events from ring buffers/perf buffers and aggregating in user space.
- Enriching events with host metadata (hostname, cgroup/container IDs where available, PID/comm mapping with privacy controls).
- Applying redaction/sampling/rate limiting before export.
- Exposing local health and diagnostics (read-only), and optionally Prometheus/OTel metrics for the agent itself.

#### B. eBPF Collectors (program sets)
Small, purpose-specific programs attached to kernel hooks. Initial design favors **tracepoints** and **cgroup-aware** hooks where possible for stability, with kprobes/fentry used selectively and version-gated.

Collector categories (MVP + phased):
- **Process/syscall latency collectors:** syscall entry/exit timing for selected syscalls (e.g. `connect`, `accept`, `read`, `write`, `sendmsg`, `recvmsg`, `epoll_wait`, `fsync`) with per-cgroup/per-PID aggregation.
- **TCP/network health collectors:** retransmits, resets, connect latency, accept queue overflows, RTT/sock state signals from tracepoints (no payload capture).
- **Scheduling/resource contention collectors:** runqueue latency, CPU throttling (cgroup), block I/O latency summaries.
- **Runtime correlation helpers:** process/container/cgroup identity snapshots to map PIDs/comms to Sift workers, services-under-test, or node roles.

#### C. Transport and Ingestion
Agent exports structured telemetry to Sift components over authenticated channels:
- **Primary:** batched gRPC stream to Sift master/dashboard collector endpoint (reusing distributed trust concepts where possible).
- **Alternative:** OTLP export (metrics/traces/log-like events) for environments with existing collectors; and/or local file/JSONL spool for offline evidence attachment.
- **Backpressure:** local bounded queue + drop counters + priority (aggregates over raw events).

#### D. Correlation Engine
A Sift-side component (library/service within master/dashboard or dedicated internal package) that joins:
- Sift run metadata (run ID, scenario/step IDs, target, profile, worker IDs, timestamps).
- External request telemetry (latency/errors/status, `traceparent`/trace IDs if OTel enabled, request IDs injected by Sift where applicable).
- Host agent summaries/events (PID/cgroup/container/node, syscall/network/resource metrics).

Correlation strategies:
- **Direct ID join:** propagate Sift run/request IDs via environment variables, headers (where safe), or trace context; agent records mapping hints when observable (best effort).
- **Temporal + topology join:** align time windows and host/worker identity (node, container, PID namespace, cgroup path) when direct IDs are unavailable.
- **Confidence scoring:** each correlation emits a confidence score and method (`direct`, `trace-linked`, `temporal-topology`, `heuristic`).

#### E. UI / Reporting Integration
- **Dashboard:** optional "Kernel X-Ray" panel per run/host showing key anomalies, timelines, and drill-down summaries (not raw kernel dumps).
- **CLI/reports:** include a summarized host-observability section in JSON/TXT artifacts when enabled (counts, top signals, correlation confidence, agent health/overhead stats).
- **Evidence integration:** agent summaries and manifests may be attached as auxiliary evidence artifacts; any VPMP inclusion must follow Sift's evidence model (hashing/signing boundaries defined explicitly) and remain optional.

---

## 5. Data Model (Design-Level)

### 5.1 Event/Summary Types (examples)

- `HostMeta`: agent version, kernel release, BTF available, hostname (or hashed), node/role labels (operator-provided), clock source info.
- `RunCorrelationContext`: sift_run_id, worker_id, scenario/step, trace_id/span_id (if available), target host/service hints, time window.
- `SyscallLatencySummary`: window, cgroup/pid/comm (policy-controlled), syscall, count, p50/p95/p99, max, error counts.
- `TcpHealthSummary`: window, local/remote tuple metadata (redacted/aggregated as configured), retransmits, resets, connect failures, SYN backlog drops, RTT estimates.
- `SchedIOPressureSummary`: runqueue latency buckets, CPU throttle time, block I/O wait summaries.
- `AnomalySignal`: signal_id, type, severity_hint, confidence, time window, correlated entities, evidence fields, explanation text, limitations.

### 5.2 Identity and Correlation Keys

- `sift_run_id` (required when run-scoped)
- `sift_worker_id` / node identity (distributed mode)
- `trace_id` / `span_id` (optional, from `internal/otel` context propagation)
- `cgroup_id/path`, container ID (when visible and permitted)
- PID/TID/comm/process start time (privacy-controlled; may be hashed/tokenized in reports)

### 5.3 Redaction/Minimization Defaults

- No process command-line arguments, environment variables, file contents, packet payloads, or HTTP bodies collected by default.
- Remote IP/port and DNS names can be disabled, aggregated, or hashed depending on policy.
- Executable names (`comm`) may be allowlisted/normalized; raw PIDs can be replaced with ephemeral local tokens in exported artifacts.

---

## 6. Security Model (Least Privilege, Privacy, Opt-in)

### 6.1 Opt-in and Authorization

- Feature disabled by default in Sift and in the agent.
- Explicit enablement required at multiple levels:
  1. **Host/operator opt-in:** agent installed/configured and started intentionally.
  2. **Run/session opt-in:** Sift run/dashboard requests kernel observability for a scope/time window.
  3. **Policy authorization:** integrate with Sift's authorization/audit concepts (`authorize`/audit trail patterns) for enterprise deployments; local/dev mode must still log intent clearly.
- Time-bounded capture windows by default (e.g. run duration + grace period) to prevent accidental always-on collection.

### 6.2 Privileges and Containment

Linux eBPF loading typically requires elevated privileges; production design should prefer narrow capabilities over full root where feasible:

- Potential capabilities (kernel/config dependent): `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` (only for specific networking attachments), and sometimes `CAP_SYS_RESOURCE` for memlock/RLIMIT tuning on older kernels.
- Run as a dedicated system user with minimal filesystem access; read-only mounts where possible.
- Seccomp/AppArmor/SELinux profiles for the user-space agent process (recommended deployment hardening).
- No shell-out to arbitrary commands from untrusted input; strictly validated collector configs.

### 6.3 Privacy and Data Protection

- **Collection boundaries policy:** operator-defined allow/deny for hosts, cgroups/namespaces, processes, and network tuple detail level.
- **Redaction pipeline:** normalize/drop sensitive fields before export and before persistence.
- **Retention controls:** short default retention for high-resolution summaries; configurable aggregation windows.
- **Secure transport:** mTLS/token-based auth for agent-to-Sift export; TLS required outside localhost/dev.
- **Secrets handling:** never emit credentials/tokens from process memory, packets, or environment-derived sources.

### 6.4 Auditability

Record auditable events (locally and/or centrally) for:
- Agent start/stop, version, kernel/feature compatibility.
- Collector enable/disable actions and effective config hash.
- Scope, run IDs, duration, export destination, and drop/backpressure counters.
- Policy denials (requested collector not permitted).

### 6.5 Safety Controls

- Kill switch: immediate disable/unload collectors without restarting the host.
- Safe failure mode: if exporter/correlation unavailable, agent degrades to local bounded buffering or drops with metrics (never blocks workload).
- Watchdog on overhead: auto-throttle or disable collectors if CPU/memory/drop thresholds exceeded.

---

## 7. Deployment Model

### 7.1 Supported Deployment Patterns (Linux)

1. **Systemd host agent (bare metal / VM)**  
   Recommended for observing host-level behavior (target server, load generator host, or Sift worker node). Managed via unit file, env/config, and journald logs.

2. **Kubernetes DaemonSet (node observability)**  
   One agent per node, configured with least privileges and node-scoped collectors. Useful for distributed Sift workers or services under test running on k8s.

3. **Sidecar (targeted container scope)**  
   Limited use for cgroup/task-scoped diagnostics when node-level DaemonSet is not permitted. Requires careful capability and volume configuration; more operational complexity.

4. **Local developer mode**  
   Manual run on a Linux dev machine for reproducing Sift issues; strict warnings about privileges and authorized targets.

### 7.2 Placement Relative to Sift

- **On Sift worker hosts:** highest value for correlating generated load behavior/resource contention with observed external results.
- **On target hosts (authorized):** highest diagnostic value for service-side bottlenecks, but requires strong trust/approval boundaries.
- **On master/dashboard host:** usually unnecessary except self-observability; not a primary target.

### 7.3 Compatibility Constraints (Realistic)

- **Kernel/eBPF features vary:** CO-RE/BTF, ring buffer, cgroup v2, and specific tracepoints differ by distro/kernel. Agent must perform capability probing and publish a compatibility matrix at runtime.
- **Container runtimes/namespaces:** PID/cgroup visibility depends on mounts and namespace configuration.
- **Older kernels:** fallback to reduced collector set or disable feature with explicit reason (no silent partial correctness).
- **ARM64 vs x86_64:** both possible with CO-RE, but build/test matrix and probe availability must be validated per release.

---

## 8. Correlation with Sift Signals (Runs, Traces, Metrics)

### 8.1 Correlation Inputs from Sift v0.15

- **Run context:** run IDs, config/profile, scenario/step names, timestamps, and target metadata (where available in CLI/dashboard/distributed flows).
- **Distributed context:** master/worker IDs and assignment metadata (`internal/dist` patterns) to map host agents to worker nodes.
- **Tracing context:** when OTel is enabled (`internal/otel`), propagate `trace_id`/`span_id` into correlation records for request/span-aligned analysis.
- **Metrics/health context:** align anomaly windows with dashboard metrics and `/metrics`-style signals to provide cross-layer timelines.

### 8.2 Correlation Workflow

1. Sift starts/annotates a run with a correlation context (run ID, optional trace context, expected hosts/workers).
2. Agent receives scope (time window, allowed collectors, host/worker labels) and begins bounded collection.
3. Agent emits aggregated summaries and notable events with timestamps and local identity hints.
4. Correlation engine joins host summaries with Sift run/trace/metric timelines.
5. Dashboard/reporting renders correlated findings with confidence and raw supporting counters.

### 8.3 Confidence and Explainability

Each derived insight should include:
- **Signal:** what was observed (e.g. p99 `connect` latency increased 4x; retransmit rate rose).
- **Correlation basis:** direct ID, trace-linked, temporal-topology, or heuristic.
- **Confidence:** high/medium/low with rationale.
- **Alternative explanations:** app-level queueing, network path issues outside host, benchmark configuration artifacts.
- **Limitations:** missing probes, dropped samples, clock skew, unsupported kernel features.

No output should be phrased as guaranteed future failure; use "early-warning", "anomaly", "risk indicator", or "corroborating evidence" language.

---

## 9. MVP Scope

### 9.1 MVP Goal

Deliver a **narrow, safe, Linux-first diagnostic slice** that helps explain latency/error anomalies during authorized Sift runs on compatible hosts.

### 9.2 MVP Inclusions

- **Platform:** Linux x86_64, modern kernels with BTF and ring buffer support (explicit minimums defined during implementation; unsupported hosts fail with clear diagnostics).
- **Deployment:** systemd-managed host agent for a single node (worker host or target host), manual opt-in configuration.
- **Collectors (bounded):**
  - TCP connect latency and failure counts (tracepoint-based where possible).
  - TCP retransmit/reset counters.
  - Syscall latency summaries for a small allowlisted set (e.g. `connect`, `read`, `write`, `epoll_wait`).
  - Basic CPU scheduling/runqueue latency summary (optional if overhead acceptable).
- **Correlation:** run ID + time window + host/worker identity; optional trace ID attachment when Sift OTel context is present.
- **Export:** local JSONL summaries and/or gRPC push to Sift dashboard/master endpoint in trusted environments.
- **UI/reporting:** CLI JSON section and a basic dashboard timeline/table view for correlated host signals.
- **Security:** opt-in config, capability checks, minimal field set, no payload capture, audit log of enablement and drops.

### 9.3 MVP Exclusions

- Kubernetes DaemonSet automation and CRD/operator integration.
- Deep per-request payload inspection, DNS payload logging, or file content tracing.
- Automatic remediation actions.
- Multi-kernel fallback matrix beyond "supported/unsupported with reason".
- VPMP bundle schema changes (may attach sidecar artifacts only, if needed).
- macOS/Windows support.

---

## 10. Phased Roadmap

### Phase 0 — Design & Validation (1–2 sprints)
- Finalize kernel/feature support matrix and privilege model.
- Spike collector prototypes (libbpf/cilium-ebpf) and overhead benchmarks on representative workloads.
- Define correlation schema and audit events; security/privacy review.

### Phase 1 — MVP (single-host diagnostics)
- Implement agent skeleton, compatibility probing, collector manager, bounded exporters.
- Add run-scoped correlation context plumbing in Sift CLI/dashboard/distributed flows (minimal integration).
- Produce report/dashboard summaries with confidence and limitations.
- Document deployment, permissions, and troubleshooting.

### Phase 2 — Distributed & Dashboard Integration
- Fleet-aware agent registration/health (master/worker environments).
- Multi-host correlation views for distributed runs.
- Improved OTel trace/span correlation and metrics alignment.
- Policy controls integrated with Sift authorization/audit workflows.

### Phase 3 — Hardening & Packaging
- Kubernetes DaemonSet/Helm/systemd packaging assets and hardening profiles.
- Performance tuning, adaptive sampling, and overload protection.
- Expanded collector set (disk I/O wait, cgroup memory pressure, DNS timing metadata) gated by compatibility and privacy review.
- Evidence attachment conventions and verifier/report interoperability (if adopted).

### Phase 4 — Advanced (optional, needs separate review)
- Cross-run anomaly baselines and regression hints (statistical, explainable).
- eBPF-based TLS handshake timing metadata (no secret material) where kernel/userspace hooks permit safely.
- Integration with external observability stacks via OTLP without duplicating Sift UI responsibilities.

---

## 11. Dependencies and Tooling (Design Level)

### 11.1 eBPF/User-space Stack

- **Language/runtime:** Go is a natural fit for Sift integration, but eBPF loading choices must be evaluated:
  - `cilium/ebpf` (pure-Go loader ecosystem, CO-RE support) — good integration ergonomics.
  - `libbpf` + `libbpfgo`/generated bindings — mature CO-RE workflows; may introduce CGO/build complexity.
- **Program development:** restricted C (clang/LLVM) for BPF programs, BTF/CO-RE relocations, `bpftool` for debugging/inspection.
- **Kernel features:** BTF (`/sys/kernel/btf/vmlinux`), ring buffer, tracepoints, cgroup v2 hooks (preferred when available).

### 11.2 Transport/Telemetry

- Reuse existing Sift patterns where practical: gRPC (`internal/dist` style contracts), OTLP/exporters (`internal/otel` conventions), Prometheus metrics exposure (agent self-metrics).
- Protobuf/JSON schemas for summaries and audit records with explicit versioning.

### 11.3 Packaging/Operations

- `systemd` unit + env config for host installs.
- Container image for agent with minimal base and clear capability requirements.
- Helm/DaemonSet manifests aligned with `deploy/` conventions (Phase 3).
- CI matrix for kernel-feature compatibility tests (VM-based or privileged runners) and static checks for BPF programs.

---

## 12. Integration with Current Sift v0.15

### 12.1 CLI
- Add opt-in flags/config (e.g. `--kernel-xray`, scope/profile selectors, agent endpoint/target selection) to relevant commands (`run`, possibly distributed flows) without changing default behavior.
- Surface agent availability, compatibility warnings, and correlation confidence in run summaries.

### 12.2 Distributed Mode (`master`/`worker`)
- Extend coordination metadata to advertise "xray-capable" hosts/workers and collect agent summaries per worker/node.
- Preserve existing trust boundaries; agent telemetry should be treated as an additional untrusted-until-authenticated input channel with explicit identity.

### 12.3 Dashboard
- Add a feature-gated panel/tab for kernel-level timelines and anomaly cards correlated to selected runs.
- Reuse operational status patterns (`/healthz`, `/readyz`, metrics) for agent health where appropriate.

### 12.4 Tracing and Metrics
- Leverage `internal/otel` trace context propagation when enabled to improve correlation quality.
- Export agent self-metrics (events processed/dropped, load time, verifier errors, collector overhead estimates) for observability of the observer.

### 12.5 Evidence and Reporting
- Include host-observability summaries in run artifacts/reports under an explicit schema version.
- Optional attachment to evidence workflows: hash agent summary artifacts and include manifests in reports; any direct VPMP schema evolution requires separate design/RFC due to verification compatibility requirements.

### 12.6 Authorization/Audit
- Align enablement records with existing authorization/audit semantics (`sift authorize`, `sift audit` patterns) for enterprise workflows: who approved host observation, scope, ticket/reason, and duration.

---

## 13. Risks and Limitations

| Risk / Limitation | Impact | Mitigation |
|---|---|---|
| Kernel/BTF incompatibility | Feature unavailable or partial on older/custom kernels | Runtime probing, explicit compatibility report, reduced collector sets, docs |
| Privilege requirements | Operational/security friction; misuse concerns | Least capabilities, opt-in, audit logs, hardening profiles, clear warnings |
| Observer overhead | Skewed benchmarks or host pressure | Sampling/aggregation, bounded maps/rings, overhead watchdog, default-off collectors |
| Data sensitivity (process/network metadata) | Privacy/compliance exposure | Data minimization, redaction/aggregation, retention limits, policy controls |
| Correlation ambiguity | Misleading conclusions | Confidence scoring, explainability fields, display alternative causes/limitations |
| Event loss/backpressure | Incomplete evidence | Drop counters, priority queues, adaptive rate limiting, "degraded" status in UI/reports |
| Probe instability across kernel versions | Agent crashes or missing signals | Prefer tracepoints/CO-RE, version-gated attachments, canary tests, safe rollback |
| Time skew across hosts | Incorrect temporal joins | Record clock metadata, use monotonic deltas where possible, tolerant correlation windows |
| User misinterpretation as security verdict | False assurance or blame | Defensive wording, confidence levels, "not tested/not observed" semantics similar to Sift honesty model |

**Important limitation:** eBPF X-Ray provides **host-local corroboration**. It cannot fully observe off-host network paths, managed cloud internals, or application logic without instrumentation, and it must not be presented as definitive proof of future incidents.

---

## 14. Operational Considerations

- **Performance budget:** define per-collector CPU/memory/event-rate budgets and publish benchmark methodology (including overhead on idle and loaded systems).
- **Failure handling:** collector load failures are isolated; one failing probe must not disable the entire agent unless safety requires it.
- **Versioning:** version agent protocol/schemas independently and negotiate capabilities with Sift components.
- **Troubleshooting UX:** `sift-ebpf-agent doctor`/status commands (future) to report kernel support, permissions, active collectors, drops, and last export errors.
- **Documentation:** operator runbooks for permissions, kernel prerequisites, privacy settings, and known blind spots.

---

## 15. Open Questions (to resolve before implementation)

1. **Primary loader stack:** `cilium/ebpf` vs libbpf-based approach given build/release constraints in Sift's Go toolchain and CI.
2. **Correlation transport contract:** extend distributed gRPC APIs vs introduce a dedicated observability ingestion endpoint/protocol.
3. **Trace propagation depth:** how consistently Sift can attach trace/run identifiers across all protocols/scenario step types in v0.15+.
4. **Evidence model boundary:** whether host summaries become first-class VPMP artifacts or remain auxiliary signed/hashed attachments.
5. **Default privacy posture for multi-tenant/enterprise environments:** tenant labels, hashing strategy, and RBAC integration requirements.
6. **Support baseline:** minimum kernel/distribution versions for "supported" MVP vs "experimental".

---

## 16. Summary

eBPF Kernel-Level X-Ray is a **high-value, opt-in diagnostic extension** for Sift: it correlates external test/scanner/replay signals with kernel-level host evidence to explain anomalies, surface early-warning risk indicators, and improve investigation quality. The design must remain defensive, Linux-focused, privilege-aware, low-overhead, and explainable, with strict data minimization and clear integration points into Sift v0.15's CLI, distributed execution, dashboard, tracing/metrics, and evidence workflows.
