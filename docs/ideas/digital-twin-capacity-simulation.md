# Digital Twin / Capacity Simulation

**Status:** Idea / design draft  
**Target project:** Sift `v0.15.x`  
**Document scope:** Defensive capacity planning and "what-if" risk modeling for systems you own or are explicitly authorized to test  
**Last updated:** 2026-11-14

---

## 1. Summary

This document proposes a **Digital Twin / Capacity Simulation** capability for Sift: a way to model how a target service is likely to behave under alternative load, traffic-shape, and dependency conditions using **observed evidence** from Sift runs (engine telemetry, timeline samples, replay traces/captures, reports, and optionally attested bundles) rather than intuition alone.

The capability is intentionally **evidence-based and probabilistic**. It produces bounded estimates (with scenarios and confidence/uncertainty) for questions such as:

- "If request rate grows 2× during peak, where do we expect saturation and error amplification?"
- "Which endpoint/step becomes the bottleneck first under a changed traffic mix?"
- "What headroom remains before p95/p99 latency or error-rate SLO thresholds are likely breached?"
- "How would a slower dependency or larger payload affect queueing and throughput?"

It does **not** promise precise future prediction (for example, "99% accuracy at minute 14"). Instead, it provides calibrated ranges, explicit assumptions, and reproducible simulation artifacts that can be compared against later real runs.

---

## 2. Problem and Value

### 2.1 Problem

Teams already use Sift to generate load (`run`), replay captured traffic (`replay`), scan for weaknesses, and produce reports/evidence. However, turning those results into forward-looking capacity decisions is still manual:

- **Point-in-time results are hard to extrapolate.** A single run at fixed concurrency/RPS does not answer how the system behaves at 1.5×, 2×, or under a different arrival pattern.
- **Traffic shape matters.** Real incidents are often caused by mix shifts (endpoint distribution, payload sizes, burstiness), not just higher average RPS.
- **Bottlenecks are inferred informally.** Queueing effects, per-step saturation, and dependency limits are often guessed from charts rather than modeled.
- **Uncertainty is rarely stated.** Plans based on a single number ("we can handle 5k RPS") hide variability, measurement noise, and model error.

### 2.2 Value

A Sift-native simulation capability would:

- **Improve capacity planning quality** by converting observed runs/replays into scenario-based forecasts with stated confidence.
- **Reduce risky trial-and-error** by exploring "what-if" conditions offline before running higher-impact authorized load tests.
- **Make bottlenecks explainable** via endpoint/step/resource-queue assumptions and sensitivity outputs (what changed the result most).
- **Fit existing workflows** by reusing Sift artifacts (reports, timelines, captures, attestations) and producing comparable, exportable outputs.
- **Support defensible decisions** with calibration/error reporting and, when desired, attestable simulation inputs/outputs.

---

## 3. Goals and Non-Goals

### 3.1 Goals

1. **Model "what-if" capacity and risk from observed evidence.**
   - Inputs: Sift run telemetry/reports/timelines, replay captures and replay results, scenario/config metadata, and optional attested bundles/samples.
2. **Represent endpoint behavior and bottleneck/queue assumptions explicitly.**
   - Per-step/per-endpoint service-time behavior, concurrency/resource limits, queueing, and optional dependency latency/error multipliers.
3. **Support scenario analysis with uncertainty.**
   - Best/likely/worst (and custom) scenarios; confidence intervals/bands derived from calibration and Monte Carlo/sensitivity runs.
4. **Calibrate and validate models.**
   - Fit/tune against known runs; report fit quality and out-of-sample error; refuse/flag low-confidence extrapolations.
5. **Integrate with current Sift architecture incrementally.**
   - New internal package(s), CLI entry points, report artifacts, and dashboard views that reuse existing data structures where practical.
6. **Remain defensive and authorized-use only.**
   - Capacity planning and authorized load simulation only; no exploit automation, no bypass guidance, no unauthorized target interaction.

### 3.2 Non-Goals

- **Not a perfect predictor or digital replica of all internals.** No claim of exact future latency/throughput at a specific minute; outputs are estimates with uncertainty.
- **Not automatic production topology discovery.** The twin models what Sift can observe (and what the operator declares); it does not infer hidden infrastructure without evidence/config.
- **Not a replacement for real load/replay tests.** Simulation guides and prioritizes authorized tests; it does not certify production readiness by itself.
- **Not distributed-system formal verification.** Focus is pragmatic performance/capacity risk estimation.
- **Not an attack tool.** No vulnerability exploitation, evasion, or scanning automation beyond Sift's existing authorized capabilities (out of scope for this feature).

---

## 4. Alignment with Current v0.15 Architecture

This design is grounded in existing Sift components (inspected in-repo):

| Existing area | Relevant current behavior (v0.15) | How the Digital Twin fits |
|---|---|---|
| `internal/engine` | Executes scenario/profile-driven load (`steady`, `soak`, `linear-ramp`, `spike`, `wave`, `constant-rps`, `burst`), tracks live telemetry (`metrics.Telemetry`: RPS, errors, latency percentiles, status codes, per-step stats, timeline), supports paced runs and coordinated-omission correction, and can emit per-request samples via `RunOptions.Samples` for attestation. | Primary source of observed service/latency/error behavior and arrival profiles; simulation can consume built reports/timelines and (optionally) per-request samples to fit service-time and queue models. |
| `internal/replay` (`cmd/sift-replay`, `internal/replay/*`) | Replays captured traffic (PCAP/HAR) with pacing modes (`timing`, `rps`, `legacy`), rate multiplier, concurrency, filtering, base URL override, and response assertions/latency summaries. | Provides **traffic-shape ground truth** (endpoint/method/timing distributions) for mix-shift scenarios and replay-vs-sim calibration. |
| `internal/report` | Builds structured run reports (overall and per-step latency percentiles, status/error breakdowns, RPS, SLA evaluation, timeline, pre-warm time) and renders terminal/JSON-oriented outputs. | Simulation results should emit a parallel, comparable report schema (`SimulationReport`) and reuse SLA/timeline visualization conventions. |
| `internal/attest` | VPMP v1 evidence bundles with canonicalized records, Merkle commitments over sample sidecars, Ed25519 signatures, and verification; samples include `seq`, `worker`, `start_ns`, `latency_ns`, `status`, `bytes`. | Enables verifiable simulation inputs (and optionally signed simulation outputs) and higher-trust calibration datasets. Memory/size caps in sample loading must be respected. |
| `cmd/sift` | CLI subcommand architecture (`run`, `replay`, `scan`, dashboard modes, `verify`, etc.) with report-dir and evidence-related flags (e.g. `--emit-bundle`). | Natural home for `sift simulate` (and related subcommands) with file-based inputs/outputs consistent with existing UX. |
| `internal/dashboard` | Web UI with live snapshots, run control/history, and attestation info; assets bundled into a single script; bounded API/WS surface. | Dashboard can host a read-focused simulation workspace (configure, run, compare scenarios) without weakening existing control-plane limits. |
| Reports/artifacts | Runs produce structured artifacts under report directories; attestation produces bundle + `.samples.jsonl`. | Simulation should write deterministic JSON/CSV/Markdown artifacts alongside existing report conventions for CI and offline review. |

**Key implication:** v0.15 already captures much of the evidence a first simulator needs (latency distributions, per-step stats, timelines, paced-run behavior). The MVP should therefore start as an **offline, artifact-driven simulator** before any tightly coupled live-engine changes.

---

## 5. User Experience and Primary Workflows

### 5.1 Core workflows

1. **Run → Simulate (single-run extrapolation)**
   - User runs an authorized baseline test (`sift run ...`) producing `report.json` (+ optional timeline/bundle).
   - User runs `sift simulate` to estimate behavior at different RPS/concurrency/mix/scenario assumptions.

2. **Replay-informed simulation (traffic mix "what-if")**
   - User provides a capture-derived summary (or replay report) to preserve endpoint distribution/timing shape.
   - Simulation applies mix shifts (e.g., +30% `POST /checkout`) and forecasts bottleneck/latency/error risk.

3. **Calibration (model trust-building)**
   - User supplies two or more observed runs at different load levels (or train/test split).
   - Tool fits parameters, evaluates prediction error on held-out data, and reports confidence/fit grade.

4. **Scenario comparison (planning artifact)**
   - Produce best/likely/worst scenario outputs side-by-side with assumptions, uncertainty bands, and SLA-breach probabilities.

### 5.2 Example CLI concepts (illustrative)

```bash
# Build a model from a baseline run report (+ optional timeline/samples)
sift simulate fit \
  --from-report ./reports/run-2026-11-14T10:00:00Z/report.json \
  --timeline ./reports/run-2026-11-14T10:00:00Z/timeline.csv \
  --out ./reports/sim/model.json

# Run what-if scenarios
sift simulate run \
  --model ./reports/sim/model.json \
  --scenario ./scenarios/peak-2x.yaml \
  --out ./reports/sim/peak-2x

# Compare best/likely/worst and emit planning report
sift simulate compare \
  --model ./reports/sim/model.json \
  --scenarios ./scenarios/best.yaml,./scenarios/likely.yaml,./scenarios/worst.yaml \
  --out ./reports/sim/compare
```

(Exact flag names are implementation details; the design goal is artifact-driven, scriptable usage consistent with existing Sift CLI patterns.)

---

## 6. Proposed Architecture

### 6.1 High-level components

```
Observed Evidence (inputs)                Simulation & Validation                Outputs
--------------------------                -----------------------                -------
engine run report/timeline  --+        +---------------------------+        +----------------------+
replay capture/replay stats   +------> | Ingestion & Normalization | -----> | Twin Model (fitted)  |
attest bundle + samples (opt) +------> | (parsers, schema mapping) |        | + assumptions        |
operator assumptions/scenario -+        +-------------+-------------+        +----------+-----------+
                                                       |                                 |
                                                       v                                 v
                                            +---------------------+           +----------------------+
                                            | Calibration/Fit     |           | Scenario Simulator   |
                                            | (params + fit stats)|           | (discrete-event/MC)  |
                                            +----------+----------+           +----------+-----------+
                                                       |                                 |
                                                       v                                 v
                                            +---------------------+           +----------------------+
                                            | Validation & Error  |           | Reports + Dashboard  |
                                            | (holdout, bounds)   |           | + CI artifacts       |
                                            +---------------------+           +----------------------+
```

### 6.2 Component responsibilities

1. **Ingestion & Normalization (`internal/sim/input` or equivalent)**
   - Parse Sift run reports (`report.Report` JSON), optional timeline CSV/samples, replay summaries/captures, and scenario/model files.
   - Normalize into a common observation schema (time buckets, per-step metrics, arrival rates, error/status classes).
   - Enforce defensive parsing limits (file size/count/record caps), reusing `internal/attest` sample-loading limits for sidecars.

2. **Feature Extraction (`internal/sim/features`)**
   - Derive arrival/process characteristics: achieved RPS, concurrency/load profile shape, per-step latency distributions (p50/p95/p99 and histogram/quantile approximations where available), error rates by class/status, and endpoint mix (from replay/capture summaries).
   - Compute derived signals: utilization proxies, queue-growth indicators, tail-latency inflation vs load, timeout/error amplification.

3. **Twin Model (`internal/sim/model`)**
   - Parameterized representation of the system under test as observed:
     - **Workload model:** arrivals (open/closed-loop approximation), step/endpoint mix, think-time/pacing assumptions.
     - **Service model:** per-step/service-center service-time distributions (empirical/bootstrap or parametric fits with guardrails).
     - **Capacity model:** effective parallelism/concurrency limits and queueing disciplines (initially simple, explicit queues).
     - **Failure model:** error/timeout probability as a function of load/queueing/saturation (bounded; calibrated from observations, not invented).
   - Stores assumptions, calibration range, and versioned schema.

4. **Calibration/Fit (`internal/sim/calibrate`)**
   - Fits model parameters to one or more baseline observations.
   - Supports train/validation split (or k-fold on time buckets/runs when enough data exists).
   - Produces fit diagnostics: residual/error metrics (e.g., relative error on RPS, p95/p99, error rate), bias notes, and a **confidence/fit grade**.

5. **Scenario Simulator (`internal/sim/engine`)**
   - Executes "what-if" scenarios using discrete-event simulation (DES) and/or Monte Carlo sampling over uncertain parameters.
   - Produces distributions (not single points) for key outputs: throughput, latency percentiles, queue lengths, saturation time, and SLA-breach likelihood.
   - Supports deterministic seeded runs for reproducibility.

6. **Validation & Guardrails (`internal/sim/validate`)**
   - Detects extrapolation beyond calibrated range and downgrades confidence/widens uncertainty.
   - Flags unsupported assumptions (insufficient data, contradictory runs, missing timeline/mix detail).
   - Emits "model limits" alongside results.

7. **Reporting & Integration (`internal/sim/report`, CLI/dashboard adapters)**
   - Writes machine-readable (`.json`) and human-readable (`.md`/`.txt`) artifacts plus optional CSV series for charts.
   - Integrates with dashboard for visualization and comparison (read-only views over generated artifacts in MVP).

### 6.3 Modeling approach (MVP philosophy)

- **Start simple, explicit, and inspectable.** Prefer queueing/network-of-queues abstractions and empirical distributions over opaque ML.
- **Closed-loop vs open-loop awareness:**
  - Sift `run` engine user loops (virtual users) behave closer to **closed-loop** systems unless paced/constant-RPS modes dominate; the model must represent the workload generation mode actually used.
  - Replay pacing (`timing`/`rps`) can represent **open-loop or trace-driven** arrivals; the simulator should support both.
- **Coordinated omission (CO):** when input reports/timelines come from CO-corrected paced runs, calibration must treat them as corrected measurements; when uncorrected, uncertainty and bias warnings should increase (especially for tail latency under saturation). Dashboard-generated artifacts should be labeled according to existing `coCorrected` semantics.

---

## 7. Data Inputs (from Existing Sift Evidence)

### 7.1 Supported/target inputs

| Source | Typical artifact/path | Data used | Notes |
|---|---|---|---|
| Load test run | `report.json` (from `internal/report.Report`) | Overall/step latency (avg/p50/p95/p99), request/error counts, status/error maps, RPS, duration, load profile, SLA results, optional timeline | Primary MVP input; already structured and machine-readable. |
| Run timeline | timeline CSV / embedded timeline samples | Time-bucketed RPS/latency/error progression, ramp/saturation shape | Improves fit for dynamic profiles (ramp/spike/wave/soak). |
| Scenario/config metadata | YAML/JSON scenario used by `run` | Steps/endpoints, profiles, pacing/rate hints, user counts, assertions | Needed to map step-level behavior and workload intent. |
| Replay capture | PCAP/HAR via `internal/replay` | Endpoint/method mix, timing gaps, payload/size hints (where available), host/path distributions | Ground truth for traffic-shape and mix-shift scenarios. |
| Replay result/report | replay output (JSON/report artifacts where available) | Realized replay rate, errors, latency summaries, assertion failures | Calibration/validation for trace-driven simulations. |
| Attested evidence | `*.bundle.json` + `*.samples.jsonl` (VPMP v1) | Verified per-request records (`start_ns`, `latency_ns`, `status`, `bytes`, `seq`, `worker`) and bundle metadata | High-trust calibration input; must honor `attest` load caps and verification status. |
| Operator assumptions | simulation scenario file (new) | Hypothetical multipliers/limits (traffic growth, dependency slowdown, capacity changes), confidence preferences, seeds | Explicit, auditable assumptions; never silently inferred as fact. |

### 7.2 Input trust levels (recommended)

- **Verified:** attestation bundle passes `sift verify` (or equivalent library verification) and hashes/metadata match. Highest trust for calibration.
- **Observed-unverified:** locally produced reports/timelines/captures without cryptographic verification. Suitable for planning, labeled accordingly.
- **Assumed:** user-provided hypothetical parameters. Always echoed in outputs.

Outputs must surface the trust level of each input class.

### 7.3 Privacy and data minimization for inputs

- Prefer **aggregated reports/timelines** over raw samples when sufficient.
- Raw captures/samples may contain sensitive URLs, headers, payload metadata, or identifiers; ingestion must support redaction/field filtering and avoid copying unnecessary payload bodies into simulation artifacts.
- See §13 for security/privacy/authorization details.

---

## 8. Data Model (Proposed)

The following is a logical model; concrete Go types/JSON schemas may evolve during implementation. Version all persisted artifacts (e.g., `schema_version`).

### 8.1 `TwinModel` (fitted model artifact)

```json
{
  "schema_version": "sift.sim.model/v1",
  "created_at": "RFC3339",
  "tool_version": "0.15.x",
  "inputs": [
    {"kind": "run_report", "path": "...", "trust": "observed_unverified", "sha256": "..."}
  ],
  "calibration_range": {
    "rps_min": 100, "rps_max": 1200,
    "users_min": 10, "users_max": 200,
    "profiles": ["steady", "linear-ramp"],
    "notes": ["Extrapolation above 1200 rps is low-confidence"]
  },
  "workload": {
    "mode": "closed_loop|open_loop|trace_driven",
    "steps": [{"id": "login", "weight": 0.2}, {"id": "search", "weight": 0.8}],
    "arrival": {"base_rps": 600, "burstiness_index": 1.3}
  },
  "service_centers": [
    {
      "name": "step:search",
      "service_time_ms": {"dist": "empirical_quantiles|lognormal", "params": {"p50": 40, "p95": 120, "p99": 240}},
      "concurrency_limit": {"estimate": 150, "confidence": "medium"},
      "queue_model": "fcfs"
    }
  ],
  "failure_model": {
    "error_rate_curve": [{"rps": 600, "rate": 0.001}, {"rps": 1200, "rate": 0.02}],
    "timeout_ms_assumption": 5000
  },
  "fit": {
    "method": "quantile_fit+des_calibration",
    "holdout_metrics": {"rps_mape": 0.08, "p95_rel_error": 0.14, "error_rate_abs_error": 0.004},
    "confidence_grade": "medium",
    "warnings": ["Limited samples above knee point"]
  },
  "assumptions": ["No backend capacity change between observations"]
}
```

### 8.2 `SimulationScenario`

```json
{
  "schema_version": "sift.sim.scenario/v1",
  "name": "likely-peak",
  "class": "best|likely|worst|custom",
  "seed": 42,
  "horizon_seconds": 900,
  "warmup_seconds": 60,
  "iterations": 500,
  "workload_overrides": {
    "rps_multiplier": 1.8,
    "users_multiplier": 1.5,
    "mix_overrides": {"step:checkout": 1.3, "step:search": 0.9}
  },
  "system_overrides": {
    "dependency_latency_multiplier": 1.2,
    "capacity_multiplier": 1.0,
    "payload_size_multiplier": 1.1
  },
  "sla_targets": {"p95_ms_max": 300, "error_rate_pct_max": 1.0},
  "output_options": {"timeseries": true, "percentiles": [50,95,99]}
}
```

### 8.3 `SimulationResult` / `SimulationReport`

Key fields (aligned in spirit with `internal/report.Report` for comparability):

- **Identity/metadata:** scenario name/class, model hash/id, seed(s), iteration count, horizon/warmup, timestamps, tool/schema versions.
- **Inputs & trust:** referenced artifacts, verification status, assumptions applied.
- **Estimated aggregates (distributions):**
  - Throughput/RPS: median and interval (e.g., p10/p50/p90 across runs).
  - Latency (overall and per step/endpoint): p50/p95/p99 as intervals/bands, not single certainties.
  - Error rate and status/error-class distribution: expected value + interval.
  - Queue/concurrency/utilization proxies and inferred saturation point/range.
- **Risk/SLA outcomes:** estimated probability of breaching each SLA target; time-to-breach distribution when applicable.
- **Sensitivity:** which parameters most influenced outcomes (ranked).
- **Confidence & limitations:** confidence grade, calibration range checks, extrapolation flags, model/data warnings.
- **Reproducibility:** deterministic seed/config echo; optional hash of normalized inputs.

### 8.4 `CalibrationReport`

- Train/validation split description, per-metric errors (absolute/relative), bias direction, goodness-of-fit summary, recommended safe operating range, and reasons for low confidence (if any).

---

## 9. Simulation and Calibration Methodology

### 9.1 Evidence-driven parameterization

1. **Ingest observed runs/replays** and normalize metrics by time bucket and step/endpoint.
2. **Estimate arrival/workload** from profile + achieved RPS/users/timeline (and replay timing/mix when provided).
3. **Estimate service behavior** per step from observed latency samples/percentiles:
   - Prefer empirical/bootstrapped distributions when sufficient sample detail exists (e.g., verified sample sidecars).
   - Fall back to parametric approximations (e.g., lognormal/Gamma) fit to quantiles when only report-level percentiles are available, with wider uncertainty.
4. **Infer capacity/queueing effects** from non-linear latency/error growth vs load (knee detection), concurrency saturation signals, and timeout/error patterns.
5. **Model failures conservatively** using observed status/error classes and saturation-linked probabilities; never assume zero failures outside observed regimes.

### 9.2 Scenario execution

- **Engine:** discrete-event simulation with configurable queue/service centers representing endpoint/step processing and shared bottleneck assumptions.
- **Uncertainty propagation:** Monte Carlo repetitions sampling uncertain parameters (service-time draws, fitted parameter ranges, arrival variability) to produce output distributions and confidence bands.
- **Scenarios (required):**
  - **Best case:** favorable but plausible assumptions (e.g., lower burstiness, stable dependency latency, modest growth).
  - **Likely case:** baseline-calibrated assumptions with expected growth/mix.
  - **Worst case:** adverse but plausible assumptions (e.g., higher burstiness, dependency slowdown, traffic skew to expensive endpoints), still within operator-declared/justified bounds.
- **Determinism:** all stochastic runs accept a seed; reports record seeds and iteration counts.

### 9.3 Confidence and uncertainty (how it is computed and reported)

Confidence is **not** a single accuracy promise. It is derived from multiple factors:

- **Data sufficiency:** number of runs, duration, sample density, presence of timeline/per-step detail, and verified vs unverified inputs.
- **Calibration fit:** holdout/residual errors on throughput, tail latency, and error rate.
- **Extrapolation distance:** how far scenario parameters move outside calibrated RPS/concurrency/mix regimes.
- **Model stability:** sensitivity/variance across Monte Carlo iterations and plausible parameter perturbations.

Reporting requirements:
- Present **intervals/bands** (e.g., p10–p90) and/or confidence intervals for key metrics, plus **probabilities** of threshold breach (e.g., "estimated 35–55% chance p95 > 300 ms in likely scenario").
- Attach a **confidence grade** (`high`/`medium`/`low`/`insufficient`) with reasons.
- Explicitly label results **"estimate, not measurement"** and **"not a guarantee"**.

### 9.4 Example uncertainty phrasing (acceptable)

> "In the *likely* scenario (1.8× peak RPS, calibrated on runs A/B), the model estimates p95 latency of 220–340 ms (p10–p90 across 500 seeded iterations) with a ~40% estimated probability of exceeding the 300 ms SLA. Confidence: **medium** (limited observations above 1.2k RPS). Validate with an authorized staged load test before committing capacity."

Unacceptable phrasing: "The system will be at 312 ms at minute 14 with 99% accuracy."

---

## 10. APIs, CLI, and Dashboard Integration Points

### 10.1 CLI (proposed, additive)

Integrate via `cmd/sift` subcommand dispatch (consistent with existing `run`, `replay`, `scan`, etc.):

- `sift simulate fit` — ingest artifacts, calibrate model, emit `model.json` + `calibration.md/json`.
- `sift simulate run` — execute one scenario against a model, emit simulation report artifacts.
- `sift simulate compare` — run/aggregate best-likely-worst (or named sets) into a comparison report.
- `sift simulate validate` — compare predicted vs observed for a held-out run (offline backtest).
- (Optional later) `sift simulate from-bundle --verify` — require attestation verification before using samples.

**CLI principles:** file-in/file-out, deterministic `--seed`, explicit `--report-dir/--out`, machine-readable JSON output option, and non-zero exit codes on invalid inputs / failed validation gates (analogous to SLA/regression gating semantics, but scoped to simulation).

### 10.2 Go/package APIs (proposed)

- `internal/sim` (or `pkg/sim` if later promoted): parsing, fitting, simulation, reporting.
- Potential reuse/adapters:
  - consume `internal/report.Report` structs/JSON,
  - consume replay types/summaries,
  - verify/load attestation via `internal/attest` (respecting caps),
  - optionally expose a library surface under `api/` later if stable (out of MVP unless demanded).

### 10.3 Dashboard integration (incremental)

- **MVP (read-focused):** new "Simulation" view/panel that loads simulation artifacts from a report/output directory or via a bounded API endpoint; renders scenario comparison charts, uncertainty bands, SLA-breach probabilities, and assumption/confidence summaries.
- **Phase 2:** form-driven scenario authoring and "run simulation" trigger backed by a server-side job (subject to existing dashboard auth/rate-limit/connection controls in `internal/dashboard`).
- **Non-goal for dashboard MVP:** direct mutation of production systems or execution of unauthorized tests. Dashboard remains a control/visualization plane consistent with current safety posture.

### 10.4 CI/CD integration

- Emit stable JSON artifacts for pipeline consumption.
- Optional policy gates (advisory by default): e.g., warn/fail if likely-scenario SLA-breach probability exceeds a threshold **given stated confidence**.
- Store model/simulation artifacts alongside existing reports for traceability.

---

## 11. MVP Scope

The MVP should deliver value without deep coupling to engine internals:

1. **Offline artifact ingestion:** parse one or more `sift run` report JSON files and (optionally) timeline CSV; basic replay summary/capture-mix input if readily available.
2. **Single-service/step aggregate twin:** closed-loop/open-loop approximation with per-step latency distributions and a simple capacity/queue saturation model.
3. **Scenario engine:** best/likely/worst + custom multipliers (RPS/users/mix/dependency latency/capacity), seeded Monte Carlo runs.
4. **Calibration & backtest (basic):** fit on N-1 runs and evaluate on 1 held-out run (or time-split) with error metrics and confidence grade.
5. **Reports:** `model.json`, `scenario-result.json`, and human-readable summary including assumptions, uncertainty bands, SLA-breach probabilities, and limitations.
6. **CLI commands:** `fit`, `run`, `compare` (minimal viable flags).
7. **Documentation and examples:** sample scenario files and interpretation guidance.

**MVP exclusions:** full dashboard authoring UI, distributed simulation workers, automatic infrastructure discovery, and attested simulation outputs (inputs may be supported read-only if low-risk).

---

## 12. Phased Roadmap

### Phase 0 — Design & prototyping (spike)
- Validate data sufficiency from real `report.json`/timeline artifacts.
- Prototype fitting/simulation on synthetic and recorded datasets; define schema v1.
- **Exit criteria:** reproducible prototype with backtest error reporting on sample runs.

### Phase 1 — MVP (offline CLI)
- Implement ingestion, model/calibration, scenario simulation, and report outputs.
- Add tests (unit + golden fixtures) and documentation.
- **Exit criteria:** users can generate best/likely/worst estimates with uncertainty and calibration diagnostics from local artifacts.

### Phase 2 — Replay & attestation-aware inputs
- Deeper replay capture/mix integration for trace-driven scenarios.
- Optional verified-input path using `internal/attest` (`sift verify` integration / library verification) and sample-aware fitting.
- **Exit criteria:** trace-driven simulations and verified-input labeling work within memory/time limits.

### Phase 3 — Dashboard and collaboration
- Read-only dashboard visualization/comparison of simulation artifacts; later controlled "run simulation" jobs.
- Export/shareable planning reports (Markdown/HTML/PDF via existing report pipelines if appropriate).
- **Exit criteria:** teams can compare scenarios in UI with consistent confidence/assumption display.

### Phase 4 — Advanced modeling (optional, evidence-gated)
- Multi-stage dependency/queue networks, richer failure models, and adaptive calibration suggestions.
- Optional policy gates in CI (advisory → enforceable with explicit config).
- **Exit criteria:** measurable improvement in backtest accuracy vs MVP on representative workloads, without overstating certainty.

---

## 13. Validation Methodology

### 13.1 Correctness and trustworthiness validation

- **Unit tests:** parsers, statistical/quantile estimators, queueing/simulation primitives, seed determinism, schema round-trips.
- **Golden/fixture tests:** known inputs produce stable summary outputs (within defined numeric tolerances).
- **Backtesting:** for datasets with ≥2 runs (or time splits), fit on subset and compare predictions to held-out observations (RPS, p50/p95/p99, error rate, saturation onset).
- **Calibration quality gates:** mark model `insufficient`/`low` confidence when fit errors exceed thresholds or data coverage is poor.

### 13.2 Operational validation

- **Performance:** simulation runtime/memory bounded by iteration count, horizon, and input size; document recommended defaults.
- **Robustness:** malformed/missing artifacts fail with actionable errors; no panics on untrusted files.
- **Reproducibility:** same model + scenario + seed => identical (or tolerance-bounded) results across platforms.

### 13.3 What "good" looks like

- Predictions are **directionally and quantitatively useful within calibrated ranges**, with honest error bars.
- The tool reliably warns when asked to extrapolate too far or when inputs are weak.
- Outputs are comparable against subsequent authorized `sift run`/`replay` results to close the loop.

---

## 14. Risks and Limitations

| Risk / limitation | Impact | Mitigation |
|---|---|---|
| **Overconfidence / false precision** | Bad capacity decisions | Mandatory uncertainty bands, confidence grades, extrapolation warnings; ban point-prediction claims without ranges. |
| **Insufficient or unrepresentative data** | Poor fit, misleading scenarios | Minimum data checks, `insufficient` confidence state, guidance to collect targeted authorized runs. |
| **Hidden variables (cache warmness, autoscaling, downstream limits, noisy neighbors)** | Model drift vs reality | Explicit assumptions, sensitivity analysis, "assumed" trust labels, encourage re-calibration. |
| **Closed/open-loop mismatch** | Throughput/latency errors | Model workload mode explicitly; detect paced/CO-corrected contexts from reports/config. |
| **Coordinated omission misinterpretation** | Underestimated tail latency | Honor CO-corrected vs raw measurements; surface `coCorrected`/measurement semantics in outputs. |
| **Replay capture fidelity limits** | Inaccurate mix/timing | Validate capture completeness; treat missing protocol/body details as uncertainty. |
| **Large sample sidecars / memory pressure** | Verifier/simulator instability | Reuse `internal/attest` streaming/cap concepts (`DefaultMaxSamples*`), allow downsampling/aggregation, document limits. |
| **Non-stationary systems** | Fast staleness of model | Timestamp/version models, recommend periodic recalibration, show calibration recency. |

**Fundamental limitation:** a simulation is only as good as its evidence and assumptions. Sift's Digital Twin estimates **risk and capacity envelopes**; it cannot guarantee real-world behavior.

---

## 15. Security, Privacy, and Authorization Considerations

### 15.1 Authorization and scope

- **Authorized use only.** The feature is for systems the operator owns or has explicit written permission to test/plan for, consistent with Sift's project-wide policy.
- **Defensive/capacity-planning focus.** No attack automation, exploit generation, credential abuse, or control/evasion features. Any generated load profiles/scenarios must map to Sift's existing authorized load mechanisms and safety controls (rate/budget/host gating where applicable).
- **Respect existing gates.** If future integrations trigger live runs, they must pass the same authorization/host-allowlist/audit mechanisms used by `run`/dashboard today (e.g., authz/audit hooks, `--allow-private` semantics as currently enforced).

### 15.2 Data handling and privacy

- Inputs may include URLs, hostnames, headers, payload fragments (captures), IPs, and performance traces.
- **Minimize and redact:** default to aggregate metrics; provide options to exclude/ redact query params, headers, bodies, and identifiers in exported artifacts.
- **Local-first by default:** store models/reports in user-specified report/output directories; do not transmit externally unless an operator explicitly configures an existing integration.
- **Access control:** when surfaced in the dashboard, enforce existing dashboard authentication/authorization controls and avoid exposing raw sensitive artifacts to unauthorized viewers.

### 15.3 Integrity and supply chain of evidence

- Prefer verified attestation bundles for high-stakes calibration; clearly label unverified inputs.
- Simulation outputs should include hashes/identifiers of inputs and model versions for auditability; optionally sign simulation bundles in a later phase (aligned with VPMP patterns) without claiming more trust than warranted.

### 15.4 Safe failure modes

- Fail closed on parse/verification errors for "verified" input paths.
- Cap resource consumption (input sizes, iterations, horizon) to prevent accidental self-DoS in CLI/dashboard jobs.
- Never emit recommendations phrased as guarantees; always include confidence/limitations.

---

## 16. Observability and Operational Concerns

- **Simulation run metadata:** duration, iteration count, seed(s), resource usage, and warnings in every report.
- **Explainability artifacts:** top sensitivity drivers, saturation indicators, and assumption echo for peer review.
- **Versioning:** schema versions for model/scenario/result; compatibility/migration notes as formats evolve.
- **Deterministic CI mode:** fixed seed and bounded iterations for stable pipeline checks.

---

## 17. Open Questions

1. **Canonical artifact ingestion:** should MVP depend only on `report.json` (+ timeline CSV) or also define a stable replay-summary JSON export?
2. **Per-endpoint modeling granularity:** how much endpoint identity can be recovered reliably from current reports vs captures without invasive instrumentation?
3. **Attested sample scale:** what aggregation/downsampling strategy best balances fidelity and the existing sample-load memory caps?
4. **Dashboard execution model:** background job queue/process model for in-UI simulations under current server constraints.
5. **Standard confidence vocabulary:** finalize numeric thresholds for `high/medium/low/insufficient` grades based on empirical backtests.
6. **Library/API exposure:** when (if ever) to promote `internal/sim` types into `api/` for external consumers.

---

## 18. Acceptance Criteria for This Design (for future implementation planning)

- A reader can understand **what** is being modeled, **from which Sift artifacts**, and **how uncertainty is produced and presented**.
- The proposal is implementable incrementally on Sift v0.15 without requiring speculative infrastructure.
- All forecasts are framed as **scenario-based estimates with confidence/limitations**, never as guaranteed precise predictions.
- Security/privacy/authorization and defensive-use boundaries are explicit and consistent with Sift's existing posture.

---

## 19. References (in-repo)

- `README.md` — product scope, capabilities, and authorized-use policy
- `docs/ROADMAP.md` — current limitations and planned directions
- `docs/ENTERPRISE.md` — enterprise planning context (non-certification)
- `docs/VPMP-RFC.md` — attestation protocol overview
- `internal/engine/*` — load execution, telemetry, coordinated omission, sampling hooks
- `internal/replay/*` — capture formats, pacing, replay execution
- `internal/report/*` — report model, SLA evaluation, rendering
- `internal/attest/*` — bundle/record/verification and sample sidecar handling
- `internal/dashboard/*` — live snapshots, history, attestation UI/API surfaces
- `cmd/sift/*` — CLI command structure and run/report/evidence flags
