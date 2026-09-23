# POWER FEATURES — step control flow, branching, burst & gRPC streaming

Advanced scenario features added by the backend team ("Qudratli Funksiyalar").
All features work through the existing `stress-strike run --config file.yaml`
path and the same normalized scenario model; no protocol client changes were
required.

---

## 1. Step control flow

Every step (http, ws, grpc, tcp, udp — and nested branch steps) accepts the
following control-flow fields:

| Field            | Type    | Default | Meaning                                                        |
|------------------|---------|---------|----------------------------------------------------------------|
| `think_time`     | float64 | 0       | Seconds to pause **after** the step (0.1 = 100ms)              |
| `on_error`       | string  | `stop`  | `continue` → next step runs; `stop` → abort this iteration     |
| `skip_on_error`  | bool    | false   | Skip **this** step when the *previous* step errored (iteration continues) |
| `retries`        | int     | 0       | Extra attempts when the step fails                             |
| `retry_backoff`  | float64 | 0.1     | Seconds between failed attempts                                |
| `stop_on_status` | string  | ""      | `2xx`/`4xx`/`5xx` or an exact code (`429`) → halt the whole run |

```yaml
steps:
  - name: login
    type: http
    url: /api/auth/login
    method: POST
    body: '{"email":"{{email}}","password":"{{pass}}"}'
    retries: 2               # transient failures are retried twice
    retry_backoff: 0.1       # 100ms between attempts
    on_error: continue       # a failed login doesn't kill the iteration
    stop_on_status: "429"    # origin rate-limited us → stop the entire run
    think_time: 0.2          # 200ms breather before the next step
```

Semantics, precisely:

- **`think_time`** — applied after the step settles (after retries are
  exhausted, after `on_error: continue`, and after an `if` branch completes).
  It is skipped when the step aborts the iteration (`on_error: stop`) or when a
  `stop_on_status` fires. Sleeps are context-aware: they end early when the run
  is canceled.
- **`on_error`** — `stop` preserves the legacy behavior (break the iteration at
  the first failure). `continue` records the error, keeps iterating, and lets a
  later successful step reset the error state.
- **`skip_on_error`** — checks the *previous* executed step. A skipped step
  leaves the error state untouched, so several consecutive `skip_on_error`
  steps are all skipped after one failure. The state clears on the first
  successful executed step. A skipped step is **not** recorded in `stepStats`
  (no request was made).
- **`retries`** — the step is attempted `1 + retries` times. Every attempt is
  recorded in the per-step stats (retried requests really hit the server), so
  request counts and error counts reflect real traffic. The **final** attempt
  drives iteration-level state: if it succeeds, the iteration is a success
  (`Overall` records the final status, no error). Retries apply to any failed
  attempt — transport errors and status errors alike — whenever `retries > 0`.
  `retry_backoff` falls back to 0.1s when unset (values ≤ 0 are treated as the
  default).
- **`stop_on_status`** — when a response status falls into the configured
  range, the **entire run** stops issuing new requests (every worker becomes a
  no-op). In-flight requests finish and are recorded normally. Note: the run
  window itself is owned by `Engine.Run` (see Integration notes below), so the
  run currently winds down when the configured duration elapses instead of
  cutting it short; the halt of *request generation* is immediate.

### Built-in per-step variables

After each executed step, three variables become available for conditions and
later steps (name = the step's `name`):

```
<name>_status      → "200"            (absent when no status, e.g. transport error)
<name>_error       → "" | "timeout" | "status_5xx" | ...  (always set)
<name>_latency_ms  → "12.34"
```

So a classic flow reads naturally: `condition: "${login_status} == 200"` or
`condition: "${login_error} == ''"`.

---

## 2. Conditional branching — `type: if`

```yaml
steps:
  - name: login
    type: http
    url: /login
    # ...
  - name: auth-flow
    type: if
    condition: "${login_status} == 200"     # or "${extracted_token} != ''"
    steps:
      - name: dashboard
        type: http
        url: /dashboard
```

- **`condition`** — a single comparison (no AND/OR by design; keep it simple
  and predictable):

| Operator   | Meaning                        | Example                        |
|------------|--------------------------------|--------------------------------|
| `==`       | equality (numeric-aware)       | `${status} == 200`             |
| `!=`       | inequality                     | `${token} != ''`               |
| `contains` | substring match                | `${host} contains "api-"`      |
| `=~`       | regular-expression match      | `${trace} =~ ^[0-9a-f]{32}$`   |

  The variable may be written `${var}`, `{{var}}` or bare. Expected values may
  be quoted with `"` or `'`.
- **`steps`** — one or more nested steps, recursively normalized (depth limit
  32) and executed in order when the condition is true. Nested steps support
  the full control-flow set (`think_time`, `on_error`, `skip_on_error`,
  `retries`, `stop_on_status`, nested `if`s).
- **Normalize** requires a parseable `condition` and at least one `steps`
  entry for `type: if`; anything else is a config error.
- Result aggregation: nested step results are recorded into the enclosing
  top-level step's stats slot (the `if` step's slot), keeping the report schema
  unchanged. A false condition skips the branch without clearing a pending
  previous-step error, so `skip_on_error` cascades naturally through skipped
  branches.

---

## 3. Burst profile

`--profile burst` (or `load_profile: type: burst` in YAML) is a short,
maximum-speed volley:

```
type: burst        # normalized to steady + ramp_up: 0
duration: 3        # default; override with --duration / duration:
```

- Every virtual user starts at t=0 (zero ramp-up).
- No RPS limiter is installed (`rps: 0`), so each user loops as fast as the
  server allows for the whole window — unlike `gate`, which fires a single
  one-shot volley.
- Default window: **3 seconds**.

```sh
stress-strike run --url https://api.example.com --profile burst --users 500
```

The transform happens in `config.Profile.Normalize`: `burst` degrades to
`steady` + `ramp_up: 0` before the engine ever sees it, so no engine changes
were needed (see Integration notes).

---

## 4. HTTP/2 control

`load_profile.http2` (bool, **default enabled**) and the `--no-http2` CLI flag
opt out of HTTP/2 negotiation:

```yaml
load_profile:
  type: steady
  users: 100
  duration: 60
  http2: false       # force HTTP/1.1
```

```sh
stress-strike run --url https://api.example.com --users 100 --no-http2
```

- `Http2` is stored as `*bool` on the profile: absent → enabled (Go's transport
  already sets `ForceAttemptHTTP2: true`); explicit `false`/`--no-http2` →
  disabled. `Profile.HTTP2Enabled()` is the accessor.
- ⚠️ **Wiring pending**: the flag currently stops at the profile because the
  transport construction in `internal/engine/client.go` (`baseTransport` /
  `newTransport`) is owned by another team. Integration point: after
  `newTransport`, set `tr.ForceAttemptHTTP2 = false` when
  `scenario.Profile.HTTP2Enabled()` is false. Note TLS-fingerprint mode already
  forces HTTP/1.1 internally.

---

## 5. gRPC client-streaming

New step form (`grpc_stream: true` on a grpc step, or the `grpc-stream` alias):

```yaml
steps:
  - name: ingest
    type: grpc-stream                     # alias: type grpc + grpc_stream true
    grpc_method: /ingest.Service/IngestEvents
    headers:
      authorization: "Bearer {{token}}"
    body: |
      {"event":"click","item":"{{item}}"}
      {"event":"purchase","item":"{{item}}"}
    extract:
      - name: ack
        from: json
        path: ack_id
    assertions:
      - type: status
        value: "200"
    retries: 1
    think_time: 0.05
```

- Each non-empty line of the rendered `body` is sent via `SendMsg`; the stream
  is half-closed with `CloseSend`, then one reply is read via `RecvMsg` (raw
  payload, so json/regex assertions and `extract` work against it). An empty
  body sends one empty message to keep the RPC well-formed.
- Headers become outgoing gRPC metadata. The pooled connection from
  `sharedGRPCConn` is reused across users.
- Error mapping follows the unary gRPC client: deadline → `timeout`,
  `Unavailable` → `connection_error`, 4xx-class codes → `status_4xx`,
  5xx-class codes → `status_5xx`.
- Normalize validation: `grpc_stream: true` requires `grpc_method`
  (`/package.Service/Method`), and `grpc_stream` on a non-grpc step is an error.
- ⚠️ Streaming dispatch lives in `stepflow.go` (a new `grpc-stream` branch), so
  the existing `runStepForUser` switch in `engine.go` was **not** modified.
  Library callers using `Engine.runStep` directly with a streaming step are not
  covered (see Integration notes).

---

## Examples

- `examples/branching-flow.yaml` — login → conditional dashboard → checkout →
  logout, with think time, retries, `on_error`, `skip_on_error` and
  `stop_on_status: "429"`.
- `examples/streaming.yaml` — client-streaming gRPC ingest with extraction,
  assertions and a follow-up HTTP verification step.

---

## Integration notes (for the teams owning the other files)

These are deliberate, documented seams where the feature stops because of file
ownership; they can be wired up next:

1. **`stop_on_status` early-run termination** — `runIteration` (stepflow.go)
   halts all new request generation via a per-engine stop flag
   (`stopFlags` registry in `stepflow.go`, keyed by `*Engine`, since the Engine
   struct may not be touched). The run **window** itself lives in
   `Engine.Run` (`runCtx`/`runCancel`); to end the run early, `Run` should also
   watch the stop flag (e.g. select on a wrapped context or poll
   `e.stopFlag().armed()`) and cancel `runCtx`. Until then the run winds down
   at the configured duration.
2. **`--no-http2` transport wiring** — profile carries `Http2 *bool` +
   `HTTP2Enabled()`; `newTransport`/`baseTransport` in `client.go` should honor
   it (`tr.ForceAttemptHTTP2 = profile.HTTP2Enabled()` after construction).
3. **gRPC streaming via library API** — `stepflow.go` dispatches
   `grpc-stream` steps; `runStepForUser`'s switch was left untouched to avoid
   conflicts. If direct `runStep` callers need streaming, dispatch there too.
4. **No `profile.go` changes** — `burst` is handled entirely in
   `config.Profile.Normalize` (degrades to steady + ramp_up 0). `buildProfile`
   never sees the `burst` type, so the engine team has nothing to do.