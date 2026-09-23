# Distributed Load Testing

stress-strike can spread a single scenario across many machines so the
generated load is not limited by one host's CPU, sockets or network link. One
**master** coordinates a fleet of **workers**; each worker runs a slice of the
virtual users and streams live telemetry back.

```
            +-------------------+          +-------------------+
            |  stress-strike-   |  gRPC    |  stress-strike-   |
            |  worker (Linux 1) |<-------->|  worker (Linux 2) |
            +-------------------+          +-------------------+
                       ^                             ^
                       |        gRPC / control      |
                       +-------------+---------------+
                                     |
                          +----------------------+
                          |  stress-strike-      |
                          |  master (control)    |
                          +----------------------+
```

## Why it matters

- **More load** — N hosts × their socket limits, not one laptop.
- **Realistic sources** — workers on real Linux distributions generate traffic
  with Linux TCP stacks, ephemeral-port ranges and (when configured) Linux HTTP
  fingerprints.
- **Live visibility** — the master aggregates per-worker telemetry every 200 ms
  and prints an updating status line.
- **Fault tolerant** — if a worker dies mid-run, the master notices instantly,
  keeps the surviving workers running and reports partial results.

## Quick start

### 1. Build the Linux worker packages

```bash
./scripts/build-worker-linux.sh 0.13.0
# -> dist/linux-worker/stress-strike-worker-v0.13.0-linux-amd64.tar.gz
#    dist/linux-worker/stress-strike-worker-v0.13.0-linux-arm64.tar.gz
```

Each archive contains `stress-strike-worker`, `stress-strike-master`, the
systemd unit and `worker.env.example`.

### 2. Install on each load host

```bash
tar -xzf stress-strike-worker-v0.13.0-linux-amd64.tar.gz
sudo install -m 0755 stress-strike-worker-v0.13.0-linux-amd64/stress-strike-worker /usr/local/bin/
sudo install -m 0644 stress-strike-worker-v0.13.0-linux-amd64/stress-strike-worker.service /etc/systemd/system/
sudo mkdir -p /etc/stress-strike
sudo cp stress-strike-worker-v0.13.0-linux-amd64/worker.env.example /etc/stress-strike/worker.env
sudo editor /etc/stress-strike/worker.env      # set WORKER_ARGS
sudo groupadd --system stress-strike
sudo useradd  --system --gid stress-strike --no-create-home stress-strike
sudo systemctl daemon-reload
sudo systemctl enable --now stress-strike-worker
```

### 3. Run a distributed test

**Static fleet** (the master is told the worker addresses):

```bash
stress-strike-master \
  -listen :50051 \
  -workers "10.0.0.11:50061,10.0.0.12:50061,10.0.0.13:50061" \
  -url https://target.example.com \
  -users 30000 -duration 120 -profile steady
```

**Auto-discovery** (workers register themselves):

```bash
# control host
stress-strike-master -listen :50051 -wait-workers 3 \
  -url https://target.example.com -users 30000 -duration 120

# each worker: add -master <control-host>:50051 (see worker.env)
stress-strike-worker -listen 0.0.0.0:50061 -id w1 \
  -master control.example.com:50051 -advertise 10.0.0.11:50061
```

## How the workload is split

Every load-shaping field is divided across the fleet — not just `users` — so
ramp, spike and constant-RPS profiles keep their shape:

| Field        | Split across workers        |
|--------------|-----------------------------|
| `users`      | yes (remainder distributed) |
| `spike_users`| yes                         |
| `rps` / `target_rps` | yes                 |
| `duration`, `ramp_up`, `spike_warmup`, `spike_hold`, `wave_period` | shared (each worker keeps the same timing) |
| `steps`, `variables`, `sla` | shared verbatim  |

Shares always sum back to the requested total (the first `total % workers`
workers get one extra user).

## Live telemetry and aggregation

Each worker polls its running engine every 200 ms and sends a cumulative
`TelemetrySnapshot` (requests, errors, status codes, error names, latency
percentiles and per-step breakdowns). Because snapshots are cumulative, the
master keeps only the **latest** snapshot per worker and sums those — summing
every tick would double-count.

The master prints:

```
workers=3 req=1.2M err=4.3K (0.36%) rps=24.1K p95=48ms
```

For latency, percentiles take the **worst** worker (a conservative bound) and
averages are request-weighted. This avoids shipping raw histograms over the
wire while staying meaningful.

## Fault tolerance

- **Run deadline** — `-run-timeout SECONDS` (default: `duration + 60`). When it
  elapses the master finalizes with whatever results it has.
- **Dead workers** — a closed stream, a `RunFailed` event, or a worker that
  goes silent marks it as failed; the run does not hang waiting for it.
  Failures are listed at the end.
- **Liveness monitoring** — every worker streams a `StatusReport` heartbeat
  every 2 s. If the master receives nothing from a worker for 30 s it probes
  the worker with `Ping`; a worker that fails the probe is declared dead,
  its telemetry is dropped from the live aggregate and the run continues with
  the survivors. A worker that answers the probe is kept.
- **Partial reports** — results from surviving workers are still merged and
  written to `reports/`.
- **Graceful stop** — `Ctrl-C` sends a stop command and waits up to 15 s.

## Fleet health monitoring

There is no master-side "list my workers" RPC yet, so `scripts/fleet-status.sh`
probes each worker directly with the same gRPC `Ping`/`GetCapabilities` calls
the master uses during `Connect`:

```bash
./scripts/fleet-status.sh --master 10.0.0.5:50051 \
  --workers srv1:10.0.0.11:50061,srv2:10.0.0.12:50061
```

It prints one line per worker (address, worker id, version, reachability).
Full gRPC answers need `grpcurl`
(`brew install grpcurl`); without it the script falls back to TCP
reachability checks. Exit status is 0 only when every probe succeeds — hook it
into cron/nagios/healthchecks.io for fleet-level alerting:

```bash
*/5 * * * * /opt/stress-strike/scripts/fleet-status.sh --workers srv1:10.0.0.11:50061,srv2:10.0.0.12:50061 >/dev/null || echo "fleet DEGRADED"
```

## Scaling to 100+ workers

### Right-sizing the fleet

A worker's practical ceiling is set by its CPU (the engine is Go, so it scales
with cores), its ephemeral-port range and the target's patience. Measure one
worker against your target first (see *Benchmark methodology* below), then:

```
requested RPS
workers = ───────────────────────────  (+10–20% headroom)
           RPS per worker @ target p95
```

So a 200 000 RPS campaign against an API that sustains ~2 400 RPS per worker
on your box type needs `200000 / 2400 ≈ 84` workers → deploy ~95. Each worker
must be able to open ~`users_per_worker` sockets; spread the virtual users
evenly (the master's splitter divides `users`, `spike_users`, `rps` and
`target_rps` across the fleet so shares always sum back to the total).

### Per-host OS tuning (put this on every load box)

```bash
# /etc/sysctl.d/99-stress-strike.conf
net.core.somaxconn = 65535          # accept queue for the target conns
net.ipv4.ip_local_port_range = 1024 65535   # ephemeral source ports
net.ipv4.tcp_tw_reuse = 1           # recycle TIME_WAIT quickly
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
fs.file-max = 2000000               # host-wide fd ceiling
fs.nr_open = 2000000                # per-process fd ceiling (must be >=)
```

plus `ulimit -n 1048576` (the shipped systemd unit already sets
`LimitNOFILE=1048576`). Verify with `ulimit -n` and
`ss -s | head -1` before a big run. The worker's own gRPC port only needs one
listener — the *target* connections are the ones that consume ports.

### Master advice for big fleets

- Run the master on its **own box** (or a small VM) — it only aggregates
  telemetry, but at 100 workers × 5 events/s the gRPC streams and the
  per-second snapshot cost real CPU.
- Raise the same fd limits on the master: it holds one stream per worker plus
  dialed connections.
- Keep `-wait-timeout` ≥ 60 s when auto-discovering large fleets so slow boxes
  finish booting and registering.
- `-token` is mandatory for any fleet outside a private, trusted network; see
  the TLS section for encrypting the control plane itself.
- Deploy in waves: `./scripts/deploy-fleet.sh --parallel 10 --hosts
  batch1-10` — the deploy script parallels SSH with `xargs -P` and retries
  each host, so a few flaky boxes do not block the rollout.

### Failure scenarios at scale

- **A worker dies mid-run** — its stream closes (or the 30 s liveness probe
  catches a silent hang). The master marks it failed, drops its telemetry from
  the live aggregate, and the surviving workers keep generating load. The final
  report contains partial results from the survivors and the worker is listed
  in the `WARNING: N worker(s) failed or disconnected` line. The run is NOT
  restarted — the load is simply smaller than requested. For repeatable
  campaigns, rerun the whole run at a quieter hour.
- **The master dies mid-run** — workers notice when their progress
  `send()` fails and cancel their local engine, so the fleet stops generating
  load. Any results already streamed are lost. Run-to-completion with local
  result spooling is a planned enhancement; for now treat the master as
  stateful-single-node and restart it for a new run.
- **A worker restarts mid-run** — its re-registration replaces the old entry
  (same `WorkerId`), but the in-flight run stream is gone: the master counts
  it as failed for that run. Next run picks it up normally. Stale registrations
  (no re-register within 35 s) are pruned so auto-discovery never waits on a
  dead box.
- **Master restarts before a run** — workers re-register automatically with
  backoff (1 s, 2 s, 5 s … 30 s), so `-wait-workers N` finds the fleet again
  without restarting the workers.

### Benchmark methodology (2 workers, Telegram-scale probe)

A quick capacity probe of "how much load can 2 workers push" before committing
to 100 boxes:

1. **Identify the target metric.** For a Telegram-style API you usually care
   about *messages/sec* (one step) and p95 latency under load, not raw RPS.

2. **Calibrate one worker locally.** Run a short steady probe and read RPS +
   p95 from the report:
   ```bash
   stress-strike-master -workers "w1:50061" -url https://api.example.com/msg \
     -users 2000 -duration 60 -profile steady
   ```
   Record RPS and check p95 stays under your SLA (e.g. 300 ms). Ramp `-users`
   until p95 breaks your SLA — that's this target's per-worker ceiling.

3. **Double it with 2 workers.** Same run with `-workers "w1:50061,w2:50061"`,
   `-users 4000`. The master splits users 2000/2000 and sums the telemetry;
   expect ~2× RPS and similar p95. If p95 degrades, the bottleneck is the
   target, not the fleet — verify by watching the target's CPU/bandwidth.

4. **Sanity-check the aggregate.** `workers=2 req=… rps=… p95=…` in the live
   line, then the final report: requests ≈ 2 × single-worker requests, errors
   ~0, status histogram plausible (e.g. 200s).

5. **Extrapolate.** `workers = desired_RPS / (2-worker_RPS / 2)`, add 20 %
   headroom, deploy with `deploy-fleet.sh --parallel`, and re-run the same
   methodology on 10, then 50, then N workers — the extrapolation holds as long
   as p95 stays flat and the target does not saturate.

## Session migration (planned)

The control-plane proto defines `MigrateSession` (move a session from one
worker to another, e.g. for draining a box mid-run) and workers log the
command, but session transfer is **not implemented yet** — the engine keeps
sessions pinned to the worker that started them. Treat the field as reserved;
no code depends on it. Draining a worker today means finishing/stopping the
run and starting a new one without the drained box.

## Control-plane security

Pass the same `-token` to the master and every worker. The token is attached to
gRPC metadata as `authorization: Bearer <token>` and validated with a
constant-time comparison on every unary and streaming call. An empty token
disables authentication (use only on trusted networks). This is a shared-secret
control plane; for untrusted networks also terminate gRPC over TLS.

### TLS (control-plane encryption)

By default the control plane is plaintext. When the fleet crosses untrusted
networks, enable TLS on both directions — every member acts as server (accepts
control traffic) and client (master dials workers, workers register with the
master):

```bash
# per host: generate a cert (one shared CA for the fleet is easiest)
# master
stress-strike-master -listen 0.0.0.0:50051 -tls-cert master.crt -tls-key master.key \
    -tls-ca fleet-ca.crt -wait-workers 100 ...
# each worker
stress-strike-worker -listen 0.0.0.0:50061 -id w1 \
    -master master:50051 -tls-cert w1.crt -tls-key w1.key \
    -tls-ca fleet-ca.crt ...
```

- `-tls-cert` + `-tls-key` enable TLS on the **serving** side.
- `-tls-ca FILE` makes outgoing dials verify the peer against your CA.
- `-tls-skip-verify` disables verification for self-signed demo fleets —
  never mix it with real credentials on a public network.
- A TLS client dialing a plaintext peer (or the reverse) fails fast with a
  handshake error; keep the whole fleet on the same setting.
- No client certificates are required: the `-token` shared secret is still the
  identity boundary, TLS just adds wire encryption + endpoint authentication.
- Alternative deployment: keep the control plane on a private/VPN network and
  skip TLS entirely (plaintext is fine inside WireGuard/ZeroTier).

## CLI reference

### `stress-strike-master`

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:50051` | Master gRPC listen address |
| `-workers` | | Comma-separated static worker addresses |
| `-wait-workers` | `0` | Wait for N self-registering workers |
| `-wait-timeout` | `30` | Auto-discovery timeout (seconds) |
| `-token` | | Shared control-plane token |
| `-run-timeout` | `0` | Run deadline in seconds (0 = duration + 60) |
| `-config` / `-url` | | Scenario file or quick target URL |
| `-users`, `-duration`, `-profile`, `-name` | | Quick scenario |
| `-expect-p99-ms`, `-expect-error-rate`, `-expect-min-rps` | `0` | SLA gates |
| `-compare`, `-regress-pct` | | Regression comparison |
| `-timeline`, `-quiet` | `false` | CSV timeline / suppress progress |
| `-tls-fingerprint` | | TLS ClientHello every worker presents (chrome, firefox, ios, ...). Propagated to workers in the scenario wire payload. |
| `-tls-cert` / `-tls-key` | | Serve the master's gRPC endpoint over TLS |
| `-tls-ca` | | CA bundle for verifying workers the master dials |
| `-tls-skip-verify` | `false` | Skip peer verification when dialing workers (self-signed demos) |

### `stress-strike-worker`

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:0` | Worker gRPC listen address |
| `-advertise` | listen addr | Address told to the master |
| `-master` | | Master to self-register with |
| `-id` | hostname-pid | Worker ID |
| `-max-users` | `100000` | Reject runs above this user count |
| `-max-runs` | `4` | Max concurrent runs |
| `-token` | | Shared control-plane token |
| `-tls-cert` / `-tls-key` | | Serve the worker's gRPC endpoint over TLS |
| `-tls-ca` | | CA bundle for verifying the master on registration dials |
| `-tls-skip-verify` | `false` | Skip master verification when self-registering (self-signed demos) |

## Docker

```bash
docker build -f Dockerfile.worker -t stress-strike-worker:0.13.0 .
docker network create strike
docker run -d --name master --network strike -p 50051:50051 \
  stress-strike-master...            # or run the master on a host
docker run -d --name worker-1 --network strike \
  --ulimit nofile=1048576:1048576 \
  stress-strike-worker:0.13.0 \
  -listen 0.0.0.0:50061 -advertise worker-1:50061 \
  -master master:50051 -id worker-1
```

## Tuning the load hosts

High concurrency needs OS limits raised, not just worker flags:

```bash
# /etc/sysctl.d/99-stress-strike.conf
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
fs.file-max = 2000000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
```

```bash
ulimit -n 1048576        # or the systemd LimitNOFILE above
sysctl --system
```

## Tests

The control plane is covered by unit and in-process integration tests
(`internal/dist/coordinator`): fleet aggregation, all-profile splitting, report
merging, SLA recomputation, token enforcement, auto-discovery, live streaming
across two workers, and a dead-worker scenario. Run them with:

```bash
go test ./internal/dist/coordinator/
```
