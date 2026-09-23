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
./scripts/build-worker-linux.sh 0.12.0
# -> dist/linux-worker/stress-strike-worker-v0.12.0-linux-amd64.tar.gz
#    dist/linux-worker/stress-strike-worker-v0.12.0-linux-arm64.tar.gz
```

Each archive contains `stress-strike-worker`, `stress-strike-master`, the
systemd unit and `worker.env.example`.

### 2. Install on each load host

```bash
tar -xzf stress-strike-worker-v0.12.0-linux-amd64.tar.gz
sudo install -m 0755 stress-strike-worker-v0.12.0-linux-amd64/stress-strike-worker /usr/local/bin/
sudo install -m 0644 stress-strike-worker-v0.12.0-linux-amd64/stress-strike-worker.service /etc/systemd/system/
sudo mkdir -p /etc/stress-strike
sudo cp stress-strike-worker-v0.12.0-linux-amd64/worker.env.example /etc/stress-strike/worker.env
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
- **Dead workers** — a closed stream or a `RunFailed` event marks the worker as
  failed; the run does not hang waiting for it. Failures are listed at the end.
- **Partial reports** — results from surviving workers are still merged and
  written to `reports/`.
- **Graceful stop** — `Ctrl-C` sends a stop command and waits up to 15 s.

## Control-plane security

Pass the same `-token` to the master and every worker. The token is attached to
gRPC metadata as `authorization: Bearer <token>` and validated with a
constant-time comparison on every unary and streaming call. An empty token
disables authentication (use only on trusted networks). This is a shared-secret
control plane; for untrusted networks also terminate gRPC over TLS.

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

## Docker

```bash
docker build -f Dockerfile.worker -t stress-strike-worker:0.12.0 .
docker network create strike
docker run -d --name master --network strike -p 50051:50051 \
  stress-strike-master...            # or run the master on a host
docker run -d --name worker-1 --network strike \
  --ulimit nofile=1048576:1048576 \
  stress-strike-worker:0.12.0 \
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
