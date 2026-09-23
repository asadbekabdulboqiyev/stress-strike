# Deploying to real Linux hosts (VPS fleet)

This guide covers putting stress-strike's load generators on actual Linux
boxes — the state where an off-host, multi-server demo becomes possible. Two
supported paths:

1. **systemd fleet over SSH** (recommended for VPS) — see
   [`deploy/fleet/bootstrap-worker.sh`] and [`scripts/deploy-fleet.sh`].
2. **Docker compose on one host** — see [`deploy/docker-compose.yml`].

Both ship the same binaries already proven in local end-to-end tests, but they
have never been run against a live outside host yet, so verify on your first
box before scaling out.

---

## Quick start for ordinary users

Run the friendly launcher — it checks what you have installed and walks you
through the rest:

```sh
./scripts/deploy.sh            # choose: 1) Docker   2) VPS fleet (SSH)
```

### Path 1 — Docker (no Linux server needed)
```sh
make deploy-docker            # = scripts/deploy-docker.sh
# answer 3-4 questions, then it builds and starts master + N workers
make docker-down              # stop the fleet
# advanced: ./scripts/deploy-docker.sh logs
```

### Path 2 — VPS / home server over SSH
Prereq: an SSH key already authorized (one-time): `ssh-copy-id root@HOST`.
```sh
make deploy-fleet             # = scripts/deploy-fleet.sh
# paste one 'user@host' per line, pick auto-discovery or static mode,
# optionally set a token — then every host is installed in ~30 seconds
```
`make deploy-fleet -y --master ...` and the flags in the section below stay
available for scripting.

---

## 1. systemd fleet over SSH

### Prereqs (dev machine)
- Go toolchain (to build the Linux worker packages).
- SSH key authorized on every target: `ssh-copy-id root@HOST` (or a
  passwordless-sudo user).
- Target hosts: fresh Ubuntu/Debian with systemd. One runnable load box is
  enough for a demo; a fleet is just N of them.

### Build the packages once (optional — deploy-fleet does it automatically)
```bash
./scripts/build-worker-linux.sh 0.12.0
# -> dist/linux-worker/stress-strike-worker-v0.12.0-linux-amd64.tar.gz
```

### Deploy one host (manual)
```bash
scp dist/linux-worker/stress-strike-worker-v0.12.0-linux-amd64.tar.gz \
    deploy/fleet/bootstrap-worker.sh root@HOST:/tmp/
ssh root@HOST 'cd /tmp && bash bootstrap-worker.sh stress-strike-worker-v0.12.0-linux-amd64.tar.gz \
    SS_MASTER=10.0.0.5:50051 SS_TOKEN=secret'
```
Environment knobs of the bootstrap: `SS_ID`, `SS_LISTEN` (default
`0.0.0.0:50061`), `SS_ADVERTISE`, `SS_MASTER`, `SS_TOKEN`, `SS_MAX_USERS`,
`SS_MAX_RUNS`. The bootstrap installs an unprivileged `stress-strike` user,
writes `/etc/stress-strike/worker.env`, and enables a hardened systemd unit.

### Deploy a fleet at once
```bash
# static mode (master connects to a fixed list)
./scripts/deploy-fleet.sh --static --token secret -- root@10.0.0.11 root@10.0.0.12

# auto-discovery (workers register with your master)
./scripts/deploy-fleet.sh --master 10.0.0.5:50051 --token secret -- srv1 root@10.0.0.12
```
The script prints the exact master command for your control box.

### Firewall / security groups
- Open the worker gRPC port (`50061` default) from the master's IP.
- Open the master gRPC port (`50051` diagonal) from anything that must start
  runs, or run the master on your own control box and keep 50051 closed to the
  internet.
- Always use `-token` (constant-time compared on every RPC).

### Smoke test (before loading real targets)
```bash
# on the control box, with an HTTPS target (TLDs enforce TLS these days)
stress-strike-master -listen 0.0.0.0:50051 \
  -wait-workers 1 -wait-timeout 30 \
  -url https://example.com -users 8 -duration 6 \
  -token secret -tls-fingerprint chrome
```
Expect `Requests:` with 0 errors. A `-tls-fingerprint chrome` run that returns
lots of `request failed` errors usually means TLS fingerprinting hit a WAF —
try `firefox`/`ios`, or check with `-quiet -timeline`.

---

## 2. Docker compose (single host)

```bash
docker compose -f deploy/docker-compose.yml build
docker compose -f deploy/docker-compose.yml up -d
```
The master starts one run automatically against
`${STRESS_STRIKE_URL:-http://example.com}` with 2 workers. Override the URL,
token, and extra master args via environment:
```bash
STRESS_STRIKE_URL=https://target.example.com STRESS_STRIKE_TOKEN=secret \
STRESS_STRIKE_ARGS="-tls-fingerprint firefox -duration 120" \
docker compose -f deploy/docker-compose.yml up
```
Tune `users`/`duration` inside `deploy/docker-compose.yml`. For very high
connection counts use `network_mode: host` on the workers (bridge NAT
throttles ephemeral sockets).

Note: both Dockerfiles tag `0.12.0` by default. The compose setup builds from
source, so it always reflects the current checkout.

---

## Verification checklist

- [ ] `systemctl status stress-strike-worker` shows `active (running)`
- [ ] `ss -lntp | grep 50061` (worker) listens
- [ ] Master connects (static `-workers` list) or registers (auto-discovery,
      log line `worker registered: ... (1 total)`)
- [ ] A 6s smoke run against `https://example.com` returns 0 errors
- [ ] With `-tls-fingerprint chrome` the same run stays at 0 errors
- [ ] `-token` mismatch is rejected (try a wrong token deliberately)
- [ ] `journalctl -u stress-strike-worker -e` has no TLS/fingerprint panics