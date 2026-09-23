#!/usr/bin/env bash
#
# bootstrap-worker.sh — install + enable a stress-strike worker on ONE fresh
# Linux host (Ubuntu/Debian). Idempotent: safe to re-run.
#
# Run THIS script ON THE SERVER (as root or via sudo). The companion
# scripts/deploy-fleet.sh runs it over SSH for a whole fleet at once.
#
# Usage (as root):
#   ./bootstrap-worker.sh stress-strike-worker-v0.12.0-linux-amd64.tar.gz [HOST_ID]
#
# Configuration comes from the environment (defaults in brackets):
#   SS_ID          worker id                [auto]
#   SS_LISTEN      gRPC listen address      [0.0.0.0:50061]
#   SS_ADVERTISE   address announced to master (defaults to SS_LISTEN)
#   SS_MASTER      master to self-register with (empty => static fleet)
#   SS_TOKEN       shared control-plane token ("" disables auth)
#   SS_MAX_USERS   max virtual users        [200000]
#   SS_MAX_RUNS    max concurrent runs      [4]
#
# It adds an unprivileged `stress-strike` system user, installs the binary to
# /usr/local/bin, writes /etc/stress-strike/worker.env and starts the systemd
# unit. Firewall note: the worker's gRPC port (default 50061) must be reachable
# from the master; adjust ufw/cloud security groups accordingly.

set -euo pipefail

# Logging helpers — use common.sh when present (deploy-fleet uploads it next
# to this file), otherwise fall back to the repo copy or plain echo.
if [[ -f "$(dirname "$0")/common.sh" ]]; then
  source "$(dirname "$0")/common.sh"
elif [[ -f /opt/stress-strike/common.sh ]]; then
  source /opt/stress-strike/common.sh
else
  log_step() { echo "==> $*"; }
  log_ok()   { echo "    OK: $*"; }
  log_warn() { echo "    warning: $*"; }
  log_err()  { echo "    error: $*" >&2; }
fi

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <worker.tar.gz> [HOST_ID]" >&2
  exit 2
fi

TARBALL="$1"
HOST_ID="${2:-}"
SS_LISTEN="${SS_LISTEN:-0.0.0.0:50061}"
SS_ADVERTISE="${SS_ADVERTISE:-$SS_LISTEN}"
SS_MAX_USERS="${SS_MAX_USERS:-200000}"
SS_MAX_RUNS="${SS_MAX_RUNS:-4}"

if [[ ! -f "$TARBALL" ]]; then
  echo "error: tarball not found: $TARBALL" >&2
  exit 1
fi

log_step "bootstrapping worker on $(hostname)"

# 1. System user (idempotent)
if ! id -u stress-strike >/dev/null 2>&1; then
  groupadd --system stress-strike
  useradd --system --gid stress-strike --no-create-home --shell /usr/sbin/nologin stress-strike
  log_ok "created system user/group: stress-strike"
fi

# 2. Binary
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
tar -xzf "$TARBALL" -C "$WORK_DIR"
BIN_SRC="$(find "$WORK_DIR" -name stress-strike-worker -type f | head -n1)"
install -m 0755 "$BIN_SRC" /usr/local/bin/stress-strike-worker
log_ok "installed /usr/local/bin/stress-strike-worker"

# 3. worker.env
SS_ID="${SS_ID:-worker-$(hostname -s)}"
mkdir -p /etc/stress-strike
ARGS="-listen ${SS_LISTEN} -id ${SS_ID} -max-users ${SS_MAX_USERS} -max-runs ${SS_MAX_RUNS}"
if [[ -n "$SS_ADVERTISE" && "$SS_ADVERTISE" != "$SS_LISTEN" ]]; then
  ARGS="${ARGS} -advertise ${SS_ADVERTISE}"
fi
if [[ -n "$SS_MASTER" ]]; then
  ARGS="${ARGS} -master ${SS_MASTER}"
fi

cat > /etc/stress-strike/worker.env <<EOF
WORKER_ARGS=${ARGS}
EOF
if [[ -n "$SS_TOKEN" ]]; then
  echo "TOKEN=${SS_TOKEN}" >> /etc/stress-strike/worker.env
fi
chmod 600 /etc/stress-strike/worker.env
chown root:stress-strike /etc/stress-strike/worker.env
log_ok "wrote /etc/stress-strike/worker.env"

# 4. systemd unit (installed next to the binary by the packaging scripts, or
#    fall back to the repo copy if present)
UNIT=/etc/systemd/system/stress-strike-worker.service
if [[ ! -f "$UNIT" ]]; then
  LOCAL_UNIT="$(find "$WORK_DIR" -name stress-strike-worker.service -type f | head -n1)"
  if [[ -n "$LOCAL_UNIT" ]]; then
    install -m 0644 "$LOCAL_UNIT" "$UNIT"
  else
    echo "error: no systemd unit found in tarball" >&2
    exit 1
  fi
fi

systemctl daemon-reload
systemctl enable --now stress-strike-worker.service
systemctl restart stress-strike-worker.service
log_ok "enabled + started stress-strike-worker.service"

echo
echo; log_ok "done. worker status:"
systemctl --no-pager --lines=5 status stress-strike-worker.service || true
echo
echo "advertised as: ${SS_ADVERTISE}"
[[ -n "$SS_MASTER" ]] && echo "self-registers with master: ${SS_MASTER}"
echo "open firewall for inbound TCP to: ${SS_LISTEN}"