#!/usr/bin/env bash
#
# deploy-fleet.sh — put stress-strike workers onto real Linux hosts over SSH.
# Friendly by default: run it with NO arguments and answer a few questions.
# Advanced flags stay available for scripts/automation.
#
# Usage:
#   ./scripts/deploy-fleet.sh                            # interactive wizard
#   ./scripts/deploy-fleet.sh --master 10.0.0.5:50051 --token secret -- user@host...
#   ./scripts/deploy-fleet.sh --static --token secret -- user@host...
#   ./scripts/deploy-fleet.sh --tarball dist/.../stress-strike-worker-v0.12.0-linux-amd64.tar.gz -- user@host
#   ./scripts/deploy-fleet.sh -y --master M:50051 -- host1 host2
#
# Options:
#   -y, --yes          accept defaults (no interactive prompts)
#   --master ADDR      auto-discovery: workers self-register with this master
#   --token SECRET     shared control-plane token
#   --static           static mode: print a -workers list instead of registering
#   --tarball PATH     use a prebuilt linux worker tarball (skip the Go build)
#   --                everything after -- is "user@host [user@host ...]"
#
# Requires ssh keys authorized on each target (ssh-copy-id). Target hosts
# need root (or a passwordless-sudo user) and systemd.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=deploy/fleet/common.sh
source "${REPO_ROOT}/deploy/fleet/common.sh"

VERSION="${VERSION:-0.12.0}"
ASSUME_YES=0
MASTER_ADDR=""
TOKEN=""
STATIC=0
TARBALL=""
HOSTS=()

# --- flags -------------------------------------------------------------------
VERSION_OVERRIDE="${1:-}"
if [[ -n "$VERSION_OVERRIDE" && "$VERSION_OVERRIDE" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  VERSION="$VERSION_OVERRIDE"; shift
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1; shift ;;
    --master) MASTER_ADDR="$2"; shift 2 ;;
    --token)   TOKEN="$2"; shift 2 ;;
    --static)  STATIC=1; shift ;;
    --tarball) TARBALL="$2"; shift 2 ;;
    --) shift; break ;;
    -*) log_err "unknown option: $1"; exit 2 ;;
    *) HOSTS+=("$1"); shift ;;
  esac
done
while [[ $# -gt 0 ]]; do HOSTS+=("$1"); shift; done

# --- preflight ---------------------------------------------------------------
require_cmd ssh  "install openssh (brew install openssh) or use a Linux host"
require_cmd scp  "install openssh (scp ships with it)"
require_cmd tar  "tar is built into macOS and Linux"

# --- collect hosts -----------------------------------------------------------
banner "stress-strike fleet deploy (v${VERSION})"
[[ ${#HOSTS[@]} -gt 0 ]] || { echo "Paste your SSH hosts one per line ('user@host'), empty line = done."; }
while [[ ${#HOSTS[@]} -eq 0 ]]; do
  read -erp "  SSH host [user@host]: " h
  [[ -z "$h" ]] && continue
  HOSTS+=("$h")
done

# --- deployment mode -----------------------------------------------------------
if [[ -n "$MASTER_ADDR" ]]; then
  STATIC=0                                  # explicit master wins
elif [[ $STATIC -ne 1 ]]; then
  if [[ $ASSUME_YES -eq 1 ]]; then
    log_err "-y requires an explicit mode: pass --master ADDR or --static"
    exit 2
  fi
  echo
  log_info "How should workers attach to the master?"
  log_info "  1) auto-discovery — workers find the master themselves"
  log_info "  2) static list    — master connects to a fixed worker list"
  mode_ans=""
  prompt_var mode_ans "mode (1/2)" "1"
  if [[ "$mode_ans" == "2" ]]; then
    STATIC=1
  else
    while [[ -z "$MASTER_ADDR" ]]; do
      prompt_var MASTER_ADDR "master address (host:port)" ""
    done
  fi
fi

# --- token ---------------------------------------------------------------------
if [[ -z "$TOKEN" ]] && [[ $ASSUME_YES -eq 1 ]]; then
  : # empty token with -y: allowed, warned below
elif [[ -z "$TOKEN" ]]; then
  y="y"
  prompt_yes_no y "protect the control plane with a shared token?" "y"
  if [[ "$y" == "y" ]]; then
    prompt_var TOKEN "token (any secret string)" ""
  fi
fi
[[ -z "$TOKEN" ]] && log_warn "running WITHOUT a control-plane token"

# --- build the worker packages (unless a tarball was provided) -----------------
if [[ -z "$TARBALL" ]]; then
  if ! command_available go; then
    log_err "no Go toolchain here, and we build the worker packages ourselves."
    log_err "install Go (https://go.dev/dl; $ 'brew install go') — or reuse a"
    log_err "prebuilt package: $0 --tarball PATH -- user@host"
    exit 1
  fi
  log_step "building worker packages v${VERSION} (amd64 + arm64)..."
  "${REPO_ROOT}/scripts/build-worker-linux.sh" "$VERSION" >/dev/null
fi

# --- deploy ---------------------------------------------------------------------
echo
banner "deploying to ${#HOSTS[@]} host(s)"
h=0
WORKER_ADDRS=()
for host in "${HOSTS[@]}"; do
  h=$((h + 1))
  echo
  log_step "[$h/${#HOSTS[@]}] ${host}"

  ARCH="$(detect_remote_arch "$host" || true)"
  if [[ -z "$ARCH" ]]; then
    log_err "cannot SSH to ${host} (key not authorized? host down?)."
    log_err "  fix: ssh-copy-id ${host}"
    exit 1
  fi
  log_info "arch: ${ARCH}"

  if [[ -n "$TARBALL" ]]; then
    TARBALL_PATH="$TARBALL"
  else
    TARBALL_PATH="${REPO_ROOT}/dist/linux-worker/stress-strike-worker-v${VERSION}-linux-${ARCH}.tar.gz"
  fi
  if [[ ! -f "$TARBALL_PATH" ]]; then
    log_err "worker package not found: ${TARBALL_PATH}"
    log_err "  run '${REPO_ROOT}/scripts/build-worker-linux.sh ${VERSION}' first (done automatically when no --tarball)"
    exit 1
  fi

  log_info "uploading worker package + helpers..."
  scp -q "$TARBALL_PATH" \
    "${REPO_ROOT}/deploy/fleet/bootstrap-worker.sh" \
    "${REPO_ROOT}/deploy/fleet/common.sh" \
    "${host}:/tmp/"

  ENV="SS_ID=worker-${h}"
  [[ $STATIC -eq 1 ]] || ENV="${ENV} SS_MASTER=${MASTER_ADDR}"
  [[ -z "$TOKEN" ]]   || ENV="${ENV} SS_TOKEN=${TOKEN}"

  ssh "$host" "cd /tmp && sudo env ${ENV} bash bootstrap-worker.sh ${TARBALL_PATH##*/} worker-${h}"

  WORKER_ADDRS+=("${host#*@}:50061")
done

# --- report ---------------------------------------------------------------------
banner "fleet ready — ${#WORKER_ADDRS[@]} worker(s)"
if [[ $STATIC -eq 1 ]]; then
  echo "static mode — run the master on your control box:"
  echo
  echo "  stress-strike-master -workers \"$(IFS=,; echo "${WORKER_ADDRS[*]}")\" \\"
  echo "    -url https://target.example.com -users 500 -duration 120 \\"
  [[ -z "$TOKEN" ]] || echo "    -token ${TOKEN}"
else
  echo "auto-discovery — start the master (it waits for these workers):"
  echo
  echo "  stress-strike-master -listen 0.0.0.0:50051 \\"
  echo "    -wait-workers ${#WORKER_ADDRS[@]} -wait-timeout 30 \\"
  echo "    -url https://target.example.com -users 500 -duration 120 \\"
  [[ -z "$TOKEN" ]] || echo "    -token ${TOKEN} \\"
  echo "    -timeline -quiet"
fi
echo
echo "smoke test right after the master is up:"
echo "  stress-strike-master -wait-workers ${#WORKER_ADDRS[@]} -wait-timeout 30 \\"
echo "    -url https://example.com -users 8 -duration 6 \\"
[[ -z "$TOKEN" ]] || echo "    -token ${TOKEN} \\"
echo "    -tls-fingerprint chrome   # expect 0 errors"
echo
log_info "firewall: open each worker's gRPC port (50061) to the master host."
[[ $STATIC -eq 1 ]] || log_info "and the master port (50051) to anything that starts runs."