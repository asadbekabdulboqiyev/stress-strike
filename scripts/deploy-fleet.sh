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
#   ./scripts/deploy-fleet.sh --tarball dist/.../stress-strike-worker-v0.14.0-linux-amd64.tar.gz -- user@host
#   ./scripts/deploy-fleet.sh -y --master M:50051 -- host1 host2
#   ./scripts/deploy-fleet.sh --master M:50051 --hosts h1,h2,h3   # comma-separated
#   ./scripts/deploy-fleet.sh --master M:50051 --parallel 12 -- host1..host100
#
# Options:
#   -y, --yes          accept defaults (no interactive prompts)
#   --master ADDR      auto-discovery: workers self-register with this master
#   --token SECRET     shared control-plane token
#   --static           static mode: print a -workers list instead of registering
#   --tarball PATH     use a prebuilt linux worker tarball (skip the Go build)
#   --hosts LIST       comma-separated "user@host,user@host,..." (also allowed
#                      after --, and pasted interactively)
#   --parallel N       hosts deployed concurrently over SSH (xargs -P) [6]
#   --                everything after -- is "user@host [user@host ...]"
#
# Deploys run in parallel (default 6 hosts at once) with SSH/scp retries
# (3 attempts, 3s apart); failures are reported per host and do not block the
# rest of the fleet.
#
# Requires ssh keys authorized on each target (ssh-copy-id). Target hosts
# need root (or a passwordless-sudo user) and systemd.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=deploy/fleet/common.sh
source "${REPO_ROOT}/deploy/fleet/common.sh"

VERSION="${VERSION:-0.14.0}"
ASSUME_YES=0
MASTER_ADDR=""
TOKEN=""
STATIC=0
TARBALL=""
PARALLEL="${PARALLEL:-6}"
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
    --hosts)   IFS=',' read -r -a split <<< "$2"; HOSTS+=("${split[@]}"); shift 2 ;;
    --parallel) PARALLEL="$2"; shift 2 ;;
    --) shift; break ;;
    -*) log_err "unknown option: $1"; exit 2 ;;
    *) HOSTS+=("$1"); shift ;;
  esac
done
while [[ $# -gt 0 ]]; do
  # positional hosts may be comma-separated (HOST1,HOST2,HOST3) as well
  IFS=',' read -r -a split <<< "$1"; HOSTS+=("${split[@]}"); shift
done

# --- preflight ---------------------------------------------------------------
require_cmd ssh  "install openssh (brew install openssh) or use a Linux host"
require_cmd scp  "install openssh (scp ships with it)"
require_cmd tar  "tar is built into macOS and Linux"

# --- collect hosts -----------------------------------------------------------
banner "stress-strike fleet deploy (v${VERSION})"
[[ ${#HOSTS[@]} -gt 0 ]] || { echo "Paste your SSH hosts one per line ('user@host', comma-separated ok), empty line = done."; }
while [[ ${#HOSTS[@]} -eq 0 ]]; do
  if ! read -erp "  SSH host [user@host]: " h; then
    log_err "no hosts given"
    exit 2
  fi
  [[ -z "$h" ]] && continue
  IFS=',' read -r -a split <<< "$h"; HOSTS+=("${split[@]}")
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

# --- deploy (parallel over hosts) ---------------------------------------------
echo
banner "deploying to ${#HOSTS[@]} host(s) (parallel=${PARALLEL})"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
RESULT_DIR="${TMP_DIR}/results"
mkdir -p "${RESULT_DIR}"

# deploy_one.sh — install the worker onto ONE host. Invoked by xargs -P, so it
# may run several copies concurrently: each one writes its single result line
# to ${RESULT_DIR}/${IDX} (unique per host) and streams its log to stderr.
cat > "${TMP_DIR}/deploy_one.sh" <<'HELPER'
#!/usr/bin/env bash
# usage: deploy_one.sh HOST IDX   (env: REPO_ROOT VERSION STATIC MASTER_ADDR TOKEN TARBALL_PATH RESULT_DIR)
set -euo pipefail
source "${REPO_ROOT}/deploy/fleet/common.sh"

HOST="$1"
IDX="$2"

fail() { # fail "message" -> record ERR result and exit 1
  echo "ERR|${IDX}|${HOST}|$1" > "${RESULT_DIR}/${IDX}"
  exit 1
}

# ssh_retry HOST CMD — retries a remote command up to 3 times (3s apart).
ssh_retry() {
  local host="$1" cmd="$2" i out
  for ((i = 1; i <= 3; i++)); do
    if out="$(ssh -o ConnectTimeout=10 -o BatchMode=yes "$host" "$cmd" 2>/dev/null)"; then
      printf '%s' "$out"
      return 0
    fi
    [[ $i -lt 3 ]] && sleep 3
  done
  return 1
}

# run_retry BIN ARGS... — retries any command (scp/ssh) up to 3 times.
run_retry() {
  local i
  for ((i = 1; i <= 3; i++)); do
    if "$@"; then return 0; fi
    [[ $i -lt 3 ]] && sleep 3
  done
  return 1
}

if [[ -z "$(ssh_retry "$HOST" 'uname -m' 2>/dev/null || true)" ]]; then
  fail "cannot SSH to ${HOST} (key not authorized? host down?). fix: ssh-copy-id ${HOST}"
fi
ARCH="$(ssh_retry "$HOST" 'uname -m' | sed 's/x86_64/amd64/; s/aarch64/arm64/' | tr -d '\r')"
log_info "${HOST}: arch=${ARCH}"

TB="${TARBALL_PATH:-}"
if [[ -z "$TB" ]]; then
  TB="${REPO_ROOT}/dist/linux-worker/stress-strike-worker-v${VERSION}-linux-${ARCH}.tar.gz"
fi
if [[ ! -f "$TB" ]]; then
  fail "worker package not found: ${TB} (run ${REPO_ROOT}/scripts/build-worker-linux.sh ${VERSION})"
fi

if ! run_retry scp -q "$TB" \
     "${REPO_ROOT}/deploy/fleet/bootstrap-worker.sh" \
     "${REPO_ROOT}/deploy/fleet/common.sh" \
     "${HOST}:/tmp/"; then
  fail "scp upload to ${HOST} failed"
fi

ENV="SS_ID=worker-${IDX}"
[[ $STATIC -eq 1 ]] || ENV="${ENV} SS_MASTER=${MASTER_ADDR}"
[[ -z "$TOKEN" ]]  || ENV="${ENV} SS_TOKEN=${TOKEN}"

if ! run_retry ssh "$HOST" "cd /tmp && sudo env ${ENV} bash bootstrap-worker.sh ${TB##*/} worker-${IDX}"; then
  fail "bootstrap on ${HOST} failed"
fi

echo "OK|${IDX}|${HOST}|${HOST#*@}:50061" > "${RESULT_DIR}/${IDX}"
HELPER
chmod +x "${TMP_DIR}/deploy_one.sh"

export REPO_ROOT VERSION STATIC MASTER_ADDR TOKEN RESULT_DIR
export TARBALL_PATH="${TARBALL:-}"

printf '%s\n' "${HOSTS[@]}" | xargs -P "${PARALLEL}" -n 1 bash "${TMP_DIR}/deploy_one.sh"

# --- collect results -----------------------------------------------------------
WORKER_ADDRS=()
deploy_fail=0
for ((i = 1; i <= ${#HOSTS[@]}; i++)); do
  if [[ -f "${RESULT_DIR}/${i}" ]]; then
    line="$(cat "${RESULT_DIR}/${i}")"
    case "$line" in
      OK\|*)
        rest="${line#OK|}"          # IDX|HOST|addr
        addr="${rest##*|}"
        WORKER_ADDRS+=("$addr")
        log_ok "${HOSTS[$((i - 1))]}: worker ready (idx ${i}, ${addr})"
        ;;
      ERR\|*)
        rest="${line#ERR|}"         # IDX|HOST|message
        msg="${rest#*|*|}"
        log_err "${HOSTS[$((i - 1))]}: ${msg}"
        deploy_fail=1
        ;;
    esac
  else
    log_err "${HOSTS[$((i - 1))]}: no result (parallel job aborted?)"
    deploy_fail=1
  fi
done
(( deploy_fail == 0 )) || exit 1

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