#!/usr/bin/env bash
#
# fleet-status.sh — check the health of a stress-strike worker fleet from the
# control box.
#
# The control plane has no master-side "list my workers" RPC yet, so this
# probe asks each worker directly (the same gRPC Ping/GetCapabilities calls
# the master uses during Connect). It prints one line per worker with the
# address, worker id, version and advertised limits.
#
# Usage:
#   ./scripts/fleet-status.sh --workers srv1:10.0.0.11:50061,srv2:10.0.0.12:50061
#   ./scripts/fleet-status.sh --master master.internal:50051 \
#       --workers srv1:10.0.0.11:50061,srv2:10.0.0.12:50061
#   ./scripts/fleet-status.sh 10.0.0.11:50061 10.0.0.12:50061
#
# Options:
#   --master HOST:PORT   also probe the master itself
#   --workers LIST       comma-separated "label:HOST:PORT" entries (label optional)
#   --timeout SEC        per-probe timeout in seconds          [5]
#   --token SECRET       shared control-plane token (attached to gRPC metadata)
#
# Dependency: grpcurl (https://github.com/fullstorydev/grpcurl) for full gRPC
# answers. Without it the script falls back to a TCP reachability check and
# labels the worker "tcp-reachable" — install grpcurl once for the real
# health data:
#   brew install grpcurl    # or: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
#
# Exit status: 0 when every probe succeeded, 1 otherwise.

set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=deploy/fleet/common.sh
source "${REPO_ROOT}/deploy/fleet/common.sh"

MASTER=""
WORKERS=""
TIMEOUT=5
TOKEN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --master) MASTER="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    -*) log_err "unknown option: $1"; exit 2 ;;
    *) WORKERS="${WORKERS:+$WORKERS,}$1"; shift ;;
  esac
done

if [[ -z "$MASTER" && -z "$WORKERS" ]]; then
  log_err "nothing to probe: pass --master, --workers, or bare host:port arguments"
  log_err "example: $0 --master 10.0.0.5:50051 --workers srv1:10.0.0.11:50061,srv2:10.0.0.12:50061"
  exit 2
fi

GRPCURL=""
if command -v grpcurl >/dev/null 2>&1; then
  GRPCURL=grpcurl
else
  log_warn "grpcurl not found — falling back to TCP reachability checks (install grpcurl for gRPC health)"
fi

# Local proto for grpcurl: avoids requiring the reflection API on the fleet.
PROTO_FILE="${REPO_ROOT}/internal/dist/proto/coordinator.proto"
PROTO_DIR="$(dirname "$PROTO_FILE")"

# grpc_ping HOST:PORT -> prints "version|worker_id" or exits nonzero.
# The repo's coordinator.proto is passed to grpcurl so no server-side
# reflection is needed (and no extra API surface is exposed on the fleet).
grpc_ping() {
  local addr="$1" out
  local args=()
  if [[ -f "$PROTO_FILE" ]]; then
    args=(-import-path "$PROTO_DIR" -proto coordinator.proto)
  fi
  if [[ -n "$TOKEN" ]]; then
    args+=(-H "authorization: Bearer ${TOKEN}")
  fi
  out="$("$GRPCURL" -plaintext -max-time "$TIMEOUT" "${args[@]+"${args[@]}"}" "$addr" stressstrike.dist.MasterWorker/Ping 2>/dev/null)"
  local rc=$?
  [[ $rc -ne 0 ]] && return $rc
  if command -v jq >/dev/null 2>&1; then
    echo "$out" | jq -r '[.version // "-", .workerId // "-"] | join("|")'
  else
    echo "$out" | tr -d '{}"' | sed 's/ *version:/version=/; s/ *workerId:/worker_id=/' | tr '\n' '|'
    echo
  fi
}

# tcp_check HOST:PORT -> 0 when reachable.
tcp_check() {
  local host="${1%:*}" port="${1##*:}"
  if command -v nc >/dev/null 2>&1; then
    nc -z -G "$TIMEOUT" "$host" "$port" >/dev/null 2>&1
  else
    timeout "$TIMEOUT" bash -c "echo > /dev/tcp/${host}/${port}" >/dev/null 2>&1
  fi
}

declare -i ok=0 fail=0

if [[ -n "$MASTER" ]]; then
  log_step "master: ${MASTER}"
  if [[ -n "$GRPCURL" ]]; then
    if out="$(grpc_ping "$MASTER")"; then
      log_ok "master responds (${out//|/, })"
      ok+=1
    else
      log_err "master ${MASTER} unreachable"
      fail+=1
    fi
  else
    if tcp_check "$MASTER"; then log_ok "master reachable (tcp)"; ok+=1
    else log_err "master ${MASTER} unreachable"; fail+=1; fi
  fi
  echo
fi

# Parse the worker list: "label:HOST:PORT" (label optional -> use HOST:PORT).
IFS=',' read -r -a entries <<< "$WORKERS"
if [[ ${#entries[@]} -gt 0 ]]; then
  log_step "workers: ${#entries[@]}"
  printf '  %-22s %-28s %-12s %s\n' "WORKER" "ADDRESS" "STATUS" "VERSION / ID"
  for entry in "${entries[@]}"; do
    [[ -z "$entry" ]] && continue
    label="${entry%%:*}"
    rest="${entry#*:}"
    if [[ "$rest" == *:* ]]; then
      addr="$rest"
    else
      addr="$entry"       # no label: entry is HOST:PORT
      label="${addr%%:*}"
    fi
    if [[ "$addr" != *:* ]]; then
      log_err "bad entry '$entry' (want label:HOST:PORT or HOST:PORT)"
      fail+=1
      continue
    fi

    if [[ -n "$GRPCURL" ]]; then
      if out="$(grpc_ping "$addr")"; then
        printf '  %-22s %-28s %-12s %s\n' "${label:0:22}" "$addr" "${C_GRN}healthy${C_RST}" "$out"
        ok+=1
      else
        printf '  %-22s %-28s %s\n' "${label:0:22}" "$addr" "${C_RED}unreachable${C_RST}"
        fail+=1
      fi
    else
      if tcp_check "$addr"; then
        printf '  %-22s %-28s %-12s %s\n' "${label:0:22}" "$addr" "${C_GRN}tcp-reachable${C_RST}" "install grpcurl for gRPC data"
        ok+=1
      else
        printf '  %-22s %-28s %s\n' "${label:0:22}" "$addr" "${C_RED}unreachable${C_RST}"
        fail+=1
      fi
    fi
  done
fi

echo
if [[ $fail -eq 0 ]]; then
  log_ok "fleet status: ${ok} up, ${fail} down"
  exit 0
fi
log_err "fleet status: ${ok} up, ${fail} down"
exit 1