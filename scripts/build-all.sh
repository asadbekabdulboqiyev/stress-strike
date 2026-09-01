#!/usr/bin/env bash
#
# build-all.sh — Build all stress-strike binaries for the current platform.
#
# Output:
#   bin/
#     stress-strike
#     stress-strike-scan
#     stress-strike-master
#     stress-strike-replay       (requires libpcap for CGO; skipped if unavailable)
#     stress-strike-worker
#     stress-strike-dashboard
#
# Usage:
#   ./scripts/build-all.sh [VERSION]
#
# VERSION defaults to 0.9.0 and is injected into each binary at build time.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${REPO_ROOT}/bin"

VERSION="${1:-0.9.0}"
LDFLAGS="-s -w -X main.version=${VERSION}"

BINARIES=(
  "stress-strike:./cmd/stress-strike"
  "stress-strike-scan:./cmd/stress-strike-scan"
  "stress-strike-master:./cmd/stress-strike-master"
  "stress-strike-replay:./cmd/stress-strike-replay"
  "stress-strike-worker:./cmd/stress-strike-worker"
  "stress-strike-dashboard:./cmd/stress-strike-dashboard"
)

if ! command -v go >/dev/null 2>&1; then
  echo "error: 'go' not found in PATH" >&2
  exit 1
fi

mkdir -p "${BIN_DIR}"

echo "==> Building ${#BINARIES[@]} binaries"
echo

built=0
skipped=0

for entry in "${BINARIES[@]}"; do
  name="${entry%%:*}"
  pkg="${entry#*:}"
  out="${BIN_DIR}/${name}"

  # replay binary needs CGO for gopacket/pcap — try CGO=1 first, skip on failure
  if [ "${name}" = "stress-strike-replay" ]; then
    if CGO_ENABLED=1 go build -trimpath -buildvcs=false -ldflags="${LDFLAGS}" -o "${out}" "${pkg}" 2>/dev/null; then
      echo "  ${name} (cgo)"
      built=$((built + 1))
    else
      echo "  ${name} -- SKIPPED (libpcap not installed; install with: brew install libpcap)"
      skipped=$((skipped + 1))
    fi
    continue
  fi

  echo "  ${name}"
  (
    cd "${REPO_ROOT}"
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="${LDFLAGS}" -o "${out}" "${pkg}"
  )
  built=$((built + 1))
done

echo
echo "==> Build complete: ${built} built, ${skipped} skipped"
echo
echo "==> File sizes:"
echo
ls -lhS "${BIN_DIR}"/* 2>/dev/null | awk '{printf "  %-30s %s\n", $NF, $5}'
echo
echo "==> Binaries in: ${BIN_DIR}"
