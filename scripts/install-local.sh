#!/usr/bin/env bash
#
# install-local.sh — build every stress-strike binary, install it into a
# directory on PATH, and repair the macOS code signature.
#
# Usage:
#   ./scripts/install-local.sh                 # install into $(go env GOBIN)
#   ./scripts/install-local.sh 0.14.5          # pin the version string
#   STRESS_STRIKE_INSTALL_DIR=~/.local/bin ./scripts/install-local.sh
#
# Why the signing step exists
# ---------------------------
# On Apple Silicon every Mach-O is validated by AMFI/taskgated at exec time.
# A Go binary carries a linker-generated ad-hoc signature. Copying that binary
# into place with `cp` keeps the signature bytes but the new file is a
# different inode carrying com.apple.provenance, and validation can reject it:
#
#   zsh: killed     stress-strike          # SIGKILL, exit code 137
#   termination: { namespace: CODESIGNING,
#                  indicator: Taskgated Invalid Signature }
#
# `codesign --verify` still reports "valid on disk" in that state, so the only
# reliable check is to exec the binary. This script therefore, for each binary:
#
#   1. builds into a temp directory (never overwrites a live file in place),
#   2. installs atomically (write to NAME.new, then rename over NAME),
#   3. drops com.apple.provenance and re-applies an ad-hoc signature,
#   4. execs the result with --version and fails loudly on rc=137.
#
# Requirements: go, codesign (macOS only; skipped elsewhere).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="${1:-${VERSION:-$(sed -n 's/^VERSION ?= *//p' Makefile | head -1)}}"
VERSION="${VERSION:-0.0.0}"

if ! command -v go >/dev/null 2>&1; then
  echo "error: 'go' not found in PATH" >&2
  exit 1
fi

BINARIES=(
  "stress-strike:./cmd/stress-strike"
  "stress-strike-dashboard:./cmd/stress-strike-dashboard"
  "stress-strike-scan:./cmd/stress-strike-scan"
  "stress-strike-master:./cmd/stress-strike-master"
  "stress-strike-replay:./cmd/stress-strike-replay"
  "stress-strike-worker:./cmd/stress-strike-worker"
)

dest_dir() {
  if [ -n "${STRESS_STRIKE_INSTALL_DIR:-}" ]; then echo "$STRESS_STRIKE_INSTALL_DIR"; return; fi
  local gobin
  gobin="$(go env GOBIN)"
  if [ -z "$gobin" ]; then gobin="$(go env GOPATH)/bin"; fi
  echo "$gobin"
}

DEST="$(dest_dir)"
mkdir -p "$DEST" || { echo "error: cannot create $DEST" >&2; exit 1; }
if [ ! -w "$DEST" ]; then
  echo "error: $DEST is not writable (set STRESS_STRIKE_INSTALL_DIR)" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say()  { printf '%s\n' "$*"; }
step() { printf '  \033[36m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m[warn]\033[0m %s\n' "$*"; }
err()  { printf '  \033[31m[error]\033[0m %s\n' "$*" >&2; }

IS_DARWIN=0
[ "$(uname -s)" = "Darwin" ] && IS_DARWIN=1

say "==> stress-strike v${VERSION}"
say "==> install dir: ${DEST}"
say

step "building ${#BINARIES[@]} binaries"
for entry in "${BINARIES[@]}"; do
  name="${entry%%:*}"
  pkg="${entry#*:}"
  CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o "${TMP}/${name}" "${pkg}"
  ok "built ${name}"
done

say
step "installing"

sign() {
  local path="$1"
  [ "$IS_DARWIN" -eq 1 ] || return 0
  command -v codesign >/dev/null 2>&1 || { warn "codesign missing; skipping"; return 0; }
  xattr -d com.apple.provenance "$path" 2>/dev/null || true
  if ! codesign --force --sign - --timestamp=none "$path" 2>/dev/null; then
    err "codesign failed for $path"
    return 1
  fi
  return 0
}

failed=0
for entry in "${BINARIES[@]}"; do
  name="${entry%%:*}"
  target="${DEST}/${name}"

  # Atomic replace: write a sibling then rename, so a running instance keeps
  # its old inode and a new launch sees the new file cleanly.
  install -m 0755 "${TMP}/${name}" "${target}.new"
  mv -f "${target}.new" "$target"

  sign "$target" || { failed=$((failed + 1)); continue; }

  # Exec probe — the only check that catches a taskgated rejection.
  set +e
  "${target}" --version >/dev/null 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 137 ]; then
    err "${name}: SIGKILL (Code Signature Invalid) — signing did not take"
    failed=$((failed + 1))
  else
    ok "${name} (launch rc=${rc})"
  fi
done

say
if [ "$failed" -ne 0 ]; then
  err "${failed} binary/binaries failed to install cleanly"
  exit 1
fi

ok "stress-strike v${VERSION} installed into ${DEST}"
say
if [[ ":$PATH:" != *":${DEST}:"* ]]; then
  say "  ${DEST} is not on PATH; add it:"
  say "    export PATH=\"\${PATH}:${DEST}\""
  say
fi
say "  run:     stress-strike"
say "  web:     stress-strike dashboard   → http://127.0.0.1:8888"
