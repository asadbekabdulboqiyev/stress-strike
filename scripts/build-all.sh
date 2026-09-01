#!/usr/bin/env bash
#
# build-all.sh — Build stress-strike binaries.
#
# Default: build all binaries for the current platform.
# Set RELEASE=1 to cross-compile for all platforms and create archives.
#
# Output (local mode):
#   bin/
#     stress-strike
#     stress-strike-scan
#     stress-strike-master
#     stress-strike-replay       (requires libpcap for CGO; skipped if unavailable)
#     stress-strike-worker
#     stress-strike-dashboard
#
# Output (RELEASE=1):
#   dist/
#     stress-strike-v{version}-{os}-{arch}.tar.gz   (unix)
#     stress-strike-v{version}-windows-amd64.zip    (windows)
#     sha256sums.txt
#
# Requirements:
#   - go toolchain on PATH
#   - tar, zip, sha256sum (macOS: use `shasum -a 256` fallback when sha256sum is missing)
#
# Usage:
#   ./scripts/build-all.sh [VERSION]
#   RELEASE=1 VERSION=1.0.0 ./scripts/build-all.sh
#
# Environment overrides:
#   VERSION    release version injected via ldflags (default 0.9.0)
#   RELEASE    set to 1 for cross-platform release builds with archives
#   DIST_DIR   alternative dist/ root (default: <repo>/dist)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VERSION="${1:-${VERSION:-0.9.0}}"
LDFLAGS="-s -w -X main.version=${VERSION}"

if ! command -v go >/dev/null 2>&1; then
  echo "error: 'go' not found in PATH" >&2
  exit 1
fi

# ── Cross-platform release build ─────────────────────────────────────────────

if [ "${RELEASE:-0}" = "1" ]; then
  DIST_DIR="${DIST_DIR:-${REPO_ROOT}/dist}"

  PLATFORMS=(
    darwin/arm64
    darwin/amd64
    linux/arm64
    linux/amd64
    windows/amd64
  )

  checksum_cmd() {
    if command -v sha256sum >/dev/null 2>&1; then
      echo "sha256sum"
    else
      echo "shasum -a 256"
    fi
  }

  echo "==> stress-strike release build v${VERSION}"
  echo "==> output directory: ${DIST_DIR}"
  echo

  rm -rf "${DIST_DIR}/pkg"
  mkdir -p "${DIST_DIR}/pkg"

  for platform in "${PLATFORMS[@]}"; do
    os="${platform%/*}"
    arch="${platform#*/}"

    suffix=""
    if [ "${os}" = "windows" ]; then
      suffix=".exe"
    fi

    name="stress-strike-v${VERSION}-${os}-${arch}"
    build_tmp="${DIST_DIR}/pkg/stress-strike${suffix}"

    echo "==> building ${os}/${arch}"
    (
      cd "${REPO_ROOT}"
      CGO_ENABLED=0 \
        GOOS="${os}" \
        GOARCH="${arch}" \
        go build -trimpath -buildvcs=false -ldflags="${LDFLAGS}" -o "${build_tmp}" ./cmd/stress-strike
    )

    if [ "${os}" = "windows" ]; then
      (cd "${DIST_DIR}/pkg" && zip -q "../${name}.zip" "stress-strike${suffix}")
    else
      tar -czf "${DIST_DIR}/${name}.tar.gz" -C "${DIST_DIR}/pkg" "stress-strike"
    fi
    rm -f "${build_tmp}"
  done

  (
    cd "${DIST_DIR}"
    # shellcheck disable=SC2046
    $(checksum_cmd) ./*.tar.gz ./*.zip > sha256sums.txt
    rm -rf pkg
  )

  echo
  echo "==> done. artifacts:"
  ls -l "${DIST_DIR}"
  exit 0
fi

# ── Local build (all binaries for current platform) ──────────────────────────

BIN_DIR="${REPO_ROOT}/bin"

BINARIES=(
  "stress-strike:./cmd/stress-strike"
  "stress-strike-scan:./cmd/stress-strike-scan"
  "stress-strike-master:./cmd/stress-strike-master"
  "stress-strike-replay:./cmd/stress-strike-replay"
  "stress-strike-worker:./cmd/stress-strike-worker"
  "stress-strike-dashboard:./cmd/stress-strike-dashboard"
)

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
