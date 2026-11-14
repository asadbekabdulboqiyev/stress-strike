#!/usr/bin/env bash
#
# build-all.sh — Build Sift binaries.
#
# Default: build all binaries for the current platform.
# Set RELEASE=1 to cross-compile for all platforms and create archives.
#
# Output (local mode):
#   bin/
#     Sift
#     Sift-scan
#     Sift-master
#     Sift-replay       (pure-Go, no CGO/libpcap required)
#     Sift-worker
#     Sift-dashboard
#
# Output (RELEASE=1):
#   dist/
#     Sift-v{version}-{os}-{arch}.tar.gz   (unix)
#     Sift-v{version}-windows-amd64.zip    (windows)
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
#   VERSION    release version injected via ldflags (default 0.15.2)
#   RELEASE    set to 1 for cross-platform release builds with archives
#   DIST_DIR   alternative dist/ root (default: <repo>/dist)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VERSION="${1:-${VERSION:-0.15.2}}"
LDFLAGS="-s -w -X github.com/asadbekabdulboqiyev/sift/internal/version.Version=${VERSION}"

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

  echo "==> Sift release build v${VERSION}"
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

    name="Sift-v${VERSION}-${os}-${arch}"
    build_tmp="${DIST_DIR}/pkg/Sift${suffix}"

    echo "==> building ${os}/${arch}"
    (
      cd "${REPO_ROOT}"
      CGO_ENABLED=0 \
        GOOS="${os}" \
        GOARCH="${arch}" \
        go build -trimpath -buildvcs=false -ldflags="${LDFLAGS}" -o "${build_tmp}" ./cmd/sift
    )

    if [ "${os}" = "windows" ]; then
      (cd "${DIST_DIR}/pkg" && zip -q "../${name}.zip" "Sift${suffix}")
    else
      tar -czf "${DIST_DIR}/${name}.tar.gz" -C "${DIST_DIR}/pkg" "Sift"
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
  "Sift:./cmd/sift"
  "Sift-scan:./cmd/sift-scan"
  "Sift-master:./cmd/sift-master"
  "Sift-replay:./cmd/sift-replay"
  "Sift-worker:./cmd/sift-worker"
  "Sift-dashboard:./cmd/sift-dashboard"
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

  # All binaries are pure-Go (replay uses pcapgo, no CGO/libpcap needed).
  echo "  ${name}"
  (
    cd "${REPO_ROOT}"
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="${LDFLAGS}" -o "${out}" "${pkg}"
  )
  # Cross-platform convenience: provide lowercase aliases (Linux is case-sensitive).
  # Skip on Darwin (default case-insensitive filesystem) to avoid clobbering binaries.
  lower="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
  if [ "$lower" != "$name" ] && [ "$(uname -s 2>/dev/null || echo)" != "Darwin" ]; then
    ln -sf "$name" "${BIN_DIR}/${lower}"
  fi
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
