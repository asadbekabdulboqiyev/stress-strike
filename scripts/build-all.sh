#!/usr/bin/env bash
#
# build-all.sh — cross-compile stress-strike for all supported platforms.
#
# Output layout:
#   dist/stress-strike-v{version}-{os}-{arch}/stress-strike[.exe]
#
# Requirements:
#   - go toolchain on PATH (no CGO needed: binaries are static)
#
# Usage:
#   VERSION=0.2.0 ./scripts/build-all.sh     # explicit version
#   make release                             # uses Makefile's VERSION variable
#
# Environment overrides:
#   VERSION   release version used in the output directory name (default 0.2.0)
#   DIST_DIR  alternative dist/ root (default: <repo>/dist)

set -euo pipefail

# Resolve version: prefer VERSION env (set by `make release`), else default.
VERSION="${VERSION:-0.2.0}"

# Always resolve paths relative to the repository root, so this script
# works regardless of the caller's current working directory.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DIST_DIR:-${REPO_ROOT}/dist}"

BIN_NAME="stress-strike"

# Supported platforms: GOOS/GOARCH.
PLATFORMS=(
  darwin/arm64
  darwin/amd64
  linux/arm64
  linux/amd64
  windows/amd64
)

if ! command -v go >/dev/null 2>&1; then
  echo "error: 'go' not found in PATH" >&2
  exit 1
fi

echo "==> stress-strike release build v${VERSION}"
echo "==> output directory: ${DIST_DIR}"
echo

for platform in "${PLATFORMS[@]}"; do
  os="${platform%/*}"
  arch="${platform#*/}"

  # Windows binaries get the classic .exe suffix.
  suffix=""
  if [ "${os}" = "windows" ]; then
    suffix=".exe"
  fi

  out_dir="${DIST_DIR}/stress-strike-v${VERSION}-${os}-${arch}"
  out_bin="${out_dir}/${BIN_NAME}${suffix}"

  mkdir -p "${out_dir}"

  echo "==> building ${os}/${arch} -> ${out_bin}"
  (
    cd "${REPO_ROOT}"
    CGO_ENABLED=0 \
      GOOS="${os}" \
      GOARCH="${arch}" \
      go build -trimpath -buildvcs=false -o "${out_bin}" ./cmd/stress-strike
  )
done

echo
echo "==> done. artifacts:"
find "${DIST_DIR}" -maxdepth 2 -type f -name "${BIN_NAME}*" | sort