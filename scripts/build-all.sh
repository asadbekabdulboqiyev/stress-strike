#!/usr/bin/env bash
#
# build-all.sh — cross-compile stress-strike for all supported platforms
# and package per-platform archives plus sha256 checksums.
#
# Output layout:
#   dist/stress-strike-v{version}-{os}-{arch}.tar.gz   (unix)
#   dist/stress-strike-v{version}-windows-amd64.zip    (windows)
#   dist/sha256sums.txt
#
# Requirements:
#   - go toolchain on PATH (no CGO needed: binaries are static)
#   - tar, zip, sha256sum (macOS: coreutils' shasum fallback not needed;
#     use `shasum -a 256` when sha256sum is missing)
#
# Usage:
#   VERSION=0.5.1 ./scripts/build-all.sh     # explicit version
#   make release                             # uses Makefile's VERSION variable
#
# Environment overrides:
#   VERSION   release version used in the artifact names (default 0.5.1)
#   DIST_DIR  alternative dist/ root (default: <repo>/dist)

set -euo pipefail

VERSION="${VERSION:-0.5.1}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DIST_DIR:-${REPO_ROOT}/dist}"

BIN_NAME="stress-strike"

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
  build_tmp="${DIST_DIR}/pkg/${BIN_NAME}${suffix}"

  echo "==> building ${os}/${arch}"
  (
    cd "${REPO_ROOT}"
    CGO_ENABLED=0 \
      GOOS="${os}" \
      GOARCH="${arch}" \
      go build -trimpath -buildvcs=false -o "${build_tmp}" ./cmd/stress-strike
  )

  if [ "${os}" = "windows" ]; then
    (cd "${DIST_DIR}/pkg" && zip -q "../${name}.zip" "${BIN_NAME}${suffix}")
  else
    tar -czf "${DIST_DIR}/${name}.tar.gz" -C "${DIST_DIR}/pkg" "${BIN_NAME}"
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
