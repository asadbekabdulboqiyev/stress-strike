#!/usr/bin/env bash
#
# build-worker-linux.sh — Cross-compile the distributed master/worker control
# plane for real Linux load-generator hosts (amd64 + arm64).
#
# Every Linux worker package contains:
#   stress-strike-worker   load generator (run this on the load hosts)
#   stress-strike-master   coordinator (optional; run one on a control host)
#   stress-strike-worker.service   ready-to-install systemd unit
#   worker.env.example     template for the systemd EnvironmentFile
#   DISTRIBUTED.md         quick deployment guide
#
# Usage:
#   ./scripts/build-worker-linux.sh [VERSION]
#
# Output:
#   dist/linux-worker/stress-strike-worker-v{VERSION}-linux-{arch}.tar.gz
#   dist/linux-worker/sha256sums.txt
#
# Environment overrides:
#   VERSION    version injected via ldflags (default 0.11.0)
#   DIST_DIR   alternative dist/ root (default: <repo>/dist)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-${VERSION:-0.11.0}}"
DIST_ROOT="${DIST_DIR:-${REPO_ROOT}/dist}"
OUT_DIR="${DIST_ROOT}/linux-worker"
LDFLAGS="-s -w -X main.version=${VERSION}"

if ! command -v go >/dev/null 2>&1; then
  echo "error: 'go' not found in PATH" >&2
  exit 1
fi

PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
)

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

echo "==> Building Linux worker packages v${VERSION}"
echo "==> output: ${OUT_DIR}"
echo

for platform in "${PLATFORMS[@]}"; do
  os="${platform%/*}"
  arch="${platform#*/}"
  pkg="stress-strike-worker-v${VERSION}-${os}-${arch}"
  pkg_dir="${OUT_DIR}/${pkg}"
  mkdir -p "${pkg_dir}"

  echo "  ${os}/${arch}"
  (
    cd "${REPO_ROOT}"
    CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" \
      go build -trimpath -buildvcs=false -ldflags="${LDFLAGS}" \
      -o "${pkg_dir}/stress-strike-worker" ./cmd/stress-strike-worker
    CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" \
      go build -trimpath -buildvcs=false -ldflags="${LDFLAGS}" \
      -o "${pkg_dir}/stress-strike-master" ./cmd/stress-strike-master
  )

  cp "${REPO_ROOT}/deploy/systemd/stress-strike-worker.service" "${pkg_dir}/"
  cp "${REPO_ROOT}/deploy/systemd/worker.env.example" "${pkg_dir}/"
  cp "${REPO_ROOT}/docs/DISTRIBUTED.md" "${pkg_dir}/"

  tar -czf "${OUT_DIR}/${pkg}.tar.gz" -C "${OUT_DIR}" "${pkg}"
  rm -rf "${pkg_dir}"
done

if command -v sha256sum >/dev/null 2>&1; then
  (cd "${OUT_DIR}" && sha256sum ./*.tar.gz > sha256sums.txt)
else
  (cd "${OUT_DIR}" && shasum -a 256 ./*.tar.gz > sha256sums.txt)
fi

echo
echo "==> done. artifacts:"
ls -lh "${OUT_DIR}"
echo
echo "==> checksums:"
cat "${OUT_DIR}/sha256sums.txt"
