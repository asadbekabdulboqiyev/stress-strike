#!/usr/bin/env bash
#
# release.sh — Cross-compile, package, and publish a GitHub release.
#
# Usage:
#   ./scripts/release.sh v0.4.0
#
# Requirements:
#   - go toolchain on PATH
#   - gh (GitHub CLI) authenticated — optional, falls back to manual instructions

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <version>" >&2
  echo "  e.g. $0 v0.4.0" >&2
  exit 1
fi

VERSION="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
BIN_NAME="stress-strike"
PACKAGE_PREFIX="stress-strike-${VERSION}"

LDFLAGS="-s -w -X main.version=${VERSION#v}"

PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
)

# ── Build ──────────────────────────────────────────────────────────────────────

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

echo "==> Building ${BIN_NAME} ${VERSION} for ${#PLATFORMS[@]} platforms"
echo

for platform in "${PLATFORMS[@]}"; do
  os="${platform%/*}"
  arch="${platform#*/}"
  suffix=""
  if [ "${os}" = "windows" ]; then suffix=".exe"; fi

  out_dir="${DIST_DIR}/${PACKAGE_PREFIX}-${os}-${arch}"
  out_bin="${out_dir}/${BIN_NAME}${suffix}"
  mkdir -p "${out_dir}"

  echo "  ${os}/${arch} -> ${out_bin}"
  (
    cd "${REPO_ROOT}"
    CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" \
      go build -trimpath -buildvcs=false -ldflags="${LDFLAGS}" \
      -o "${out_bin}" ./cmd/stress-strike
  )
done

# ── Package ────────────────────────────────────────────────────────────────────

echo
echo "==> Packaging releases"

for dir in "${DIST_DIR}"/${PACKAGE_PREFIX}-*/; do
  basename_dir="$(basename "${dir}")"
  os_arch="${basename_dir#${PACKAGE_PREFIX}-}"
  os="${os_arch%%-*}"

  if [ "${os}" = "windows" ]; then
    archive="${DIST_DIR}/${basename_dir}.zip"
    (cd "${DIST_DIR}" && zip -qr "${archive}" "${basename_dir}")
  else
    archive="${DIST_DIR}/${basename_dir}.tar.gz"
    tar -czf "${archive}" -C "${DIST_DIR}" "${basename_dir}"
  fi

  echo "  ${archive}"
done

# ── Checksums ──────────────────────────────────────────────────────────────────

echo
echo "==> Generating checksums"

CHECKSUM_FILE="${DIST_DIR}/checksums.txt"
(cd "${DIST_DIR}" && shopt -s nullglob && files=(${PACKAGE_PREFIX}-*.tar.gz ${PACKAGE_PREFIX}-*.zip) && shasum -a 256 "${files[@]}" > checksums.txt)
(cd "${DIST_DIR}" && shasum -a 256 -c checksums.txt >/dev/null 2>&1 && echo "  checksums verified")
cat "${CHECKSUM_FILE}"

# ── Publish ────────────────────────────────────────────────────────────────────

echo

if command -v gh >/dev/null 2>&1; then
  echo "==> Creating GitHub release ${VERSION} via gh CLI"
  (
    cd "${DIST_DIR}"
    shopt -s nullglob
    assets=(*.tar.gz *.zip checksums.txt)
    gh release create "${VERSION}" \
      --title "stress-strike ${VERSION}" \
      --generate-notes \
      "${assets[@]}"
  )
  echo "==> Release published!"
else
  echo "==> gh CLI not found — manual steps:"
  echo
  echo "  1. Create a tag:"
  echo "       git tag ${VERSION} && git push origin ${VERSION}"
  echo
  echo "  2. Create a release at:"
  echo "       https://github.com/<owner>/stress-strike/releases/new?tag=${VERSION}"
  echo
  echo "  3. Upload these assets:"
  for f in "${DIST_DIR}"/${PACKAGE_PREFIX}-*.{tar.gz,zip} "${CHECKSUM_FILE}"; do
    [ -f "${f}" ] && echo "       $(basename "${f}")"
  done
fi

echo
echo "==> Done."
