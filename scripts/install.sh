#!/usr/bin/env bash
#
# install.sh — one-command installer for stress-strike.
#
# Installs all stress-strike binaries into $(go env GOPATH)/bin (or GOBIN).
# By default it installs from the module path; pass a tag to pin a version,
# e.g.:
#
#   ./scripts/install.sh                  # @latest
#   ./scripts/install.sh v0.9.0           # pinned release
#
# Requirements:
#   - Go 1.26+ on PATH
#   - network access to the module proxy
#
# The replay binary additionally needs libpcap (CGO). If libpcap is missing
# it is skipped with a notice rather than failing the whole install.

set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
  echo "error: 'go' not found in PATH — install Go 1.26+ first: https://go.dev/dl/" >&2
  exit 1
fi

MODULE="github.com/asadbekabdulboqiyev/stress-strike"
VERSION="${1:-latest}"
REF="@${VERSION}"
# Normalize a bare "0.9.0" to "v0.9.0" for the reference form.
if [[ "${VERSION}" != "latest" && "${VERSION}" != v* ]]; then
  REF="@v${VERSION}"
fi

BINARIES=(
  "cmd/stress-strike"
  "cmd/stress-strike-dashboard"
  "cmd/stress-strike-master"
  "cmd/stress-strike-worker"
  "cmd/stress-strike-replay"
  "cmd/stress-strike-scan"
)

echo "==> Installing stress-strike ${VERSION} from ${MODULE}"
echo "    install prefix: $(go env GOPATH)/bin"
echo

installed=0
skipped=0

for pkg in "${BINARIES[@]}"; do
  name="$(basename "${pkg}")"
  # replay needs CGO/libpcap — try it, tolerate failure so the rest installs.
  if [ "${name}" = "stress-strike-replay" ]; then
    if go install "${MODULE}/${pkg}${REF}" 2>/dev/null; then
      echo "  ✓ ${name}"
      installed=$((installed + 1))
    else
      echo "  - ${name} skipped (libpcap not available; install with: brew install libpcap)"
      skipped=$((skipped + 1))
    fi
    continue
  fi
  go install "${MODULE}/${pkg}${REF}"
  echo "  ✓ ${name}"
  installed=$((installed + 1))
done

echo
echo "==> Done: ${installed} installed, ${skipped} skipped"
BIN_DIR="$(go env GOPATH)/bin"
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
  echo
  echo "  ℹ  Add ${BIN_DIR} to your PATH to run 'stress-strike' from anywhere:"
  echo "     export PATH=\"\${PATH}:${BIN_DIR}\""
fi
echo
echo "==> Try it:"
echo "     stress-strike --help"
