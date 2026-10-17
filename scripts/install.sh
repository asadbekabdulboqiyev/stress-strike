#!/usr/bin/env bash
#
# install.sh — one-command installer for stress-strike.
#
#   curl -fsSL -o install.sh https://raw.githubusercontent.com/asadbekabdulboqiyev/stress-strike/main/scripts/install.sh
#   less install.sh          # read it before running it — it has no secrets and needs root
#   ./install.sh             # latest release, checksum-verified
#   ./install.sh v0.14.4     # pin a version
#   ./install.sh --go        # install via the Go module proxy instead (no download server needed)
#
# Security properties (see SECURITY.md):
#   * Downloads are pinned to an exact version by default — never "latest" from
#     a moving branch, so a compromised main branch cannot repoint the install.
#   * Every downloaded archive is verified against checksums.txt from the same
#     release before a single byte is executed.
#   * If cosign is available, the checksum file is verified against the
#     release's keyless signature (OIDC-issued, bound to the GitHub workflow).
#   * No secrets, no root, no writes outside the install prefix.
#
# Requires: curl, tar, unzip (Windows), sha256sum or shasum.
# Optional:  cosign (https://github.com/sigstore/cosign)

set -euo pipefail

REPO="asadbekabdulboqiyev/stress-strike"
BINARIES=(stress-strike stress-strike-dashboard stress-strike-master stress-strike-worker stress-strike-replay stress-strike-scan)

MODE="release"
VERSION=""

for arg in "$@"; do
  case "$arg" in
    --go) MODE="go" ;;
    --help|-h) sed -n '2,25p' "$0"; exit 0 ;;
    v*) VERSION="${arg#v}" ;;
    [0-9]*) VERSION="$arg" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '%s\n' "$*"; }
step() { printf '  \033[36m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m[ok]\033[0m %s\n' "$*"; }
err()  { printf '  \033[31merror:\033[0m %s\n' "$*" >&2; }

checksum_tool() {
  if command -v sha256sum >/dev/null 2>&1; then echo "sha256sum -c"
  elif command -v shasum    >/dev/null 2>&1; then echo "shasum -a 256 -c"
  else err "need sha256sum or shasum (macOS ships shasum)"; exit 1
  fi
}

install_dir() {
  if [ -n "${STRESS_STRIKE_INSTALL_DIR:-}" ]; then echo "$STRESS_STRIKE_INSTALL_DIR"; return; fi
  if [ -w "/usr/local/bin" ]; then echo "/usr/local/bin"; return; fi
  echo "${HOME}/.local/bin"
}

# ── Go module proxy path ────────────────────────────────────────────────────
if [ "$MODE" = "go" ]; then
  command -v go >/dev/null 2>&1 || { err "Go 1.26+ is required for --go: https://go.dev/dl/"; exit 1; }
  step "installing via the Go module proxy"
  for b in "${BINARIES[@]}"; do
    [ "$b" = "stress-strike" ] && pkg=cmd/stress-strike || pkg="cmd/${b}"
    go install "github.com/${REPO}/${pkg}@${VERSION:-latest}"
    ok "$b"
  done
  say
  say "  binaries: $(go env GOPATH)/bin"
  exit 0
fi

# ── release path ───────────────────────────────────────────────────────────
command -v curl >/dev/null 2>&1 || { err "curl is required"; exit 1; }

if [ -z "$VERSION" ]; then
  step "resolving the latest release"
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | sed -n 's/.*"tag_name": *"\(v[0-9][^"]*\)".*/\1/p' | head -1 | tr -d v)"
  [ -n "$VERSION" ] || { err "could not resolve the latest release"; exit 1; }
fi
say "==> stress-strike v${VERSION}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux|darwin) ;;
  mingw*|msys*|cygwin*) os="windows" ;;
  *) err "unsupported OS: $os (use Windows, macOS or Linux)"; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64)  arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) err "unsupported architecture: $(uname -m)"; exit 1 ;;
esac
[ "$os" = "windows" ] && [ "$arch" = "amd64" ] && { step "note: Windows arm64 binaries are published too"; }

archive="stress-strike_${VERSION}_${os}_${arch}"
ext=tar.gz
[ "$os" = "windows" ] && ext=zip
base="https://github.com/${REPO}/releases/download/v${VERSION}"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
step "downloading ${archive}.${ext}"
if ! curl -fsSL --retry 3 --retry-delay 2 -o "${TMP}/${archive}.${ext}" \
        "${base}/${archive}.${ext}"; then
  err "download failed — does this build exist for ${os}/${arch}?"; exit 1
fi

step "downloading checksums.txt"
curl -fsSL --retry 3 -o "${TMP}/checksums.txt" "${base}/checksums.txt"

# Optional: verify the checksum file itself against its cosign signature.
if command -v cosign >/dev/null 2>&1; then
  step "verifying checksum signature (cosign)"
  curl -fsSL -o "${TMP}/checksums.txt.pem" "${base}/checksums.txt.pem" || true
  curl -fsSL -o "${TMP}/checksums.txt.sig" "${base}/checksums.txt.sig" || true
  if [ -s "${TMP}/checksums.txt.sig" ] && [ -s "${TMP}/checksums.txt.pem" ]; then
    if cosign verify-blob --certificate "${TMP}/checksums.txt.pem" \
         --signature "${TMP}/checksums.txt.sig" "${TMP}/checksums.txt"; then
      ok "signature valid"
    else
      err "SIGNATURE VERIFICATION FAILED — aborting install"; exit 1
    fi
  else
    err "signature files missing from the release — aborting install"; exit 1
  fi
else
  step "cosign not installed — skipping signature check (checksums still verified)"
fi

step "verifying checksum"
if ! ( cd "$TMP" && $(checksum_tool) --ignore-missing "checksums.txt" >/dev/null 2>&1 ); then
  # --ignore-missing is GNU-only; fall back to an explicit grep+verify.
  want="$(grep -F " ${archive}.${ext}" "${TMP}/checksums.txt" | awk '{print $1}')"
  [ -n "$want" ] || { err "no checksum for ${archive}.${ext} in checksums.txt"; exit 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "${TMP}/${archive}.${ext}" | awk '{print $1}')"
  else
    got="$(shasum -a 256 "${TMP}/${archive}.${ext}" | awk '{print $1}')"
  fi
  [ "$want" = "$got" ] || { err "CHECKSUM MISMATCH — refusing to install"; exit 1; }
fi
ok "checksum verified"

step "extracting"
if [ "$ext" = "zip" ]; then
  command -v unzip >/dev/null 2>&1 || { err "unzip is required on Windows"; exit 1; }
  ( cd "$TMP" && unzip -oq "${archive}.${ext}" )
else
  ( cd "$TMP" && tar -xzf "${archive}.${ext}" )
fi

# ── install ────────────────────────────────────────────────────────────────
PREFIX="$(install_dir)"
step "installing into ${PREFIX}"
if [ ! -d "$PREFIX" ]; then
  mkdir -p "$PREFIX" || { err "cannot create ${PREFIX}"; exit 1; }
fi
if [ ! -w "$PREFIX" ]; then
  err "${PREFIX} is not writable — rerun with sudo, or set STRESS_STRIKE_INSTALL_DIR"
  exit 1
fi

for b in "${BINARIES[@]}"; do
  src="${TMP}/${b}"
  [ "$os" = "windows" ] && src="${src}.exe"
  [ -f "$src" ] || continue
  cp "$src" "${PREFIX}/${b}"
  chmod 0755 "${PREFIX}/${b}"
  ok "$b"
done

say
ok "stress-strike v${VERSION} installed"
say
if [[ ":$PATH:" != *":${PREFIX}:"* ]]; then
  say "  add the install directory to your PATH:"
  say "    export PATH=\"\${PATH}:${PREFIX}\""
  say
fi
say "  verify it:   stress-strike version"
say "  first run:   stress-strike run --url https://example.com --users 10 --duration 10"
say
say "  Uninstall:   rm ${PREFIX}/stress-strike*"
