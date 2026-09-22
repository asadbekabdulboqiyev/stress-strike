#!/usr/bin/env bash
#
# start.sh — one command, works for a complete beginner.
#
#   ./start.sh
#
# No Docker. No SSH. No servers. No accounts. Nothing to install beyond a
# Go toolchain (and on macOS/Linux you usually already have this machine
# covered). This script:
#
#   1. builds stress-strike + the bundled demo site (only on first run)
#   2. starts the demo site on http://127.0.0.1:8080
#   3. starts the live web dashboard on http://localhost:8888
#   4. opens your browser so you can press Start
#
# Stop everything at any time with Ctrl+C.
#
# Environment overrides:
#   DEMO_PORT   demo site port  (default 8080)
#   DASH_PORT   dashboard port  (default 8888)
#   NO_OPEN=1   do not auto-open the browser
#   URL=...     test a real URL instead of the demo site (e.g. URL=https://example.com)
#   USERS=...   virtual users used when you press Start (default 20)
#   DURATION=... run length in seconds (default 30)
#
# Examples:
#   ./start.sh
#   URL=https://api.example.com USERS=100 DURATION=60 ./start.sh
#   NO_OPEN=1 ./start.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${REPO_ROOT}"

DEMO_PORT="${DEMO_PORT:-8080}"
DASH_PORT="${DASH_PORT:-8888}"
URL="${URL:-}"
USERS="${USERS:-20}"
DURATION="${DURATION:-30}"

BANNER='=================================================='

say()  { printf '%s\n' "$*"; }
step() { printf '  \033[36m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m[warn]\033[0m %s\n' "$*"; }
err()  { printf '  \033[31m[error]\033[0m %s\n' "$*"; }

if ! command -v go >/dev/null 2>&1; then
  err "Go is not installed, and it is the only thing this needs."
  err "Install it in one step:"
  say ""
  say "  # macOS"
  say "  brew install go"
  say ""
  say "  # Linux (Debian/Ubuntu)"
  say "  sudo apt-get install -y golang-go"
  say ""
  err "Then run ./start.sh again."
  exit 1
fi

# --- 1. build (first run only, or when sources changed) ----------------------

NEED_RUN=false
for cmd in bin/stress-strike bin/demo-server; do
  [[ -x "$cmd" ]] || NEED_RUN=true
done

if $NEED_RUN; then
  step "first run detected — building (takes a few seconds)..."
  mkdir -p bin
  go build -trimpath -buildvcs=false -o bin/stress-strike ./cmd/stress-strike
  go build -trimpath -buildvcs=false -o bin/demo-server ./examples/demo_server.go
  ok "built bin/stress-strike and bin/demo-server"
fi

# --- 2. pick the target -------------------------------------------------------

if [[ -n "$URL" ]]; then
  TARGET="$URL"
  ok "target: ${TARGET} (${USERS} users, ${DURATION}s when you press Start)"
  DEMO_PID=""
else
  TARGET="http://127.0.0.1:${DEMO_PORT}/health"
  if lsof -nP -iTCP:${DEMO_PORT} -sTCP:LISTEN >/dev/null 2>&1; then
    warn "port ${DEMO_PORT} already in use — reusing it as the demo site"
    DEMO_PID=""
  else
    step "starting the bundled demo site on http://127.0.0.1:${DEMO_PORT}..."
    ./bin/demo-server "127.0.0.1:${DEMO_PORT}" &
    DEMO_PID=$!
    sleep 1
    ok "demo site up (a safe local target — nothing real can break)"
  fi
fi

cleanup() {
  if [[ -n "${DEMO_PID:-}" ]] && kill -0 "${DEMO_PID}" >/dev/null 2>&1; then
    kill "${DEMO_PID}" >/dev/null 2>&1 || true
    ok "demo site stopped"
  fi
}
trap cleanup EXIT

# --- 3. dashboard -------------------------------------------------------------

if lsof -nP -iTCP:${DASH_PORT} -sTCP:LISTEN >/dev/null 2>&1; then
  err "port ${DASH_PORT} is already in use."
  err "Close whatever is using it, or run again with DASH_PORT=9999 ./start.sh"
  exit 1
fi

say ""
say "${BANNER}"
say "  stress-strike — live web dashboard"
say "      stop anytime:  Ctrl+C"
say "${BANNER}"
say ""
say "  dashboard:  http://localhost:${DASH_PORT}"
say "  target:     ${TARGET}"
say ""

if [[ -n "${NO_OPEN:-}" ]]; then
  step "open http://localhost:${DASH_PORT} in your browser and press Start"
else
  step "opening your browser..."
  if command -v open >/dev/null 2>&1; then
    (sleep 1; open "http://localhost:${DASH_PORT}") &
  elif command -v xdg-open >/dev/null 2>&1; then
    (sleep 1; xdg-open "http://localhost:${DASH_PORT}") &
  else
    step "open http://localhost:${DASH_PORT} in your browser and press Start"
  fi
  ok "if nothing opened, paste this into a browser: http://localhost:${DASH_PORT}"
fi

say ""
step "press Start on the page — results stream live, nothing leaves your machine"
step "waiting on the dashboard (Ctrl+C when done)"
say ""

exec ./bin/stress-strike run \
  --url "${TARGET}" \
  --users "${USERS}" \
  --duration "${DURATION}" \
  --mode dashboard \
  --listen ":${DASH_PORT}"