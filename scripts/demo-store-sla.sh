#!/usr/bin/env bash
# demo-store-sla.sh — VeriGate SLA verify gate demo.
#
# Proves the protection system works by running the SAME stress-strike SLA
# gate twice against the VoltStore demo:
#
#   1. VeriGate ON  -> the attack is throttled -> errors > 5% -> SLA FAIL
#   2. VeriGate OFF -> the store absorbs the load -> SLA PASS
#
# A hardening system that flips a CI gate this way is exactly what a WAF is
# for. Run it on your own machine:
#
#   ./scripts/demo-store-sla.sh
#
# Exits 0 when the demo behaved as expected (ON->FAIL, OFF->PASS), 2 on a
# protection regression, 1 on infrastructure errors.
#
# Note: the store is launched from a locally built binary (not `go run`) so
# the process tree is killed cleanly and a stale orphan can never answer the
# next run from a previous protection state.

set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8092}"
ADDR="127.0.0.1:$PORT"
BASE="http://$ADDR"

# ---- pre-flight: port must be free -------------------------------------------
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "[sla] ERROR: port $PORT is already in use. Free it first:"
  echo "      lsof -nP -iTCP:$PORT"
  echo "      pkill -f demo-store"
  exit 1
fi

# Locate the stress-strike binary: prefer a fresh local build, fall back to PATH.
BIN="bin/stress-strike"
if [ ! -x "$BIN" ]; then
  BIN="$(command -v stress-strike || true)"
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "[sla] building ./bin/stress-strike ..."
  ./scripts/build-all.sh 0.14.0 >/dev/null
  BIN="bin/stress-strike"
fi
echo "[sla] using stress-strike: $BIN"

# ---- build + boot the protected store ----------------------------------------
echo "[sla] building ./bin/demo-store ..."
export GOFLAGS=-buildvcs=false CGO_ENABLED=0
go build -o bin/demo-store ./examples/demo_store

LOG="$(mktemp -t voltstore.XXXXXX.log)"
bin/demo-store -addr "$ADDR" -protect -rate-limit 100 -burst 300 \
  -block-after 6 >"$LOG" 2>&1 &
SERVER_PID=$!
cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  rm -f "$LOG"
}
trap cleanup EXIT

for _ in $(seq 1 60); do
  if curl -fsS "$BASE/health" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
curl -fsS "$BASE/health" >/dev/null

# Prove we are talking to the RIGHT instance with protection ON.
STATE="$(curl -fsS "$BASE/admin/stats")"
if ! echo "$STATE" | grep -q '"enabled": *true'; then
  echo "[sla] ERROR: store answered but VeriGate is not enabled: $STATE"
  exit 1
fi
echo "[sla] VoltStore up on $BASE (VeriGate ON — verified via /admin/stats)"

ATTACK=("$BIN" run --url "$BASE/" --users 500 --duration 6 \
  --expect-error-rate 5 --expect-min-rps 300 \
  --name verigate-sla --quiet --report-dir /tmp/verigate-sla-reports)
rm -rf /tmp/verigate-sla-reports

# ---- phase 1: protection ON ---------------------------------------------------
echo
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 1  —  VeriGate ON  (protection active)"
echo "═══════════════════════════════════════════════════════════════"
set +e
"${ATTACK[@]}"
RC1=$?
set -e
echo "  -> stress-strike exit code: $RC1 (expected 2 = SLA FAIL)"
STATE="$(curl -fsS "$BASE/admin/stats")"
echo "  -> VeriGate counters:"
echo "$STATE" | python3 -c "import json,sys; d=json.load(sys.stdin); print('     passed=%d limited=%d challenges=%d blocked=%d blocked_ips=%d' % (d['passed'], d['rate_limited'], d['challenges_served'], d['requests_blocked'], d['blocked_ips']))"

# ---- phase 2: protection OFF -------------------------------------------------
echo
echo "  [sla] toggling VeriGate OFF via POST /admin/protect ..."
curl -fsS -X POST "$BASE/admin/protect" -H 'Content-Type: application/json' \
  -d '{"enabled":false}' >/dev/null
STATE="$(curl -fsS "$BASE/admin/stats")"
if ! echo "$STATE" | grep -q '"enabled": *false'; then
  echo "[sla] ERROR: toggle OFF did not take effect: $STATE"
  exit 1
fi
echo "  [sla] VeriGate OFF confirmed via /admin/stats"
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 2  —  VeriGate OFF  (wide open)"
echo "═══════════════════════════════════════════════════════════════"
set +e
"${ATTACK[@]}"
RC2=$?
set -e
echo "  -> stress-strike exit code: $RC2 (expected 0 = SLA PASS)"

# ---- verdict -----------------------------------------------------------------
echo
echo "═══════════════════════════════════════════════════════════════"
if [ "$RC1" -eq 2 ] && [ "$RC2" -eq 0 ]; then
  echo "  VERDICT: VeriGate WORKS — ON blocks the attack (SLA FAIL),"
  echo "           OFF lets the store take the load (SLA PASS)."
  echo "═══════════════════════════════════════════════════════════════"
  exit 0
else
  echo "  VERDICT: UNEXPECTED — protection did not flip the gate."
  echo "           phase1(ON)=$RC1 (want 2)  phase2(OFF)=$RC2 (want 0)"
  echo "═══════════════════════════════════════════════════════════════"
  exit 2
fi