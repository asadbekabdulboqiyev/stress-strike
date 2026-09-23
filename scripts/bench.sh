#!/usr/bin/env bash
# bench.sh — real-world throughput benchmark for stress-strike.
#
# Boots the local demo server, builds the CLI, then drives it with a few
# concurrency levels and prints a compact req/s table. Use it to verify the
# engine's POWER targets on your own machine:
#
#   ./scripts/bench.sh            # quick sweep: 100/500/1000 users
#   ./scripts/bench.sh 2000 3000  # custom user counts
#
# Numbers depend on the machine. On a modern macOS/arm64 laptop the
# localhost shift is ~90-120k req/s (see the table in README); Linux with a
# 4096 listen backlog reaches the same engine ceiling with zero errors.
#
# shellcheck disable=SC2086
set -euo pipefail

cd "$(dirname "$0")/.."

BIN=bin/stress-strike
export GOFLAGS=-buildvcs=false

if [ ! -x "$BIN" ]; then
  echo "[bench] building $BIN ..."
  ./scripts/build-all.sh 0.14.0 >/dev/null
fi

DEMO_ADDR="${DEMO_ADDR:-127.0.0.1:8899}"
DEMO_LOG="$(mktemp -t bench-demo.XXXXXX)"
REPORT_DIR="$(mktemp -d -t bench-reports.XXXXXX)"
go run ./examples/demo_server.go "$DEMO_ADDR" >"$DEMO_LOG" 2>&1 &
DEMO_PID=$!
trap 'kill $DEMO_PID 2>/dev/null || true; rm -rf "$DEMO_LOG" "$REPORT_DIR"' EXIT

# Wait for the demo server to accept connections.
for _ in $(seq 1 50); do
  if curl -fsS "http://$DEMO_ADDR/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

fresh_report() {
  # newest JSON report in REPORT_DIR (lexical sort works: name_timestamp.json)
  ls -1t "$REPORT_DIR"/*.json 2>/dev/null | head -1
}

URL="http://$DEMO_ADDR/health"
USERS=("$@")
if [ ${#USERS[@]} -eq 0 ]; then
  USERS=(100 500 1000)
fi

printf '%-8s %-12s %-10s %-10s %-8s\n' "users" "total_reqs" "req/s" "errors" "err%"
printf '%s\n' "--------------------------------------------------------------"
for u in "${USERS[@]}"; do
  "$BIN" run --url "$URL" --users "$u" --duration 3 \
    --name "bench-u$u" --report-dir "$REPORT_DIR" --quiet >/dev/null 2>&1 || true
  RPT="$(fresh_report)"
  if [ -z "$RPT" ]; then
    printf '%-8s %s\n' "$u" "(run failed)"
    continue
  fi
  REQS=$(sed -n 's/.*"total_requests":[ ]*\([0-9]*\).*/\1/p' "$RPT")
  RPS=$(sed -n 's/.*"rps":[ ]*\([0-9.]*\).*/\1/p' "$RPT")
  ERRS=$(sed -n 's/.*"total_errors":[ ]*\([0-9]*\).*/\1/p' "$RPT")
  [ -z "$REQS" ] && REQS=0
  [ -z "$RPS" ] && RPS=0
  [ -z "$ERRS" ] && ERRS=0
  RPS=$(printf '%.0f' "$RPS")
  if [ "$REQS" -gt 0 ]; then
    ERRPCT=$((ERRS * 100 / REQS))
  else
    ERRPCT=0
  fi
  printf '%-8s %-12s %-10s %-10s %-8s\n' "$u" "$REQS" "$RPS" "$ERRS" "$ERRPCT%"
done

echo
echo "Done."