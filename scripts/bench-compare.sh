#!/usr/bin/env bash
# bench-compare.sh — independent load-test comparison harness.
#
# Runs Sift, k6, wrk2, Gatling, and Locust against the same local
# demo target and prints a compact req/s + error-rate table so the operator
# can see how Sift compares to established tools.
#
# Usage:
#   ./scripts/bench-compare.sh          # default 100s run at 500 users
#   BENCH_SECONDS=60 ./scripts/bench-compare.sh
#   BENCH_USERS=1000 ./scripts/bench-compare.sh
#
# Prerequisites (optional — missing tools are skipped with a warning):
#   k6        https://k6.io
#   wrk2      https://github.com/giltene/wrk2
#   gatling   https://gatling.io
#   locust    https://locust.io
#
set -euo pipefail

cd "$(dirname "$0")/.."

export GOFLAGS=-buildvcs=false

BIN="bin/Sift"
DEMO_ADDR="${DEMO_ADDR:-127.0.0.1:8899}"
BENCH_SECONDS="${BENCH_SECONDS:-100}"
BENCH_USERS="${BENCH_USERS:-500}"
BENCH_URL="${BENCH_URL:-http://$DEMO_ADDR/}"
REPORT_DIR="$(mktemp -d -t bench-compare.XXXXXX)"
DEMO_LOG="$(mktemp -t bench-demo-compare.XXXXXX)"

trap 'rm -rf "$REPORT_DIR" "$DEMO_LOG"' EXIT

log() { printf '[bench-compare] %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Build Sift + demo server
# ---------------------------------------------------------------------------
log "building Sift binary ..."
if [ ! -x "$BIN" ]; then
  ./scripts/build-all.sh 0.14.0 >/dev/null 2>&1 || go build -o "$BIN" ./cmd/Sift
fi

# Build demo server if needed.
if ! go run ./examples/demo_server.go "$DEMO_ADDR" >"$DEMO_LOG" 2>&1 &
then
  log "ERROR: failed to start demo server"
  cat "$DEMO_LOG"
  exit 1
fi
DEMO_PID=$!

cleanup() { kill "$DEMO_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Wait for demo server.
log "waiting for demo server at $DEMO_ADDR ..."
for _ in $(seq 1 100); do
  if curl -fsS "http://$DEMO_ADDR/health" >/dev/null 2>&1; then
    log "demo server ready"
    break
  fi
  sleep 0.1
done
if ! curl -fsS "http://$DEMO_ADDR/health" >/dev/null 2>&1; then
  log "ERROR: demo server never became healthy"
  cat "$DEMO_LOG"
  exit 1
fi

# ---------------------------------------------------------------------------
# Helper: run a command and capture {reqs, errors, duration}
# Returns JSON line: {"tool":"...","reqs":N,"errors":M,"rps":X,"duration":Y}
# ---------------------------------------------------------------------------
run_and_record() {
  local tool="$1"; shift
  local start end reqs errors duration rps out
  start=$(date +%s.%N)
  out="$("$@" 2>&1)" || true
  end=$(date +%s.%N)
  duration=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e-s}')
  # crude req/error extraction: look for "requests" and "errors" numbers
  reqs=$(echo "$out" | grep -oE '[0-9,]+ *requests' | head -1 | grep -oE '[0-9,]+' | tr -d ',' || echo 0)
  errors=$(echo "$out" | grep -oiE '[0-9,]+ *(errors|failed|non-2xx)' | head -1 | grep -oE '[0-9,]+' | tr -d ',' || echo 0)
  [ -z "$reqs" ] && reqs=0
  [ -z "$errors" ] && errors=0
  if [ "$duration" != "0.000" ]; then
    rps=$(awk -v r="$reqs" -v d="$duration" 'BEGIN{printf "%.1f", r/d}')
  else
    rps=0
  fi
  printf '{"tool":"%s","reqs":%s,"errors":%s,"rps":%s,"duration":%s}\n' \
    "$tool" "$reqs" "$errors" "$rps" "$duration" >> "$REPORT_DIR/results.jsonl"
  log "$tool: reqs=$reqs errors=$errors rps=$rps duration=${duration}s"
}

# ---------------------------------------------------------------------------
# Sift
# ---------------------------------------------------------------------------
if [ -x "$BIN" ]; then
  log "running Sift ($BENCH_USERS users, ${BENCH_SECONDS}s) ..."
  run_and_record Sift "$BIN" run \
    --url "$BENCH_URL" \
    --users "$BENCH_USERS" \
    --duration "${BENCH_SECONDS}s" \
    --rps 0 \
    --quiet
fi

# ---------------------------------------------------------------------------
# k6
# ---------------------------------------------------------------------------
if command -v k6 >/dev/null 2>&1; then
  log "running k6 ($BENCH_USERS VUs, ${BENCH_SECONDS}s) ..."
  K6_SCRIPT="$REPORT_DIR/k6-test.js"
  cat > "$K6_SCRIPT" <<K6EOF
import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
  vus: $BENCH_USERS,
  duration: '${BENCH_SECONDS}s',
  thresholds: {
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  http.get('$BENCH_URL');
  sleep(0.01);
}
K6EOF
  run_and_record k6 k6 run --quiet "$K6_SCRIPT"
else
  log "SKIP: k6 not installed"
fi

# ---------------------------------------------------------------------------
# wrk2
# ---------------------------------------------------------------------------
if command -v wrk2 >/dev/null 2>&1 || command -v wrk >/dev/null 2>&1; then
  WRK_BIN="$(command -v wrk2 2>/dev/null || command -v wrk 2>/dev/null)"
  log "running wrk2/wrk ($BENCH_USERS connections, ${BENCH_SECONDS}s) ..."
  run_and_record wrk2 "$WRK_BIN" -t 8 -c "$BENCH_USERS" -d "${BENCH_SECONDS}s" "$BENCH_URL"
else
  log "SKIP: wrk2/wrk not installed"
fi

# ---------------------------------------------------------------------------
# Gatling
# ---------------------------------------------------------------------------
if command -v gatling >/dev/null 2>&1; then
  log "running gatling ..."
  GATLING_SCRIPT="$REPORT_DIR/GatlingSim.scala"
  cat > "$GATLING_SCRIPT" <<GATEOF
import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

class BenchSim extends Simulation {
  val httpProtocol = http.baseUrl("$DEMO_ADDR")
  val scn = scenario("Bench").exec(http("get").get("/")).pause(0.01)
  setUp(scn.inject(constantUsersPerSec($BENCH_USERS) during ($BENCH_SECONDS seconds)))
    .protocols(httpProtocol)
}
GATEOF
  run_and_record gatling gatling run -s "$GATLING_SCRIPT" -rf "$REPORT_DIR" -on "bench-compare"
else
  log "SKIP: gatling not installed"
fi

# ---------------------------------------------------------------------------
# Locust
# ---------------------------------------------------------------------------
if command -v locust >/dev/null 2>&1; then
  log "running locust ($BENCH_USERS users, hatch 50/s, ${BENCH_SECONDS}s) ..."
  LOCUST_FILE="$REPORT_DIR/locustfile.py"
  cat > "$LOCUST_FILE" <<LOCEOF
from locust import HttpUser, task, between

class BenchUser(HttpUser):
    wait_time = between(0, 0.01)
    host = "$DEMO_ADDR"

    @task
    def index(self):
        self.client.get("/")
LOCEOF
  run_and_record locust locust -f "$LOCUST_FILE" --headless -u "$BENCH_USERS" -r 50 -t "${BENCH_SECONDS}s" --html "$REPORT_DIR/locust.html"
else
  log "SKIP: locust not installed"
fi

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
log ""
log "========== RESULTS =========="
printf '%-16s %-12s %-10s %-10s %-10s\n' "TOOL" "REQS" "ERRORS" "RPS" "DURATION(s)"
printf '%-16s %-12s %-10s %-10s %-10s\n' "----------------" "------------" "----------" "----------" "----------"
if [ -f "$REPORT_DIR/results.jsonl" ]; then
  while IFS= read -r line; do
    tool=$(echo "$line" | grep -oE '"tool":"[^"]+"' | grep -oE '[^"]+$')
    reqs=$(echo "$line" | grep -oE '"reqs":[0-9]+' | grep -oE '[0-9]+')
    errors=$(echo "$line" | grep -oE '"errors":[0-9]+' | grep -oE '[0-9]+')
    rps=$(echo "$line" | grep -oE '"rps":[0-9.]+' | grep -oE '[0-9.]+')
    dur=$(echo "$line" | grep -oE '"duration":[0-9.]+' | grep -oE '[0-9.]+')
    printf '%-16s %-12s %-10s %-10s %-10s\n' "$tool" "${reqs:-0}" "${errors:-0}" "${rps:-0}" "${dur:-0}"
  done < "$REPORT_DIR/results.jsonl"
fi
printf '%-16s %-12s %-10s %-10s %-10s\n' "----------------" "------------" "----------" "----------" "----------"
log ""
log "Raw results: $REPORT_DIR/results.jsonl"
log "Done."
