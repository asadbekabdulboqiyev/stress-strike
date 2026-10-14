#!/usr/bin/env bash
#
# verify-html-parity.sh — prove that the independent JavaScript verifier and the
# Go verifier agree on the same evidence, case by case.
#
# The browser page in docs/VERIFIER.html is a second, independent implementation
# of the vpmp/v1 verification algorithm. Agreement between two implementations
# is the whole point of a format: it is what turns "trust our tool" into "anyone
# can check". This script builds both verifiers, produces a real signed bundle
# with the CLI, tamper with it in four different ways, and asserts that both
# verifiers reach the same verdict — the same `valid` flag, the same number of
# checks run and failed, the same bundle digest, and the same list of failing
# check names.
#
# Usage:  bash scripts/verify-html-parity.sh
# Exit:   0 when every case agrees, 1 otherwise.

set -uo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

if ! command -v node >/dev/null 2>&1; then
  echo "verify-html-parity: node is required (the JavaScript verifier runs on it)" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "verify-html-parity: python3 is required (to tamper with the fixtures)" >&2
  exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/vb-parity.XXXXXX")
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null
    wait "$server_pid" 2>/dev/null
  fi
  rm -rf "$work"
}
trap cleanup EXIT

say() { printf '%s\n' "$*"; }

# A free loopback port, so the script never collides with a running server.
port=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)

say "verify-html-parity: building the Go CLI and a demo target"
go build -o "$work/stress-strike" ./cmd/stress-strike || { say "FAIL: could not build the CLI"; exit 1; }
go build -o "$work/demo_server" ./examples/demo_server.go || { say "FAIL: could not build the demo server"; exit 1; }

say "verify-html-parity: starting the demo target on 127.0.0.1:$port"
"$work/demo_server" "127.0.0.1:$port" >"$work/server.log" 2>&1 &
server_pid=$!

ready=0
for _ in $(seq 1 80); do
  if curl -sf -o /dev/null --max-time 1 "http://127.0.0.1:$port/health"; then ready=1; break; fi
  sleep 0.25
done
if [[ "$ready" != 1 ]]; then
  say "FAIL: the demo target never became healthy; see $work/server.log"
  cat "$work/server.log" >&2 || true
  exit 1
fi

say "verify-html-parity: signing a real bundle with the CLI"
"$work/stress-strike" keygen --out "$work/k.key" >"$work/keygen.log" 2>&1 || { say "FAIL: keygen"; exit 1; }

# The run may exit non-zero on an SLA failure; the bundle is sealed regardless,
# so capture the code instead of aborting.
"$work/stress-strike" run \
  --url "http://127.0.0.1:$port/health" \
  --rps 400 --users 8 --duration 4 \
  --coordinated-omission \
  --emit-bundle "$work/gen.json" \
  --bundle-key "$work/k.key" \
  --allow-private \
  --report-dir "$work/report" >"$work/run.log" 2>&1
say "verify-html-parity: run exited $? (a non-zero SLA exit is fine; the bundle is sealed first)"

if [[ ! -s "$work/gen.json" || ! -s "$work/gen.samples.jsonl" ]]; then
  say "FAIL: the CLI did not write a bundle and sidecar"
  cat "$work/run.log" >&2 || true
  exit 1
fi

samples=$(wc -l < "$work/gen.samples.jsonl" | tr -d ' ')
say "verify-html-parity: sealed $(basename "$work/gen.json") with $samples raw records"

# A bundle alone in its own directory, so neither verifier can find a sidecar.
mkdir -p "$work/absent"
cp "$work/gen.json" "$work/absent/absent.json"

# The tamper fixtures. Reformatting is harmless: both verifiers canonicalise.
python3 - "$work" <<'PY'
import json, sys
work = sys.argv[1]
src = open(f"{work}/gen.json").read()

# 1. A single flipped hex character in the worker's Merkle root.
j = json.loads(src)
mr = j["workers"][0]["commit"]["merkle_root"]
j["workers"][0]["commit"]["merkle_root"] = ("f" if mr[0] != "f" else "0") + mr[1:]
open(f"{work}/tamper-root.json", "w").write(json.dumps(j))

# 2. A one-nanosecond lie in the claimed p99.
j = json.loads(src)
j["aggregate"]["p99_ns"] = j["aggregate"]["p99_ns"] + 1
open(f"{work}/tamper-claim.json", "w").write(json.dumps(j))

# 3. One latency in the raw sidecar changed by a microsecond.
lines = open(f"{work}/gen.samples.jsonl").read().split("\n")
for i, line in enumerate(lines):
    if line.strip():
        o = json.loads(line)
        o["latency_ns"] = o["latency_ns"] + 1000
        lines[i] = json.dumps(o, separators=(",", ":"))
        break
open(f"{work}/tamper-sidecar.samples.jsonl", "w").write("\n".join(lines))
PY

if [[ ! -s "$work/tamper-root.json" || ! -s "$work/tamper-sidecar.samples.jsonl" ]]; then
  say "FAIL: could not build the tamper fixtures"
  exit 1
fi

run_go() {
  if [[ -n "${3:-}" ]]; then
    "$work/stress-strike" verify --bundle "$2" --samples "$3" --json >"$1" 2>/dev/null
  else
    "$work/stress-strike" verify --bundle "$2" --json >"$1" 2>/dev/null
  fi
  return 0
}
run_js() {
  if [[ -n "${3:-}" ]]; then
    node web/verifier/verify-cli.mjs --bundle "$2" --samples "$3" --json >"$1" 2>/dev/null
  else
    node web/verifier/verify-cli.mjs --bundle "$2" --json >"$1" 2>/dev/null
  fi
  return 0
}

failures=0
compare() {
  local name="$1" bundle="$2" samples="${3:-}"
  run_go "$work/go.json" "$bundle" "$samples"
  run_js "$work/js.json" "$bundle" "$samples"
  if python3 - "$work/go.json" "$work/js.json" "$name" <<'PY'
import json, sys
go_path, js_path, name = sys.argv[1], sys.argv[2], sys.argv[3]
g = json.load(open(go_path))
j = json.load(open(js_path))

bad = []
for field in ("valid", "checks_run", "checks_failed", "samples_total", "bundle_digest"):
    if g.get(field) != j.get(field):
        bad.append(f"{field}: go={g.get(field)!r} js={j.get(field)!r}")

g_fails = sorted(e["check"] for e in g.get("errors", []))
j_fails = sorted(e["check"] for e in j.get("errors", []))
if g_fails != j_fails:
    bad.append(f"failing checks: go={g_fails} js={j_fails}")

verdict = "PASS" if g.get("valid") else "FAIL"
tag = "ok  " if not bad else "DIFF"
print(f"  {tag} {name:22} verdict={verdict} checks={g.get('checks_run')}/{g.get('checks_failed')} samples={g.get('samples_total')}")
for b in bad:
    print(f"         {b}")
sys.exit(1 if bad else 0)
PY
  then
    : # agreement
  else
    failures=$((failures + 1))
  fi
}

say "verify-html-parity: comparing the Go and JavaScript verifiers"
say ""
compare "genuine"                 "$work/gen.json"        "$work/gen.samples.jsonl"
compare "tampered merkle root"    "$work/tamper-root.json" "$work/gen.samples.jsonl"
compare "tampered p99 claim"      "$work/tamper-claim.json" "$work/gen.samples.jsonl"
compare "tampered sidecar"        "$work/gen.json"        "$work/tamper-sidecar.samples.jsonl"
compare "sidecar absent"          "$work/absent/absent.json" ""
say ""

if [[ "$failures" -eq 0 ]]; then
  say "verify-html-parity: OK — the two independent verifiers agree on every case."
  exit 0
fi
say "verify-html-parity: FAILED — $failures case(s) disagree."
exit 1
