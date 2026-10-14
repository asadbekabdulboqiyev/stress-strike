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
# It then runs four *hardening* cases: structurally hostile inputs (a worker or a
# sidecar record hidden behind a "__proto__" key, a record padded past the 16 KiB
# line cap, and a bundle claiming 2^62 samples). For these the two
# implementations may legitimately enumerate different schema errors, so only the
# property that matters is asserted: neither verifier accepts the file, and
# neither one dies (a Go exit code of 2 means a panic and no report).
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

# Hardening fixtures: structurally hostile inputs. Each one used to be (or could
# have been) a differential — a file one verifier accepted and the other
# rejected — so the accept sets must stay in agreement with each other and with
# "nothing insane happens".
python3 - "$work" <<'PY'
import json, sys
work = sys.argv[1]
src = json.load(open(f"{work}/gen.json"))
recs = [l for l in open(f"{work}/gen.samples.jsonl").read().split("\n") if l.strip()]

# 1. The worker object hidden behind a key named "__proto__". In JavaScript a
#    naive reader sends that assignment through the inherited accessor, so the
#    fields stay readable through the prototype chain: the file verified, while
#    Go's struct decode saw an empty worker and rejected it.
j = json.loads(json.dumps(src))
j["workers"] = [{"__proto__": src["workers"][0]}]
open(f"{work}/hard-proto.json", "w").write(json.dumps(j))

# 2. The same trick in the unsigned sidecar (no signature needed to reach it).
with open(f"{work}/hard-proto.samples.jsonl", "w") as fh:
    for line in recs[:8]:
        fh.write(json.dumps({"__proto__": json.loads(line)}, separators=(",", ":")) + "\n")

# 3. Records padded past the 16 KiB per-line cap the Go loader enforces.
with open(f"{work}/hard-longline.samples.jsonl", "w") as fh:
    for line in recs[:8]:
        o = json.loads(line)
        o["pad"] = "x" * 20000
        fh.write(json.dumps(o, separators=(",", ":")) + "\n")

# 4. An aggregate count of 2^62: Go sized an allocation from that claim and died
#    with exit code 2 and no report at all.
huge = 1 << 62
j = json.loads(json.dumps(src))
j["workers"][0]["commit"]["sample_count"] = huge
j["workers"][0]["aggregate"]["count"] = huge
j["workers"][0]["aggregate"]["hist"] = {"1": huge}
j["aggregate"]["count"] = huge
open(f"{work}/hard-count.json", "w").write(json.dumps(j))

# 5. A worker with no commit object at all. The JS verifier used to throw a
#    TypeError here instead of returning a verdict, so `--json` printed nothing
#    at all while Go reported a schema failure.
j = json.loads(json.dumps(src))
j["workers"] = [{"id": src["workers"][0]["id"], "public_key": src["workers"][0]["public_key"]}]
open(f"{work}/hard-nocommit.json", "w").write(json.dumps(j))
PY

if [[ ! -s "$work/hard-proto.json" || ! -s "$work/hard-count.json" ]]; then
  say "FAIL: could not build the hardening fixtures"
  exit 1
fi

last_rc=0
run_go() {
  if [[ -n "${3:-}" ]]; then
    "$work/stress-strike" verify --bundle "$2" --samples "$3" --json >"$1" 2>/dev/null
  else
    "$work/stress-strike" verify --bundle "$2" --json >"$1" 2>/dev/null
  fi
  last_rc=$?
  return 0
}
run_js() {
  if [[ -n "${3:-}" ]]; then
    node web/verifier/verify-cli.mjs --bundle "$2" --samples "$3" --json >"$1" 2>/dev/null
  else
    node web/verifier/verify-cli.mjs --bundle "$2" --json >"$1" 2>/dev/null
  fi
  last_rc=$?
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

# assert_rejected checks a hostile input without demanding that both verifiers
# enumerate the same schema errors: Go reports a fatal input error for an
# unreadable sidecar, and the two implementations legitimately differ in how many
# schema errors they record. What must hold is that neither one accepts the file
# and that Go did not crash (exit code 2 = panic = no report).
assert_rejected() {
  local name="$1" bundle="$2" samples="${3:-}"
  local go_rc js_rc
  run_go "$work/go.json" "$bundle" "$samples"; go_rc=$last_rc
  run_js "$work/js.json" "$bundle" "$samples"; js_rc=$last_rc
  if python3 - "$work/go.json" "$work/js.json" "$name" "$go_rc" "$js_rc" <<'PY'
import json, sys
go_path, js_path, name, go_rc, js_rc = sys.argv[1:6]
bad = []
if go_rc == "2":
    bad.append("go exited 2 (panic): no report was produced")
elif go_rc == "0":
    bad.append("go accepted a hostile input")
if js_rc == "0":
    bad.append("js accepted a hostile input")
try:
    g = json.load(open(go_path))
    if g.get("valid"):
        bad.append("go reported valid=true")
except Exception:
    pass  # an unreadable sidecar is a fatal input error in the Go CLI
try:
    j = json.load(open(js_path))
    if j.get("valid"):
        bad.append("js reported valid=true")
except Exception:
    bad.append("js produced no JSON report")
tag = "ok  " if not bad else "DIFF"
print(f"  {tag} {name:22} verdict=both-reject go_exit={go_rc} js_exit={js_rc}")
for b in bad:
    print(f"         {b}")
sys.exit(1 if bad else 0)
PY
  then
    : # both verifiers refused it
  else
    failures=$((failures + 1))
  fi
}

say "verify-html-parity: hostile inputs (both verifiers must refuse, neither may crash)"
say ""
assert_rejected "proto-wrapped worker"  "$work/hard-proto.json"    "$work/gen.samples.jsonl"
assert_rejected "proto-wrapped sidecar" "$work/gen.json"           "$work/hard-proto.samples.jsonl"
assert_rejected "20 KiB sidecar line"   "$work/gen.json"           "$work/hard-longline.samples.jsonl"
assert_rejected "2^62 sample claim"     "$work/hard-count.json"    "$work/gen.samples.jsonl"
say ""

# compare_shape is compare without the bundle digest: for a structurally broken
# bundle one implementation may legitimately have no digest to report, but the
# verdict and the failing check names must still match exactly.
compare_shape() {
  local name="$1" bundle="$2" samples="${3:-}"
  run_go "$work/go.json" "$bundle" "$samples"
  run_js "$work/js.json" "$bundle" "$samples"
  if python3 - "$work/go.json" "$work/js.json" "$name" <<'PY'
import json, sys
go_path, js_path, name = sys.argv[1:4]
g = json.load(open(go_path))
j = json.load(open(js_path))
bad = []
for field in ("valid", "checks_run", "checks_failed"):
    if g.get(field) != j.get(field):
        bad.append(f"{field}: go={g.get(field)!r} js={j.get(field)!r}")
g_fails = sorted(e["check"] for e in g.get("errors", []))
j_fails = sorted(e["check"] for e in j.get("errors", []))
if g_fails != j_fails:
    bad.append(f"failing checks: go={g_fails} js={j_fails}")
tag = "ok  " if not bad else "DIFF"
print(f"  {tag} {name:22} verdict={'PASS' if g.get('valid') else 'FAIL'} checks={g.get('checks_run')}/{g.get('checks_failed')}")
for b in bad:
    print(f"         {b}")
sys.exit(1 if bad else 0)
PY
  then
    : # identical shape
  else
    failures=$((failures + 1))
  fi
}

say "verify-html-parity: malformed bundle (same verdict and same failing checks)"
say ""
compare_shape "worker without commit" "$work/hard-nocommit.json" ""
say ""

if [[ "$failures" -eq 0 ]]; then
  say "verify-html-parity: OK — the two independent verifiers agree on every case,"
  say "                     and neither accepts nor crashes on the hostile inputs."
  exit 0
fi
say "verify-html-parity: FAILED — $failures case(s) disagree."
exit 1
