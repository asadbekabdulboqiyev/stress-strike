#!/usr/bin/env bash
# gosec-ratchet-test.sh — self-test for scripts/gosec-ratchet.sh.
#
# The ratchet is a build gate, so it gets tests like any other gate. These use
# tiny synthetic SARIF reports and need only jq: no gosec binary, no full scan,
# no network. What is proven:
#
#   1. a fresh baseline freezes what is there, and then passes
#   2. a NEW finding fails (exit 1) and is named in the output
#   3. a new finding in an ALLOWLISTED rule (G304) does not fail — by design
#   4. a frozen finding that is GONE is reported as fixed, still exit 0
#   5. one extra occurrence of an already-frozen line is still a new finding
#   6. a rule change on the same line is a new finding (identity is not just text)
#   7. unreadable inputs (no baseline, junk baseline, no report, junk report)
#      exit 2 — the gate can never read "nothing found" out of a failure
#   8. --update is idempotent, and never freezes an allowlisted rule
#
# Usage: bash scripts/gosec-ratchet-test.sh
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RATCHET="$ROOT/scripts/gosec-ratchet.sh"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/gosec-ratchet-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok() { printf '  ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() {
  printf '  FAIL %s\n' "$1"
  [ $# -gt 1 ] && printf '       %s\n' "$2"
  fail=$((fail + 1))
}
check() { # check <label> <expected-exit> <expected-substring> <sarif> <baseline>
  local label=$1 want=$2 needle=$3 sarif=$4 baseline=$5 rc=0 out=""
  out=$(GOSEC_BASELINE="$baseline" bash "$RATCHET" "$sarif" 2>&1) || rc=$?
  if [ "$rc" -ne "$want" ]; then
    bad "$label" "exit $rc, wanted $want :: $out"
    return
  fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" <<<"$out"; then
    bad "$label" "output does not mention '$needle' :: $out"
    return
  fi
  ok "$label"
}

# mk_sarif <out> <json array of [rule, file, line, snippet, message]>
mk_sarif() {
  jq -n --argjson rows "$2" '{
    runs: [{
      results: [
        $rows[] | {
          level: "error",
          ruleId: .[0],
          message: {text: .[4]},
          locations: [{
            physicalLocation: {
              artifactLocation: {uri: .[1]},
              region: {startLine: .[2], snippet: {text: .[3]}}
            }
          }]
        }
      ]
    }]
  }' >"$WORK/$1"
}

command -v jq >/dev/null 2>&1 || { echo "gosec-ratchet-test: jq is required" >&2; exit 2; }

A='[["G115","internal/a.go",10,"x := int64(y)","integer overflow conversion"],
    ["G402","internal/b.go",20,"tls.Config{InsecureSkipVerify: true}","bad TLS"],
    ["G304","internal/c.go",30,"f, _ := os.Open(p)","file inclusion"]]'
mk_sarif a.json "$A"

echo "gosec-ratchet self-test"
echo
echo "baseline freeze and pass"
BASE="$WORK/baseline.json"
GOSEC_BASELINE="$BASE" bash "$RATCHET" --update "$WORK/a.json" >/dev/null
if [ "$(jq '.findings | length' "$BASE")" -eq 2 ]; then
  ok "--update froze the 2 non-allowlisted findings"
else
  bad "--update froze $(jq '.findings | length' "$BASE") findings, wanted 2"
fi
if jq -e '.findings[] | select(.rule == "G304")' "$BASE" >/dev/null 2>&1; then
  bad "--update froze an allowlisted G304"
else
  ok "--update did not freeze the allowlisted G304"
fi
check "the same report passes afterwards" 0 "PASS" "$WORK/a.json" "$BASE"

echo
echo "new findings fail; the failing rules are named"
NEW='[["G115","internal/a.go",10,"x := int64(y)","integer overflow conversion"],
      ["G402","internal/b.go",20,"tls.Config{InsecureSkipVerify: true}","bad TLS"],
      ["G401","internal/d.go",40,"md5.New()","weak primitive"]]'
mk_sarif new.json "$NEW"
check "a NEW G401 fails the build" 1 "G401" "$WORK/new.json" "$BASE"
check "the failure names the file" 1 "internal/d.go:40" "$WORK/new.json" "$BASE"
check "the failure tells you how to freeze it" 1 "--update" "$WORK/new.json" "$BASE"

ALLOW='[["G115","internal/a.go",10,"x := int64(y)","integer overflow conversion"],
        ["G402","internal/b.go",20,"tls.Config{InsecureSkipVerify: true}","bad TLS"],
        ["G304","internal/new.go",50,"f, _ := os.Open(q)","file inclusion"]]'
mk_sarif allow.json "$ALLOW"
check "a new ALLOWLISTED G304 still passes (design)" 0 "PASS" "$WORK/allow.json" "$BASE"

FIXED='[["G115","internal/a.go",10,"x := int64(y)","integer overflow conversion"]]'
mk_sarif fixed.json "$FIXED"
check "a frozen finding that is gone is not a failure" 0 "fixed since the baseline: 1" "$WORK/fixed.json" "$BASE"
check "the fixed finding is named" 0 "internal/b.go" "$WORK/fixed.json" "$BASE"

echo
echo "identity: occurrence count and rule, not just the text"
DUP='[["G402","internal/b.go",20,"tls.Config{InsecureSkipVerify: true}","bad TLS"],
      ["G402","internal/b.go",21,"tls.Config{InsecureSkipVerify: true}","bad TLS"]]'
mk_sarif dup.json "$DUP"
DUPBASE="$WORK/dup-baseline.json"
GOSEC_BASELINE="$DUPBASE" bash "$RATCHET" --update "$WORK/dup.json" >/dev/null
if [ "$(jq '.findings[0].count' "$DUPBASE")" -eq 2 ]; then
  ok "the same line twice freezes as count 2"
else
  bad "duplicate counting: $(jq -c '.findings[0]' "$DUPBASE")"
fi
check "the same two lines still pass" 0 "PASS" "$WORK/dup.json" "$DUPBASE"
THREE='[["G402","internal/b.go",20,"tls.Config{InsecureSkipVerify: true}","bad TLS"],
        ["G402","internal/b.go",21,"tls.Config{InsecureSkipVerify: true}","bad TLS"],
        ["G402","internal/b.go",22,"tls.Config{InsecureSkipVerify: true}","bad TLS"]]'
mk_sarif three.json "$THREE"
check "a THIRD copy of a frozen line is a new finding" 1 "G402" "$WORK/three.json" "$DUPBASE"

RERULED='[["G115","internal/a.go",10,"x := int64(y)","integer overflow conversion"],
          ["G404","internal/b.go",20,"tls.Config{InsecureSkipVerify: true}","bad TLS"]]'
mk_sarif reruled.json "$RERULED"
check "same line, different rule is a new finding" 1 "G404" "$WORK/reruled.json" "$BASE"

echo
echo "failure to run never looks like success"
check "missing baseline exits 2" 2 "no baseline" "$WORK/a.json" "$WORK/nope.json"
echo '{}' >"$WORK/junk.json"
check "malformed baseline exits 2" 2 "not a baseline file" "$WORK/a.json" "$WORK/junk.json"
check "missing report exits 2" 2 "no SARIF report" "$WORK/nope.json" "$BASE"
echo 'not json' >"$WORK/broken.json"
check "unparsable report exits 2" 2 "not a gosec SARIF report" "$WORK/broken.json" "$BASE"
echo '{"runs":[]}' >"$WORK/emptyruns.json"
check "an empty (but valid) report passes with zero findings" 0 "fixed since the baseline: 2" "$WORK/emptyruns.json" "$BASE"

echo
echo "update mode"
cp "$BASE" "$WORK/again.json"
GOSEC_BASELINE="$WORK/again.json" bash "$RATCHET" --update "$WORK/a.json" >/dev/null
if diff -q "$BASE" "$WORK/again.json" >/dev/null; then
  ok "--update is idempotent"
else
  bad "--update is not idempotent" "$(diff "$BASE" "$WORK/again.json" | head -3)"
fi

echo
if [ "$fail" -gt 0 ]; then
  printf 'gosec-ratchet-test: FAIL — %d passed, %d failed\n' "$pass" "$fail"
  exit 1
fi
printf 'gosec-ratchet-test: OK — %d checks passed\n' "$pass"
