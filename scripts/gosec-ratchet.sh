#!/usr/bin/env bash
# gosec-ratchet.sh — turn gosec from a permanently green reporter into a ratchet.
#
# Policy (maintainer decision, see .github/workflows/security.yml): a gosec
# error-level finding outside the G204/G304 allowlist FAILS the build unless it
# matches a committed baseline entry in .gosec-baseline.json. The pre-existing
# findings are frozen as debt — frozen, not accepted — so a NEW one cannot land,
# while the ratchet does not block on work that predates it. G204 (subprocess)
# and G304 (file inclusion) are allowlisted because this tool reads
# user-supplied pcap/report paths by design and never spawns a shell from
# untrusted input.
#
# Usage:
#   scripts/gosec-ratchet.sh [report.sarif]           # check; exit 1 on new findings
#   scripts/gosec-ratchet.sh --update [report.sarif]  # rewrite the baseline
#   scripts/gosec-ratchet.sh -h
#
# Exit codes: 0 no new findings, 1 new findings found, 2 the check could not run
# (missing jq, missing report, unreadable baseline) — never silently green.
#
# Generate the report with the gosec version CI pins, so the two agree:
#   GOBIN=/tmp/gobin go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0
#   /tmp/gobin/gosec -no-fail -fmt sarif -out gosec.sarif ./...
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PROGRAM="$ROOT/scripts/gosec-ratchet.jq"
BASELINE="${GOSEC_BASELINE:-$ROOT/.gosec-baseline.json}"
POLICY='Ratchet, not a report: a gosec error-level finding outside the G204/G304 allowlist fails the build unless it matches an entry below by (ruleId, file, normalised source line). These entries are frozen debt, not accepted risk - fix them when you touch the code, and do not add to them. Line numbers are deliberately not stored (they move); the occurrence count is, so an extra copy of a known line is still a new finding. Refresh after a reviewed change with: scripts/gosec-ratchet.sh --update gosec.sarif'

MODE=check
SARIF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --update) MODE=update ;;
    -h | --help)
      sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    --) shift && break ;;
    -*) echo "gosec-ratchet: unknown option: $1" >&2; exit 2 ;;
    *) SARIF=$1 ;;
  esac
  shift
done
[ -n "$SARIF" ] || SARIF="$ROOT/gosec.sarif"

command -v jq >/dev/null 2>&1 || { echo "gosec-ratchet: jq is required but not on PATH" >&2; exit 2; }
[ -f "$PROGRAM" ] || { echo "gosec-ratchet: missing $PROGRAM" >&2; exit 2; }
if [ ! -f "$SARIF" ]; then
  echo "gosec-ratchet: no SARIF report at $SARIF" >&2
  echo "  produce one with: gosec -no-fail -fmt sarif -out gosec.sarif ./..." >&2
  exit 2
fi

# A malformed report must never read as "nothing found": jq fails loudly here
# and `set -e` turns that into a non-zero exit for the whole script.
jq -e '.runs' "$SARIF" >/dev/null 2>&1 || {
  echo "gosec-ratchet: $SARIF is not a gosec SARIF report (no .runs array)" >&2
  exit 2
}

if [ "$MODE" = update ]; then
  [ -f "$BASELINE" ] || echo '{"findings":[]}' > "$BASELINE"
  jq -e '.findings' "$BASELINE" >/dev/null 2>&1 || {
    echo "gosec-ratchet: existing baseline $BASELINE is not a baseline file" >&2
    exit 2
  }
  tmp=$(mktemp "${TMPDIR:-/tmp}/gosec-baseline.XXXXXX")
  jq -n --slurpfile s "$SARIF" --slurpfile b "$BASELINE" \
    --arg mode update --arg policy "$POLICY" -f "$PROGRAM" > "$tmp"
  mv "$tmp" "$BASELINE"
  unique=$(jq '.findings | length' "$BASELINE")
  total=$(jq '[.findings[].count] | add // 0' "$BASELINE")
  echo "gosec-ratchet: baseline written to $BASELINE"
  echo "  frozen: $unique distinct finding(s), $total occurrence(s)"
  exit 0
fi

[ -f "$BASELINE" ] || {
  echo "gosec-ratchet: no baseline at $BASELINE" >&2
  echo "  create one with: scripts/gosec-ratchet.sh --update $SARIF" >&2
  exit 2
}
jq -e '.findings' "$BASELINE" >/dev/null 2>&1 || {
  echo "gosec-ratchet: baseline $BASELINE is not a baseline file" >&2
  exit 2
}

report=$(jq -n --slurpfile s "$SARIF" --slurpfile b "$BASELINE" \
  --arg mode check --arg policy "$POLICY" -f "$PROGRAM")

new_count=$(jq '.new | length' <<<"$report")
new_total=$(jq '[.new[].delta] | add // 0' <<<"$report")
fixed_total=$(jq '[.fixed[].delta] | add // 0' <<<"$report")
known_total=$(jq '.current_total' <<<"$report")

if [ "$new_count" -gt 0 ]; then
  # Annotate the offending lines in the GitHub UI, one annotation per location.
  while IFS=$'\t' read -r file line rule message code; do
    printf '::error file=%s,line=%s::gosec %s: %s\n' "$file" "$line" "$rule" "$message"
  done < <(jq -r '.new[] | [.file, .line, .rule, .message, .code] | @tsv' <<<"$report")

  echo
  echo "gosec-ratchet: FAIL — $new_total new error-level finding(s) at $new_count location(s)"
  echo "these are not in the baseline, so they would have landed unreviewed:"
  jq -r '.new[] | "  \(.rule)  \(.file):\(.line)\n      \(.message)\n      \(.code)"' <<<"$report"
  echo
  echo "Fix them, or — if each is a deliberate, reviewed exception — freeze them with:"
  echo "  scripts/gosec-ratchet.sh --update $SARIF"
  exit 1
fi

echo "gosec-ratchet: PASS — no new error-level findings (frozen: $known_total; fixed since the baseline: $fixed_total)"
if [ "$fixed_total" -gt 0 ]; then
  echo "  $fixed_total frozen finding(s) are gone — tighten the ratchet with: scripts/gosec-ratchet.sh --update $SARIF"
  jq -r '.fixed[] | "  \(.rule)  \(.file)\n      \(.code)"' <<<"$report"
fi
