# gosec-ratchet.jq — the comparison half of scripts/gosec-ratchet.sh.
#
# Inputs (slurped):
#   $s[0]  the gosec SARIF report
#   $b[0]  the committed baseline (.gosec-baseline.json)
#   $mode  "check" or "update"
#
# Identity of a finding is (ruleId, artifact path, normalised source line).
# Line numbers are deliberately NOT part of the identity: they move whenever
# unrelated code above a finding changes, and a baseline that churns on every
# unrelated edit trains reviewers to run --update without reading it. The
# occurrence COUNT is part of the identity, so one extra copy of an
# already-known line is still reported as a new finding.
#
# Storing the normalised source line (rather than a hash of it) keeps the
# baseline reviewable: you can read the file and see exactly what is frozen,
# and decide whether a frozen finding is still acceptable. Nothing is clipped,
# so two distinct lines cannot collide into one frozen entry.
#
# NOTE: gosec's SARIF spells the rule field `ruleId` (camelCase). Reading
# `.rule_id` yields null for every result, which would make this ratchet pass
# no matter what gosec found.
#
# The allowlisted rules are the two that are expected in a tool that reads
# user-supplied pcap/report paths by design and never spawns a shell:
#   G204  subprocess launched with a variable
#   G304  file inclusion via a variable
# They are filtered out here (not frozen in the baseline) so that the baseline
# stays about findings that are genuinely debt rather than accepted design.

def norm: gsub("[\\s]+"; " ") | sub("^ "; "") | sub(" $"; "");
def fkey: "\(.rule)|\(.file)|\(.code)";

[ $s[0].runs[].results[]
    | select(.level == "error")
    | select((.ruleId | test("^(G204|G304)$")) | not)
    | {
        rule: .ruleId,
        file: (.locations[0].physicalLocation.artifactLocation.uri // "?"),
        line: (.locations[0].physicalLocation.region.startLine // 0),
        message: (.message.text // ""),
        code: ((.locations[0].physicalLocation.region.snippet.text // "") | norm)
      }
] as $raw
| ($raw
   | group_by([.rule, .file, .code])
   | map({
       rule: .[0].rule,
       file: .[0].file,
       code: .[0].code,
       count: length,
       line: (map(.line) | min),
       message: .[0].message
     })) as $cur
| (($b[0].findings) // []) as $base
| (reduce $base[] as $e ({}; ($e | fkey) as $k | .[$k] = $e.count)) as $known
| (reduce $cur[] as $e ({}; ($e | fkey) as $k | .[$k] = $e.count)) as $seen

| if $mode == "update" then
    {
      policy: $policy,
      generated_by: "scripts/gosec-ratchet.sh --update",
      findings: [ $cur[] | {rule, file, code, count} ]
    }
  else
    {
      new: [
        $cur[] as $e
        | select($e.count > ($known[$e | fkey] // 0))
        | {
            rule: $e.rule,
            file: $e.file,
            line: $e.line,
            message: $e.message,
            code: $e.code,
            delta: ($e.count - ($known[$e | fkey] // 0))
          }
      ],
      fixed: [
        $base[] as $e
        | select($e.count > ($seen[$e | fkey] // 0))
        | {
            rule: $e.rule,
            file: $e.file,
            code: $e.code,
            delta: ($e.count - ($seen[$e | fkey] // 0))
          }
      ],
      current_total: ([$cur[].count] | add // 0),
      baseline_total: ([$base[].count] | add // 0)
    }
  end
