package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// cmd_scan_shared.go holds the plumbing every standalone scanner command
// shares (fuzz, dirbust, jwt, graphql, websocket, crawl, subdomain, portscan,
// sslscan). The dashboard exposes each of these as its own HTTP endpoint, all
// of them routed through one safety gate (internal/scanner.Guard) and one
// authorization layer (internal/authz). These commands mirror that: the same
// gate, the same authorization semantics, the same result shapes.
//
// Order is always the same as everywhere else in the tool:
//
//	validate the target → enforce authorization → build the Guard → scan
//
// Nothing is sent before the authorization decision is made and recorded.

// scanFlags is the shared flag surface for the scanner commands: the full
// authorization/probe gate pentest uses, minus the flags that only make sense
// for a load generator, plus the result-output knobs.
type scanFlags struct {
	// gate is the authorization surface (--authorized, --policy, --audit-log,
	// --notify-webhook). Reused verbatim from cmd_authz.go so the CLI, the
	// dashboard and `stress-strike pentest` resolve the same policy.
	gate gateOptions

	// allow / allowAll widen the Guard's scope allowlist. Default: the host
	// the operator named, on any port.
	allow    stringListFlags
	allowAll bool

	// dryRun makes the Guard evaluate policy but send nothing.
	dryRun bool

	// rate / budget are the per-host request rate and the total request
	// budget. Deliberately looser than the dashboard's web-only caps: a CLI
	// operator is not a browser click that must not pin a server goroutine.
	rate   float64
	budget int64

	// jsonOut / outputJSON control the result output: JSON to stdout, and/or
	// JSON to a file (0600).
	jsonOut    bool
	outputJSON string
}

// addScanGateFlags registers the full scanner gate on fs.
//
// The set is deliberately identical for every scanner command, so an operator
// who learned the flags on `pentest` already knows them here:
//
//	--authorized --allow-private --policy --audit-log --notify-webhook  (authorization)
//	--allow --allow-all                                  (scope allowlist)
//	--dry-run                                            (probe nothing)
//	--rate --budget                                      (throttle)
//
// plus the result-output flags (--json, --output-json).
func addScanGateFlags(fs *flag.FlagSet, sf *scanFlags) {
	fs.StringVar(&sf.gate.authorized, "authorized", "",
		"authorization ticket id recorded by an approver")
	fs.BoolVar(&sf.gate.allowPrivate, "allow-private", false,
		"allow RFC1918/link-local targets without an explicit authorization entry")
	fs.StringVar(&sf.gate.policyPath, "policy", "",
		"authorization policy file (default ~/.stress-strike/authz.json)")
	fs.StringVar(&sf.gate.auditPath, "audit-log", "",
		"audit log file (default ~/.stress-strike/audit.jsonl)")
	fs.StringVar(&sf.gate.webhook, "notify-webhook", "",
		"webhook URL for audit notifications")
	fs.Var(&sf.allow, "allow",
		"scope pattern (repeatable): example.com, *.example.com, 10.0.0.0/8")
	fs.BoolVar(&sf.allowAll, "allow-all", false,
		"treat every http(s) host as in scope (disables the scope allowlist)")
	fs.BoolVar(&sf.dryRun, "dry-run", false,
		"evaluate the probe policy and print what would be sent, without sending it")
	fs.Float64Var(&sf.rate, "rate", scanner.DefaultRPS,
		"max requests per second per host")
	fs.Int64Var(&sf.budget, "budget", scanner.DefaultMaxRequests,
		"total request budget")
	addScanOutputFlags(fs, sf)
}

// addScanOutputFlags registers the result-output flags. It is split out so
// the offline `jwt` command can offer JSON output without registering an
// authorization gate it does not use.
func addScanOutputFlags(fs *flag.FlagSet, sf *scanFlags) {
	fs.BoolVar(&sf.jsonOut, "json", false, "write the result as JSON to stdout")
	fs.StringVar(&sf.outputJSON, "output-json", "",
		"write the result as JSON to this file (mode 0600)")
}

// validateScanTarget normalizes and structurally validates a target URL,
// mirroring the dashboard's owaspValidateTarget: a bare host gets https://,
// only http(s) is accepted, userinfo is refused and the fragment is dropped.
// These are the same structural refusals the Guard applies, checked early so
// the operator gets a clear message instead of a refused probe.
func validateScanTarget(raw string) (*url.URL, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("target must use http:// or https://, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("target has no host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("target must not embed credentials")
	}
	u.Fragment = ""
	return u, nil
}

// scanScopeHost renders a parsed target as a Guard scope pattern: a bare host
// matches the host on any port, and an IPv6 literal is bracketed so the
// pattern parser can tell the host from the port. Identical to the dashboard's
// owaspScopeHost / pentest's pentestScopeHost.
func scanScopeHost(u *url.URL) string {
	host := u.Hostname()
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// scanScope returns the effective scope allowlist: --allow entries when given,
// otherwise the operator's own host. --allow-all is handled by the Guard (the
// list is then irrelevant).
func scanScope(parsed *url.URL, sf *scanFlags) []string {
	if sf.allowAll {
		return nil
	}
	if len(sf.allow) > 0 {
		return sf.allow
	}
	return []string{scanScopeHost(parsed)}
}

// scanScopeOut is the scope as it appears in results (the dashboard renders
// allow-all as a single "* (allow-all)" marker).
func scanScopeOut(parsed *url.URL, sf *scanFlags) []string {
	if sf.allowAll {
		return []string{"* (allow-all)"}
	}
	return scanScope(parsed, sf)
}

// scanScopeLabel is the human one-line form of the scope.
func scanScopeLabel(parsed *url.URL, sf *scanFlags) string {
	return strings.Join(scanScopeOut(parsed, sf), ", ")
}

// buildScanGuard validates the probe policy and returns the Guard every gated
// scanner routes its requests through. It fails on a malformed pattern, a
// negative/non-finite rate, a negative budget or a negative timeout — a bad
// policy is a configuration error, not something to discover mid-scan.
//
// intrusion is the intrusive opt-in: false for the passive scanners
// (dirbust, graphql, crawl, subdomain, portscan, sslscan) and the operator's
// --intrusive for fuzz, which can mutate server state.
func buildScanGuard(parsed *url.URL, sf *scanFlags, intrusive bool, timeout time.Duration) (*scanner.Guard, error) {
	g, err := scanner.NewGuard(scanner.GuardConfig{
		Allow:       scanScope(parsed, sf),
		AllowAll:    sf.allowAll,
		Intrusive:   intrusive,
		RPS:         sf.rate,
		MaxRequests: sf.budget,
		Timeout:     timeout,
		DryRun:      sf.dryRun,
	})
	if err != nil {
		return nil, fmt.Errorf("invalid probe policy: %w", err)
	}
	return g, nil
}

// announceScanScope prints the effective scope to stderr, the same line the
// dashboard and pentest emit, so a log shows what was actually in scope.
func announceScanScope(name string, parsed *url.URL, sf *scanFlags) {
	fmt.Fprintf(os.Stderr, "%s: scope=%s\n", name, scanScopeLabel(parsed, sf))
	if sf.dryRun {
		fmt.Fprintln(os.Stderr, "dry-run: probe policy is evaluated, nothing is sent")
	}
}

// scanWarning prints the standing legal warning every probe-sending scanner
// command shows before it builds its guard. Same wording as `pentest`.
func scanWarning(name string) {
	fmt.Fprintf(os.Stderr, "WARNING: stress-strike %s issues real requests. Only test systems you own or\n", name)
	fmt.Fprintln(os.Stderr, "have explicit permission to test. Unauthorized testing is illegal.")
}

// printScanGateStats prints the Guard's counters, mirroring pentest.
func printScanGateStats(st scanner.GuardStats) {
	fmt.Fprintf(os.Stderr, "probes: sent=%d refused=%d (scope=%d intrusive=%d budget=%d rate=%d dry-run=%d) read=%dB\n",
		st.RequestsSent, st.RequestsRefused, st.RefusedOutOfScope, st.RefusedIntrusive,
		st.RefusedBudget, st.RefusedRate, st.RefusedDryRun, st.BytesRead)
}

// scanGateNote turns the Guard's refusals into a result note, or "" when
// nothing was refused. Same wording as the dashboard's notes.
func scanGateNote(st scanner.GuardStats) string {
	if st.RequestsRefused == 0 {
		return ""
	}
	return fmt.Sprintf(
		"Gate refused %d probe(s): out-of-scope=%d intrusive-off=%d budget=%d rate=%d dry-run=%d.",
		st.RequestsRefused, st.RefusedOutOfScope, st.RefusedIntrusive,
		st.RefusedBudget, st.RefusedRate, st.RefusedDryRun)
}

// emitScanJSON writes the result as JSON: to a file when --output-json was
// given (mode 0600, never world-readable) and to stdout when --json was given.
// It is a no-op when neither flag was set. The caller prints its human summary
// separately when --json was not given.
func emitScanJSON(v any, sf *scanFlags) error {
	if !sf.jsonOut && sf.outputJSON == "" {
		return nil
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	if sf.outputJSON != "" {
		if err := os.WriteFile(sf.outputJSON, append(data, '\n'), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", sf.outputJSON, err)
		}
	}
	if sf.jsonOut {
		fmt.Println(string(data))
	}
	return nil
}

// scanDirectDialEnvelope is the JSON document a direct-dial scanner writes
// under --json / --output-json. The scanner's own result is nested under
// "result" so the envelope can state the one fact the result object cannot:
// these scanners open their own DNS/TCP/TLS sockets, so the probe gate's scope,
// rate and budget limits do NOT apply to them. scope_enforced is written out
// explicitly (always false here) instead of being left for the reader to infer
// from prose on stderr.
type scanDirectDialEnvelope struct {
	Command         string `json:"command"`
	Target          string `json:"target"`
	ScopeEnforced   bool   `json:"scope_enforced"`
	EnforcementNote string `json:"enforcement_note"`
	Skipped         bool   `json:"skipped,omitempty"`
	SkipReason      string `json:"skip_reason,omitempty"`
	Result          any    `json:"result"`
}

// scanDirectDialEnforcementNote is the machine-readable counterpart of
// scanDirectDialNote: the same disclosure, in the JSON document.
const scanDirectDialEnforcementNote = "direct dial: this scanner opens its own DNS/TCP/TLS sockets, so the probe gate's scope/rate/budget limits are validated but not enforced"

// emitScanDirectDialJSON writes a direct-dial scanner's result wrapped in the
// enforcement disclosure. It is the JSON-emitting sibling of scanDirectDialNote
// and is a no-op when neither --json nor --output-json was given.
func emitScanDirectDialJSON(name, target string, result any, sf *scanFlags) error {
	return emitScanJSON(scanDirectDialEnvelope{
		Command:         name,
		Target:          target,
		ScopeEnforced:   false,
		EnforcementNote: scanDirectDialEnforcementNote,
		Result:          result,
	}, sf)
}

// scanUsageExitCode is returned when the operator passed a flag value the
// command cannot use (a malformed --allow pattern, an out-of-range --budget, a
// target that is not http(s), ...). It matches the exit code the flag package
// itself uses for an unparsable value, and keeps CI able to tell "you asked for
// something impossible" (2) from "the scan ran and failed" (1) and "the policy
// refused" (3).
const scanUsageExitCode = 2

// usageFatal reports a bad flag value (or a required flag that is missing) and
// exits with the usage code. Runtime failures keep using fatal (exit 1).
func usageFatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	exitProcess(scanUsageExitCode)
}

// scanDryRunSkip handles --dry-run for a scanner that performs its own dialing
// and therefore cannot route every request through the Guard (subdomain,
// portscan, sslscan, websocket: the scanner package dials DNS/TCP/TLS
// directly). For those, the only honest dry run is not to run them at all: a
// dry run may never send a byte. It reports the intent, emits the skip document
// when --json/--output-json was requested (so a machine caller sees the same
// reason a human does) and returns true so the caller stops.
func scanDryRunSkip(name, target string, sf *scanFlags) (bool, error) {
	if !sf.dryRun {
		return false, nil
	}
	fmt.Fprintf(os.Stderr,
		"dry-run: %s would run against %s; nothing is sent (this scanner dials directly, outside the probe gate)\n",
		name, target)
	err := emitScanJSON(scanDirectDialEnvelope{
		Command:         name,
		Target:          target,
		ScopeEnforced:   false,
		EnforcementNote: scanDirectDialEnforcementNote,
		Skipped:         true,
		SkipReason:      "dry-run: direct-dial scanner skipped so that no byte is sent",
	}, sf)
	return true, err
}

// scanDirectDialNote prints the honesty note for a scanner that performs its
// own dialing and therefore cannot route every request through the Guard
// (subdomain, portscan, sslscan, websocket: the scanner package dials
// DNS/TCP/TLS directly). The Guard was still built, so a malformed --allow
// policy fails fast and the rate/budget numbers were validated — but those
// knobs cannot be applied to the scanner's own sockets. Saying so is the honest
// thing; silently implying the gate covered the dial would not be.
func scanDirectDialNote(name, target string) {
	fmt.Fprintf(os.Stderr,
		"note: %s dials %s directly, outside the probe gate; scope/rate/budget are validated but NOT enforced on those sockets\n",
		name, target)
}

// compactJSON renders a decoded JSON object on one line for the human summary.
// Encoding a map that came from json.Unmarshal cannot fail, so a failure here
// falls back to a plain placeholder rather than aborting an already-computed
// report.
func compactJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "<unencodable>"
	}
	return string(data)
}

// guardRoundTripper adapts *scanner.Guard to http.RoundTripper so a crawler's
// http.Client routes every hop through the safety gate (scope, rate, budget,
// dry-run). The dashboard defines an identical type; the CLI re-declares it
// because the dashboard's copy is unexported.
type guardRoundTripper struct{ g *scanner.Guard }

func (t *guardRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.g.Do(req)
}
