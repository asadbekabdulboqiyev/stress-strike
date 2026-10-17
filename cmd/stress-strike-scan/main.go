// Command stress-strike-scan is the standalone TLS/WAF/HTTP deep scanner.
//
// On top of the existing fingerprinting phases it wires the OWASP Top 10
// checker and the shared safety gate (scanner.Guard): every vulnerability probe
// goes through the gate, so the scope allowlist, the intrusive opt-in, the
// total request budget, the per-host rate limit, the per-request timeout and
// dry-run all apply. The authorization policy (OpScan) is evaluated before any
// network work, mirroring the main binary's gate.
//
// Honesty rule: a category for which no probe reached the server is reported as
// NOT TESTED, never as PASS. Coverage, not confidence.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// version is stamped at build time: go build -ldflags "-X main.version=0.14.5"
var version = "0.14.5"

const (
	// authzDeniedExitCode is returned when the authorization policy blocks the
	// scan. It is distinct from 1 (runtime error) and 2 (bad usage) so CI can
	// tell "the tool broke" from "the policy refused".
	authzDeniedExitCode = 3

	// usageExitCode is the flag/configuration error exit code, matching Go's
	// flag package convention.
	usageExitCode = 2

	// statusNotTested marks an OWASP category for which NO probe reached the
	// server (the gate refused it, dry-run was on, or the connection failed).
	// It is deliberately distinct from PASS: an untested category is not a
	// clean one.
	statusNotTested = "NOT TESTED"
)

// ── repeatable string flag ──────────────────────────────────────────────────

// stringSliceFlag is a repeatable string flag (--allow, --enable). It is
// registered as a pointer so flag.Value is satisfied and an empty value prints
// as "", which keeps the "(default ...)" hint out of the usage listing.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	fs := flag.CommandLine
	// Friendly flag errors + consistent help (exit 2 on usage errors).
	fs.Init("stress-strike-scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	target := fs.String("target", "", "Target host to scan (e.g. example.com)")
	port := fs.Int("port", 443, "Target port")
	outputJSON := fs.String("output-json", "", "Export results to JSON file")
	scanAll := fs.Bool("all", false, "Run all scans (TLS + HTTP + WAF + Security)")
	tlsOnly := fs.Bool("tls", false, "TLS scan only")
	httpOnly := fs.Bool("http", false, "HTTP fingerprint only")
	wafOnly := fs.Bool("waf", false, "WAF detection only")
	securityOnly := fs.Bool("security", false, "Security headers only")

	// OWASP Top 10 phase.
	owaspEnabled := fs.Bool("owasp", false, "Run the OWASP Top 10 checker (A01-A10) through the safety gate")
	pathFlag := fs.String("path", "", "Comma-separated extra base paths to probe (e.g. /,/login); empty means the target URL")

	// Safety gate (scanner.Guard).
	rate := fs.Float64("rate", scanner.DefaultRPS, "Per-host requests per second permitted by the safety gate")
	budget := fs.Int64("budget", scanner.DefaultMaxRequests, "Total request budget for the safety gate")
	timeoutSec := fs.Int("timeout", 10, "Per-request timeout in seconds")
	var allow stringSliceFlag
	fs.Var(&allow, "allow", "Scope pattern to allow (repeatable): host, *.domain, CIDR, optional :port, optional '/pathPrefix'")
	allowAll := fs.Bool("allow-all", false, "Bypass the scope allowlist (does not relax the intrusive gate)")
	passiveEnabled := fs.Bool("passive", false, "Run the passive response/header check family")
	intrusiveEnabled := fs.Bool("intrusive", false, "Allow intrusive probes (injection, traversal, logins, SSRF)")
	var enable stringSliceFlag
	fs.Var(&enable, "enable", "Intrusive probe family (repeatable): "+strings.Join(intrusiveFamilyNames(), ", "))
	dryRun := fs.Bool("dry-run", false, "Evaluate policy and send nothing")
	verbose := fs.Bool("verbose", false, "Verbose output (per-path detail, coverage counts)")

	// Authorization gate (OpScan).
	authorized := fs.String("authorized", "", "Authorization ticket id naming an entry approved with `authorize add`")
	policyPath := fs.String("policy", "", "Authorization policy JSON (default ~/.stress-strike/authz.json)")
	auditLog := fs.String("audit-log", "", "Append-only audit log path; when set, the authorization decision is recorded")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
╔═══════════════════════════════════════════════════════════════╗
║  stress-strike scan — TLS/WAF Deep Scanner + Fingerprinting  ║
║                                                               ║
║  Scan servers for:                                            ║
║  • TLS cipher suites, cert chain, version vulnerabilities     ║
║  • WAF fingerprinting (Cloudflare, Akamai, AWS WAF, etc.)    ║
║  • HTTP technology detection (server, frameworks, languages)  ║
║  • Security headers audit (HSTS, CSP, CORS, etc.)           ║
║  • Vulnerability detection with risk scoring                 ║
║  • OWASP Top 10 (A01-A10) through a fail-closed safety gate  ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
  stress-strike-scan -target example.com [flags]

Every vulnerability probe goes through the safety gate: scope allowlist,
request budget, per-host rate limit, intrusive opt-in and dry-run.

Flags:
`)
		cliux.PrintFlagList(os.Stderr, flag.CommandLine)
		fmt.Fprintf(os.Stderr, `
Safety:
  The scope defaults to the host named by --target (hostname only, no port,
  no path); it is printed so nothing is implicit. Intrusive probes (the
  A03/A05/A07/A10 OWASP categories and every --enable family) are OFF unless
  --intrusive or --enable is given.

Examples:
  # Full scan
  stress-strike-scan -target example.com -all

  # OWASP Top 10 against the named host (non-intrusive categories only)
  stress-strike-scan -target example.com -owasp

  # OWASP Top 10 with intrusive probes, extra paths and a JSON export
  stress-strike-scan -target example.com -owasp -intrusive -path /,/login -output-json scan.json

  # Preview exactly what the gate would allow, sending nothing
  stress-strike-scan -target example.com -owasp -dry-run

  # TLS scan only
  stress-strike-scan -target example.com -port 443 -tls

  # WAF detection
  stress-strike-scan -target example.com -waf

  # Security headers audit
  stress-strike-scan -target example.com -security

  # Export to JSON
  stress-strike-scan -target example.com -all -output-json scan.json
`)
	}

	cliux.Parse(fs, os.Args[1:], flag.Usage, cliux.Options{
		Command: "scan",
		FlagSet: fs,
		Examples: []string{
			"stress-strike scan -target example.com -all",
			"stress-strike scan -target example.com -owasp -dry-run",
		},
	})

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required.")
		fmt.Fprintln(os.Stderr, "Example: stress-strike scan -target example.com -all")
		fmt.Fprintln(os.Stderr, "")
		flag.Usage()
		os.Exit(1)
	}

	// Default to all if no specific flag
	if !*tlsOnly && !*httpOnly && !*wafOnly && !*securityOnly {
		*scanAll = true
	}

	// Configuration errors are usage errors (exit 2), resolved before any
	// network work.
	baseURL, err := targetBaseURL(*target, *port)
	if err != nil {
		usageError("invalid --target: %v", err)
	}
	intrusiveOpts, enabledFamilies, err := parseEnable(enable)
	if err != nil {
		usageError("%v", err)
	}
	paths := parsePathList(*pathFlag)

	// ── authorization gate (OpScan): before ANY network work ────────────────
	// The TLS/HTTP/WAF/security phases dial the target directly, so the gate
	// must run first, exactly like the main binary.
	enforceScanAuthz(baseURL, scanGateOptions{
		policyPath: *policyPath,
		auditPath:  *auditLog,
		authorized: *authorized,
	})

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  stress-strike scan — Deep Security Scanner                  ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Target: %s:%d\n", *target, *port)
	fmt.Printf("  URL:    %s\n", baseURL)

	// ── safety gate scope ───────────────────────────────────────────────────
	// Never scan more than the operator named: with no --allow and no
	// --allow-all the allowlist is derived from --target itself.
	switch {
	case *allowAll:
		fmt.Println("  scope: ALL HOSTS (--allow-all; intrusive probes still need --intrusive)")
	case len(allow) > 0:
		fmt.Printf("  scope: %s (from --allow)\n", strings.Join(allow, ", "))
	default:
		pattern, scopeErr := derivedScopePattern(baseURL)
		if scopeErr != nil {
			usageError("cannot derive scope from --target: %v", scopeErr)
		}
		allow = append(allow, pattern)
		fmt.Printf("  scope: %s (derived from --target; override with --allow)\n", pattern)
	}
	fmt.Println()

	// ── safety gate ─────────────────────────────────────────────────────────
	guardCfg := scanner.GuardConfig{
		Allow:       allow,
		AllowAll:    *allowAll,
		Intrusive:   *intrusiveEnabled || len(enabledFamilies) > 0,
		RPS:         *rate,
		MaxRequests: *budget,
		Timeout:     time.Duration(*timeoutSec) * time.Second,
		DryRun:      *dryRun,
	}
	guard, guardErr := scanner.NewGuard(guardCfg)
	if guardErr != nil {
		// A malformed allowlist pattern or a non-finite RPS is a configuration
		// error, not something to discover mid-scan.
		fmt.Fprintf(os.Stderr, "Error: %v\n", guardErr)
		os.Exit(usageExitCode)
	}
	if *dryRun {
		fmt.Println("  dry-run: the policy is evaluated, nothing is sent.")
		fmt.Println("  dry-run: TLS/HTTP/WAF/security phases are skipped (they do not go through the safety gate).")
		if reason := gatedPhaseSkipReason(*dryRun); reason != "" {
			fmt.Printf("  dry-run: %s\n", reason)
		}
		fmt.Println()
	}

	start := time.Now()

	result := &scanner.ScanResult{
		Target:   *target,
		ScanTime: start,
	}

	// Phases that will actually run, so the [n/total] numbering is honest.
	runTLS := (*scanAll || *tlsOnly) && !*dryRun
	runHTTP := (*scanAll || *httpOnly) && !*dryRun
	runWAF := (*scanAll || *wafOnly) && !*dryRun
	runSecurity := (*scanAll || *securityOnly) && !*dryRun
	// The gated phases are skipped under dry-run rather than run: parts of the
	// OWASP checker dial outside the safety gate (an HTTP-to-HTTPS redirect
	// probe and a service-port sweep), so running it would send bytes the
	// dry-run promise says must not be sent.
	runOWASP := *owaspEnabled && !*dryRun
	runPassive := *passiveEnabled && !*dryRun
	runIntrusive := len(enabledFamilies) > 0 && !*dryRun

	totalSteps := 0
	for _, on := range []bool{runTLS, runHTTP, runWAF, runSecurity, runOWASP, runPassive, runIntrusive} {
		if on {
			totalSteps++
		}
	}
	step := 0
	nextStep := func(label string) {
		step++
		fmt.Printf("  [%d/%d] %s...\n", step, totalSteps, label)
	}

	// TLS Scan
	if runTLS {
		nextStep("TLS Scan")
		tlsInfo, err := scanner.ScanTLS(*target, *port)
		if err != nil {
			fmt.Printf("    ⚠ TLS scan error: %v\n", err)
		} else {
			result.TLS = tlsInfo
			printTLSInfo(tlsInfo)
		}
	}

	// HTTP Fingerprint
	httpTarget := fmt.Sprintf("http://%s:%d", *target, *port)
	if runHTTP {
		nextStep("HTTP Fingerprint")
		httpInfo, err := scanner.ScanHTTP(httpTarget)
		if err != nil {
			fmt.Printf("    ⚠ HTTP scan error: %v\n", err)
		} else {
			result.HTTP = httpInfo
			printHTTPInfo(httpInfo)
		}
	}

	// WAF Detection
	if runWAF {
		nextStep("WAF Detection")
		wafInfo, err := scanner.ScanWAF(httpTarget)
		if err != nil {
			fmt.Printf("    ⚠ WAF scan error: %v\n", err)
		} else {
			result.WAF = wafInfo
			printWAFInfo(wafInfo)
		}
	}

	// Security Headers
	if runSecurity {
		nextStep("Security Headers")
		secInfo, err := scanner.ScanSecurity(httpTarget)
		if err != nil {
			fmt.Printf("    ⚠ Security scan error: %v\n", err)
		} else {
			result.Security = secInfo
			printSecurityInfo(secInfo)
		}
	}

	// OWASP Top 10
	var owaspResults *owaspExport
	if runOWASP {
		nextStep("OWASP Top 10 Check")
		bases := owaspBaseURLs(baseURL, paths)
		if *verbose && len(bases) > 1 {
			fmt.Printf("    routes: %s\n", strings.Join(bases, ", "))
		}
		owaspResults = runOWASPScan(bases, guard, result.TLS, result.Security, result.HTTP)
		printOWASP(owaspResults, *verbose)
		if ids := notTestedIDs(owaspResults); len(ids) > 0 {
			fmt.Printf("  %s NOT TESTED — %s\n", strings.Join(ids, "/"),
				notTestedReason(ids, guardCfg.Intrusive, *dryRun, guard.Stats()))
		}
	}

	// Passive checks
	var passiveFindings []scanner.Vulnerability
	if runPassive {
		nextStep("Passive Checks")
		passive, err := scanner.NewPassiveScanner(baseURL, guard, scanner.PassiveOptions{Paths: paths})
		if err != nil {
			fmt.Printf("    ⚠ passive scan error: %v\n", err)
		} else {
			passiveFindings = passive.ScanAll(context.Background())
			printProbeFindings(passiveFindings, *verbose)
			if *verbose {
				for _, n := range passive.Notes() {
					fmt.Printf("    note: %s %s: %s (%s)\n", n.Method, n.URL, n.Err, n.Sentinel)
				}
			}
		}
	}

	// Intrusive probes
	var intrusiveFindings []scanner.Vulnerability
	if runIntrusive {
		nextStep("Intrusive Probes")
		intrusive, err := scanner.NewIntrusiveScanner(baseURL, guard, intrusiveOpts)
		if err != nil {
			fmt.Printf("    ⚠ intrusive scan error: %v\n", err)
		} else {
			if *verbose {
				fmt.Printf("    families: %s\n", strings.Join(intrusive.Enabled(), ", "))
			}
			intrusiveFindings = intrusive.ScanAll(context.Background())
			printProbeFindings(intrusiveFindings, *verbose)
		}
	}

	// Safety-gate accounting, so a quiet result can be told apart from a
	// refused one.
	if runOWASP || runPassive || runIntrusive || *dryRun {
		fmt.Println()
		printGuardStats(guard.Stats())
	}

	result.Duration = time.Since(start)

	// Vulnerabilities
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  VULNERABILITIES & RISK SCORE")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	result.Vulns = calculateVulns(result)
	result.RiskScore = calculateRiskScore(result)

	for _, v := range result.Vulns {
		severityIcon := map[string]string{
			"critical": "🔴",
			"high":     "🟠",
			"medium":   "🟡",
			"low":      "🔵",
			"info":     "⚪",
		}
		fmt.Printf("  %s [%s] %s\n", severityIcon[v.Severity], strings.ToUpper(v.Severity), v.Title)
		fmt.Printf("     %s\n", v.Description)
		if v.Remediation != "" {
			fmt.Printf("     Fix: %s\n", v.Remediation)
		}
		fmt.Println()
	}

	// Risk Score
	riskColor := "🟢"
	if result.RiskScore < 70 {
		riskColor = "🟡"
	}
	if result.RiskScore < 40 {
		riskColor = "🟠"
	}
	if result.RiskScore < 20 {
		riskColor = "🔴"
	}

	fmt.Printf("  %s Risk Score: %d/100\n", riskColor, result.RiskScore)
	fmt.Printf("  Scan Duration: %s\n", result.Duration.Round(time.Millisecond))
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// Export JSON
	if *outputJSON != "" {
		f, err := os.Create(*outputJSON)
		if err != nil {
			fmt.Printf("  ⚠ Failed to create JSON: %v\n", err)
		} else {
			defer f.Close()
			export := &scanExport{
				ScanResult: result,
				OWASP:      owaspResults,
				Passive:    passiveFindings,
				Intrusive:  intrusiveFindings,
			}
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(export); err != nil {
				fmt.Printf("  ⚠ Failed to write JSON report: %v\n", err)
			}
			fmt.Printf("\n  JSON report: %s\n", *outputJSON)
		}
	}
}

// ── output model ────────────────────────────────────────────────────────────

// scanExport is the --output-json document: the existing scan result plus the
// gated scan phases (OWASP statuses are strings, including "NOT TESTED").
type scanExport struct {
	*scanner.ScanResult
	OWASP     *owaspExport            `json:"owasp,omitempty"`
	Passive   []scanner.Vulnerability `json:"passive,omitempty"`
	Intrusive []scanner.Vulnerability `json:"intrusive,omitempty"`
}

// owaspCategoryResult is one merged OWASP category, ready for output/export.
type owaspCategoryResult struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Status        string   `json:"status"`
	Score         int      `json:"score"`
	ProbesCovered int      `json:"probes_covered"`
	Findings      []string `json:"findings"`
	Remediation   []string `json:"remediation"`
}

// owaspExport is the OWASP phase's contribution to the report.
type owaspExport struct {
	Paths      []string                        `json:"paths"`
	Categories map[string]*owaspCategoryResult `json:"categories"`
	Guard      scanner.GuardStats              `json:"guard"`
}

// owaspCategoryOrder is the canonical A01..A10 display order.
var owaspCategoryOrder = []string{"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"}

// intrusiveOWASPCategories are the categories whose probes are intrusive: with
// the gate's intrusive opt-in off the checker never runs them, so they come
// back with no evidence at all.
var intrusiveOWASPCategories = []string{"A03", "A05", "A07", "A10"}

// fabricatedIntrusiveCategories are the intrusive categories whose checker
// bodies emit findings even when the safety gate refused every probe they
// sent. A07, for example, reports "no brute force protection" simply because
// its twenty blocked login attempts never produced a lockout — not because any
// attempt was actually made. None of these categories has a probe that runs
// outside the gate, so with zero gate coverage their findings cannot be
// evidence and are dropped in favour of NOT TESTED.
//
// A05 is deliberately NOT in this list: it also dials common service ports
// directly, outside the gate, so a finding it reports with zero gate coverage
// can be a real exposure and must stand.
var fabricatedIntrusiveCategories = []string{"A03", "A07", "A10"}

// ── OWASP phase ─────────────────────────────────────────────────────────────

// runOWASPScan runs the OWASP checker against every base URL and merges the
// categories, applying the coverage-honesty mapping and the TLS/header
// evidence downgrades. It prints nothing; the caller renders.
func runOWASPScan(bases []string, g *scanner.Guard, tlsInfo *scanner.TLSInfo, secInfo *scanner.SecurityInfo, httpInfo *scanner.HTTPInfo) *owaspExport {
	out := &owaspExport{
		Paths:      append([]string(nil), bases...),
		Categories: make(map[string]*owaspCategoryResult, len(owaspCategoryOrder)),
	}

	type acc struct {
		name        string
		score       int
		covered     int
		coverStatus string // worst status seen on a path where this category had coverage
		anyStatus   string // worst status seen on any path
		findings    []string
		remediation []string
	}
	accs := make(map[string]*acc, len(owaspCategoryOrder))
	seenFindings := make(map[string]bool)

	for _, base := range bases {
		checker := scanner.NewOWASPChecker(base)
		checker.Requester = g
		report := checker.CheckAll()
		coverage := checker.ProbeCoverage()

		for _, id := range owaspCategoryOrder {
			cat := report.Categories[id]
			if cat == nil {
				continue
			}
			a := accs[id]
			if a == nil {
				a = &acc{name: cat.Name, score: cat.Score}
				accs[id] = a
			}
			if cat.Score < a.score {
				a.score = cat.Score
			}
			a.anyStatus = worseStatus(a.anyStatus, cat.Status)
			if coverage[id] > 0 {
				a.covered += coverage[id]
				a.coverStatus = worseStatus(a.coverStatus, cat.Status)
			}
			// Union the findings, keeping the remediation list aligned.
			for i, f := range cat.Findings {
				if seenFindings[f] {
					continue
				}
				seenFindings[f] = true
				a.findings = append(a.findings, f)
				rem := ""
				if i < len(cat.Remediation) {
					rem = cat.Remediation[i]
				}
				a.remediation = append(a.remediation, rem)
			}
		}
	}

	for _, id := range owaspCategoryOrder {
		a := accs[id]
		if a == nil {
			continue
		}
		// Only a path that actually reached the server may set the computed
		// status; a path with no coverage has no status to contribute.
		computed := a.coverStatus
		if computed == "" {
			computed = a.anyStatus
		}
		findings := a.findings
		if findings == nil {
			findings = []string{}
		}
		remediation := a.remediation
		if remediation == nil {
			remediation = []string{}
		}
		catRes := &owaspCategoryResult{
			ID:            id,
			Name:          a.name,
			Status:        mapOWASPStatus(computed, a.covered, len(a.findings)),
			Score:         a.score,
			ProbesCovered: a.covered,
			Findings:      findings,
			Remediation:   remediation,
		}
		if fabricatesFindings(catRes.ID, catRes.ProbesCovered, catRes.Findings) {
			catRes.ProbesCovered = 0
			catRes.Findings = make([]string, 0)
			catRes.Remediation = make([]string, 0)
			catRes.Score = 100
			catRes.Status = statusNotTested
		}
		out.Categories[id] = catRes
	}

	applyOWASPEvidenceDowngrades(out, tlsInfo, secInfo, httpInfo)
	if g != nil {
		out.Guard = g.Stats()
	}
	return out
}

// mapOWASPStatus is the coverage-honesty rule, in its entirety:
//
//	covered  + clean    → PASS
//	covered  + warning  → WARNING   (the checker's own status is trusted)
//	covered  + fail     → FAIL
//	uncovered + clean   → NOT TESTED
//	uncovered + findings→ FAIL      (evidence beats coverage)
//
// It never returns PASS for an uncovered category: an untested category must
// not look like a clean one. When findings exist but no probe reached the
// server, the category is not clean, and with nothing to soften it the honest
// answer is FAIL — never a pass on no coverage.
func mapOWASPStatus(computed string, covered, findings int) string {
	if covered > 0 {
		return computed
	}
	if findings > 0 {
		return "FAIL"
	}
	return statusNotTested
}

// statusRank orders the statuses by severity for the worst-wins merges.
func statusRank(s string) int {
	switch s {
	case "FAIL":
		return 3
	case "WARNING":
		return 2
	case "PASS":
		return 1
	default: // "" and NOT TESTED carry no severity
		return 0
	}
}

// worseStatus returns the more severe of two statuses.
func worseStatus(a, b string) string {
	if statusRank(b) > statusRank(a) {
		return b
	}
	return a
}

// escalateStatus makes current at least as severe as target. It never returns
// PASS (targets are never PASS), and a NOT TESTED status yields to conclusive
// evidence, because "no evidence" is not a clean result to defend.
func escalateStatus(current, target string) string {
	if statusRank(target) == 0 {
		return current
	}
	if current == statusNotTested {
		return target
	}
	if statusRank(target) > statusRank(current) {
		return target
	}
	return current
}

// fabricatesFindings reports whether a category that produced findings with
// zero gate coverage is known to emit them structurally rather than from
// evidence. Such findings are an artefact of the checker's shape, not a
// signal, and must be discarded before reporting.
func fabricatesFindings(id string, covered int, findings []string) bool {
	if len(findings) == 0 || covered > 0 {
		return false
	}
	for _, c := range fabricatedIntrusiveCategories {
		if c == id {
			return true
		}
	}
	return false
}

// applyOWASPEvidenceDowngrades folds the TLS and security-header evidence this
// command already collects into A02/A05, which the OWASP probes themselves can
// only partially see. It only ever makes a status MORE severe.
func applyOWASPEvidenceDowngrades(out *owaspExport, tlsInfo *scanner.TLSInfo, secInfo *scanner.SecurityInfo, httpInfo *scanner.HTTPInfo) {
	if out == nil {
		return
	}
	// A02 Cryptographic Failures: a deprecated protocol version or an expired
	// certificate is conclusive evidence from the TLS phase, which does not go
	// through the OWASP probes at all.
	if cat := out.Categories["A02"]; cat != nil && tlsSignatureBad(tlsInfo) {
		cat.Status = escalateStatus(cat.Status, "FAIL")
	}
	// A05 Security Misconfiguration: security headers that are provably absent
	// are conclusive evidence collected by the security-headers phase.
	if cat := out.Categories["A05"]; cat != nil {
		if missing := securityHeaderEvidence(secInfo, httpInfo); len(missing) > 0 {
			target := "WARNING"
			if len(missing) >= 3 {
				target = "FAIL"
			}
			cat.Status = escalateStatus(cat.Status, target)
		}
	}
}

// tlsSignatureBad reports whether the TLS phase found a deprecated protocol
// version or an expired certificate.
func tlsSignatureBad(t *scanner.TLSInfo) bool {
	if t == nil {
		return false
	}
	switch t.Version {
	case "TLS 1.0", "TLS 1.1":
		return true
	}
	return t.Certificate != nil && t.Certificate.IsExpired
}

// securityHeaderEvidence returns the security headers known to be missing,
// preferring the dedicated security-headers phase and falling back to the raw
// HTTP header map when that phase did not run.
func securityHeaderEvidence(sec *scanner.SecurityInfo, httpInfo *scanner.HTTPInfo) []string {
	if sec != nil {
		return sec.MissingHeaders
	}
	if httpInfo == nil {
		return nil
	}
	var missing []string
	for _, h := range []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
	} {
		found := false
		for k := range httpInfo.Headers {
			if strings.EqualFold(k, h) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, h)
		}
	}
	return missing
}

// notTestedIDs lists the categories reported as NOT TESTED, in order.
func notTestedIDs(out *owaspExport) []string {
	if out == nil {
		return nil
	}
	var ids []string
	for _, id := range owaspCategoryOrder {
		if c := out.Categories[id]; c != nil && c.Status == statusNotTested {
			ids = append(ids, id)
		}
	}
	return ids
}

// onlyIntrusive reports whether every id belongs to the intrusive family.
func onlyIntrusive(ids []string) bool {
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		found := false
		for _, i := range intrusiveOWASPCategories {
			if i == id {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// notTestedReason explains, in one line, why categories produced no evidence.
func notTestedReason(ids []string, intrusiveAllowed, dryRun bool, st scanner.GuardStats) string {
	if onlyIntrusive(ids) && (!intrusiveAllowed || st.RefusedIntrusive > 0) {
		return "intrusive probes are off; enable with --intrusive"
	}
	if dryRun {
		return "dry-run is on: the policy was evaluated and nothing was sent"
	}
	switch {
	case st.RefusedOutOfScope > 0:
		return "the safety gate refused them as out of scope"
	case st.RefusedBudget > 0:
		return "the request budget was exhausted"
	case st.RefusedRate > 0:
		return "the per-host rate limit refused them"
	}
	return "no probe reached the server (gate refusal, dry-run, or connection failure)"
}

// printOWASP prints one line per category, with NOT TESTED as a distinct,
// clearly non-passing status.
func printOWASP(out *owaspExport, verbose bool) {
	if out == nil {
		return
	}
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  OWASP TOP 10 — COVERAGE-AWARE RESULTS")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	for _, id := range owaspCategoryOrder {
		cat := out.Categories[id]
		if cat == nil {
			continue
		}
		fmt.Printf("  %s %s: %s\n", cat.ID, cat.Name, cat.Status)
		if verbose {
			fmt.Printf("      probes answered: %d, score: %d\n", cat.ProbesCovered, cat.Score)
			for i, f := range cat.Findings {
				fmt.Printf("      - %s\n", f)
				if i < len(cat.Remediation) && cat.Remediation[i] != "" {
					fmt.Printf("        fix: %s\n", cat.Remediation[i])
				}
			}
		}
	}
}

// printGuardStats prints the safety-gate accounting, including the refusal
// breakdown, so a quiet scan can be told apart from a refused one.
func printGuardStats(st scanner.GuardStats) {
	fmt.Printf("  guard: sent=%d refused=%d (out-of-scope=%d intrusive=%d budget=%d rate=%d dry-run=%d)",
		st.RequestsSent, st.RequestsRefused, st.RefusedOutOfScope, st.RefusedIntrusive,
		st.RefusedBudget, st.RefusedRate, st.RefusedDryRun)
	if st.DryRunChecked > 0 {
		fmt.Printf(" dry-run-checked=%d", st.DryRunChecked)
	}
	fmt.Printf(" bytes-read=%d\n", st.BytesRead)
}

// printProbeFindings prints the findings of a gated phase.
func printProbeFindings(vulns []scanner.Vulnerability, verbose bool) {
	if len(vulns) == 0 {
		fmt.Println("    no findings")
		return
	}
	icons := map[string]string{
		"critical": "🔴",
		"high":     "🟠",
		"medium":   "🟡",
		"low":      "🔵",
		"info":     "⚪",
	}
	for _, v := range vulns {
		icon := icons[v.Severity]
		if icon == "" {
			icon = "⚪"
		}
		fmt.Printf("    %s [%s] %s\n", icon, strings.ToUpper(v.Severity), v.Title)
		fmt.Printf("       id: %s category: %s\n", v.ID, v.Category)
		if v.URL != "" {
			fmt.Printf("       url: %s\n", v.URL)
		}
		if v.Parameter != "" {
			fmt.Printf("       parameter: %s\n", v.Parameter)
		}
		if verbose {
			if v.Evidence != "" {
				fmt.Printf("       evidence: %s\n", v.Evidence)
			}
			if v.Remediation != "" {
				fmt.Printf("       fix: %s\n", v.Remediation)
			}
		}
	}
}

// ── intrusive families ──────────────────────────────────────────────────────

// intrusiveFamily is one --enable name and the IntrusiveOptions field it sets.
type intrusiveFamily struct {
	name  string
	apply func(*scanner.IntrusiveOptions)
}

var intrusiveFamilyList = []intrusiveFamily{
	{"crlf", func(o *scanner.IntrusiveOptions) { o.CRLFInjection = true }},
	{"boolean-sqli", func(o *scanner.IntrusiveOptions) { o.BooleanSQLi = true }},
	{"time-sqli", func(o *scanner.IntrusiveOptions) { o.TimeBasedSQLi = true }},
	{"path-traversal", func(o *scanner.IntrusiveOptions) { o.PathTraversal = true }},
	{"ssrf", func(o *scanner.IntrusiveOptions) { o.SSRFIndicators = true }},
	{"write-methods", func(o *scanner.IntrusiveOptions) { o.WriteMethodProbes = true }},
}

// intrusiveFamilyNames returns the valid --enable values, in order.
func intrusiveFamilyNames() []string {
	names := make([]string, 0, len(intrusiveFamilyList))
	for _, f := range intrusiveFamilyList {
		names = append(names, f.name)
	}
	return names
}

// parseEnable maps --enable names onto IntrusiveOptions. An unknown name is a
// usage error: quietly ignoring it would run fewer probes than the operator
// asked for.
func parseEnable(names []string) (scanner.IntrusiveOptions, []string, error) {
	var opts scanner.IntrusiveOptions
	var enabled []string
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		matched := false
		for _, f := range intrusiveFamilyList {
			if f.name == name {
				f.apply(&opts)
				enabled = append(enabled, name)
				matched = true
				break
			}
		}
		if !matched {
			return opts, nil, fmt.Errorf("unknown intrusive family %q; valid names are: %s",
				name, strings.Join(intrusiveFamilyNames(), ", "))
		}
	}
	return opts, enabled, nil
}

// ── target / scope helpers ──────────────────────────────────────────────────

// targetBaseURL normalizes --target (+ --port) into a full http(s) URL. A
// target that already carries a scheme is used as given; otherwise https is
// assumed and the port is appended only when it is not the scheme default.
func targetBaseURL(target string, port int) (string, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", fmt.Errorf("empty target")
	}
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return "", fmt.Errorf("unparsable URL %q: %w", t, err)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return "", fmt.Errorf("scheme %q is not http/https", u.Scheme)
		}
		if u.Host == "" {
			return "", fmt.Errorf("URL %q has no host", t)
		}
		if u.User != nil {
			return "", fmt.Errorf("URL %q must not carry userinfo", t)
		}
		return u.String(), nil
	}

	host, explicitPort := t, ""
	if h, p, err := net.SplitHostPort(t); err == nil {
		host, explicitPort = h, p
	} else if strings.Count(t, ":") > 1 {
		host = strings.Trim(t, "[]") // bare IPv6 literal without a port
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + ip.String() + "]"
	}
	if explicitPort == "" {
		if port != 443 {
			if port < 1 || port > 65535 {
				return "", fmt.Errorf("invalid --port %d", port)
			}
			explicitPort = strconv.Itoa(port)
		}
	} else if n, err := strconv.Atoi(explicitPort); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port %q", explicitPort)
	}
	if explicitPort != "" {
		return "https://" + host + ":" + explicitPort, nil
	}
	return "https://" + host, nil
}

// derivedScopePattern is the guard scope pattern for the target the operator
// explicitly named: the hostname only, with IPv6 literals bracketed. No port
// and no path prefix, so the derived scope is never wider than the named host
// and never accidentally narrower either.
func derivedScopePattern(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("target %q has no host", baseURL)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	return host, nil
}

// parsePathList splits the comma-separated --path value into root-relative
// paths.
func parsePathList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.HasPrefix(part, "/") {
			part = "/" + part
		}
		out = append(out, part)
	}
	return out
}

// owaspBaseURLs expands the target origin by the --path entries into full probe
// base URLs. With no paths the origin itself is the single base.
func owaspBaseURLs(origin string, paths []string) []string {
	if len(paths) == 0 {
		return []string{origin}
	}
	u, err := url.Parse(origin)
	if err != nil {
		return []string{origin}
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		pu, perr := url.Parse(p)
		if perr != nil {
			continue
		}
		next := *u
		next.Path = pu.Path
		next.RawPath = pu.RawPath
		next.RawQuery = pu.RawQuery
		out = append(out, next.String())
	}
	if len(out) == 0 {
		return []string{origin}
	}
	return out
}

// gatedPhaseSkipReason explains why the gated phases (OWASP / passive /
// intrusive) are skipped. Dry-run is the only current reason: the OWASP
// checker contains probes that dial outside the safety gate, so it cannot be
// run without sending bytes. Returns "" when the phases should run.
func gatedPhaseSkipReason(dryRun bool) string {
	if dryRun {
		return "gated phases (OWASP/passive/intrusive) are skipped: the OWASP checker has probes that dial outside the safety gate, so nothing would be sent"
	}
	return ""
}

// ── authorization gate (OpScan) ─────────────────────────────────────────────

// scanGateOptions is the CLI surface of the authorization layer for this
// binary. There is deliberately no --allow-private: private and metadata
// targets are denied by the default policy.
type scanGateOptions struct {
	policyPath string
	auditPath  string
	authorized string
}

// enforceScanAuthz classifies the target, applies the policy, records an audit
// record when --audit-log is set, and either returns or terminates with the
// denial exit code. A denial is an outcome, not an error.
func enforceScanAuthz(targetURL string, opts scanGateOptions) {
	policyPath := strings.TrimSpace(opts.policyPath)
	if policyPath == "" {
		policyPath = defaultPolicyPath()
	}
	pol, err := authz.LoadPolicyOrDefault(policyPath)
	if err != nil {
		fatal(err)
	}
	if env := os.Getenv("STRESS_STRIKE_ALLOW"); env != "" {
		if err := pol.AddEnvRules(env); err != nil {
			fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tgt, err := authz.Classify(ctx, targetURL, nil)
	if err != nil {
		fatal(err)
	}

	now := time.Now()
	var d authz.Decision
	if strings.TrimSpace(opts.authorized) != "" {
		// The operator named a ticket: it must actually cover the target.
		if pat, ok := pol.AuthorizedBy(tgt, opts.authorized, now); ok {
			d = authz.Decision{Allowed: true, Class: tgt.Class(), Rule: pat,
				Reason: fmt.Sprintf("authorization ticket %q (%s)", opts.authorized, pat)}
		} else {
			d = authz.Decision{Class: tgt.Class(),
				Reason: fmt.Sprintf("no active authorization with ticket %q covers %s", opts.authorized, tgt.Host)}
		}
	} else {
		d = pol.Check(tgt, authz.OpScan, now)
	}

	ips := make([]string, 0, len(tgt.IPs))
	for _, ip := range tgt.IPs {
		ips = append(ips, ip.String())
	}

	if strings.TrimSpace(opts.auditPath) != "" {
		recordScanAuthz(authz.Entry{
			Action:  authz.OpScan.String(),
			Targets: []string{targetURL},
			IPs:     ips,
			Class:   tgt.Class().String(),
			Allowed: d.Allowed,
			Rule:    d.Rule,
			Reason:  d.Reason,
			Version: version,
			Argv:    os.Args,
		}, opts.auditPath)
	}

	if d.Allowed {
		if d.Rule != "" {
			fmt.Fprintf(os.Stderr, "authorization: ok (class=%s, rule=%s)\n", tgt.Class().String(), d.Rule)
		} else {
			fmt.Fprintf(os.Stderr, "authorization: ok (class=%s)\n", tgt.Class().String())
		}
		return
	}

	fmt.Fprintf(os.Stderr, "\nBLOCKED by authorization policy\n")
	fmt.Fprintf(os.Stderr, "  target: %s\n", targetURL)
	fmt.Fprintf(os.Stderr, "  reason: %s\n\n", d.Reason)
	fmt.Fprintln(os.Stderr, "To authorize a test, have the approver add an entry:")
	fmt.Fprintln(os.Stderr, "  stress-strike authorize add --pattern <host-or-cidr> --approver <name> --ticket <id>")
	fmt.Fprintln(os.Stderr, "then re-run with --authorized <id>.")
	cancel()
	os.Exit(authzDeniedExitCode)
}

// recordScanAuthz appends one decision to the audit log, warning (never
// failing) when the log cannot be written.
func recordScanAuthz(e authz.Entry, auditPath string) {
	log, err := authz.Open(auditPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot write audit log: %v\n", err)
		return
	}
	_, appendErr := log.Append(e)
	_ = log.Close()
	if appendErr != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot write audit log: %v\n", appendErr)
	}
}

// defaultPolicyPath is the policy location, honouring STRESS_STRIKE_POLICY.
func defaultPolicyPath() string {
	return authz.DefaultPolicyPath()
}

// ── errors ──────────────────────────────────────────────────────────────────

// fatal prints a runtime error and exits 1.
func fatal(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

// usageError prints a configuration error, the usage, and exits 2.
func usageError(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	fmt.Fprintln(os.Stderr, "")
	flag.Usage()
	os.Exit(usageExitCode)
}

// ── existing phase printers ─────────────────────────────────────────────────

func printTLSInfo(t *scanner.TLSInfo) {
	fmt.Printf("    Version: %s\n", t.Version)
	fmt.Printf("    Cipher Suite: %s\n", t.CipherSuite)
	fmt.Printf("    Secure: %v\n", t.IsSecure)
	fmt.Printf("    Forward Secrecy: %v\n", t.ForwardSecrecy)
	fmt.Printf("    HTTP/2: %v\n", t.HTTP2Supported)
	if t.Certificate != nil {
		fmt.Printf("    Certificate Subject: %s\n", t.Certificate.Subject)
		fmt.Printf("    Certificate Issuer: %s\n", t.Certificate.Issuer)
		fmt.Printf("    Key Type: %s %d-bit\n", t.Certificate.KeyType, t.Certificate.KeySize)
		fmt.Printf("    Expires: %s (expired=%v)\n", t.Certificate.NotAfter.Format("2006-01-02"), t.Certificate.IsExpired)
	}
	if len(t.SupportedVersions) > 0 {
		fmt.Printf("    Supported: %s\n", strings.Join(t.SupportedVersions, ", "))
	}
	fmt.Println()
}

func printHTTPInfo(h *scanner.HTTPInfo) {
	fmt.Printf("    Server: %s\n", h.Server)
	fmt.Printf("    X-Powered-By: %s\n", h.XPoweredBy)
	fmt.Printf("    HTTP Version: %s\n", h.HTTPVersion)
	if len(h.Technologies) > 0 {
		fmt.Printf("    Technologies: %s\n", strings.Join(h.Technologies, ", "))
	}
	if len(h.Methods) > 0 {
		fmt.Printf("    Allowed Methods: %s\n", strings.Join(h.Methods, ", "))
	}
	if h.CORS != nil && h.CORS.AllowOrigin != "" {
		fmt.Printf("    CORS Origin: %s\n", h.CORS.AllowOrigin)
	}
	fmt.Println()
}

func printWAFInfo(w *scanner.WAFInfo) {
	if w.Detected {
		fmt.Printf("    Detected: ✅ %s (%s)\n", w.Name, w.Vendor)
		fmt.Printf("    Confidence: %d%%\n", w.Confidence)
		if len(w.Indicators) > 0 {
			fmt.Printf("    Indicators: %s\n", strings.Join(w.Indicators[:min(5, len(w.Indicators))], ", "))
		}
	} else {
		fmt.Println("    Detected: ❌ No WAF found")
	}
	fmt.Println()
}

func printSecurityInfo(s *scanner.SecurityInfo) {
	fmt.Printf("    Score: %d/100\n", s.Score)
	for _, d := range s.Details {
		icon := "✅"
		switch d.Status {
		case "missing":
			icon = "❌"
		case "weak":
			icon = "⚠️ "
		case "info":
			icon = "ℹ️ "
		}
		val := d.Value
		if val == "" {
			val = "(not set)"
		}
		fmt.Printf("    %s %s: %s\n", icon, d.Header, val)
	}
	if len(s.MissingHeaders) > 0 {
		fmt.Printf("    Missing: %s\n", strings.Join(s.MissingHeaders, ", "))
	}
	fmt.Println()
}

func calculateVulns(r *scanner.ScanResult) []scanner.Vuln {
	var vulns []scanner.Vuln

	if r.TLS != nil {
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsExpired {
			vulns = append(vulns, scanner.Vuln{
				ID: "TLS-001", Severity: "critical",
				Title:       "Expired SSL/TLS Certificate",
				Description: "Certificate expired on " + r.TLS.Certificate.NotAfter.Format("2006-01-02"),
				Remediation: "Renew the certificate immediately",
			})
		}
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsSelfSigned {
			vulns = append(vulns, scanner.Vuln{
				ID: "TLS-002", Severity: "high",
				Title:       "Self-Signed Certificate",
				Description: "Certificate is self-signed, not trusted by browsers",
				Remediation: "Use a certificate from a trusted CA",
			})
		}
		if r.TLS.Version == "TLS 1.0" || r.TLS.Version == "TLS 1.1" {
			vulns = append(vulns, scanner.Vuln{
				ID: "TLS-003", Severity: "high",
				Title:       "Deprecated TLS Version",
				Description: "Server supports " + r.TLS.Version + " which has known vulnerabilities",
				Remediation: "Disable TLS 1.0 and 1.1, use TLS 1.2+",
			})
		}
	}

	if r.Security != nil {
		for _, h := range r.Security.MissingHeaders {
			vulns = append(vulns, scanner.Vuln{
				ID:          "SEC-" + strings.ReplaceAll(strings.ToUpper(h), "-", ""),
				Severity:    "medium",
				Title:       "Missing " + h + " header",
				Description: "The " + h + " security header is not set",
				Remediation: "Add '" + h + "' header to HTTP responses",
			})
		}
	}

	if r.HTTP != nil && r.HTTP.CORS != nil && r.HTTP.CORS.IsPermissive {
		vulns = append(vulns, scanner.Vuln{
			ID: "CORS-001", Severity: "medium",
			Title:       "Permissive CORS Policy",
			Description: "Access-Control-Allow-Origin: " + r.HTTP.CORS.AllowOrigin,
			Remediation: "Restrict CORS to specific trusted origins",
		})
	}

	return vulns
}

func calculateRiskScore(r *scanner.ScanResult) int {
	score := 100

	if r.TLS != nil {
		if !r.TLS.IsSecure {
			score -= 20
		}
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsExpired {
			score -= 30
		}
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsSelfSigned {
			score -= 15
		}
		if r.TLS.Version == "TLS 1.0" || r.TLS.Version == "TLS 1.1" {
			score -= 15
		}
	}

	if r.Security != nil {
		score -= (100 - r.Security.Score) / 5
	}

	for _, v := range r.Vulns {
		switch v.Severity {
		case "critical":
			score -= 25
		case "high":
			score -= 15
		case "medium":
			score -= 8
		case "low":
			score -= 3
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
