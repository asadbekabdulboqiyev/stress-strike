package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// --- OWASP control plane ----------------------------------------------------
//
// The dashboard exposes the same OWASP Top 10 checker the CLI runs, through the
// same safety gate, so a browser user is never a back door around the tool's
// own rules:
//
//   - The scope defaults to the host in the target the operator typed. Nothing
//     else on the internet is contacted, not even by a redirect.
//   - Intrusive probes (payloads, logins, write methods) stay OFF until the
//     request explicitly asks for them, and asking for them makes the request
//     an offensive operation for the authorization gate.
//   - A category whose probes never reached the server is reported
//     "NOT TESTED", never PASS. Coverage, not confidence.
//   - Every gate decision is written to the same append-only audit log the CLI
//     uses, so the web path cannot quietly bypass the consent trail.

const (
	// owaspMaxRequestBody caps the POST body.
	owaspMaxRequestBody = 32 << 10

	// owaspDefaultBudget / owaspMaxBudget bound one web scan. The web control
	// plane is deliberately tighter than the CLI: a browser request must not be
	// able to pin a server goroutine for a long time.
	owaspDefaultBudget = 400
	owaspMaxBudget     = 2000 // scanner.DefaultMaxRequests

	// owaspMaxScanSeconds caps budget/rate. It is a guard against a
	// well-formed but slow combination (budget=2000, rate=1) turning a click
	// into a five minute HTTP request.
	owaspMaxScanSeconds = 120.0

	owaspMaxRate    = 50.0
	owaspMaxTimeout = 30 // seconds
	owaspMaxPaths   = 25
)

// owaspFamilies is the set of intrusive family names the API accepts, in probe
// order. One table so the help text, the validation and the mapping to
// IntrusiveOptions cannot drift apart.
var owaspFamilies = []string{
	"crlf", "boolean-sqli", "time-sqli", "path-traversal", "ssrf", "write-methods",
}

// owaspCategoryIDs is the fixed OWASP Top 10 order the API reports in. The
// scanner's own name map is package-private, so the display name is taken from
// the report when present and falls back to the ID.
var owaspCategoryIDs = []string{
	"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10",
}

// OWASPScanRequest is the POST body for /api/owasp/scan. Unknown fields are
// rejected (DisallowUnknownFields) so a typo fails loudly instead of silently
// scanning with a default the operator did not ask for.
type OWASPScanRequest struct {
	Target     string   `json:"target"`
	Paths      []string `json:"paths,omitempty"`
	Allow      []string `json:"allow,omitempty"`
	AllowAll   bool     `json:"allowAll,omitempty"`
	Intrusive  bool     `json:"intrusive,omitempty"`
	Enable     []string `json:"enable,omitempty"`
	Passive    bool     `json:"passive,omitempty"`
	DryRun     bool     `json:"dryRun,omitempty"`
	Rate       float64  `json:"rate,omitempty"`
	Budget     int64    `json:"budget,omitempty"`
	TimeoutSec int      `json:"timeoutSec,omitempty"`
	Authorized string   `json:"authorized,omitempty"`
}

// OWASPCategoryResult is one OWASP Top 10 row as the browser sees it. Status is
// PASS, WARNING, FAIL or NOT TESTED — the last of which is not a pass.
type OWASPCategoryResult struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Findings    []string `json:"findings,omitempty"`
	Remediation []string `json:"remediation,omitempty"`
}

// OWASPFinding is a passive or intrusive finding. Confidence is lifted out of
// the Evidence prefix (scanner.Vulnerability has no Confidence field).
type OWASPFinding struct {
	ID         string `json:"id"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Parameter  string `json:"parameter,omitempty"`
	CWE        string `json:"cwe,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

// OWASPScanResult is the /api/owasp/scan response.
type OWASPScanResult struct {
	OK         bool                  `json:"ok"`
	Target     string                `json:"target"`
	Scope      []string              `json:"scope"`
	DryRun     bool                  `json:"dryRun"`
	Intrusive  bool                  `json:"intrusive"`
	Passive    bool                  `json:"passive"`
	Tested     int                   `json:"tested"`
	Total      int                   `json:"total"`
	Score      int                   `json:"score"`
	Grade      string                `json:"grade"`
	Categories []OWASPCategoryResult `json:"categories"`
	Findings   []OWASPFinding        `json:"findings,omitempty"`
	Gate       scanner.GuardStats    `json:"gate"`
	Notes      []string              `json:"notes,omitempty"`
}

// owaspDeny is the 403 body. `denied` distinguishes an authorization refusal
// from a malformed request, so the UI can show the reason instead of a
// generic failure.
type owaspDeny struct {
	OK     bool   `json:"ok"`
	Denied bool   `json:"denied"`
	Reason string `json:"reason"`
}

// owaspGateOutcome is one authorization decision, with everything the audit
// entry needs.
type owaspGateOutcome struct {
	Allowed bool
	Class   string
	Rule    string
	Reason  string
	IPs     []string
}

// owaspStatus applies the coverage-honesty rule.
//
// A category whose probes never reached the server (gate refused them, dry-run
// was on, or the connection failed) produced no evidence, so it is NOT TESTED
// rather than PASS. It can only hold or downgrade the checker's own verdict:
// there is no input here that turns anything into PASS.
func owaspStatus(checkerStatus string, coverage int) string {
	// An explicit "NOT TESTED" verdict is honoured even with coverage: a
	// category the checker declined to judge must never read as PASS.
	if coverage == 0 || checkerStatus == "" || checkerStatus == "NOT TESTED" {
		return "NOT TESTED"
	}
	if checkerStatus == "FAIL" || checkerStatus == "WARNING" {
		return checkerStatus
	}
	// Only the checker's own PASS counts as PASS. An unrecognised verdict is
	// not evidence of anything, so it is not a pass either: treating the
	// default branch as PASS would silently upgrade whatever a future status
	// string happened to mean.
	if checkerStatus == "PASS" {
		return "PASS"
	}
	return "NOT TESTED"
}

// owaspWorstStatus merges verdicts for the same category across several scanned
// paths: FAIL beats WARNING beats PASS. Scanning a second path may only make
// the picture worse, never better.
func owaspWorstStatus(a, b string) string {
	rank := func(s string) int {
		switch s {
		case "FAIL":
			return 3
		case "WARNING":
			return 2
		case "PASS":
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// owaspGrade maps a score to the letter grade used everywhere else in the tool.
func owaspGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// owaspSplitConfidence lifts the "confidence=<level>; <observation>" prefix
// scanner findings carry (there is no Confidence field on Vulnerability) back
// into its own column.
func owaspSplitConfidence(evidence string) (confidence, rest string) {
	const prefix = "confidence="
	if !strings.HasPrefix(evidence, prefix) {
		return "", evidence
	}
	rest = strings.TrimPrefix(evidence, prefix)
	if i := strings.IndexAny(rest, "; "); i != -1 {
		return rest[:i], strings.TrimSpace(strings.TrimLeft(rest[i:], "; "))
	}
	return rest, ""
}

// owaspToFinding converts a scanner finding into the API shape.
func owaspToFinding(v scanner.Vulnerability) OWASPFinding {
	confidence, evidence := owaspSplitConfidence(v.Evidence)
	return OWASPFinding{
		ID:         v.ID,
		Severity:   v.Severity,
		Title:      v.Title,
		Parameter:  v.Parameter,
		CWE:        v.CWE,
		Confidence: confidence,
		Evidence:   evidence,
	}
}

// owaspScopeHost renders a parsed target as a Guard scope pattern: a bare host
// matches the host on any port, and an IPv6 literal is bracketed so the
// pattern parser can tell the host from the port.
func owaspScopeHost(u *url.URL) string {
	host := u.Hostname()
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// owaspFamilyOptions maps validated family names onto scanner options.
// `intrusive` with no family list means every family.
func owaspFamilyOptions(intrusive bool, families []string) (scanner.IntrusiveOptions, error) {
	if intrusive && len(families) == 0 {
		return scanner.IntrusiveOptions{
			CRLFInjection:     true,
			BooleanSQLi:       true,
			TimeBasedSQLi:     true,
			PathTraversal:     true,
			SSRFIndicators:    true,
			WriteMethodProbes: true,
		}, nil
	}
	var o scanner.IntrusiveOptions
	for _, name := range families {
		known := false
		for _, valid := range owaspFamilies {
			if name == valid {
				known = true
				break
			}
		}
		if !known {
			return scanner.IntrusiveOptions{}, fmt.Errorf(
				"unknown probe family %q (valid: %s)", name, strings.Join(owaspFamilies, ", "))
		}
		switch name {
		case "crlf":
			o.CRLFInjection = true
		case "boolean-sqli":
			o.BooleanSQLi = true
		case "time-sqli":
			o.TimeBasedSQLi = true
		case "path-traversal":
			o.PathTraversal = true
		case "ssrf":
			o.SSRFIndicators = true
		case "write-methods":
			o.WriteMethodProbes = true
		}
	}
	return o, nil
}

// owaspValidateTarget normalizes and structurally validates the target. Only
// http(s) URLs with a host and without userinfo are accepted — the same
// structural refusals the Guard applies, checked early so the operator gets a
// clear message instead of a refused probe.
func owaspValidateTarget(raw string) (*url.URL, error) {
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

// owaspValidatePaths checks the extra base paths: root-relative, no scheme or
// host of their own, bounded in number.
func owaspValidatePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	if len(paths) > owaspMaxPaths {
		return nil, fmt.Errorf("at most %d paths, got %d", owaspMaxPaths, len(paths))
	}
	out := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("path %q must start with /", p)
		}
		if strings.Contains(p, "://") {
			return nil, fmt.Errorf("path %q must not include a scheme or host", p)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// owaspValidateFlags bounds every numeric knob the browser can send. Zero means
// "use the default"; anything out of range is a usage error, not something to
// silently clamp — the operator should know what will actually be enforced.
func owaspValidateFlags(req *OWASPScanRequest) (rps float64, budget int64, timeout time.Duration, err error) {
	rps = req.Rate
	switch {
	case rps == 0:
		rps = scanner.DefaultRPS
	case rps < 1 || rps > owaspMaxRate:
		return 0, 0, 0, fmt.Errorf("rate must be between 1 and %g, got %g", owaspMaxRate, rps)
	}

	budget = req.Budget
	switch {
	case budget == 0:
		budget = owaspDefaultBudget
	case budget < 1 || budget > owaspMaxBudget:
		return 0, 0, 0, fmt.Errorf("budget must be between 1 and %d, got %d", owaspMaxBudget, budget)
	}

	secs := req.TimeoutSec
	switch {
	case secs == 0:
		secs = 10
	case secs < 1 || secs > owaspMaxTimeout:
		return 0, 0, 0, fmt.Errorf("timeout must be between 1 and %d seconds, got %d", owaspMaxTimeout, secs)
	}

	// budget/rate is the wall-clock floor of a rate-limited scan. Refuse a
	// combination that would hold the HTTP request open past the cap.
	if seconds := float64(budget) / rps; seconds > owaspMaxScanSeconds {
		return 0, 0, 0, fmt.Errorf(
			"budget/rate is %.0fs, over the %gs cap for a web scan: lower budget or raise rate",
			seconds, owaspMaxScanSeconds)
	}
	return rps, budget, time.Duration(secs) * time.Second, nil
}

// owaspGate runs the authorization decision the CLI runs before it scans. The
// web path is not a bypass: an offensive (intrusive) scan needs an approval
// entry AND the ticket naming it, exactly like `stress-strike pentest`.
func owaspGate(op authz.Operation, target, ticket string) (owaspGateOutcome, error) {
	pol, err := authz.LoadPolicyOrDefault(authz.DefaultPolicyPath())
	if err != nil {
		return owaspGateOutcome{}, err
	}
	if env := os.Getenv("STRESS_STRIKE_ALLOW"); env != "" {
		if err := pol.AddEnvRules(env); err != nil {
			return owaspGateOutcome{}, err
		}
	}

	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tgt, err := authz.Classify(ctx, target, nil)
	if err != nil {
		return owaspGateOutcome{}, err
	}

	out := owaspGateOutcome{Allowed: true, Class: tgt.Class().String()}
	for _, ip := range tgt.IPs {
		out.IPs = append(out.IPs, ip.String())
	}

	var d authz.Decision
	switch {
	case op == authz.OpPentest:
		// Offensive operation: an approval entry must exist in the policy AND
		// the caller must name its ticket. Neither alone is enough.
		if strings.TrimSpace(ticket) == "" {
			d = authz.Decision{Class: tgt.Class(), Reason: fmt.Sprintf(
				"intrusive scanning of %s requires an authorization ticket approved with `stress-strike authorize add`", tgt.Host)}
		} else if pat, ok := pol.AuthorizedBy(tgt, ticket, now); ok {
			d = authz.Decision{Allowed: true, Class: tgt.Class(), Rule: pat,
				Reason: fmt.Sprintf("authorization ticket %q (%s)", ticket, pat)}
		} else {
			d = authz.Decision{Class: tgt.Class(), Reason: fmt.Sprintf(
				"no active authorization with ticket %q covers %s", ticket, tgt.Host)}
		}
	case strings.TrimSpace(ticket) != "":
		if pat, ok := pol.AuthorizedBy(tgt, ticket, now); ok {
			d = authz.Decision{Allowed: true, Class: tgt.Class(), Rule: pat,
				Reason: fmt.Sprintf("authorization ticket %q (%s)", ticket, pat)}
		} else {
			d = authz.Decision{Class: tgt.Class(), Reason: fmt.Sprintf(
				"no active authorization with ticket %q covers %s", ticket, tgt.Host)}
		}
	default:
		d = pol.Check(tgt, op, now)
	}

	out.Allowed = d.Allowed
	out.Rule = d.Rule
	out.Reason = d.Reason
	return out, nil
}

// owaspAudit appends the decision to the dashboard's audit log — the same
// hash-chained file the CLI writes, kept next to the dashboard's own state.
func owaspAudit(e authz.Entry) error {
	// One trail for every entry point, so `stress-strike audit` shows scans
	// started from the browser alongside those started from a shell.
	log, err := authz.Open(authz.DefaultAuditPath())
	if err != nil {
		return err
	}
	_, appendErr := log.Append(e)
	closeErr := log.Close()
	if appendErr != nil {
		return appendErr
	}
	return closeErr
}

// handleOWASPScan runs the OWASP Top 10 checker (plus the optional passive and
// intrusive families) against an operator-supplied target.
//
// Order matters: validate, then serialize (one scan at a time), then authorize,
// then build the gate, then send anything. The authorization decision is
// recorded whether it allows or denies.
func (s *Server) handleOWASPScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}

	// One scan at a time: a second click gets a clear 409 instead of a second
	// set of probes racing the first.
	select {
	case s.owaspSem <- struct{}{}:
	default:
		owaspWriteError(w, http.StatusConflict, "a scan is already running — wait for it to finish")
		return
	}
	defer func() { <-s.owaspSem }()

	r.Body = http.MaxBytesReader(w, r.Body, owaspMaxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req OWASPScanRequest
	if err := dec.Decode(&req); err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	parsed, err := owaspValidateTarget(req.Target)
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	target := parsed.String()
	paths, err := owaspValidatePaths(req.Paths)
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	rps, budget, timeout, err := owaspValidateFlags(&req)
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	intrusive := req.Intrusive || len(req.Enable) > 0
	intrusiveOpts, err := owaspFamilyOptions(req.Intrusive, req.Enable)
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Authorization: a passive scan is an OpScan; anything intrusive is an
	// OpPentest and needs a ticket.
	op := authz.OpScan
	if intrusive {
		op = authz.OpPentest
	}
	decision, err := owaspGate(op, target, req.Authorized)
	if err != nil {
		owaspWriteError(w, http.StatusInternalServerError, "authorization policy error: "+err.Error())
		return
	}
	auditErr := owaspAudit(authz.Entry{
		Action:  op.String(),
		Targets: []string{target},
		IPs:     decision.IPs,
		Class:   decision.Class,
		Allowed: decision.Allowed,
		Rule:    decision.Rule,
		Reason:  decision.Reason,
		Argv:    []string{"stress-strike dashboard", "POST /api/owasp/scan"},
	})
	if !decision.Allowed {
		// Deny is the safe action, so a broken audit trail must not turn a
		// refusal into a scan — but say so, because the trail is now incomplete.
		reason := decision.Reason
		if auditErr != nil {
			reason += " (audit log unavailable: " + auditErr.Error() + ")"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(owaspDeny{OK: false, Denied: true, Reason: reason}); err != nil {
			// Status line already sent: the client cannot receive a second
			// failure, so keep the error referenced instead of dropping it.
			_ = err
		}
		return
	}
	if auditErr != nil {
		// Fail closed: an allowed scan that cannot be recorded is not an
		// authorized scan.
		owaspWriteError(w, http.StatusInternalServerError,
			"cannot record the authorization decision: "+auditErr.Error())
		return
	}

	// Scope: the host the operator named, unless they widened or replaced it.
	var scope []string
	switch {
	case req.AllowAll:
	default:
		scope = req.Allow
		if len(scope) == 0 {
			scope = []string{owaspScopeHost(parsed)}
		}
	}

	gate, err := scanner.NewGuard(scanner.GuardConfig{
		Allow:       scope,
		AllowAll:    req.AllowAll,
		Intrusive:   intrusive,
		RPS:         rps,
		MaxRequests: budget,
		Timeout:     timeout,
		DryRun:      req.DryRun,
	})
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, "invalid probe policy: "+err.Error())
		return
	}

	var notes []string
	if req.DryRun {
		notes = append(notes, "Dry run: the probe policy was evaluated and nothing was sent.")
	}
	if !intrusive {
		notes = append(notes,
			"Intrusive probes are off, so A03/A05/A07/A10 can only be tested by passive checks; enable intrusive probes to test them properly.")
	}

	// --- The checker itself -------------------------------------------------
	// Paths: the target as given, plus any extra root-relative paths.
	bases := []string{target}
	if len(paths) > 0 {
		bases = bases[:0]
		for _, p := range paths {
			u := *parsed
			u.Path = p
			u.RawQuery = ""
			bases = append(bases, u.String())
		}
	}

	statuses := make(map[string]string, len(owaspCategoryIDs))
	findings := make(map[string][]string, len(owaspCategoryIDs))
	remediation := make(map[string][]string, len(owaspCategoryIDs))
	names := make(map[string]string, len(owaspCategoryIDs))
	coverage := make(map[string]int, len(owaspCategoryIDs))

	for _, base := range bases {
		checker := scanner.NewOWASPChecker(base)
		checker.Requester = gate
		report := checker.CheckAll()
		for _, id := range owaspCategoryIDs {
			cat, ok := report.Categories[id]
			if !ok {
				continue
			}
			names[id] = cat.Name
			coverage[id] += checker.ProbeCoverage()[id]
			// Several paths are scanned: keep the worst verdict seen for the
			// category, never the best one.
			statuses[id] = owaspWorstStatus(statuses[id], cat.Status)
			findings[id] = append(findings[id], cat.Findings...)
			remediation[id] = append(remediation[id], cat.Remediation...)
		}
	}

	// Passive and intrusive families: extra, finer-grained findings on top of
	// the ten categories. Both go through the same gate.
	var allFindings []OWASPFinding
	if req.Passive {
		if ps, perr := scanner.NewPassiveScanner(target, gate, scanner.PassiveOptions{Paths: paths}); perr == nil {
			for _, f := range ps.ScanAll(context.Background()) {
				allFindings = append(allFindings, owaspToFinding(f))
			}
		} else {
			notes = append(notes, "Passive checks skipped: "+perr.Error())
		}
	}
	if intrusive {
		if is, ierr := scanner.NewIntrusiveScanner(target, gate, intrusiveOpts); ierr == nil {
			if families := is.Enabled(); len(families) > 0 {
				notes = append(notes, "Intrusive families: "+strings.Join(families, ", ")+
					". These probes can change server state; the target must be yours.")
				for _, f := range is.ScanAll(context.Background()) {
					allFindings = append(allFindings, owaspToFinding(f))
				}
			}
		} else {
			notes = append(notes, "Intrusive checks skipped: "+ierr.Error())
		}
	}

	// --- Honest assembly ----------------------------------------------------
	cats := make([]OWASPCategoryResult, 0, len(owaspCategoryIDs))
	tested, passed := 0, 0
	var notTested []string
	for _, id := range owaspCategoryIDs {
		status := owaspStatus(statuses[id], coverage[id])
		if status == "NOT TESTED" {
			notTested = append(notTested, id)
		} else {
			tested++
			if status == "PASS" {
				passed++
			}
		}
		name := names[id]
		if name == "" {
			name = id
		}
		cats = append(cats, OWASPCategoryResult{
			ID:          id,
			Name:        name,
			Status:      status,
			Findings:    dedupe(findings[id]),
			Remediation: dedupe(remediation[id]),
		})
	}

	// Score and grade cover the categories that were actually tested. Claiming
	// a grade over untested categories would be the exact dishonesty this tool
	// exists to avoid, so the counts travel with the score.
	score, grade := 0, ""
	if tested > 0 {
		score = (100*passed + tested/2) / tested
		grade = owaspGrade(score)
	}
	if len(notTested) > 0 {
		notes = append(notes, fmt.Sprintf(
			"NOT TESTED: %s — no probe reached the server for these categories (gate refusal, dry run, or connection failure). Score covers %d of %d categories.",
			strings.Join(notTested, ", "), tested, len(owaspCategoryIDs)))
	}

	st := gate.Stats()
	if st.RequestsRefused > 0 {
		notes = append(notes, fmt.Sprintf(
			"Gate refused %d probe(s): out-of-scope=%d intrusive-off=%d budget=%d rate=%d dry-run=%d.",
			st.RequestsRefused, st.RefusedOutOfScope, st.RefusedIntrusive,
			st.RefusedBudget, st.RefusedRate, st.RefusedDryRun))
	}

	scopeOut := scope
	if req.AllowAll {
		scopeOut = []string{"* (allow-all)"}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(OWASPScanResult{
		OK:         true,
		Target:     target,
		Scope:      scopeOut,
		DryRun:     req.DryRun,
		Intrusive:  intrusive,
		Passive:    req.Passive,
		Tested:     tested,
		Total:      len(owaspCategoryIDs),
		Score:      score,
		Grade:      grade,
		Categories: cats,
		Findings:   allFindings,
		Gate:       st,
		Notes:      notes,
	}); err != nil {
		// Status line already sent: the client cannot receive a second
		// failure, so keep the error referenced instead of dropping it.
		_ = err
	}
}

// owaspWriteError writes a JSON error body, so the UI never has to parse a
// plain-text http.Error response.
func owaspWriteError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"ok":    false,
		"error": msg,
	}); err != nil {
		// Status line already sent: the client cannot receive a second
		// failure, so keep the error referenced instead of dropping it.
		_ = err
	}
}

// dedupe keeps repeated findings/remediation strings out of the report while
// preserving first-seen order.
func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
