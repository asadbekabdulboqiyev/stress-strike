package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// --- Crawler (katana-like site spider) control plane -------------------------
//
// The dashboard exposes the same site crawler the scanner package provides,
// through the same safety gate, so a browser user is never a back door around
// the tool's own rules:
//
//   - Crawl is an information-gathering operation (OpScan): it needs no
//     explicit ticket unless the operator attaches one, but the gate still
//     refuses anything off the scope allowlist (default: the named host).
//   - Offsite links are never followed (AllowOffsite=false by default) and
//     redirect hops stay on the original host (crawlerRedirectGuard).
//   - Every gate decision is written to the append-only audit log the CLI
//     uses, so the web path cannot quietly bypass the consent trail.

const (
	// crawlMaxRequestBody caps the POST body.
	crawlMaxRequestBody = 32 << 10

	// crawlDefaultBudget / crawlMaxBudget bound one crawl. The web control
	// plane is deliberately tighter than the CLI.
	crawlDefaultBudget = 400
	crawlMaxBudget     = 2000 // scanner.DefaultMaxRequests

	// crawlMaxScanSeconds caps budget/rate.
	crawlMaxScanSeconds = 120.0

	crawlMaxRate    = 50.0
	crawlMaxTimeout = 30 // seconds
	crawlMaxDepth   = 10
	crawlMaxPages   = 1000
	crawlMaxConc    = 20
)

// CrawlScanRequest is the POST body for /api/crawl/scan. Unknown fields are
// rejected (DisallowUnknownFields).
type CrawlScanRequest struct {
	Target     string   `json:"target"`
	Depth      int      `json:"depth,omitempty"`
	Pages      int      `json:"pages,omitempty"`
	Timeout    int      `json:"timeoutSec,omitempty"`
	Rate       float64  `json:"rate,omitempty"`
	Budget     int64    `json:"budget,omitempty"`
	Concur     int      `json:"concurrency,omitempty"`
	Allow      []string `json:"allow,omitempty"`
	AllowAll   bool     `json:"allowAll,omitempty"`
	Offsite    bool     `json:"offsite,omitempty"`
	DryRun     bool     `json:"dryRun,omitempty"`
	Authorized string   `json:"authorized,omitempty"`
}

// CrawlEndpoint is one discovered endpoint as the browser sees it.
type CrawlEndpoint struct {
	URL     string   `json:"url"`
	Method  string   `json:"method"`
	Params  []string `json:"params,omitempty"`
	FoundAt string   `json:"found_at,omitempty"`
	Kind    string   `json:"kind"`
}

// CrawlGate is the gate decision summary the browser sees.
type CrawlGate struct {
	RequestsSent      int64 `json:"requests_sent"`
	RequestsRefused   int64 `json:"requests_refused"`
	RefusedOutOfScope int64 `json:"refused_out_of_scope"`
	RefusedIntrusive  int64 `json:"refused_intrusive"`
	RefusedBudget     int64 `json:"refused_budget"`
	RefusedRate       int64 `json:"refused_rate"`
	RefusedDryRun     int64 `json:"refused_dry_run"`
}

// CrawlScanResult is the /api/crawl/scan response.
type CrawlScanResult struct {
	OK          bool            `json:"ok"`
	Target      string          `json:"target"`
	Scope       []string        `json:"scope"`
	Pages       int             `json:"pages"`
	Endpoints   int             `json:"endpoints"`
	DurationSec float64         `json:"duration_sec"`
	DryRun      bool            `json:"dryRun"`
	Offsite     bool            `json:"offsite"`
	Gate        CrawlGate       `json:"gate"`
	Discovered  []CrawlEndpoint `json:"discovered,omitempty"`
	Notes       []string        `json:"notes,omitempty"`
}

// crawlValidateFlags bounds numeric knobs the browser can send. Zero means
// "use the default"; anything out of range is a usage error, never clamped.
func crawlValidateFlags(req *CrawlScanRequest) (rps float64, budget int64, timeout time.Duration, err error) {
	rps = req.Rate
	switch {
	case rps == 0:
		rps = scanner.DefaultRPS
	case rps < 1 || rps > crawlMaxRate:
		return 0, 0, 0, fmt.Errorf("rate must be between 1 and %g, got %g", crawlMaxRate, rps)
	}

	budget = req.Budget
	switch {
	case budget == 0:
		budget = crawlDefaultBudget
	case budget < 1 || budget > crawlMaxBudget:
		return 0, 0, 0, fmt.Errorf("budget must be between 1 and %d, got %d", crawlMaxBudget, budget)
	}

	secs := req.Timeout
	switch {
	case secs == 0:
		secs = 10
	case secs < 1 || secs > crawlMaxTimeout:
		return 0, 0, 0, fmt.Errorf("timeout must be between 1 and %d seconds, got %d", crawlMaxTimeout, secs)
	}

	if seconds := float64(budget) / rps; seconds > crawlMaxScanSeconds {
		return 0, 0, 0, fmt.Errorf(
			"budget/rate is %.0fs, over the %gs cap for a web scan: lower budget or raise rate",
			seconds, crawlMaxScanSeconds)
	}
	return rps, budget, time.Duration(secs) * time.Second, nil
}

// crawlGate runs the authorization decision: crawl is OpScan (information
// gathering), not offensive, so a named ticket is not required but the gate
// still enforces scope.
func crawlGate(target string) (owaspGateOutcome, error) {
	return owaspGate(authz.OpScan, target, "")
}

// crawlAudit appends the decision to the dashboard's audit log.
func crawlAudit(e authz.Entry) error {
	return owaspAudit(e)
}

// handleCrawlScan runs the site crawler against an operator-supplied target.
//
// Order: validate → serialize → authorize → build gate → crawl. The
// authorization decision is recorded whether it allows or denies.
func (s *Server) handleCrawlScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}

	select {
	case s.owaspSem <- struct{}{}:
	default:
		owaspWriteError(w, http.StatusConflict, "a scan is already running — wait for it to finish")
		return
	}
	defer func() { <-s.owaspSem }()

	r.Body = http.MaxBytesReader(w, r.Body, crawlMaxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req CrawlScanRequest
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

	depth := req.Depth
	switch {
	case depth < 1:
		depth = 3
	case depth > crawlMaxDepth:
		depth = crawlMaxDepth
	}
	pages := req.Pages
	switch {
	case pages < 1:
		pages = 100
	case pages > crawlMaxPages:
		pages = crawlMaxPages
	}
	conc := req.Concur
	switch {
	case conc < 1:
		conc = 5
	case conc > crawlMaxConc:
		conc = crawlMaxConc
	}

	rps, budget, timeout, err := crawlValidateFlags(&req)
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	decision, err := crawlGate(target)
	if err != nil {
		owaspWriteError(w, http.StatusInternalServerError, "authorization policy error: "+err.Error())
		return
	}
	auditErr := crawlAudit(authz.Entry{
		Action:  authz.OpScan.String(),
		Targets: []string{target},
		IPs:     decision.IPs,
		Class:   decision.Class,
		Allowed: decision.Allowed,
		Rule:    decision.Rule,
		Reason:  decision.Reason,
		Argv:    []string{"stress-strike dashboard", "POST /api/crawl/scan"},
	})
	if !decision.Allowed {
		reason := decision.Reason
		if auditErr != nil {
			reason += " (audit log unavailable: " + auditErr.Error() + ")"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"ok":     false,
			"denied": true,
			"reason": reason,
		}); err != nil {
			_ = err
		}
		return
	}
	if auditErr != nil {
		owaspWriteError(w, http.StatusInternalServerError,
			"cannot record the authorization decision: "+auditErr.Error())
		return
	}

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
		Intrusive:   false, // crawl is never intrusive
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
		notes = append(notes, "Dry run: the probe policy was evaluated and nothing was fetched.")
	}
	if req.Offsite {
		notes = append(notes, "Offsite links are allowed to be followed (may leave the target host).")
	}

	crawler := scanner.NewCrawler(target, scanner.CrawlOptions{
		MaxDepth:     depth,
		MaxPages:     pages,
		Timeout:      timeout,
		AllowOffsite: req.Offsite,
		UserAgent:    "stress-strike-crawler/1.0",
		Concurrency:  conc,
	})
	crawler.Client = &http.Client{
		Timeout:   timeout,
		Transport: &guardRoundTripper{g: gate}, // every hop passes through the safety gate
	}
	result := crawler.Crawl()

	discovered := make([]CrawlEndpoint, 0, len(result.Endpoints))
	for _, ep := range result.Endpoints {
		discovered = append(discovered, CrawlEndpoint{
			URL:     ep.URL,
			Method:  ep.Method,
			Params:  ep.Params,
			FoundAt: ep.FoundAt,
			Kind:    ep.Kind,
		})
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
	if err := json.NewEncoder(w).Encode(CrawlScanResult{
		OK:          true,
		Target:      target,
		Scope:       scopeOut,
		Pages:       result.Pages,
		Endpoints:   len(discovered),
		DurationSec: result.Duration.Seconds(),
		DryRun:      req.DryRun,
		Offsite:     req.Offsite,
		Gate: CrawlGate{
			RequestsSent:      st.RequestsSent,
			RequestsRefused:   st.RequestsRefused,
			RefusedOutOfScope: st.RefusedOutOfScope,
			RefusedIntrusive:  st.RefusedIntrusive,
			RefusedBudget:     st.RefusedBudget,
			RefusedRate:       st.RefusedRate,
			RefusedDryRun:     st.RefusedDryRun,
		},
		Discovered: discovered,
		Notes:      notes,
	}); err != nil {
		_ = err
	}
}

// guardRoundTripper adapts *scanner.Guard to http.RoundTripper so the crawler's
// http.Client routes every hop through the safety gate (scope, rate, budget,
// dry-run, intrusive gate).
type guardRoundTripper struct{ g *scanner.Guard }

func (t *guardRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.g.Do(req)
}
