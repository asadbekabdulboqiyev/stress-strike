package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// --- Fuzz dashboard ----------------------------------------------------------
const (
	fuzzMaxRequestBody = 32 << 10
	fuzzDefaultBudget  = 400
	fuzzMaxBudget      = 2000
	fuzzMaxScanSeconds = 120.0
	fuzzMaxRate        = 50.0
	fuzzMaxTimeout     = 30
	fuzzMaxPaths       = 25
	fuzzMaxMutations   = 1000
)

// FuzzScanRequest is the POST body for /api/fuzz/scan.
type FuzzScanRequest struct {
	Target     string   `json:"target"`
	Paths      []string `json:"paths,omitempty"`
	Methods    []string `json:"methods,omitempty"`
	Mutations  int      `json:"mutations,omitempty"`
	Concur     int      `json:"concurrency,omitempty"`
	Timeout    int      `json:"timeoutSec,omitempty"`
	Rate       float64  `json:"rate,omitempty"`
	Budget     int64    `json:"budget,omitempty"`
	Intrusive  bool     `json:"intrusive,omitempty"`
	Allow      []string `json:"allow,omitempty"`
	AllowAll   bool     `json:"allowAll,omitempty"`
	Authorized string   `json:"authorized,omitempty"`
}

// FuzzGate is the gate decision summary the browser sees.
type FuzzGate struct {
	RequestsSent      int64 `json:"requests_sent"`
	RequestsRefused   int64 `json:"requests_refused"`
	RefusedOutOfScope int64 `json:"refused_out_of_scope"`
	RefusedIntrusive  int64 `json:"refused_intrusive"`
	RefusedBudget     int64 `json:"refused_budget"`
	RefusedRate       int64 `json:"refused_rate"`
	RefusedDryRun     int64 `json:"refused_dry_run"`
}

// FuzzScanResult is the /api/fuzz/scan response.
type FuzzScanResult struct {
	OK          bool                  `json:"ok"`
	Target      string                `json:"target"`
	Scope       []string              `json:"scope"`
	Sent        int                   `json:"sent"`
	Refused     int                   `json:"refused"`
	Interesting int                   `json:"interesting"`
	Findings    []scanner.FuzzFinding `json:"findings,omitempty"`
	Gate        FuzzGate              `json:"gate"`
	Notes       []string              `json:"notes,omitempty"`
}

func fuzzValidateFlags(req *FuzzScanRequest) (rps float64, budget int64, timeout time.Duration, err error) {
	rps = req.Rate
	switch {
	case rps == 0:
		rps = scanner.DefaultRPS
	case rps < 1 || rps > fuzzMaxRate:
		return 0, 0, 0, fmt.Errorf("rate must be between 1 and %g, got %g", fuzzMaxRate, rps)
	}
	budget = req.Budget
	switch {
	case budget == 0:
		budget = fuzzDefaultBudget
	case budget < 1 || budget > fuzzMaxBudget:
		return 0, 0, 0, fmt.Errorf("budget must be between 1 and %d, got %d", fuzzMaxBudget, budget)
	}
	secs := req.Timeout
	switch {
	case secs == 0:
		secs = 10
	case secs < 1 || secs > fuzzMaxTimeout:
		return 0, 0, 0, fmt.Errorf("timeout must be between 1 and %d seconds, got %d", fuzzMaxTimeout, secs)
	}
	if seconds := float64(budget) / rps; seconds > fuzzMaxScanSeconds {
		return 0, 0, 0, fmt.Errorf("budget/rate is %.0fs, over the %gs cap for a web scan", seconds, fuzzMaxScanSeconds)
	}
	return rps, budget, time.Duration(secs) * time.Second, nil
}

func fuzzGate(target, ticket string) (owaspGateOutcome, error) {
	return owaspGate(authz.OpScan, target, ticket)
}

func fuzzAudit(e authz.Entry) error { return owaspAudit(e) }

func fuzzValidatePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	if len(paths) > fuzzMaxPaths {
		return nil, fmt.Errorf("at most %d paths, got %d", fuzzMaxPaths, len(paths))
	}
	out := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || strings.Contains(p, "://") {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

func (s *Server) handleFuzzScan(w http.ResponseWriter, r *http.Request) {
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

	r.Body = http.MaxBytesReader(w, r.Body, fuzzMaxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req FuzzScanRequest
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
	paths, err := fuzzValidatePaths(req.Paths)
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	methods := req.Methods
	if len(methods) == 0 {
		methods = []string{http.MethodGet, http.MethodPost}
	}
	mutations := req.Mutations
	if mutations <= 0 {
		mutations = 100
	}
	if mutations > fuzzMaxMutations {
		mutations = fuzzMaxMutations
	}
	conc := req.Concur
	if conc <= 0 {
		conc = 10
	}
	rps, budget, timeout, err := fuzzValidateFlags(&req)
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	decision, err := fuzzGate(target, req.Authorized)
	if err != nil {
		owaspWriteError(w, http.StatusInternalServerError, "authorization policy error: "+err.Error())
		return
	}
	auditErr := fuzzAudit(authz.Entry{Action: authz.OpScan.String(), Targets: []string{target}, IPs: decision.IPs, Class: decision.Class, Allowed: decision.Allowed, Rule: decision.Rule, Reason: decision.Reason, Argv: []string{"stress-strike dashboard", "POST /api/fuzz/scan"}})
	if !decision.Allowed {
		reason := decision.Reason
		if auditErr != nil {
			reason += " (audit log unavailable: " + auditErr.Error() + ")"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "denied": true, "reason": reason})
		return
	}
	if auditErr != nil {
		owaspWriteError(w, http.StatusInternalServerError, "cannot record the authorization decision: "+auditErr.Error())
		return
	}
	var scope []string
	if !req.AllowAll {
		scope = req.Allow
		if len(scope) == 0 {
			scope = []string{owaspScopeHost(parsed)}
		}
	}
	gate, err := scanner.NewGuard(scanner.GuardConfig{Allow: scope, AllowAll: req.AllowAll, Intrusive: req.Intrusive, RPS: rps, MaxRequests: budget, Timeout: timeout})
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, "invalid probe policy: "+err.Error())
		return
	}
	fuzzer, err := scanner.NewFuzzer(scanner.FuzzConfig{BaseURL: target, Paths: paths, Methods: methods, Mutations: mutations, Concurrency: conc, Timeout: timeout, Intrusive: req.Intrusive, Seed: time.Now().UnixNano()}, gate)
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	result := fuzzer.Run(context.Background())
	st := gate.Stats()
	var notes []string
	if st.RequestsRefused > 0 {
		notes = append(notes, fmt.Sprintf("Gate refused %d probe(s): out-of-scope=%d intrusive-off=%d budget=%d rate=%d dry-run=%d.", st.RequestsRefused, st.RefusedOutOfScope, st.RefusedIntrusive, st.RefusedBudget, st.RefusedRate, st.RefusedDryRun))
	}
	scopeOut := scope
	if req.AllowAll {
		scopeOut = []string{"* (allow-all)"}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(FuzzScanResult{OK: true, Target: target, Scope: scopeOut, Sent: result.Sent, Refused: result.Refused, Interesting: result.Interesting, Findings: result.Findings, Gate: FuzzGate{RequestsSent: st.RequestsSent, RequestsRefused: st.RequestsRefused, RefusedOutOfScope: st.RefusedOutOfScope, RefusedIntrusive: st.RefusedIntrusive, RefusedBudget: st.RefusedBudget, RefusedRate: st.RefusedRate, RefusedDryRun: st.RefusedDryRun}, Notes: notes})
}
