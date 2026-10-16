package dashboard

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// --- Subdomain dashboard -----------------------------------------------------
const (
	subdomainMaxRequestBody = 32 << 10
)

// SubdomainScanRequest is the POST body for /api/subdomain/scan.
type SubdomainScanRequest struct {
	Target     string `json:"target"`
	Authorized string `json:"authorized,omitempty"`
}

// SubdomainScanResult is the /api/subdomain/scan response.
type SubdomainScanResult struct {
	OK         bool                `json:"ok"`
	Target     string              `json:"target"`
	Found      int                 `json:"found"`
	Resolved   int                 `json:"resolved"`
	Subdomains []scanner.Subdomain `json:"subdomains,omitempty"`
	Duration   float64             `json:"duration_seconds"`
	Notes      []string            `json:"notes,omitempty"`
}

func subdomainGate(target string) (owaspGateOutcome, error) {
	return owaspGate(authz.OpScan, target, "")
}

func subdomainAudit(e authz.Entry) error { return owaspAudit(e) }

func (s *Server) handleSubdomainScan(w http.ResponseWriter, r *http.Request) {
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

	r.Body = http.MaxBytesReader(w, r.Body, subdomainMaxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req SubdomainScanRequest
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

	decision, err := subdomainGate(target)
	if err != nil {
		owaspWriteError(w, http.StatusInternalServerError, "authorization policy error: "+err.Error())
		return
	}
	auditErr := subdomainAudit(authz.Entry{Action: authz.OpScan.String(), Targets: []string{target}, IPs: decision.IPs, Class: decision.Class, Allowed: decision.Allowed, Rule: decision.Rule, Reason: decision.Reason, Argv: []string{"stress-strike dashboard", "POST /api/subdomain/scan"}})
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

	result := scanner.EnumerateSubdomains(context.Background(), target, nil)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SubdomainScanResult{OK: true, Target: target, Found: result.Found, Resolved: result.Resolved, Subdomains: result.Subdomains, Duration: result.Duration.Seconds()})
}
