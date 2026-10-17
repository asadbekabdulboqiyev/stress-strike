package dashboard

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// --- Dir bust dashboard ------------------------------------------------------
const (
	dirbustMaxRequestBody = 32 << 10
)

// DirBustScanRequest is the POST body for /api/dirbust.
type DirBustScanRequest struct {
	Target     string   `json:"target"`
	Paths      []string `json:"paths,omitempty"`
	Authorized string   `json:"authorized,omitempty"`
}

// DirBustScanResult is the /api/dirbust response.
type DirBustScanResult struct {
	OK       bool               `json:"ok"`
	Target   string             `json:"target"`
	Found    int                `json:"found"`
	Entries  []scanner.DirEntry `json:"entries,omitempty"`
	Duration float64            `json:"duration_seconds"`
	Notes    []string           `json:"notes,omitempty"`
}

func dirbustGate(target string) (owaspGateOutcome, error) {
	return owaspGate(authz.OpScan, target, "")
}

func dirbustAudit(e authz.Entry) error { return owaspAudit(e) }

func (s *Server) handleDirBust(w http.ResponseWriter, r *http.Request) {
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

	r.Body = http.MaxBytesReader(w, r.Body, dirbustMaxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req DirBustScanRequest
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

	decision, err := dirbustGate(target)
	if err != nil {
		owaspWriteError(w, http.StatusInternalServerError, "authorization policy error: "+err.Error())
		return
	}
	auditErr := dirbustAudit(authz.Entry{Action: authz.OpScan.String(), Targets: []string{target}, IPs: decision.IPs, Class: decision.Class, Allowed: decision.Allowed, Rule: decision.Rule, Reason: decision.Reason, Argv: []string{"stress-strike dashboard", "POST /api/dirbust"}})
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

	// Build scope gate: default to the target hostname only (no Allow/AllowAll on this endpoint).
	gate, err := scanner.NewGuard(scanner.GuardConfig{
		Allow:       []string{owaspScopeHost(parsed)},
		AllowAll:    false,
		Intrusive:   false,
		RPS:         scanner.DefaultRPS,
		MaxRequests: scanner.DefaultMaxRequests,
		Timeout:     scanner.DefaultTimeout,
		DryRun:      false,
	})
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, "invalid probe policy: "+err.Error())
		return
	}

	result := scanner.DirBust(context.Background(), target, req.Paths, gate)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(DirBustScanResult{OK: true, Target: target, Found: result.Found, Entries: result.Entries, Duration: result.Duration.Seconds()})
}
