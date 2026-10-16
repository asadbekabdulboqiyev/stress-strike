package dashboard

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// --- Port scan dashboard -----------------------------------------------------
const (
	portscanMaxRequestBody = 32 << 10
)

// PortScanRequest is the POST body for /api/portscan.
type PortScanRequest struct {
	Target     string `json:"target"`
	Ports      []int  `json:"ports,omitempty"`
	Authorized string `json:"authorized,omitempty"`
}

// PortScanResult is the /api/portscan response.
type PortScanResult struct {
	OK       bool                `json:"ok"`
	Target   string              `json:"target"`
	Opened   int                 `json:"opened"`
	Closed   int                 `json:"closed"`
	Ports    []scanner.PortEntry `json:"ports,omitempty"`
	Duration float64             `json:"duration_seconds"`
	Notes    []string            `json:"notes,omitempty"`
}

func portscanGate(target string) (owaspGateOutcome, error) {
	return owaspGate(authz.OpScan, target, "")
}

func portscanAudit(e authz.Entry) error { return owaspAudit(e) }

func (s *Server) handlePortScan(w http.ResponseWriter, r *http.Request) {
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

	r.Body = http.MaxBytesReader(w, r.Body, portscanMaxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req PortScanRequest
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

	decision, err := portscanGate(target)
	if err != nil {
		owaspWriteError(w, http.StatusInternalServerError, "authorization policy error: "+err.Error())
		return
	}
	auditErr := portscanAudit(authz.Entry{Action: authz.OpScan.String(), Targets: []string{target}, IPs: decision.IPs, Class: decision.Class, Allowed: decision.Allowed, Rule: decision.Rule, Reason: decision.Reason, Argv: []string{"stress-strike dashboard", "POST /api/portscan"}})
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

	result := scanner.ScanPorts(context.Background(), target, req.Ports, nil)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(PortScanResult{OK: true, Target: target, Opened: result.Opened, Closed: result.Closed, Ports: result.Ports, Duration: result.Duration.Seconds()})
}
