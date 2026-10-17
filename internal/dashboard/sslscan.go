package dashboard

import (
	"context"
	"encoding/json"
	"net"
	"net/http"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// --- SSL scan dashboard ------------------------------------------------------
const (
	sslscanMaxRequestBody = 32 << 10
)

// SSLScanRequest is the POST body for /api/sslscan.
type SSLScanRequest struct {
	Target     string `json:"target"`
	Authorized string `json:"authorized,omitempty"`
}

// SSLScanResult is the /api/sslscan response.
type SSLScanResult struct {
	OK        bool     `json:"ok"`
	Target    string   `json:"target"`
	Valid     bool     `json:"valid"`
	Issuer    string   `json:"issuer,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	Expired   bool     `json:"expired"`
	SANs      []string `json:"sans,omitempty"`
	Cipher    string   `json:"cipher,omitempty"`
	Version   string   `json:"version,omitempty"`
	Issues    []string `json:"issues,omitempty"`
	Duration  float64  `json:"duration_seconds"`
	Notes     []string `json:"notes,omitempty"`
}

func sslscanGate(target string) (owaspGateOutcome, error) {
	return owaspGate(authz.OpScan, target, "")
}

func sslscanAudit(e authz.Entry) error { return owaspAudit(e) }

func (s *Server) handleSSLScan(w http.ResponseWriter, r *http.Request) {
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

	r.Body = http.MaxBytesReader(w, r.Body, sslscanMaxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req SSLScanRequest
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

	decision, err := sslscanGate(target)
	if err != nil {
		owaspWriteError(w, http.StatusInternalServerError, "authorization policy error: "+err.Error())
		return
	}
	auditErr := sslscanAudit(authz.Entry{Action: authz.OpScan.String(), Targets: []string{target}, IPs: decision.IPs, Class: decision.Class, Allowed: decision.Allowed, Rule: decision.Rule, Reason: decision.Reason, Argv: []string{"stress-strike dashboard", "POST /api/sslscan"}})
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

	// ScanSSL needs host:port; parsed.String() includes the scheme which breaks dialing.
	var scanTarget string
	if p := parsed.Port(); p != "" {
		scanTarget = net.JoinHostPort(parsed.Hostname(), p)
	} else if parsed.Scheme == "https" {
		scanTarget = net.JoinHostPort(parsed.Hostname(), "443")
	} else {
		scanTarget = net.JoinHostPort(parsed.Hostname(), "80")
	}

	result := scanner.ScanSSL(context.Background(), scanTarget)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SSLScanResult{OK: true, Target: target, Valid: result.Valid, Issuer: result.Issuer, Subject: result.Subject, NotBefore: result.NotBefore, NotAfter: result.NotAfter, Expired: result.Expired, SANs: result.SANs, Cipher: result.Cipher, Version: result.Version, Issues: result.Issues, Duration: result.Duration.Seconds()})
}
