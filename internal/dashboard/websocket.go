package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// --- WebSocket dashboard -----------------------------------------------------
const (
	websocketMaxRequestBody = 32 << 10
)

// WebSocketScanRequest is the POST body for /api/websocket/scan.
type WebSocketScanRequest struct {
	URL        string `json:"url"`
	Authorized string `json:"authorized,omitempty"`
}

// WebSocketScanResult is the /api/websocket/scan response.
type WebSocketScanResult struct {
	OK          bool     `json:"ok"`
	URL         string   `json:"url"`
	Connected   bool     `json:"connected"`
	Subprotocol string   `json:"subprotocol,omitempty"`
	Issues      []string `json:"issues,omitempty"`
	Messages    int      `json:"messages_sent,omitempty"`
	Duration    float64  `json:"duration_seconds"`
}

func websocketGate(target string) (owaspGateOutcome, error) {
	return owaspGate(authz.OpScan, target, "")
}

func websocketAudit(e authz.Entry) error { return owaspAudit(e) }

func (s *Server) handleWebSocketScan(w http.ResponseWriter, r *http.Request) {
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

	r.Body = http.MaxBytesReader(w, r.Body, websocketMaxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req WebSocketScanRequest
	if err := dec.Decode(&req); err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	start := time.Now()

	decision, err := websocketGate(req.URL)
	if err != nil {
		owaspWriteError(w, http.StatusInternalServerError, "authorization policy error: "+err.Error())
		return
	}
	auditErr := websocketAudit(authz.Entry{Action: authz.OpScan.String(), Targets: []string{req.URL}, IPs: decision.IPs, Class: decision.Class, Allowed: decision.Allowed, Rule: decision.Rule, Reason: decision.Reason, Argv: []string{"stress-strike dashboard", "POST /api/websocket/scan"}})
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

	result := scanner.TestWebSocket(context.Background(), req.URL, nil)
	result.Duration = time.Since(start).Seconds()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(WebSocketScanResult{OK: true, URL: result.URL, Connected: result.Connected, Subprotocol: result.Subprotocol, Issues: result.Issues, Messages: result.Messages, Duration: result.Duration})
}
