package dashboard

import (
	"encoding/json"
	"net/http"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// --- JWT dashboard -----------------------------------------------------------
const (
	jwtMaxRequestBody = 32 << 10
)

// JWTScanRequest is the POST body for /api/jwt/scan.
type JWTScanRequest struct {
	Token      string `json:"token"`
	Authorized string `json:"authorized,omitempty"`
}

// JWTScanResult is the /api/jwt/scan response.
type JWTScanResult struct {
	OK            bool           `json:"ok"`
	Token         string         `json:"token"`
	Valid         bool           `json:"valid"`
	AlgoConfusion bool           `json:"algo_confusion,omitempty"`
	Header        map[string]any `json:"header,omitempty"`
	Payload       map[string]any `json:"payload,omitempty"`
	Issues        []string       `json:"issues,omitempty"`
}

func (s *Server) handleJWTScan(w http.ResponseWriter, r *http.Request) {
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

	r.Body = http.MaxBytesReader(w, r.Body, jwtMaxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req JWTScanRequest
	if err := dec.Decode(&req); err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	result := scanner.AnalyzeJWT(req.Token)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(JWTScanResult{OK: true, Token: result.Token, Valid: result.Valid, AlgoConfusion: result.AlgoConfusion, Header: result.Header, Payload: result.Payload, Issues: result.Issues})
}
