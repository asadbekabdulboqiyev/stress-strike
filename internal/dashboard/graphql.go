package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// --- GraphQL dashboard -------------------------------------------------------
const (
	graphqlMaxRequestBody = 32 << 10
)

// GraphQLScanRequest is the POST body for /api/graphql/scan.
type GraphQLScanRequest struct {
	Endpoint   string `json:"endpoint"`
	Authorized string `json:"authorized,omitempty"`
}

// GraphQLScanResult is the /api/graphql/scan response.
type GraphQLScanResult struct {
	OK            bool     `json:"ok"`
	Endpoint      string   `json:"endpoint"`
	Reachable     bool     `json:"reachable"`
	Introspection bool     `json:"introspection"`
	Schema        string   `json:"schema,omitempty"`
	Types         []string `json:"types,omitempty"`
	Issues        []string `json:"issues,omitempty"`
	Duration      float64  `json:"duration_seconds"`
}

func graphqlGate(target string) (owaspGateOutcome, error) {
	return owaspGate(authz.OpScan, target, "")
}

func graphqlAudit(e authz.Entry) error { return owaspAudit(e) }

func (s *Server) handleGraphQLScan(w http.ResponseWriter, r *http.Request) {
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

	r.Body = http.MaxBytesReader(w, r.Body, graphqlMaxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req GraphQLScanRequest
	if err := dec.Decode(&req); err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	start := time.Now()

	decision, err := graphqlGate(req.Endpoint)
	if err != nil {
		owaspWriteError(w, http.StatusInternalServerError, "authorization policy error: "+err.Error())
		return
	}
	auditErr := graphqlAudit(authz.Entry{Action: authz.OpScan.String(), Targets: []string{req.Endpoint}, IPs: decision.IPs, Class: decision.Class, Allowed: decision.Allowed, Rule: decision.Rule, Reason: decision.Reason, Argv: []string{"stress-strike dashboard", "POST /api/graphql/scan"}})
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

	result := scanner.ScanGraphQL(context.Background(), req.Endpoint, nil)
	result.Duration = time.Since(start).Seconds()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(GraphQLScanResult{OK: true, Endpoint: result.Endpoint, Reachable: result.Reachable, Introspection: result.Introspection, Schema: result.Schema, Types: result.Types, Issues: result.Issues, Duration: result.Duration})
}
