package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/bounty"
	"github.com/asadbekabdulboqiyev/sift/internal/hostxray"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
	"github.com/asadbekabdulboqiyev/sift/internal/twin"
)

const (
	insightsMaxBody = 4 << 20
	triageMaxBody   = 2 << 20
)

type twinFitRequest struct {
	Report      report.Report `json:"report"`
	TargetP99MS float64       `json:"target_p99_ms,omitempty"`
}

type twinSimulateRequest struct {
	Model            twin.Model `json:"model"`
	Scenario         string     `json:"scenario"`
	Mode             string     `json:"mode,omitempty"`
	TargetRPS        float64    `json:"target_rps,omitempty"`
	TargetUsers      float64    `json:"target_users,omitempty"`
	DurationSeconds  float64    `json:"duration_seconds,omitempty"`
	SLAP99MS         float64    `json:"sla_p99_ms,omitempty"`
	MaxErrorRatePct  float64    `json:"max_error_rate_pct,omitempty"`
	Iterations       int        `json:"iterations,omitempty"`
	Seed             int64      `json:"seed,omitempty"`
	RampSeconds      *float64   `json:"ramp_seconds,omitempty"`
	FailOnBreachProb float64    `json:"fail_on_breach_prob,omitempty"`
}

type xrayCorrelateRequest struct {
	Samples []hostxray.Sample `json:"samples"`
	Signals []hostxray.Signal `json:"signals"`
	Window  string            `json:"window,omitempty"`
}

type bountyValidateRequest struct {
	Manifest bounty.Manifest `json:"manifest"`
}

type bountyStatusRequest struct {
	Events []bounty.Event `json:"events"`
}

func insightsJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	writeJSON(w, v)
}

func (s *Server) handleInsightsXRayCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caps := hostxray.DetectCapabilities()
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"capabilities": caps,
		"note":         "Informational only. This server never loads eBPF programs and never escalates privileges.",
	})
}

func (s *Server) handleInsightsTwinFit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, insightsMaxBody)
	defer r.Body.Close()

	var req twinFitRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	if req.Report.Duration <= 0 && req.Report.TotalRequests == 0 {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "report is missing required fields (duration/total_requests)"})
		return
	}
	if req.TargetP99MS < 0 {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "target_p99_ms must not be negative"})
		return
	}

	model, err := twin.Fit(req.Report, twin.FitOptions{TargetP99MS: req.TargetP99MS})
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"model": model,
		"note":  "Capacity estimates are model-based extrapolations, not guarantees.",
	})
}

func (s *Server) handleInsightsTwinSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, insightsMaxBody)
	defer r.Body.Close()

	var req twinSimulateRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.Model.SchemaVersion) == "" && req.Model.Curve.CapacityRPS <= 0 {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "model is required"})
		return
	}

	sc, err := buildTwinScenario(req)
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	seed := req.Seed
	if seed == 0 {
		seed = 42
	}
	res, err := twin.Simulate(req.Model, sc, seed)
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	status := http.StatusOK
	breached := false
	if req.FailOnBreachProb > 0 && res.Summary.SLAProbabilityBreach > req.FailOnBreachProb {
		breached = true
		status = http.StatusConflict
	}
	insightsJSON(w, status, map[string]any{
		"ok":          !breached,
		"result":      res,
		"breach_gate": breached,
		"note":        "Simulation results are scenario-based estimates with uncertainty, not guarantees.",
	})
}

func buildTwinScenario(req twinSimulateRequest) (twin.Scenario, error) {
	name := strings.ToLower(strings.TrimSpace(req.Scenario))
	if name == "" {
		name = "likely"
	}
	var sc twin.Scenario
	switch name {
	case "best", "likely", "worst":
		preset, err := twin.Preset(name, req.Model)
		if err != nil {
			return twin.Scenario{}, err
		}
		sc = preset
	default:
		// Custom: start from likely preset defaults if available, else minimal.
		if preset, err := twin.Preset("likely", req.Model); err == nil {
			sc = preset
			sc.Name = name
		} else {
			sc = twin.Scenario{Name: name, Mode: twin.LoopOpen, DurationSeconds: 60, Iterations: 200}
		}
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "closed" || req.TargetUsers > 0 {
		sc.Mode = twin.LoopClosed
		if req.TargetUsers > 0 {
			sc.TargetUsers = req.TargetUsers
		}
		if sc.TargetUsers <= 0 {
			sc.TargetUsers = req.Model.Workload.Concurrency
		}
	} else {
		sc.Mode = twin.LoopOpen
		if req.TargetRPS > 0 {
			sc.TargetRPS = req.TargetRPS
		}
		if sc.TargetRPS <= 0 {
			sc.TargetRPS = req.Model.Workload.RPS
		}
	}

	if req.DurationSeconds > 0 {
		sc.DurationSeconds = req.DurationSeconds
	}
	if req.SLAP99MS > 0 {
		sc.SLAP99MS = req.SLAP99MS
	}
	if req.MaxErrorRatePct > 0 {
		sc.MaxErrorRatePct = req.MaxErrorRatePct
	}
	if req.Iterations > 0 {
		sc.Iterations = req.Iterations
	}
	if req.RampSeconds != nil {
		sc.RampSeconds = *req.RampSeconds
	}
	if sc.Iterations <= 0 {
		sc.Iterations = 200
	}
	if sc.DurationSeconds <= 0 {
		sc.DurationSeconds = 60
	}
	return sc, nil
}

func (s *Server) handleInsightsXRayCorrelate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, insightsMaxBody)
	defer r.Body.Close()

	var req xrayCorrelateRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	if len(req.Samples) == 0 || len(req.Signals) == 0 {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "samples and signals are required"})
		return
	}

	opts := hostxray.CorrelateOptions{}
	if strings.TrimSpace(req.Window) != "" {
		d, err := time.ParseDuration(req.Window)
		if err != nil {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid window: " + err.Error()})
			return
		}
		opts.Window = d
	}
	indicators := hostxray.Correlate(req.Samples, req.Signals, opts)
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"indicators": indicators,
		"note":       "Indicators are correlated evidence, not causal findings.",
	})
}

func (s *Server) handleInsightsBountyValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, insightsMaxBody)
	defer r.Body.Close()

	var req bountyValidateRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	m := req.Manifest
	if strings.TrimSpace(m.SchemaVersion) == "" {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "manifest is required"})
		return
	}

	checks := make([]bounty.Check, 0, 4)
	if err := m.Validate(); err != nil {
		checks = append(checks, bounty.Check{Name: "manifest", Status: bounty.StatusFail, Detail: err.Error()})
		insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "verdict": bounty.VerdictFailed, "checks": checks, "reasons": []string{err.Error()}})
		return
	}
	checks = append(checks, bounty.Check{Name: "manifest", Status: bounty.StatusPass, Detail: "structure and fields are valid"})

	want, err := m.ComputeDigest()
	if err != nil {
		checks = append(checks, bounty.Check{Name: "package_digest", Status: bounty.StatusFail, Detail: err.Error()})
		insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "verdict": bounty.VerdictFailed, "checks": checks, "reasons": []string{err.Error()}})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(m.PackageDigest), want) {
		checks = append(checks, bounty.Check{Name: "package_digest", Status: bounty.StatusFail, Detail: "manifest digest mismatch"})
		insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "verdict": bounty.VerdictFailed, "checks": checks, "reasons": []string{"package digest does not match canonical manifest"}})
		return
	}
	checks = append(checks, bounty.Check{Name: "package_digest", Status: bounty.StatusPass, Detail: "canonical digest matches"})

	wantID := want
	if len(wantID) > 16 {
		wantID = wantID[:16]
	}
	if strings.TrimSpace(m.PackageID) != "" && !strings.EqualFold(strings.TrimSpace(m.PackageID), wantID) && !strings.EqualFold(strings.TrimSpace(m.PackageID), want) {
		checks = append(checks, bounty.Check{Name: "package_id", Status: bounty.StatusFail, Detail: "package id does not match digest"})
		insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "verdict": bounty.VerdictFailed, "checks": checks, "reasons": []string{"package id mismatch"}})
		return
	}
	checks = append(checks, bounty.Check{Name: "package_id", Status: bounty.StatusPass, Detail: "package id is consistent"})

	for _, a := range m.Artifacts {
		if len(strings.TrimSpace(a.SHA256)) != 64 {
			checks = append(checks, bounty.Check{Name: "artifact:" + string(a.Role), Status: bounty.StatusFail, Detail: "invalid sha256"})
			insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "verdict": bounty.VerdictFailed, "checks": checks, "reasons": []string{"artifact hash format invalid"}})
			return
		}
	}

	checks = append(checks, bounty.Check{Name: "artifacts", Status: bounty.StatusSkip, Detail: "artifact bytes not provided; re-hash verification requires files (use CLI 'sift bounty verify')"})

	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"verdict":        bounty.VerdictUnverified,
		"checks":         checks,
		"package_digest": m.PackageDigest,
		"package_id":     m.PackageID,
		"notes": []string{
			"Manifest integrity is valid, but artifact bytes and attestation were not re-verified in this browser flow.",
			"Use 'sift bounty verify --package ... --dir ...' for full file and attestation verification.",
			"Evidence integrity is not finding validity; human triage is required.",
		},
	})
}

func (s *Server) handleInsightsBountyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, triageMaxBody)
	defer r.Body.Close()

	var req bountyStatusRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	events := req.Events
	if len(events) == 0 {
		insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "state": "(none)", "events": 0})
		return
	}
	current, err := bounty.CurrentState(events)
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error(), "events": len(events)})
		return
	}
	last := events[len(events)-1]
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"state":  string(current),
		"events": len(events),
		"last":   last,
		"note":   "Triage states are audit outcomes; 'rewarded' is not an automatic payment.",
	})
}

// Keep references for stable builds if refactoring trims imports.
var _ = fmt.Sprintf
var _ = errors.New
var _ = sort.Strings
