package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
		"note":  "Capacity model fitted from observed evidence with quantified confidence and uncertainty bounds.",
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
		"note":        "Scenario results include quantified uncertainty and confidence intervals for planning decisions.",
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
	const maxCorrelateSamples = 50000
	const maxCorrelateSignals = 50000
	if len(req.Samples) > maxCorrelateSamples || len(req.Signals) > maxCorrelateSignals {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "too many samples or signals"})
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
		"note":       "Indicators highlight time-correlated host and workload evidence to guide investigation.",
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
	const bountyIDPrefix = "bty_"
	const bountyIDWidth = 26
	if len(wantID) >= bountyIDWidth {
		wantID = bountyIDPrefix + wantID[:bountyIDWidth]
	} else {
		wantID = bountyIDPrefix + wantID
	}
	pid := strings.TrimSpace(m.PackageID)
	if pid != "" && !strings.EqualFold(pid, wantID) && !strings.EqualFold(pid, want) && !strings.EqualFold(pid, "bty_"+want) {
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

	checks = append(checks, bounty.Check{Name: "artifacts", Status: bounty.StatusSkip, Detail: "artifact bytes not provided in manifest-only validation; use full verify (upload) for re-hash and attestation replay"})

	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"verdict":        bounty.VerdictUnverified,
		"checks":         checks,
		"package_digest": m.PackageDigest,
		"package_id":     m.PackageID,
		"notes": []string{
			"Manifest structure and canonical digest are valid.",
			"Full artifact re-hash and attestation replay are available via POST /api/insights/bounty/verify-upload (or 'sift bounty verify').",
			"Evidence integrity supports triage; human review determines finding validity and outcomes.",
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
		"note":   "Triage states provide a complete auditable workflow and outcomes log.",
	})
}

func (s *Server) handleInsightsBountyVerifyUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	// Allow manifest + artifact files + optional bundle/samples.
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil { // #nosec G120 -- request body is bounded by MaxBytesReader above; form memory cap is intentional.
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid multipart form: " + err.Error()})
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	manifestJSON := strings.TrimSpace(r.FormValue("manifest"))
	if manifestJSON == "" {
		// Also accept uploaded manifest file named "bounty-package.json" or field "manifest_file".
		manifestJSON = readUploadedText(r, "manifest_file")
		if manifestJSON == "" {
			manifestJSON = readUploadedFileByName(r, "bounty-package.json")
		}
	}
	if manifestJSON == "" {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "manifest JSON is required (field 'manifest' or uploaded manifest file)"})
		return
	}
	var m bounty.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid manifest JSON: " + err.Error()})
		return
	}

	tmpDir, err := os.MkdirTemp("", "sift-bounty-verify-*")
	if err != nil {
		insightsJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to create temp directory"})
		return
	}
	defer os.RemoveAll(tmpDir)

	// Persist all uploaded files into temp dir using sanitized relative paths.
	saved := map[string]string{} // rel path as saved -> absolute path
	for _, fhs := range r.MultipartForm.File {
		for _, fh := range fhs {
			if fh == nil {
				continue
			}
			rel := sanitizeUploadPath(fh.Filename)
			if rel == "" {
				continue
			}
			dst := filepath.Join(tmpDir, filepath.FromSlash(rel))
			if err := saveMultipartFile(fh, tmpDir, dst); err != nil {
				insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "save " + rel + ": " + err.Error()})
				return
			}
			saved[rel] = dst
		}
	}

	// Write manifest into temp dir as bounty-package.json for consistency.
	manifestPath := filepath.Join(tmpDir, "bounty-package.json")
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "failed to encode manifest: " + err.Error()})
		return
	}
	if err := os.WriteFile(manifestPath, mb, 0o600); err != nil {
		insightsJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to write manifest: " + err.Error()})
		return
	}

	// Ensure uploaded files are available at manifest-declared artifact paths.
	// Browsers often provide basenames only; copy matched uploads to expected paths.
	for _, art := range m.Artifacts {
		want := filepath.ToSlash(art.Path)
		wantAbs := filepath.Join(tmpDir, filepath.FromSlash(want))
		if _, err := os.Stat(wantAbs); err == nil {
			saved[want] = wantAbs
			continue
		}
		var src string
		if pth, ok := saved[want]; ok {
			src = pth
		} else {
			for rel, pth := range saved {
				if filepath.Base(rel) == filepath.Base(want) || rel == filepath.Base(want) {
					src = pth
					break
				}
			}
		}
		if src == "" {
			continue
		}
		if err := copyFileTo(src, tmpDir, wantAbs); err == nil {
			saved[want] = wantAbs
		}
	}

	opts := bounty.VerifyOptions{
		Target:       strings.TrimSpace(r.FormValue("target")),
		PublicKeyHex: strings.TrimSpace(r.FormValue("key")),
		SkipCICheck:  strings.EqualFold(strings.TrimSpace(r.FormValue("skip_ci_check")), "true") || r.FormValue("skip_ci_check") == "1",
	}
	if v := strings.TrimSpace(r.FormValue("max_samples_total")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			opts.MaxSamplesTotal = n
		}
	}

	// Auto-detect bundle/samples paths from manifest artifact roles.
	for _, art := range m.Artifacts {
		pth, ok := saved[filepath.ToSlash(art.Path)]
		if !ok {
			continue
		}
		switch art.Role {
		case bounty.ArtifactBundle:
			if opts.BundlePath == "" {
				opts.BundlePath = pth
			}
		case bounty.ArtifactSamples:
			if opts.SamplesPath == "" {
				opts.SamplesPath = pth
			}
		}
	}
	// Allow explicit upload field names "bundle"/"samples".
	if opts.BundlePath == "" {
		if pth, ok := saved["bundle"]; ok {
			opts.BundlePath = pth
		}
		if pth, ok := saved["bundle.json"]; ok && opts.BundlePath == "" {
			opts.BundlePath = pth
		}
	}
	if opts.SamplesPath == "" {
		if pth, ok := saved["samples"]; ok {
			opts.SamplesPath = pth
		}
		if pth, ok := saved["samples.jsonl"]; ok && opts.SamplesPath == "" {
			opts.SamplesPath = pth
		}
	}

	report, err := bounty.VerifyPackage(m, tmpDir, opts)
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	status := http.StatusOK
	if report.Verdict == bounty.VerdictFailed {
		status = http.StatusConflict
	}
	insightsJSON(w, status, map[string]any{
		"ok":                 report.Verdict != bounty.VerdictFailed,
		"report":             report,
		"verdict":            report.Verdict,
		"uploaded_artifacts": len(saved),
		"note":               "Full package verification executed on uploaded artifacts. Evidence integrity does not by itself establish finding validity; human triage determines outcomes.",
	})
}

func copyFileTo(src, baseDir, dst string) error {
	base := filepath.Clean(baseDir)
	cleanDst := filepath.Clean(dst)
	rel, err := filepath.Rel(base, cleanDst)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes temp directory")
	}
	if err := os.MkdirAll(filepath.Dir(cleanDst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src) // #nosec G304 -- src is an internal path previously saved within the request-scoped temp directory.
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(cleanDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, io.LimitReader(in, 16<<20))
	return err
}

func readUploadedText(r *http.Request, field string) string {
	fhs := r.MultipartForm.File[field]
	if len(fhs) == 0 {
		return ""
	}
	f, err := fhs[0].Open()
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 2<<20))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readUploadedFileByName(r *http.Request, name string) string {
	for _, fhs := range r.MultipartForm.File {
		for _, fh := range fhs {
			if fh == nil || filepath.Base(fh.Filename) != name {
				continue
			}
			f, err := fh.Open()
			if err != nil {
				return ""
			}
			b, err := io.ReadAll(io.LimitReader(f, 2<<20))
			_ = f.Close()
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func sanitizeUploadPath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.ToSlash(filepath.Clean(name))
	name = strings.TrimPrefix(name, "/")
	if name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		return filepath.Base(name)
	}
	// keep relative subpaths; verifier will reject unsafe ones too
	return name
}

func saveMultipartFile(fh *multipart.FileHeader, baseDir, dst string) error {
	base := filepath.Clean(baseDir)
	cleanDst := filepath.Clean(dst)
	rel, err := filepath.Rel(base, cleanDst)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes temp directory")
	}
	if err := os.MkdirAll(filepath.Dir(cleanDst), 0o700); err != nil {
		return err
	}
	src, err := fh.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.OpenFile(cleanDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, io.LimitReader(src, 16<<20))
	return err
}

// Keep references for stable builds if refactoring trims imports.
var _ = fmt.Sprintf
var _ = errors.New
var _ = sort.Strings
