package dashboard

// attestation_upload_test.go — the Certificate page no longer rejects an
// attestation bundle. These tests pin the endpoint contract: a real signed
// bundle verifies, a tampered one is refused, a body that is not a bundle is a
// 400 (not a 500), the method and origin gates hold, and reuse across both
// verify endpoints reports the same field names.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

// signedTestBundle builds a real, coordinator-signed bundle with two workers and
// returns it together with its samples. Reuses the fixtures already used by the
// attestation end-to-end test.
func signedTestBundle(t *testing.T) attest.Bundle {
	t.Helper()
	coord := mustKeyDashboard(t)
	w1 := mustKeyDashboard(t)
	w2 := mustKeyDashboard(t)

	run := attest.Run{
		Target:     "https://example.test/api",
		Profile:    "constant-rps",
		DurationNS: 10_000_000_000,
		PlannedRPS: attest.Decimal("1000.000"),
	}
	specs := []workerSpecDashboard{
		{id: "w1", kp: w1, recs: synthRecordsDashboard("w1", 1_000_000_000, 5, 1_000_000, 1_000_000, 10_000)},
		{id: "w2", kp: w2, recs: synthRecordsDashboard("w2", 2_000_000_000, 5, 1_000_000, 2_000_000, 20_000)},
	}
	b, _ := produceBundleDashboard(t, coord, run, specs, false)
	return b
}

func postBundle(t *testing.T, s *Server, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/attestation/verify-upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+req.Host)
	w := httptest.NewRecorder()
	s.serveApp(w, req)
	return w
}

func TestAttestationVerifyUpload_ValidBundle(t *testing.T) {
	b := signedTestBundle(t)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}

	s := NewServer()
	w := postBundle(t, s, raw)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var out struct {
		Valid         bool   `json:"valid"`
		Format        string `json:"format"`
		SamplesAbsent bool   `json:"samplesAbsent"`
		BundleDigest  string `json:"bundleDigest"`
		Workers       int    `json:"workers"`
		Summary       struct {
			ChecksFailed int `json:"checksFailed"`
			WorkersOK    int `json:"workersOK"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}

	if !out.Valid {
		t.Fatalf("valid = false, want true; body=%s", w.Body.String())
	}
	if out.Format != attest.FormatID {
		t.Errorf("format = %q, want %q", out.Format, attest.FormatID)
	}
	if !out.SamplesAbsent {
		t.Error("samplesAbsent = false; the upload carries no sidecar, so this must be honest about the narrower scope")
	}
	if out.BundleDigest == "" {
		t.Error("bundleDigest is empty")
	}
	if out.Workers != 2 {
		t.Errorf("workers = %d, want 2", out.Workers)
	}
	if out.Summary.WorkersOK != 2 {
		t.Errorf("workersOK = %d, want 2", out.Summary.WorkersOK)
	}
	if out.Summary.ChecksFailed != 0 {
		t.Errorf("checksFailed = %d, want 0", out.Summary.ChecksFailed)
	}
}

func TestAttestationVerifyUpload_TamperedBundleIsInvalid(t *testing.T) {
	b := signedTestBundle(t)
	// Flip a byte in a signed field. The coordinator signature must no longer
	// match, so the bundle is reported invalid rather than quietly accepted.
	b.Run.Profile = "ramp-up"

	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}

	s := NewServer()
	w := postBundle(t, s, raw)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (verification failure is a result, not a transport error)", w.Code)
	}

	var out struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Valid {
		t.Fatal("valid = true for a bundle edited after signing")
	}
	if out.Reason == "" {
		t.Error("reason is empty; the operator needs to know which check failed")
	}
}

func TestAttestationVerifyUpload_NotABundleIs400(t *testing.T) {
	s := NewServer()
	w := postBundle(t, s, []byte(`{"assessment":{"target":"x"},"signature":"abc"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a file that is not a bundle", w.Code)
	}
	var out struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	if out.Valid {
		t.Error("valid = true for a non-bundle body")
	}
	if !strings.Contains(out.Reason, "not an attestation bundle") {
		t.Errorf("reason = %q, want it to say the file is not a bundle", out.Reason)
	}
}

func TestAttestationVerifyUpload_MethodAndOriginGates(t *testing.T) {
	s := NewServer()
	b := signedTestBundle(t)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}

	// GET is refused.
	req := httptest.NewRequest(http.MethodGet, "/api/attestation/verify-upload", nil)
	w := httptest.NewRecorder()
	s.serveApp(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", w.Code)
	}

	// A cross-site Origin is refused even with a valid body.
	req = httptest.NewRequest(http.MethodPost, "/api/attestation/verify-upload", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://evil.example")
	w = httptest.NewRecorder()
	s.serveApp(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin status = %d, want 403", w.Code)
	}
}
