package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/certificate"
)

func resetCertStoreForTest() {
	certStoreMu.Lock()
	defer certStoreMu.Unlock()
	certStore = nil
	certStoreByID = make(map[string]certificate.Certificate)
	certStoreHash = nil
	certStoreErr = nil
	// Point the store at the current (isolated) home: t.TempDir() dirs are
	// removed when a test finishes, and the path is only assigned inside the
	// sync.Once, which tests cannot reset.
	certStorePath = filepath.Join(authz.ConfigHome(), "certificates.jsonl")
}

func pentestReportJSON() map[string]any {
	return map[string]any{
		"target":     "https://example.com",
		"risk_score": 12,
		"grade":      "B",
		"verdict":    "PASS",
		"critical":   0,
		"high":       0,
		"medium":     0,
		"low":        0,
		"info":       0,
		"owasp_pass": 0,
	}
}

func issueCertificateRequest(t *testing.T, report map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"report": report, "issuer": "test-issuer"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/certificate/issue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	(&Server{}).handleCertificateIssue(w, req)
	return w
}

func TestCertificateIssueMethodNotAllowed(t *testing.T) {
	resetCertStoreForTest()
	req := httptest.NewRequest(http.MethodGet, "/api/certificate/issue", nil)
	w := httptest.NewRecorder()
	(&Server{}).handleCertificateIssue(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("issue = %d, want 405", w.Code)
	}
}

func TestCertificateIssueCrossOriginRejected(t *testing.T) {
	resetCertStoreForTest()
	body, _ := json.Marshal(pentestReportJSON())
	req := httptest.NewRequest(http.MethodPost, "/api/certificate/issue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	(&Server{}).handleCertificateIssue(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin issue = %d, want 403", w.Code)
	}
}

func TestCertificateIssueEmptyBodyRejected(t *testing.T) {
	resetCertStoreForTest()
	req := httptest.NewRequest(http.MethodPost, "/api/certificate/issue", nil)
	w := httptest.NewRecorder()
	(&Server{}).handleCertificateIssue(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty body = %d, want 400", w.Code)
	}
}

func TestCertificateIssueInvalidJSONRejected(t *testing.T) {
	resetCertStoreForTest()
	req := httptest.NewRequest(http.MethodPost, "/api/certificate/issue", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	(&Server{}).handleCertificateIssue(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid json = %d, want 400", w.Code)
	}
}

func TestCertificateIssueReportWithoutTargetRejected(t *testing.T) {
	resetCertStoreForTest()
	w := issueCertificateRequest(t, map[string]any{"risk_score": 5})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("report without target = %d, want 400: %s", w.Code, w.Body.String())
	}
}

func TestCertificateIssueProducesSignedCertificate(t *testing.T) {
	resetCertStoreForTest()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())

	w := issueCertificateRequest(t, pentestReportJSON())
	if w.Code != http.StatusOK {
		t.Fatalf("issue = %d, want 200: %s", w.Code, w.Body.String())
	}
	var cert certificate.Certificate
	if err := json.Unmarshal(w.Body.Bytes(), &cert); err != nil {
		t.Fatalf("decode cert: %v", err)
	}
	if cert.CertificateID == "" {
		t.Fatalf("no certificate_id in response: %s", w.Body.String())
	}
	if cert.Assessment.Target != "https://example.com" {
		t.Errorf("target = %q", cert.Assessment.Target)
	}
	if cert.Assessment.Issuer != "test-issuer" {
		t.Errorf("issuer = %q", cert.Assessment.Issuer)
	}
	if cert.Signature == "" || cert.PublicKey == "" {
		t.Errorf("seal missing: %+v", cert)
	}
	if cert.Version != certificate.Version {
		t.Errorf("version = %q", cert.Version)
	}

	if got := w.Header().Get("X-Certificate-ID"); got != cert.CertificateID {
		t.Errorf("X-Certificate-ID = %q, want %q", got, cert.CertificateID)
	}
	if got := w.Header().Get("X-Certificate-Key-Created"); got != "true" {
		t.Errorf("X-Certificate-Key-Created = %q, want true", got)
	}
}

func TestCertificateDownloadUnknownIDNotFound(t *testing.T) {
	resetCertStoreForTest()
	req := httptest.NewRequest(http.MethodGet, "/api/certificate/download/does-not-exist", nil)
	w := httptest.NewRecorder()
	(&Server{}).handleCertificateDownload(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown cert = %d, want 404", w.Code)
	}
}

func TestCertificateDownloadFormats(t *testing.T) {
	resetCertStoreForTest()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())
	w := issueCertificateRequest(t, pentestReportJSON())
	if w.Code != http.StatusOK {
		t.Fatalf("issue = %d: %s", w.Code, w.Body.String())
	}
	var cert certificate.Certificate
	if err := json.Unmarshal(w.Body.Bytes(), &cert); err != nil {
		t.Fatalf("decode: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/certificate/download/"+cert.CertificateID+"?format=html", nil)
	w = httptest.NewRecorder()
	(&Server{}).handleCertificateDownload(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/html" {
		t.Fatalf("html = %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	body := w.Body.String()
	if !strings.Contains(body, "Security Assessment Certificate") {
		t.Error("html body must contain the document title")
	}
	if !strings.Contains(body, cert.Assessment.Grade) || !strings.Contains(body, cert.Assessment.Verdict) {
		t.Errorf("html body must contain grade/verdict: %s", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/certificate/download/"+cert.CertificateID+"?format=pdf", nil)
	w = httptest.NewRecorder()
	(&Server{}).handleCertificateDownload(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/pdf" {
		t.Fatalf("pdf = %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if len(w.Body.Bytes()) == 0 {
		t.Fatal("pdf body empty")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/certificate/download/"+cert.CertificateID, nil)
	w = httptest.NewRecorder()
	(&Server{}).handleCertificateDownload(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("json = %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Header().Get("Content-Disposition"), ".json") {
		t.Errorf("disposition = %q", w.Header().Get("Content-Disposition"))
	}
	var got certificate.Certificate
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.CertificateID != cert.CertificateID {
		t.Fatalf("json roundtrip: %v %s", err, w.Body.String())
	}
}

func TestCertificateVerifyRejectsInvalidCertificate(t *testing.T) {
	resetCertStoreForTest()
	body, _ := json.Marshal(pentestReportJSON()) // a report, not a certificate
	req := httptest.NewRequest(http.MethodPost, "/api/certificate/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	(&Server{}).handleCertificateVerify(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("verify invalid = %d, want 400", w.Code)
	}
	var resp struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Valid {
		t.Error("invalid certificate must be reported invalid")
	}
}

func TestCertificateVerifyAcceptsIssuedCertificate(t *testing.T) {
	resetCertStoreForTest()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())
	w := issueCertificateRequest(t, pentestReportJSON())
	if w.Code != http.StatusOK {
		t.Fatalf("issue = %d: %s", w.Code, w.Body.String())
	}
	var cert certificate.Certificate
	if err := json.Unmarshal(w.Body.Bytes(), &cert); err != nil {
		t.Fatalf("decode: %v", err)
	}
	certBytes, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/certificate/verify", bytes.NewReader(certBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	(&Server{}).handleCertificateVerify(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("verify valid = %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Valid         bool   `json:"valid"`
		CertificateID string `json:"certificate_id"`
		ChainIntact   bool   `json:"chain_intact"`
		FindingsCount int    `json:"findings_count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("valid certificate rejected: %s", w.Body.String())
	}
	if resp.CertificateID != cert.CertificateID {
		t.Errorf("certificate_id = %q, want %q", resp.CertificateID, cert.CertificateID)
	}
	if !resp.ChainIntact {
		t.Error("single-certificate chain must be intact")
	}
	if resp.FindingsCount != 0 {
		t.Errorf("findings_count = %d, want 0", resp.FindingsCount)
	}
}

func TestCertificateVerifyRejectsTamperedBody(t *testing.T) {
	resetCertStoreForTest()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())
	w := issueCertificateRequest(t, pentestReportJSON())
	if w.Code != http.StatusOK {
		t.Fatalf("issue = %d: %s", w.Code, w.Body.String())
	}
	var cert certificate.Certificate
	if err := json.Unmarshal(w.Body.Bytes(), &cert); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cert.Assessment.RiskScore = 99
	certBytes, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/certificate/verify", bytes.NewReader(certBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	(&Server{}).handleCertificateVerify(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("verify tampered = %d, want 400: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Valid {
		t.Error("tampered certificate must not verify")
	}
}

func TestCertificateHistory(t *testing.T) {
	resetCertStoreForTest()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())
	if w := issueCertificateRequest(t, pentestReportJSON()); w.Code != http.StatusOK {
		t.Fatalf("issue = %d: %s", w.Code, w.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/certificate/history", nil)
	w := httptest.NewRecorder()
	(&Server{}).handleCertificateHistory(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("history = %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Certificates []certificate.Certificate `json:"certificates"`
		Count        int                       `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 || len(resp.Certificates) != 1 {
		t.Errorf("history = %+v, want one certificate", resp)
	}
}
