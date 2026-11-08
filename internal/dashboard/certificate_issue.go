package dashboard

// Certificate issuing from the browser.
//
// The dashboard already verifies a dropped certificate (handleCertificateVerify
// calls certificate.VerifyBytes, which needs no key). This file adds the other
// half: turn a dropped pentest report into a signed certificate.
//
// It deliberately reuses the CLI's code path — certificate.ParsePentestReport,
// certificate.BuildAssessment and certificate.Issue — so a certificate produced
// in the browser and one produced in a shell are the same document, sealed the
// same way, and verify identically.

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/certificate"
)

// maxCertificateBody caps a dropped pentest report. Reports are JSON with a
// finding list; 16 MiB is far above a realistic one and far below "let a peer
// exhaust the heap".
const maxCertificateBody = 16 << 20

// certificateIssueMu serializes first-time key creation so two tabs dropping a
// report at once cannot both mint a key and race the file.
var certificateIssueMu sync.Mutex

// dashboardCertificateKeyPath is the same persistent sealing identity the CLI
// uses, so certificates issued from either entry point share one signer.
func dashboardCertificateKeyPath() string {
	return filepath.Join(authz.ConfigHome(), "certificate-key.pem")
}

type certificateIssueRequest struct {
	Issuer string `json:"issuer,omitempty"`
}

// handleCertificateIssue turns a pentest report into a signed certificate.
//
// Request body: the pentest report JSON as `stress-strike pentest --format
// json` wrote it (optionally wrapped as {"report": {...}, "issuer": "..."}).
// Response: the ss-cert/v1 certificate JSON, including its printable HTML.
func (s *Server) handleCertificateIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCertificateBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read report: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		http.Error(w, "empty body — drop a pentest report JSON", http.StatusBadRequest)
		return
	}

	reportRaw, issuer := unwrapCertificateIssueBody(raw)
	report, err := certificate.ParsePentestReport(reportRaw)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
			"hint":  "this endpoint needs the JSON report `stress-strike pentest --format json` writes",
		})
		return
	}
	if strings.TrimSpace(issuer) == "" {
		issuer = "stress-strike assessment"
	}

	kp, created, err := loadDashboardSealingKey()
	if err != nil {
		http.Error(w, "load sealing key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	a := certificate.BuildAssessment(report, issuer, s.versionOrDefault())
	cert, err := certificate.Issue(kp, a)
	if err != nil {
		http.Error(w, "sign certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Certificate-Key-Created", boolString(created))
	if err := json.NewEncoder(w).Encode(cert); err != nil {
		http.Error(w, "encode certificate: "+err.Error(), http.StatusInternalServerError)
	}
}

// unwrapCertificateIssueBody accepts either a bare pentest report or a small
// envelope {"report": {...}, "issuer": "..."} so the browser can carry both.
func unwrapCertificateIssueBody(raw []byte) ([]byte, string) {
	var env struct {
		Report json.RawMessage `json:"report"`
		Issuer string          `json:"issuer"`
	}
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Report) > 0 {
		return env.Report, env.Issuer
	}
	return raw, ""
}

func loadDashboardSealingKey() (*attest.Keypair, bool, error) {
	certificateIssueMu.Lock()
	defer certificateIssueMu.Unlock()
	kp, created, err := attest.LoadOrCreateKeypairPEM(dashboardCertificateKeyPath())
	if err != nil {
		return nil, false, err
	}
	return kp, created, nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
