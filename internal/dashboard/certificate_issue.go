package dashboard

// Certificate issuing, download, verify and history from the browser.
//
// The dashboard reuses the CLI's code path — certificate.ParsePentestReport,
// certificate.BuildAssessment and certificate.Issue — so a certificate produced
// in the browser and one produced in a shell are the same document, sealed the
// same way, and verify identically.
//
// Certificates are persisted in $SIFT_HOME/certificates.jsonl and form
// a hash chain: each certificate stores the SHA-256 of the previous one, so
// removal or re-ordering is detectable during verification.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/certificate"
)

// maxCertificateBody caps a dropped pentest request body.
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
	Report              json.RawMessage `json:"report"`
	Issuer              string          `json:"issuer,omitempty"`
	ExperimentReference string          `json:"experiment_reference,omitempty"`
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

// handleCertificateIssue turns a pentest report into a signed certificate and
// stores it in the local certificate store.
//
// Request body: {"report": <pentest json>, "issuer": "..."} or bare pentest json.
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

	var req certificateIssueRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	reportRaw := req.Report
	if len(reportRaw) == 0 {
		reportRaw = raw
	}
	issuer := strings.TrimSpace(req.Issuer)
	if issuer == "" {
		issuer = "Sift assessment"
	}
	experimentRef := strings.TrimSpace(req.ExperimentReference)

	report, err := certificate.ParsePentestReport(reportRaw)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
			"hint":  "this endpoint needs the JSON report `Sift pentest --format json` writes",
		})
		return
	}

	certStoreEnsure()
	kp, created, err := loadDashboardSealingKey()
	if err != nil {
		http.Error(w, "load sealing key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	a := certificate.BuildAssessment(report, issuer, s.versionOrDefault())
	a.SignedAt = certTimestamp()
	// prevHash is set atomically by certStoreIssue at write time; pass empty here.
	cert, err := certificate.Issue(kp, a, "", experimentRef)
	if err != nil {
		http.Error(w, "sign certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Atomic: sets PreviousCertificateHash to current newest hash and appends.
	// Two concurrent issues cannot receive the same predecessor hash.
	storedCert, _, err := certStoreIssue(*cert)
	if err != nil {
		http.Error(w, "store certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cert = storedCert

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Certificate-Key-Created", boolString(created))
	w.Header().Set("X-Certificate-ID", cert.CertificateID)
	if err := json.NewEncoder(w).Encode(cert); err != nil {
		http.Error(w, "encode certificate: "+err.Error(), http.StatusInternalServerError)
	}
}

// handleCertificateDownload returns a stored certificate in the requested
// format: json (default), html or pdf.
func (s *Server) handleCertificateDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/certificate/download/")
	if id == "" || id == r.URL.Path {
		http.Error(w, "certificate id required", http.StatusBadRequest)
		return
	}
	certStoreEnsure()
	cert, ok := certStoreGet(id)
	if !ok {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}

	format := r.URL.Query().Get("format")
	switch format {
	case "html":
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Disposition", `attachment; filename="`+cert.CertificateID+`.html"`)
		_, _ = w.Write([]byte(cert.HTML))
		return
	case "pdf":
		pdf, err := certToPDF(&cert)
		if err != nil {
			http.Error(w, "render pdf: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+cert.CertificateID+`.pdf"`)
		_, _ = w.Write(pdf)
		return
	default: // json
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+cert.CertificateID+`.json"`)
		_ = json.NewEncoder(w).Encode(cert)
	}
}

// handleCertificateVerify verifies a submitted certificate JSON and returns the
// verification result plus chain-integrity information.
func (s *Server) handleCertificateVerify(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		http.Error(w, "empty body — paste certificate JSON", http.StatusBadRequest)
		return
	}

	cert, err := certificate.VerifyBytes(raw)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":  false,
			"reason": err.Error(),
		})
		return
	}

	certStoreEnsure()
	chainBreak := certStoreVerifyChain()
	chainIntact := chainBreak == -1

	resp := map[string]interface{}{
		"valid":                     true,
		"certificate_id":            cert.CertificateID,
		"target":                    cert.Assessment.Target,
		"grade":                     cert.Assessment.Grade,
		"verdict":                   cert.Assessment.Verdict,
		"risk_score":                cert.Assessment.RiskScore,
		"signed_at":                 cert.SignedAt,
		"experiment_reference":      cert.ExperimentReference,
		"previous_certificate_hash": cert.PreviousCertificateHash,
		"chain_intact":              chainIntact,
		"findings_count":            len(cert.Assessment.Findings),
		"covered":                   cert.Assessment.Covered,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleCertificateHistory returns the list of issued certificates (newest
// first) as lightweight summaries.
func (s *Server) handleCertificateHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	certStoreEnsure()
	summaries := certStoreSummaries()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"certificates": summaries,
		"count":        len(summaries),
	})
}

// certToPDF renders a certificate to PDF bytes.
func certToPDF(c *certificate.Certificate) ([]byte, error) {
	a := c.Assessment
	total := a.Counts.Critical + a.Counts.High + a.Counts.Medium + a.Counts.Low + a.Counts.Info
	pdf := certificate.NewPDF().
		Text("Sift - Security Assessment Certificate (ss-cert/v1)").
		Text("").
		Text("Certificate ID: " + displayOrDashDash(c.CertificateID)).
		Text("Target: " + displayOrDashDash(a.Target)).
		Text("Grade: " + displayOrDashDash(a.Grade) + "   Verdict: " + displayOrDashDash(a.Verdict) + "   Risk: " + fmt.Sprintf("%d", a.RiskScore) + "/100").
		Text(fmt.Sprintf("Findings: %d (critical %d, high %d, medium %d, low %d, info %d)", total, a.Counts.Critical, a.Counts.High, a.Counts.Medium, a.Counts.Low, a.Counts.Info)).
		Text("Scope: " + displayOrDashDash(a.Scope)).
		Text("Started: " + displayOrDashDash(a.Started) + "   Ended: " + displayOrDashDash(a.Ended)).
		Text("Duration: " + displayOrDashDash(a.Duration)).
		Text("Issuer: " + displayOrDashDash(a.Issuer) + "   Issued: " + displayOrDashDash(a.SignedAt)).
		Text("Tool: " + displayOrDashDash(strings.TrimSpace(a.Tool+" "+a.ToolVersion))).
		Text("Scanner families: " + displayOrDashDash(strings.Join(a.Covered, ", "))).
		Text("Experiment reference: " + displayOrDashDash(c.ExperimentReference)).
		Text("Previous certificate hash: " + displayOrDashDash(c.PreviousCertificateHash)).
		Text("Validity period: " + displayOrDashDash(c.ValidityPeriod)).
		Text("").
		Text("Signature (Ed25519, over canonical assessment JSON):").
		Text(displayOrDashDash(c.Signature)).
		Text("Signer public key:").
		Text(displayOrDashDash(c.PublicKey)).
		Text("Document SHA-256: " + displayOrDashDash(a.DocumentSHA))
	return pdf.Bytes()
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func displayOrDashDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
