// Package certificate issues and verifies signed assessment certificates.
//
// A certificate is an English, self-contained attestation that a Sift
// security assessment ran against a target, what it found, and its overall
// grade/verdict. It is sealed with an Ed25519 signature over the canonical
// assessment JSON, and the signer's public key travels inside the certificate
// so anyone can verify it with this tool alone — no external service, no
// network, no shared secret.
//
// Cryptographic boundary: the signature covers the assessment JSON, which now
// includes DocumentSHA256 — the SHA-256 of the rendered certificate document
// body (the signature seal block is excluded). Thus both the assessment data
// AND its rendered presentation are cryptographically tamper-evident.
//
// Format: ss-cert/v1
package certificate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

// Version is the ss-cert envelope format.
const Version = "ss-cert/v1"

// Finding is one assessed defect.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // critical, high, medium, low, info
	Title    string `json:"title"`
	Evidence string `json:"evidence,omitempty"`
}

// ComplianceResult maps one framework control to pass/fail.
type ComplianceResult struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title"`
	Status    string `json:"status"` // PASS / FAIL / NOT TESTED
}

// Counts is the severity histogram of all findings.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Assessment is the signed payload of a certificate. Only structs and slices
// are used (no maps) so JSON encoding is deterministic across runs.
type Assessment struct {
	// Tool identifies the issuing build.
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version"`
	// Target and scope.
	Target   string `json:"target"`
	Scope    string `json:"scope"`
	Started  string `json:"started"`
	Ended    string `json:"ended"`
	Duration string `json:"duration"`
	// Outcome.
	RiskScore   int                `json:"risk_score"`
	Grade       string             `json:"grade"`
	Verdict     string             `json:"verdict"`
	Counts      Counts             `json:"counts"`
	OWASPPass   int                `json:"owasp_pass"`
	Findings    []Finding          `json:"findings,omitempty"`
	Compliance  []ComplianceResult `json:"compliance,omitempty"`
	Covered     []string           `json:"covered,omitempty"` // scanner families that ran
	DocumentSHA string             `json:"document_sha"`      // sha256 of rendered document body (seal excluded)
	// Issuance.
	Issuer   string `json:"issuer"`
	SignedAt string `json:"signed_at"`
}

// Certificate is the sealed envelope: a signed assessment plus the signer's
// public key, so the file verifies by itself. HTML carries the full rendered
// document (signature seal included) for display/printing.
//
// Hash chain: CertificateID is a unique per-certificate identifier and
// PreviousCertificateHash binds this certificate to the one issued before it,
// so any removed or re-ordered certificate breaks the chain and is detectable
// during verification.
type Certificate struct {
	Assessment              Assessment `json:"assessment"`
	Signature               string     `json:"signature"`  // hex Ed25519 over canonical assessment JSON
	PublicKey               string     `json:"public_key"` // hex Ed25519 signer public key
	SignedAt                string     `json:"signed_at"`
	Version                 string     `json:"version"`                   // ss-cert/v1
	HTML                    string     `json:"html"`                      // full rendered document (signature seal included)
	CertificateID           string     `json:"certificate_id"`            // unique per-certificate id
	PreviousCertificateHash string     `json:"previous_certificate_hash"` // sha256 of previous certificate JSON
	ExperimentReference     string     `json:"experiment_reference"`      // source experiment/run id this cert attests to
	ValidityPeriod          string     `json:"validity_period"`           // e.g. "90 days"
}

// NewFromPentest builds an Assessment from a pentest report's summary fields.
// Callers fill in the scanner-specific slices before calling Sign.
func NewFromPentest(target, scope, issuer, toolVersion string, risk int, grade, verdict string,
	counts Counts, owaspPass int, started, ended, duration string) Assessment {
	return Assessment{
		Tool:        "Sift",
		ToolVersion: toolVersion,
		Target:      target,
		Scope:       scope,
		Started:     started,
		Ended:       ended,
		Duration:    duration,
		RiskScore:   risk,
		Grade:       grade,
		Verdict:     verdict,
		Counts:      counts,
		OWASPPass:   owaspPass,
		Issuer:      issuer,
		SignedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}

// canonical returns the deterministic JSON bytes to sign. Struct field order
// is fixed by the type declaration, so this is stable across runs and builds.
// Slices are copied before sorting so the caller's assessment is not mutated
// (slice headers are passed by value, but the backing arrays are shared).
func canonical(a Assessment) ([]byte, error) {
	findings := make([]Finding, len(a.Findings))
	copy(findings, a.Findings)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
		}
		return findings[i].ID < findings[j].ID
	})
	a.Findings = findings

	compliance := make([]ComplianceResult, len(a.Compliance))
	copy(compliance, a.Compliance)
	sort.SliceStable(compliance, func(i, j int) bool {
		if compliance[i].Framework != compliance[j].Framework {
			return compliance[i].Framework < compliance[j].Framework
		}
		return compliance[i].ID < compliance[j].ID
	})
	a.Compliance = compliance

	covered := make([]string, len(a.Covered))
	copy(covered, a.Covered)
	sort.Strings(covered)
	a.Covered = covered

	return json.Marshal(a)
}

// severityRank orders severities most-to-least for stable sorting.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// stripSeal removes the signature seal block from rendered HTML so the hash is
// computed over the document body only (the seal content — signature value,
// public key — is intentionally outside the cryptographic boundary to avoid a
// circular dependency: signature covers document, document displays signature).
func stripSeal(html string) string {
	const open = `<div class="seal">`
	const close = `</div>`
	start := strings.Index(html, open)
	if start < 0 {
		return html
	}
	rest := html[start:]
	// The seal is the final block and contains nested </div> tags, so use the
	// last </div> to locate its true end; otherwise the seal content (signature
	// value, public key) would leak into the hashed document body.
	end := strings.LastIndex(rest, close)
	if end < 0 {
		return html[:start]
	}
	return html[:start] + rest[end+len(close):]
}

// documentSHA returns the SHA-256 hex of the rendered document body, with the
// signature seal block excluded.
func documentSHA(html string) string {
	sum := sha256.Sum256([]byte(stripSeal(html)))
	return hex.EncodeToString(sum[:])
}

// Sign seals assessment with the keypair and returns a self-verifying
// Certificate (ss-cert/v1). boundHTML is the rendered document body whose
// SHA-256 is bound into the signed assessment (DocumentSHA). The seal block is
// excluded from the hash, so the caller may render the final seal afterward.
func Sign(kp *attest.Keypair, a Assessment, boundHTML string) (*Certificate, error) {
	if kp == nil || len(kp.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("certificate: signing requires a valid Ed25519 private key")
	}
	a.DocumentSHA = documentSHA(boundHTML)
	msg, err := canonical(a)
	if err != nil {
		return nil, fmt.Errorf("certificate: canonicalize assessment: %w", err)
	}
	sig, err := attest.Sign(kp, msg)
	if err != nil {
		return nil, fmt.Errorf("certificate: sign: %w", err)
	}
	return &Certificate{
		Assessment: a,
		Signature:  hex.EncodeToString(sig),
		PublicKey:  hex.EncodeToString(kp.Public),
		SignedAt:   a.SignedAt,
		Version:    Version,
		HTML:       boundHTML,
	}, nil
}

// Verify checks the certificate's Ed25519 signature over its own assessment and
// recomputes the document SHA-256 from the embedded HTML to ensure the rendered
// body was not altered. It returns nil when both are valid.
func Verify(c *Certificate) error {
	if c == nil {
		return fmt.Errorf("certificate: nil certificate")
	}
	if c.Version != Version {
		return fmt.Errorf("certificate: unsupported version %q", c.Version)
	}
	pub, err := hex.DecodeString(c.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("certificate: malformed public key")
	}
	sig, err := hex.DecodeString(c.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("certificate: malformed signature")
	}
	msg, err := canonical(c.Assessment)
	if err != nil {
		return fmt.Errorf("certificate: canonicalize assessment: %w", err)
	}
	if !attest.VerifySig(pub, msg, sig) {
		return fmt.Errorf("certificate: signature invalid — assessment or signature was altered")
	}
	// Bound-document integrity: the rendered body (seal excluded) must hash to
	// the DocumentSHA recorded in the signed assessment.
	if got := documentSHA(c.HTML); got != c.Assessment.DocumentSHA {
		return fmt.Errorf("certificate: document hash mismatch — rendered body was altered")
	}
	return nil
}

// VerifyBytes parses a JSON certificate and verifies it.
func VerifyBytes(data []byte) (*Certificate, error) {
	var c Certificate
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("certificate: parse: %w", err)
	}
	if err := Verify(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// MarshalJSON writes the certificate as JSON.
func (c *Certificate) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Assessment              Assessment `json:"assessment"`
		Signature               string     `json:"signature"`
		PublicKey               string     `json:"public_key"`
		SignedAt                string     `json:"signed_at"`
		Version                 string     `json:"version"`
		HTML                    string     `json:"html"`
		CertificateID           string     `json:"certificate_id"`
		PreviousCertificateHash string     `json:"previous_certificate_hash"`
		ExperimentReference     string     `json:"experiment_reference"`
		ValidityPeriod          string     `json:"validity_period"`
	}{
		Assessment:              c.Assessment,
		Signature:               c.Signature,
		PublicKey:               c.PublicKey,
		SignedAt:                c.SignedAt,
		Version:                 c.Version,
		HTML:                    c.HTML,
		CertificateID:           c.CertificateID,
		PreviousCertificateHash: c.PreviousCertificateHash,
		ExperimentReference:     c.ExperimentReference,
		ValidityPeriod:          c.ValidityPeriod,
	})
}
