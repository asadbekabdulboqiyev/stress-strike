package certificate

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
)

// Issue renders, binds and signs one assessment. The document's SHA-256 is
// computed over the rendered body with a placeholder seal, then the real
// signature seal is applied for display — so the JSON, the HTML and the PDF all
// describe the same signed evidence and a tampered body still fails Verify.
//
// Both the CLI (`stress-strike certificate`) and the dashboard call this, so
// the two cannot produce certificates that verify differently.
//
// prevHash is the SHA-256 of the previously issued certificate JSON (empty for
// the first one). experimentReference identifies the source experiment/run this
// certificate attests to.
func Issue(kp *attest.Keypair, a Assessment, prevHash string, experimentReference string) (*Certificate, error) {
	bound := RenderHTML(a, "SIGNATURE_PLACEHOLDER", "KEY_PLACEHOLDER", a.SignedAt, Version)
	cert, err := Sign(kp, a, bound)
	if err != nil {
		return nil, err
	}
	cert.HTML = RenderHTML(a, cert.Signature, cert.PublicKey, cert.SignedAt, cert.Version)
	cert.CertificateID = certID(cert)
	cert.PreviousCertificateHash = prevHash
	cert.ExperimentReference = experimentReference
	cert.ValidityPeriod = "90 days"
	return cert, nil
}

// certID returns a deterministic, certificate-unique id derived from the
// signed payload (target + signed-at + signature prefix).
func certID(c *Certificate) string {
	h := sha256.Sum256([]byte(c.Assessment.Target + "|" + c.Assessment.SignedAt + "|" + c.Signature[:16]))
	return "ss-cert-" + hex.EncodeToString(h[:])[:16]
}
