package certificate

import (
	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
)

// Issue renders, binds and signs one assessment. The document's SHA-256 is
// computed over the rendered body with a placeholder seal, then the real
// signature seal is applied for display — so the JSON, the HTML and the PDF all
// describe the same signed evidence and a tampered body still fails Verify.
//
// Both the CLI (`stress-strike certificate`) and the dashboard call this, so
// the two cannot produce certificates that verify differently.
func Issue(kp *attest.Keypair, a Assessment) (*Certificate, error) {
	bound := RenderHTML(a, "SIGNATURE_PLACEHOLDER", "KEY_PLACEHOLDER", a.SignedAt, Version)
	cert, err := Sign(kp, a, bound)
	if err != nil {
		return nil, err
	}
	cert.HTML = RenderHTML(a, cert.Signature, cert.PublicKey, cert.SignedAt, cert.Version)
	return cert, nil
}
