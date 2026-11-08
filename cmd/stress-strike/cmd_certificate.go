package main

// cmdCertificate implements `stress-strike certificate` — issue and verify
// Ed25519-signed security assessment certificates (ss-cert/v1, pure English).
//
// The command is zero-flag by design: point it at a file and it works out what
// the file is.
//
//	stress-strike certificate                        # short guide
//	stress-strike certificate pentest.json           # issue cert.json/.html/.pdf
//	stress-strike certificate cert.json              # verify it
//	stress-strike certificate --explain              # plain-English explanation
//
// The old flag forms still work (`--from`, `--verify --cert`); nothing that
// scripts already use was removed.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/certificate"
)

// defaultCertificateKeyPath is the persistent sealing identity. It lives with
// the rest of the local state so every certificate this machine issues carries
// the same signer and re-sealing does not require hunting for a key file.
func defaultCertificateKeyPath() string {
	return filepath.Join(authz.ConfigHome(), "certificate-key.pem")
}

func cmdCertificate() {
	var (
		from     string
		out      string
		format   string
		keyPath  string
		issuer   string
		verify   bool
		certPath string
		explain  bool
		quiet    bool
	)

	fs := flag.NewFlagSet("certificate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&from, "from", "", "pentest JSON report to certify (optional: a positional file is auto-detected)")
	fs.StringVar(&out, "out", "cert", "output certificate stem (json/html/pdf derived from it)")
	fs.StringVar(&format, "format", "all", "output format: json, html, pdf, all")
	fs.StringVar(&keyPath, "key", "", "Ed25519 keypair PEM that seals the certificate (default: persistent key in the stress-strike home)")
	fs.StringVar(&issuer, "issuer", "stress-strike assessment", "certificate issuer name")
	fs.BoolVar(&verify, "verify", false, "force verify mode")
	fs.StringVar(&certPath, "cert", "", "certificate file to verify")
	fs.BoolVar(&explain, "explain", false, "explain what the certificate is and how to get/check one")
	fs.BoolVar(&quiet, "quiet", false, "only print the result, not the next steps")

	if err := fs.Parse(os.Args[2:]); err != nil {
		fatal(fmt.Errorf("certificate: %v", err))
	}

	positional := fs.Arg(0)

	if explain || (positional == "" && from == "" && certPath == "" && !verify && !hasCertFlags(fs)) {
		printCertificateGuide(explain)
		return
	}

	// Normalise the three ways to name a file into one path + intent.
	if certPath == "" && verify {
		certPath = positional
	}
	if from == "" && !verify && certPath == "" {
		from = positional
	}

	// A bare file argument decides issue vs verify by its contents.
	if from != "" && certPath == "" {
		kind, err := detectCertificateInput(from)
		if err != nil {
			fatal(err)
		}
		if kind == inputCertificate {
			certPath = from
			from = ""
		}
	}

	if certPath != "" {
		verifyCertificateFile(certPath, quiet)
		return
	}

	if from == "" {
		fatal(fmt.Errorf("no input file. Try:\n  stress-strike certificate pentest.json    # issue\n  stress-strike certificate cert.json       # verify\n  stress-strike certificate --explain      # what is this?"))
	}

	issueCertificate(from, out, format, keyPath, issuer, quiet)
}

// hasCertFlags reports whether the operator passed any flag at all, so a bare
// `certificate --format html` still reaches the "no input" error instead of the
// guide.
func hasCertFlags(fs *flag.FlagSet) bool {
	found := false
	fs.Visit(func(*flag.Flag) { found = true })
	return found
}

type certificateInput int

const (
	inputUnknown certificateInput = iota
	inputCertificate
	inputPentestReport
)

// detectCertificateInput sniffs a JSON file. A certificate carries "assessment"
// and "signature"; a pentest report carries "target" and a risk/grade summary.
func detectCertificateInput(path string) (certificateInput, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return inputUnknown, fmt.Errorf("file not found: %s", path)
		}
		return inputUnknown, fmt.Errorf("read %s: %w", path, err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return inputUnknown, fmt.Errorf("%s is not JSON — expected a pentest report or a certificate: %w", path, err)
	}
	if _, ok := probe["assessment"]; ok {
		if _, ok := probe["signature"]; ok {
			return inputCertificate, nil
		}
	}
	if _, ok := probe["target"]; ok {
		return inputPentestReport, nil
	}
	return inputUnknown, fmt.Errorf("%s is JSON but neither a pentest report (needs \"target\") nor a certificate (needs \"assessment\"+\"signature\")", path)
}

func verifyCertificateFile(path string, quiet bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal(fmt.Errorf("read certificate: %w", err))
	}
	c, err := certificate.VerifyBytes(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "INVALID —", err)
		os.Exit(1)
	}
	a := c.Assessment
	total := a.Counts.Critical + a.Counts.High + a.Counts.Medium + a.Counts.Low + a.Counts.Info
	fmt.Println("VALID — ss-cert/v1 Ed25519 certificate")
	fmt.Printf("  target:    %s\n", a.Target)
	fmt.Printf("  grade:     %s\n", a.Grade)
	fmt.Printf("  verdict:   %s\n", a.Verdict)
	fmt.Printf("  risk:      %d/100\n", a.RiskScore)
	fmt.Printf("  findings:  %d (c %d h %d m %d l %d i %d)\n",
		total, a.Counts.Critical, a.Counts.High, a.Counts.Medium, a.Counts.Low, a.Counts.Info)
	fmt.Printf("  signer:    %s...\n", firstN(c.PublicKey, 16))
	fmt.Printf("  signed at: %s UTC\n", c.SignedAt)
	if quiet {
		return
	}
	fmt.Println()
	fmt.Println("The seal covers the assessment above and the rendered document body.")
	fmt.Println("Editing either one makes this check fail; verification needs no key and no network.")
	if c.HTML != "" {
		fmt.Println("The printable copy is inside the JSON (\"html\" field).")
	}
}

func issueCertificate(from, out, format, keyPath, issuer string, quiet bool) {
	raw, err := os.ReadFile(from)
	if err != nil {
		fatal(fmt.Errorf("read report: %w", err))
	}
	report, err := certificate.ParsePentestReport(raw)
	if err != nil {
		fatal(err)
	}

	if keyPath == "" {
		keyPath = defaultCertificateKeyPath()
	}
	kp, created, err := attest.LoadOrCreateKeypairPEM(keyPath)
	if err != nil {
		fatal(fmt.Errorf("load sealing key: %w", err))
	}
	if created && !quiet {
		fmt.Fprintf(os.Stderr, "sealing key created: %s (mode 0600)\n", keyPath)
	}

	a := certificate.BuildAssessment(report, issuer, binaryVersion())
	cert, err := certificate.Issue(kp, a, "", "")
	if err != nil {
		fatal(fmt.Errorf("sign certificate: %w", err))
	}

	stem := strings.TrimSuffix(out, filepath.Ext(out))
	written := []string{}
	write := func(ext string, data []byte) {
		path := stem + ext
		if err := os.WriteFile(path, data, 0o644); err != nil {
			fatal(fmt.Errorf("write %s: %w", path, err))
		}
		written = append(written, path)
	}

	jdata, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		fatal(fmt.Errorf("marshal json: %w", err))
	}

	switch strings.ToLower(format) {
	case "json":
		write(".json", jdata)
	case "html":
		write(".html", []byte(certificate.HTML(cert)))
	case "pdf":
		write(".pdf", renderPDF(a, cert))
	case "all":
		write(".json", jdata)
		write(".html", []byte(certificate.HTML(cert)))
		write(".pdf", renderPDF(a, cert))
	default:
		fatal(fmt.Errorf("unknown --format %q (use json, html, pdf, all)", format))
	}

	if quiet {
		fmt.Fprintln(os.Stdout, strings.Join(written, " "))
		return
	}

	total := a.Counts.Critical + a.Counts.High + a.Counts.Medium + a.Counts.Low + a.Counts.Info
	fmt.Println("Certificate issued")
	fmt.Println()
	fmt.Printf("  target     %s\n", a.Target)
	fmt.Printf("  result     grade %s · risk %d/100 · %s\n", a.Grade, a.RiskScore, a.Verdict)
	fmt.Printf("  findings   %d (c %d h %d m %d l %d i %d)\n",
		total, a.Counts.Critical, a.Counts.High, a.Counts.Medium, a.Counts.Low, a.Counts.Info)
	fmt.Printf("  signer     %s…\n", firstN(cert.PublicKey, 16))
	fmt.Printf("  key file   %s\n", keyPath)
	fmt.Println()
	fmt.Println("  files")
	for _, p := range written {
		fmt.Printf("    %s\n", p)
	}
	fmt.Println()
	fmt.Println("Verify it (offline, no key needed):")
	if hasFile(written, stem+".json") {
		fmt.Printf("  stress-strike certificate %s.json\n", stem)
	} else {
		fmt.Printf("  stress-strike certificate <certificate>.json\n")
	}
	fmt.Println()
	fmt.Println("Share the .html copy for a printable view; the .json is the proof.")
	fmt.Println("Tip: the dashboard's Certificate page verifies a dropped file and issues from a dropped report.")
}

func hasFile(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func printCertificateGuide(explain bool) {
	fmt.Println(`stress-strike certificate — signed proof of a security assessment

  ISSUE a certificate from a pentest report:
    stress-strike certificate pentest.json

  VERIFY a certificate someone sent you:
    stress-strike certificate cert.json

  Both forms are the same command: it looks at the file and knows which one
  you meant. No flags, no key hunting, no network.

  First issue creates a persistent sealing key at:
    ` + defaultCertificateKeyPath() + `
  Back that file up if you want to re-seal certificates as the same signer.`)

	if !explain {
		fmt.Println(`
  More:
    stress-strike certificate --explain     what the certificate proves
    stress-strike pentest --target URL --authorized TICKET --format json`)
		return
	}

	fmt.Println(`
WHAT IT IS
  A certificate is one JSON file containing:
    · the assessment summary (target, grade, risk, findings, coverage),
    · the full printable document,
    · an Ed25519 signature over both.
  Anyone can check it with this binary. They need no key, no network and no
  access to your machine. If a single byte of the assessment or the document
  changes, verification fails.

WHAT IT PROVES — AND WHAT IT DOES NOT
  It proves: this report was sealed by this signing key, and the document you
  are reading is the one that was sealed.
  It does not prove: the target is secure, the scan was exhaustive, or the
  signer is a trusted authority. It is tamper-evident evidence, not a warranty.
  That is why every certificate states the coverage and marks untested
  categories as NOT TESTED instead of inventing a PASS.

HOW TO OBTAIN ONE
  1. Register the authorization the target owner gave you:
       stress-strike authorize add --pattern example.com --approver "Owner Name" --ticket TICKET-001
  2. Run the assessment:
       stress-strike pentest --target https://example.com --authorized TICKET-001 --format json
  3. Seal the report:
       stress-strike certificate pentest-example.com-....json
  4. Send cert.json (proof) and cert.html (readable copy).

HOW TO VERIFY ONE
  Command line:   stress-strike certificate cert.json
  Dashboard:      open the dashboard, Certificate page, drop cert.json
  Exit codes:     0 = VALID, 1 = INVALID (the reason is printed)

WHERE THE CODE LIVES
  internal/certificate — ss-cert/v1 sign/verify, document binding, HTML/PDF.
  The seal is excluded from the document hash by design, so printing or saving
  the HTML does not change what was signed.)`)
}

// renderPDF renders the one-page printable certificate.
func renderPDF(a certificate.Assessment, cert *certificate.Certificate) []byte {
	total := a.Counts.Critical + a.Counts.High + a.Counts.Medium + a.Counts.Low + a.Counts.Info
	pdf := certificate.NewPDF().
		Text("stress-strike — Security Assessment Certificate (ss-cert/v1)").
		Text("Target: " + a.Target).
		Text("Grade: " + a.Grade + "   Verdict: " + a.Verdict + "   Risk: " + fmt.Sprintf("%d", a.RiskScore) + "/100").
		Text("Findings: " + fmt.Sprintf("%d", total)).
		Text("Issuer: " + a.Issuer + "   Signed: " + a.SignedAt + " UTC").
		Text("Signature: " + cert.Signature).
		Text("Public key: " + cert.PublicKey)
	out, err := pdf.Bytes()
	if err != nil {
		fatal(fmt.Errorf("render pdf: %w", err))
	}
	return out
}

// certJSONBytes serializes the certificate in the exact ss-cert/v1 shape that
// certificate.VerifyBytes accepts.
func certJSONBytes(c *certificate.Certificate) ([]byte, error) {
	return json.MarshalIndent(struct {
		Assessment              certificate.Assessment `json:"assessment"`
		Signature               string                 `json:"signature"`
		PublicKey               string                 `json:"public_key"`
		SignedAt                string                 `json:"signed_at"`
		Version                 string                 `json:"version"`
		HTML                    string                 `json:"html"`
		CertificateID           string                 `json:"certificate_id"`
		PreviousCertificateHash string                 `json:"previous_certificate_hash"`
		ExperimentReference     string                 `json:"experiment_reference"`
		ValidityPeriod          string                 `json:"validity_period"`
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
	}, "", "  ")
}

// binaryVersion is the build version stamped into issued certificates.
func binaryVersion() string { return version }
