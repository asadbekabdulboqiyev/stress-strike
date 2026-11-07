package main

// cmdCertificate implements `stress-strike certificate` — issue and verify
// Ed25519-signed security assessment certificates (ss-cert/v1, pure English).
//
// Usage:
//   stress-strike certificate --from pentest.json --key coordinator.pem
//       # issues cert.json / cert.html / cert.pdf from a pentest report
//   stress-strike certificate --verify --cert cert.json
//       # verifies the certificate offline

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/certificate"
)

func cmdCertificate() {
	var (
		from     string
		out      string
		format   string
		keyPath  string
		issuer   string
		verify   bool
		certPath string
	)

	fs := flag.NewFlagSet("certificate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&from, "from", "", "pentest JSON report to certify (produced by stress-strike pentest --format json)")
	fs.StringVar(&out, "out", "cert.json", "output certificate stem (json/html/pdf derived from it)")
	fs.StringVar(&format, "format", "all", "output format: json, html, pdf, all")
	fs.StringVar(&keyPath, "key", "", "Ed25519 keypair PEM that seals the certificate (ephemeral when omitted)")
	fs.StringVar(&issuer, "issuer", "stress-strike assessment", "certificate issuer name")
	fs.BoolVar(&verify, "verify", false, "verify mode: check --cert and report valid/invalid")
	fs.StringVar(&certPath, "cert", "", "certificate file to verify (with --verify)")

	if err := fs.Parse(os.Args[2:]); err != nil {
		fatal(fmt.Errorf("certificate: %v\n\nusage: stress-strike certificate [--from report.json] [--out cert] [--format json|html|pdf|all] [--key key.pem] [--issuer name]\n   or: stress-strike certificate --verify --cert cert.json", err))
	}

	if verify {
		if certPath == "" {
			fatal(fmt.Errorf("--cert is required with --verify"))
		}
		data, err := os.ReadFile(certPath)
		if err != nil {
			fatal(fmt.Errorf("read certificate: %w", err))
		}
		c, err := certificate.VerifyBytes(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID —", err)
			os.Exit(1)
		}
		a := c.Assessment
		fmt.Println("VALID — ss-cert/v1 Ed25519 certificate")
		fmt.Printf("  target:    %s\n", a.Target)
		fmt.Printf("  grade:     %s\n", a.Grade)
		fmt.Printf("  verdict:   %s\n", a.Verdict)
		fmt.Printf("  risk:      %d/100\n", a.RiskScore)
		total := a.Counts.Critical + a.Counts.High + a.Counts.Medium + a.Counts.Low + a.Counts.Info
		fmt.Printf("  findings:  %d (c %d h %d m %d l %d i %d)\n",
			total, a.Counts.Critical, a.Counts.High, a.Counts.Medium, a.Counts.Low, a.Counts.Info)
		fmt.Printf("  signer:    %s...\n", c.PublicKey[:16])
		fmt.Printf("  signed at: %s UTC\n", c.SignedAt)
		return
	}

	if from == "" {
		fatal(fmt.Errorf("--from is required (pentest JSON report); or use --verify --cert <file>"))
	}

	raw, err := os.ReadFile(from)
	if err != nil {
		fatal(fmt.Errorf("read report: %w", err))
	}
	var report PentestReport
	if err := json.Unmarshal(raw, &report); err != nil {
		fatal(fmt.Errorf("parse report: %w", err))
	}

	var kp *attest.Keypair
	if keyPath != "" {
		kp, err = attest.LoadKeypairPEM(keyPath)
		if err != nil {
			fatal(fmt.Errorf("load key: %w", err))
		}
	} else {
		kp, err = attest.GenerateKeypair()
		if err != nil {
			fatal(fmt.Errorf("generate key: %w", err))
		}
		fmt.Fprintf(os.Stderr, "warning: ephemeral sealing key (anyone can verify, only the key holder can re-seal)\n")
	}

	started := report.StartedAt.UTC().Format(time.RFC3339)
	ended := report.StartedAt.Add(report.Duration).UTC().Format(time.RFC3339)
	a := certificate.NewFromPentest(report.Target, report.Scope, issuer, binaryVersion(),
		report.RiskScore, report.Grade, report.Verdict,
		certificate.Counts{
			Critical: report.Critical,
			High:     report.High,
			Medium:   report.Medium,
			Low:      report.Low,
			Info:     report.InfoCount,
		},
		report.OWASPPass, started, ended, report.Duration.String())

	for _, v := range report.Vulns {
		a.Findings = append(a.Findings, certificate.Finding{
			ID:       v.ID,
			Severity: v.Severity,
			Title:    v.Title,
			Evidence: v.Evidence,
		})
	}
	for _, c := range report.Compliance {
		for _, ctl := range c.Controls {
			a.Compliance = append(a.Compliance, certificate.ComplianceResult{
				Framework: c.Framework,
				ID:        ctl.ID,
				Title:     ctl.Title,
				Status:    ctl.Status,
			})
		}
	}
	if report.Tech != nil {
		a.Covered = append(a.Covered, "tech")
	}
	if report.Ports != nil {
		a.Covered = append(a.Covered, "ports")
	}
	if report.Subdomains != nil {
		a.Covered = append(a.Covered, "subdomains")
	}
	if report.Headers != nil {
		a.Covered = append(a.Covered, "headers")
	}
	if report.TLS != nil {
		a.Covered = append(a.Covered, "tls")
	}
	if report.WAF != nil {
		a.Covered = append(a.Covered, "waf")
	}
	if len(report.Vulns) > 0 {
		a.Covered = append(a.Covered, "vulns")
	}
	if len(report.CVEs) > 0 {
		a.Covered = append(a.Covered, "cves")
	}
	if len(report.OWASP) > 0 {
		a.Covered = append(a.Covered, "owasp")
	}
	if report.LoadTest != nil {
		a.Covered = append(a.Covered, "load_test")
	}
	if len(report.Compliance) > 0 {
		a.Covered = append(a.Covered, "compliance")
	}

	// Render the bound document (seal placeholder) whose SHA-256 is bound into
	// the signed assessment. The real seal is applied after signing.
	boundHTML := certificate.RenderHTML(a, "SIGNATURE_PLACEHOLDER", "KEY_PLACEHOLDER", a.SignedAt, certificate.Version)

	cert, err := certificate.Sign(kp, a, boundHTML)
	if err != nil {
		fatal(fmt.Errorf("sign certificate: %w", err))
	}

	// Apply the real signature seal for display (the seal is outside the
	// cryptographic boundary). Render from the same assessment `a` used to
	// build boundHTML so the stripped document body matches DocumentSHA.
	cert.HTML = certificate.RenderHTML(a, cert.Signature, cert.PublicKey, cert.SignedAt, cert.Version)

	stem := strings.TrimSuffix(out, filepath.Ext(out))
	written := []string{}
	write := func(ext string, data []byte) {
		path := stem + ext
		if err := os.WriteFile(path, data, 0644); err != nil {
			fatal(fmt.Errorf("write %s: %w", path, err))
		}
		written = append(written, path)
	}

	f := strings.ToLower(format)
	switch f {
	case "json":
		data, err := certJSONBytes(cert)
		if err != nil {
			fatal(fmt.Errorf("marshal json: %w", err))
		}
		write(".json", data)
	case "html":
		write(".html", []byte(certificate.HTML(cert)))
	case "pdf":
		write(".pdf", renderPDF(a, cert))
	case "all":
		jdata, err := certJSONBytes(cert)
		if err != nil {
			fatal(fmt.Errorf("marshal json: %w", err))
		}
		write(".json", jdata)
		write(".html", []byte(certificate.HTML(cert)))
		write(".pdf", renderPDF(a, cert))
	default:
		fatal(fmt.Errorf("unknown --format %q (use json, html, pdf, all)", format))
	}

	fmt.Fprintf(os.Stderr, "certificate issued: %s\n", strings.Join(written, ", "))
	fmt.Fprintf(os.Stderr, "verify with: stress-strike certificate --verify %s.json\n", stem)
}

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

func certJSONBytes(c *certificate.Certificate) ([]byte, error) {
	return json.MarshalIndent(struct {
		Assessment certificate.Assessment `json:"assessment"`
		Signature  string                 `json:"signature"`
		PublicKey  string                 `json:"public_key"`
		SignedAt   string                 `json:"signed_at"`
		Version    string                 `json:"version"`
		HTML       string                 `json:"html"`
	}{
		Assessment: c.Assessment,
		Signature:  c.Signature,
		PublicKey:  c.PublicKey,
		SignedAt:   c.SignedAt,
		Version:    c.Version,
		HTML:       c.HTML,
	}, "", "  ")
}

func binaryVersion() string {
	return "0.14.5"
}
