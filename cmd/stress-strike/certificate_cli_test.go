package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCertificateCLIExplain(t *testing.T) {
	res := runCommandFn(t, cmdCertificate, "certificate", "--explain")
	if res.code != 0 {
		t.Fatalf("certificate --explain exit = %d, stderr = %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "signed proof of a security assessment") {
		t.Errorf("guide output = %q", res.stdout)
	}
}

func TestCertificateCLIMissingFileFails(t *testing.T) {
	res := runCommandFn(t, cmdCertificate, "certificate", "/tmp/stress-strike-definitely-missing-"+strings.ReplaceAll(t.Name(), "/", "-")+".json")
	if res.code != 1 {
		t.Fatalf("missing file exit = %d, stderr = %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "file not found") {
		t.Errorf("stderr = %q", res.stderr)
	}
}

func TestCertificateCLIIssueThenVerifyRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("STRESS_STRIKE_HOME", home)
	dir := t.TempDir()

	report := []byte(`{
		"target": "https://example.com",
		"risk_score": 12,
		"grade": "B",
		"verdict": "PASS",
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
		"owasp_pass": 0
	}`)
	reportPath := filepath.Join(dir, "pentest.json")
	if err := os.WriteFile(reportPath, report, 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	out := filepath.Join(dir, "cert")

	res := runCommandFn(t, cmdCertificate, "certificate", "--out", out, reportPath)
	if res.code != 0 {
		t.Fatalf("issue exit = %d, stdout = %s, stderr = %s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "Certificate issued") {
		t.Errorf("issue output = %q", res.stdout)
	}

	certPath := out + ".json"
	res = runCommandFn(t, cmdCertificate, "certificate", certPath)
	if res.code != 0 {
		t.Fatalf("verify exit = %d, stdout = %s, stderr = %s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "VALID") {
		t.Errorf("verify output = %q", res.stdout)
	}
}

// An attestation bundle is verifiable evidence, just not a certificate. Pointing
// the operator at the wrong command is worse than saying nothing, so pin the
// exact invocation the CLI prints: `verify` requires --bundle.
func TestCertificateCLIAttestationBundleHint(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundle, []byte(`{"format":"vpmp/v1","workers":[],"aggregate":{},"signature":{"alg":"ed25519"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	res := runCommandFn(t, cmdCertificate, "certificate", bundle)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1; stdout = %s", res.code, res.stdout)
	}
	if !strings.Contains(res.stderr, "attestation bundle") {
		t.Errorf("stderr should name the file as an attestation bundle: %q", res.stderr)
	}
	if want := "verify --bundle " + bundle; !strings.Contains(res.stderr, want) {
		t.Errorf("stderr should suggest %q; got %q", want, res.stderr)
	}
}
