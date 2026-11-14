package bounty

// verify_test.go — tamper detection, scope matching and attestation folding.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyPackageVerifiedWithAttestation(t *testing.T) {
	dir := t.TempDir()
	ev := buildEvidenceFixture(t, dir)

	opts := basePackageOptions(t, dir)
	opts.BundlePath = ev.BundlePath
	opts.SamplesPath = ev.SamplesPath

	m, err := BuildManifest(opts)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if m.Attest.BundlePublicKey != ev.PublicKey {
		t.Fatalf("manifest key %q, want %q", m.Attest.BundlePublicKey, ev.PublicKey)
	}
	if m.Attest.SidecarDigest == "" {
		t.Fatal("manifest did not record the sidecar digest")
	}

	report, err := VerifyPackage(m, dir, VerifyOptions{
		BundlePath:   ev.BundlePath,
		SamplesPath:  ev.SamplesPath,
		PublicKeyHex: ev.PublicKey,
		Target:       "https://api.example.com/invoices",
	})
	if err != nil {
		t.Fatalf("VerifyPackage: %v", err)
	}
	if report.Verdict != VerdictVerified {
		t.Fatalf("verdict = %s, want %s (reasons: %v)", report.Verdict, VerdictVerified, report.Reasons)
	}
	if report.Attest == nil || !report.Attest.Checked || !report.Attest.Valid {
		t.Fatalf("attestation summary = %+v, want a valid replay", report.Attest)
	}
	if report.Attest.SamplesAbsent {
		t.Fatal("attestation reported absent samples despite a sidecar")
	}
	for _, name := range []string{"manifest", "package-digest", "artifact:bundle", "artifact:samples", "artifact:report", "artifact:scope", "artifact:claim", "scope", "attest"} {
		c, ok := findCheck(report, name)
		if !ok {
			t.Fatalf("report is missing check %q", name)
		}
		if c.Status != StatusPass {
			t.Fatalf("check %q = %s (%s), want pass", name, c.Status, c.Detail)
		}
	}
}

func TestVerifyPackageDetectsArtifactTamper(t *testing.T) {
	dir := t.TempDir()
	m := buildBaseManifest(t, dir)
	if _, err := WritePackage(m, dir); err != nil {
		t.Fatalf("WritePackage: %v", err)
	}

	// Same length, different byte: size alone would not catch this.
	reportPath := filepath.Join(dir, "report.md")
	original, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	tampered := append([]byte{}, original...)
	tampered[0] ^= 0x01
	if err := os.WriteFile(reportPath, tampered, 0o600); err != nil {
		t.Fatalf("tamper report: %v", err)
	}

	report, err := VerifyPackage(m, dir, VerifyOptions{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("VerifyPackage: %v", err)
	}
	if report.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want failed", report.Verdict)
	}
	c, ok := findCheck(report, "artifact:report")
	if !ok || c.Status != StatusFail {
		t.Fatalf("artifact:report check = %+v, want fail", c)
	}
	if len(report.Reasons) == 0 {
		t.Fatal("failed report has no reasons")
	}
}

func TestVerifyPackageDetectsManifestTamper(t *testing.T) {
	dir := t.TempDir()
	m := buildBaseManifest(t, dir)
	m.Program.Name = "Someone Else" // digest no longer matches

	report, err := VerifyPackage(m, dir, VerifyOptions{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("VerifyPackage: %v", err)
	}
	if report.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want failed", report.Verdict)
	}
	c, ok := findCheck(report, "package-digest")
	if !ok || c.Status != StatusFail {
		t.Fatalf("package-digest check = %+v, want fail", c)
	}
}

func TestVerifyPackageScope(t *testing.T) {
	dir := t.TempDir()
	m := buildBaseManifest(t, dir)

	cases := []struct {
		name    string
		target  string
		status  string
		verdict string
	}{
		{"in scope", "https://api.example.com/invoices", StatusPass, VerdictUnverified},
		{"bare host", "example.com", StatusPass, VerdictUnverified},
		{"wildcard entry", "https://app.acme.test/x", StatusPass, VerdictUnverified},
		{"out of scope", "https://evil.example.org/x", StatusFail, VerdictFailed},
		{"lookalike host", "https://notexample.com/x", StatusFail, VerdictFailed},
		{"target omitted", "", StatusSkip, VerdictUnverified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := VerifyPackage(m, dir, VerifyOptions{Target: tc.target})
			if err != nil {
				t.Fatalf("VerifyPackage: %v", err)
			}
			c, ok := findCheck(report, "scope")
			if !ok {
				t.Fatal("report is missing the scope check")
			}
			if c.Status != tc.status {
				t.Fatalf("scope status = %s (%s), want %s", c.Status, c.Detail, tc.status)
			}
			if report.Verdict != tc.verdict {
				t.Fatalf("verdict = %s, want %s", report.Verdict, tc.verdict)
			}
		})
	}
}

func TestVerifyPackageMissingArtifact(t *testing.T) {
	dir := t.TempDir()
	m := buildBaseManifest(t, dir)
	if err := os.Remove(filepath.Join(dir, "scope.txt")); err != nil {
		t.Fatalf("remove scope: %v", err)
	}

	report, err := VerifyPackage(m, dir, VerifyOptions{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("VerifyPackage: %v", err)
	}
	if report.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want failed", report.Verdict)
	}
	for _, name := range []string{"artifact:scope", "scope"} {
		c, ok := findCheck(report, name)
		if !ok || c.Status != StatusFail {
			t.Fatalf("%s check = %+v, want fail", name, c)
		}
	}
}

func TestVerifyPackageAttestationKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	ev := buildEvidenceFixture(t, dir)
	opts := basePackageOptions(t, dir)
	opts.BundlePath = ev.BundlePath
	opts.SamplesPath = ev.SamplesPath
	m, err := BuildManifest(opts)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	other := newPublicKeyHex(t)

	report, err := VerifyPackage(m, dir, VerifyOptions{
		BundlePath:   ev.BundlePath,
		SamplesPath:  ev.SamplesPath,
		PublicKeyHex: other,
		Target:       "https://example.com",
	})
	if err != nil {
		t.Fatalf("VerifyPackage: %v", err)
	}
	if report.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want failed", report.Verdict)
	}
	c, ok := findCheck(report, "attest")
	if !ok || c.Status != StatusFail {
		t.Fatalf("attest check = %+v, want fail", c)
	}
	if !strings.Contains(c.Detail, "pinned") {
		t.Fatalf("attest detail %q does not mention the pinned key", c.Detail)
	}
}

func TestVerifyPackageAttestationRequiresBundle(t *testing.T) {
	dir := t.TempDir()
	m := buildBaseManifest(t, dir)

	report, err := VerifyPackage(m, dir, VerifyOptions{
		SamplesPath: filepath.Join(dir, "samples.jsonl"),
		Target:      "https://example.com",
	})
	if err != nil {
		t.Fatalf("VerifyPackage: %v", err)
	}
	c, ok := findCheck(report, "attest")
	if !ok || c.Status != StatusFail {
		t.Fatalf("attest check = %+v, want fail", c)
	}
	if report.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want failed", report.Verdict)
	}
}

func TestVerifyPackageRequiresBaseDir(t *testing.T) {
	m := Manifest{}
	if _, err := VerifyPackage(m, "  ", VerifyOptions{}); err == nil {
		t.Fatal("VerifyPackage accepted an empty base directory")
	}
}

func TestVerifyPackageInvalidManifestReportsFailed(t *testing.T) {
	report, err := VerifyPackage(Manifest{}, t.TempDir(), VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyPackage returned an error for an invalid manifest: %v", err)
	}
	if report.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want failed", report.Verdict)
	}
	if c, ok := findCheck(report, "manifest"); !ok || c.Status != StatusFail {
		t.Fatalf("manifest check = %+v, want fail", c)
	}
}

func TestScopeContains(t *testing.T) {
	scope := []byte("# comment\n\nexample.com\n*.acme.test\nhttps://api.other.test/v1\n")
	cases := []struct {
		target string
		want   bool
	}{
		{"https://example.com/x", true},
		{"http://example.com:8080/x", true},
		{"https://a.b.example.com", true},
		{"https://app.acme.test", true},
		{"https://api.other.test/v2", true},
		{"https://notexample.com", false},
		{"https://example.com.evil.test", false},
		{"https://example.org", false},
	}
	for _, tc := range cases {
		got, err := scopeContains(scope, tc.target)
		if err != nil {
			t.Fatalf("scopeContains(%q): %v", tc.target, err)
		}
		if got != tc.want {
			t.Errorf("scopeContains(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}

	if _, err := scopeContains(scope, "   "); err == nil {
		t.Fatal("scopeContains accepted an empty target")
	}
}

func TestResolveArtifactPathRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	if _, err := resolveArtifactPath(base, "../escape.txt"); err == nil {
		t.Fatal("resolveArtifactPath accepted a traversal path")
	}
	if _, err := resolveArtifactPath(base, "/etc/passwd"); err == nil {
		t.Fatal("resolveArtifactPath accepted an absolute path")
	}
	got, err := resolveArtifactPath(base, "nested/report.md")
	if err != nil {
		t.Fatalf("resolveArtifactPath: %v", err)
	}
	if filepath.Dir(got) != filepath.Join(base, "nested") {
		t.Fatalf("resolved path %q is not inside the base directory", got)
	}
}
