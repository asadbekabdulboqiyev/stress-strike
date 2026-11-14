package bounty

// helpers_test.go — shared fixtures for the bounty package tests.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
	"github.com/asadbekabdulboqiyev/sift/internal/evidence"
)

// fixedTime is the manifest timestamp used everywhere a deterministic digest
// matters.
var fixedTime = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

const testScope = `# Acme Web scope
example.com
*.acme.test
`

const testClaimJSON = `{
  "schema_version": "bounty-claim/v1",
  "title": "Cross-tenant invoice read",
  "severity": "high",
  "component": "billing-api",
  "reproduction_steps": ["create an invoice", "request it as another tenant"],
  "impact": "Any authenticated tenant can read another tenant's invoices.",
  "cwe": ["CWE-639"],
  "owasp": ["A01:2021"]
}
`

// writeTestFile writes a fixture file and returns its path.
func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	return path
}

// basePackageOptions returns options for a report+scope+claim package.
func basePackageOptions(t *testing.T, dir string) PackageOptions {
	t.Helper()
	return PackageOptions{
		ReportPath:   writeTestFile(t, dir, "report.md", "# Report\n\nA cross-tenant read.\n"),
		ScopePath:    writeTestFile(t, dir, "scope.txt", testScope),
		ClaimPath:    writeTestFile(t, dir, "claim.json", testClaimJSON),
		Program:      "Acme Web",
		ProgramScope: "api.example.com and *.acme.test",
		CreatedAt:    fixedTime,
		ToolName:     "sift",
		ToolVersion:  "test",
	}
}

// buildBaseManifest builds the standard fixture package.
func buildBaseManifest(t *testing.T, dir string) Manifest {
	t.Helper()
	m, err := BuildManifest(basePackageOptions(t, dir))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	return m
}

// evidenceFixture is a signed bundle with a matching sidecar.
type evidenceFixture struct {
	BundlePath  string
	SamplesPath string
	PublicKey   string
	Bundle      attest.Bundle
	Records     []attest.Record
}

// buildEvidenceFixture synthesises records, seals them into a signed bundle and
// writes both the bundle and its sidecar. It uses the same producer path as a
// real run (evidence.BuildBundle), so the verifier exercises the real format.
func buildEvidenceFixture(t *testing.T, dir string) evidenceFixture {
	t.Helper()

	col, err := evidence.NewCollector("fixture-1")
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	for i := uint64(0); i < 10; i++ {
		col.Emit(engine.Sample{
			Seq:       i,
			StartNS:   int64(i) * int64(time.Millisecond),
			LatencyNS: int64(500 * time.Microsecond),
			Status:    200,
			Bytes:     128,
		})
	}
	if err := col.Err(); err != nil {
		t.Fatalf("collector: %v", err)
	}

	workerKey, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("worker keypair: %v", err)
	}
	coordKey, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("coordinator keypair: %v", err)
	}
	planned, err := attest.DecimalFromMilli(1000)
	if err != nil {
		t.Fatalf("planned rps: %v", err)
	}

	bundle, err := evidence.BuildBundle(evidence.BundleInput{
		Collector:      col,
		WorkerKey:      workerKey,
		CoordinatorKey: coordKey,
		Tool:           attest.Tool{Name: "sift", Version: "test"},
		Run: attest.Run{
			Target:     "https://api.example.com/invoices",
			Profile:    "steady",
			DurationNS: int64(time.Second),
			PlannedRPS: planned,
		},
		CreatedAt: fixedTime,
	})
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	bundlePath := filepath.Join(dir, "bundle.json")
	if err := attest.SaveBundle(bundle, bundlePath); err != nil {
		t.Fatalf("SaveBundle: %v", err)
	}
	samplesPath := filepath.Join(dir, "samples.jsonl")
	f, err := os.OpenFile(samplesPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create sidecar: %v", err)
	}
	if err := attest.WriteSamples(f, col.Records()); err != nil {
		_ = f.Close()
		t.Fatalf("WriteSamples: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close sidecar: %v", err)
	}

	return evidenceFixture{
		BundlePath:  bundlePath,
		SamplesPath: samplesPath,
		PublicKey:   attest.PublicKeyHex(coordKey.Public),
		Bundle:      bundle,
		Records:     col.Records(),
	}
}

// findCheck returns the named check from a report.
func findCheck(report VerificationReport, name string) (Check, bool) {
	for _, c := range report.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

// newPublicKeyHex returns the lowercase hex public key of a fresh keypair.
func newPublicKeyHex(t *testing.T) string {
	t.Helper()
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return attest.PublicKeyHex(kp.Public)
}
