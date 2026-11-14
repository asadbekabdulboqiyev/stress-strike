package main

// cmd_bounty_test.go — in-process tests for the bounty CLI surface.
//
// The tests drive cmdBounty through the shared harness, so flag parsing, the
// subcommand dispatch and the exit-code contract are all exercised without
// building a binary.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/bounty"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
	"github.com/asadbekabdulboqiyev/sift/internal/evidence"
)

const bountyScopeFixture = `# Acme Web scope
example.com
`

const bountyClaimFixture = `{
  "schema_version": "bounty-claim/v1",
  "title": "Cross-tenant invoice read",
  "severity": "high",
  "component": "billing-api",
  "reproduction_steps": ["create an invoice", "request it as another tenant"],
  "impact": "Any tenant can read another tenant's invoices.",
  "cwe": ["CWE-639"],
  "owasp": ["A01:2021"]
}
`

// writeBountyFixture writes a fixture file.
func writeBountyFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	return path
}

// runBounty drives cmdBounty with the given arguments.
func runBounty(t *testing.T, args ...string) cliRunResult {
	t.Helper()
	return runCommandFn(t, cmdBounty, args...)
}

// buildBountyEvidence seals a synthetic run into a real bundle and sidecar.
func buildBountyEvidence(t *testing.T, dir string) (bundlePath, samplesPath, key string) {
	t.Helper()

	col, err := evidence.NewCollector("cli-1")
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	for i := uint64(0); i < 8; i++ {
		col.Emit(engine.Sample{
			Seq:       i,
			StartNS:   int64(i) * int64(time.Millisecond),
			LatencyNS: int64(400 * time.Microsecond),
			Status:    200,
			Bytes:     64,
		})
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
		CreatedAt: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	bundlePath = filepath.Join(dir, "bundle.json")
	if err := attest.SaveBundle(bundle, bundlePath); err != nil {
		t.Fatalf("SaveBundle: %v", err)
	}
	samplesPath = filepath.Join(dir, "samples.jsonl")
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
	return bundlePath, samplesPath, attest.PublicKeyHex(coordKey.Public)
}

func TestBountyPackageVerifyStatusFlow(t *testing.T) {
	dir := t.TempDir()
	report := writeBountyFixture(t, dir, "report.md", "# Report\n\nCross-tenant read.\n")
	scope := writeBountyFixture(t, dir, "scope.txt", bountyScopeFixture)
	claim := writeBountyFixture(t, dir, "claim.json", bountyClaimFixture)
	pkgDir := filepath.Join(dir, "pkg")

	res := runBounty(t, "bounty", "package",
		"--report", report, "--scope", scope, "--claim", claim,
		"--program", "Acme Web", "--out", pkgDir)
	if res.code != 0 {
		t.Fatalf("package exit = %d, stderr = %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "digest:") || !strings.Contains(res.stdout, "bty_") {
		t.Fatalf("package output does not report identity: %s", res.stdout)
	}
	packagePath := filepath.Join(pkgDir, bounty.PackageFilename)
	if _, err := os.Stat(packagePath); err != nil {
		t.Fatalf("package manifest not written: %v", err)
	}

	// Without evidence replay the package is honestly unverified (exit 2), even
	// though artifact and digest checks pass.
	res = runBounty(t, "bounty", "verify", "--package", packagePath, "--dir", dir,
		"--target", "https://api.example.com/x", "--json")
	if res.code != 2 {
		t.Fatalf("verify exit = %d, want 2 (unverified); stderr = %s", res.code, res.stderr)
	}
	var reportJSON bounty.VerificationReport
	if err := json.Unmarshal([]byte(res.stdout), &reportJSON); err != nil {
		t.Fatalf("verify --json is not valid JSON: %v\n%s", err, res.stdout)
	}
	if reportJSON.Verdict != bounty.VerdictUnverified {
		t.Fatalf("verdict = %s, want unverified", reportJSON.Verdict)
	}

	// A target outside the scope fails closed.
	res = runBounty(t, "bounty", "verify", "--package", packagePath, "--dir", dir,
		"--target", "https://evil.example.org/x")
	if res.code != 1 {
		t.Fatalf("verify out-of-scope exit = %d, want 1; output = %s", res.code, res.stdout)
	}

	// Tampering with an artifact after packaging must fail verification.
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
	res = runBounty(t, "bounty", "verify", "--package", packagePath, "--dir", dir,
		"--target", "https://api.example.com/x")
	if res.code != 1 {
		t.Fatalf("verify tampered exit = %d, want 1; output = %s", res.code, res.stdout)
	}

	// Triage workflow.
	logPath := filepath.Join(dir, "triage.jsonl")
	res = runBounty(t, "bounty", "triage", "--package", packagePath, "--log", logPath,
		"--to", "submitted", "--actor", "reporter-1", "--role", "reporter",
		"--reason", "initial submission")
	if res.code != 0 {
		t.Fatalf("triage submit exit = %d, stderr = %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "state:  submitted") {
		t.Fatalf("triage output = %s", res.stdout)
	}

	res = runBounty(t, "bounty", "triage", "--package", packagePath, "--log", logPath,
		"--to", "triaged", "--actor", "alice", "--role", "triager",
		"--reason", "confirmed on staging")
	if res.code != 0 {
		t.Fatalf("triage triage exit = %d, stderr = %s", res.code, res.stderr)
	}

	// A reporter may not perform triage.
	res = runBounty(t, "bounty", "triage", "--package", packagePath, "--log", logPath,
		"--to", "accepted", "--actor", "reporter-1", "--role", "reporter",
		"--reason", "self-accept")
	if res.code != 1 {
		t.Fatalf("denied triage exit = %d, want 1; output = %s", res.code, res.stdout)
	}

	res = runBounty(t, "bounty", "status", "--log", logPath)
	if res.code != 0 {
		t.Fatalf("status exit = %d, stderr = %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "state:  triaged") || !strings.Contains(res.stdout, "events: 2") {
		t.Fatalf("status output = %s", res.stdout)
	}
}

func TestBountyVerifyVerifiedWithEvidence(t *testing.T) {
	dir := t.TempDir()
	bundlePath, samplesPath, key := buildBountyEvidence(t, dir)
	report := writeBountyFixture(t, dir, "report.md", "# Report\n\nCross-tenant read.\n")
	scope := writeBountyFixture(t, dir, "scope.txt", bountyScopeFixture)
	pkgDir := filepath.Join(dir, "pkg")

	res := runBounty(t, "bounty", "package", "--bundle", bundlePath, "--samples", samplesPath,
		"--report", report, "--scope", scope, "--program", "Acme Web", "--out", pkgDir)
	if res.code != 0 {
		t.Fatalf("package exit = %d, stderr = %s", res.code, res.stderr)
	}
	packagePath := filepath.Join(pkgDir, bounty.PackageFilename)

	res = runBounty(t, "bounty", "verify", "--package", packagePath, "--dir", dir,
		"--bundle", bundlePath, "--samples", samplesPath, "--key", key,
		"--target", "https://api.example.com/invoices")
	if res.code != 0 {
		t.Fatalf("verify exit = %d, want 0; output = %s\nstderr = %s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "VERIFIED") {
		t.Fatalf("verify output does not report VERIFIED: %s", res.stdout)
	}

	// A wrong pinned key fails closed.
	other, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	res = runBounty(t, "bounty", "verify", "--package", packagePath, "--dir", dir,
		"--bundle", bundlePath, "--samples", samplesPath,
		"--key", attest.PublicKeyHex(other.Public),
		"--target", "https://api.example.com/invoices")
	if res.code != 1 {
		t.Fatalf("wrong-key verify exit = %d, want 1; output = %s", res.code, res.stdout)
	}
}

func TestBountyUsageAndErrors(t *testing.T) {
	res := runBounty(t, "bounty")
	if res.code != 1 {
		t.Fatalf("no-subcommand exit = %d, want 1", res.code)
	}
	if !strings.Contains(res.stderr, "Usage: Sift bounty") {
		t.Fatalf("no-subcommand stderr = %s", res.stderr)
	}

	res = runBounty(t, "bounty", "nonsense")
	if res.code != 1 {
		t.Fatalf("unknown-subcommand exit = %d, want 1", res.code)
	}

	res = runBounty(t, "bounty", "package", "--program", "Acme Web")
	if res.code != 1 {
		t.Fatalf("incomplete package exit = %d, want 1", res.code)
	}

	res = runBounty(t, "bounty", "verify", "--package", "x.json")
	if res.code != 1 {
		t.Fatalf("verify without --dir exit = %d, want 1", res.code)
	}

	res = runBounty(t, "bounty", "status", "--log", filepath.Join(t.TempDir(), "absent.jsonl"))
	if res.code != 0 {
		t.Fatalf("status on missing log exit = %d, want 0", res.code)
	}
	if !strings.Contains(res.stdout, "(none)") {
		t.Fatalf("status on missing log output = %s", res.stdout)
	}

	res = runBounty(t, "bounty", "triage", "--package", filepath.Join(t.TempDir(), "absent.json"),
		"--log", filepath.Join(t.TempDir(), "triage.jsonl"), "--to", "submitted",
		"--actor", "a", "--role", "reporter", "--reason", "r")
	if res.code != 1 {
		t.Fatalf("triage with missing package exit = %d, want 1", res.code)
	}
}
