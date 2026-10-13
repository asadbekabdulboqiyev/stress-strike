package main

// cmd_verify_more_test.go — the remaining black-box cases for the verify gate.
//
// cmd_verify_test.go covers the valid path and the first tamper vector. This
// file completes the adversarial matrix: every remaining way a pack can be
// altered (a deleted sidecar line, a severed line, an edited aggregate, a
// swapped coordinator key) and the argument-robustness paths (a wrong but valid
// pinned key, a missing file, valid JSON that is not a vpmp/v1 bundle, and the
// documented "bundle only" mode).
//
// It reuses the CLI build harness, the pack producer and runCLI from
// cmd_verify_test.go, which live in the same package.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
)

// -----------------------------------------------------------------------------
// The valid path, asserted more tightly
// -----------------------------------------------------------------------------

// TestCLIVerifyJSONProofsVerifiedNonzero checks the machine-readable report a CI
// job gates on actually attests to inclusion proofs: a valid pack with a sidecar
// must report valid=true, no failed checks, samples present, and a non-zero
// proofs_verified count.
func TestCLIVerifyJSONProofsVerifiedNonzero(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath, "--json")
	if res.code != 0 {
		t.Fatalf("verify --json exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	var got verifyJSON
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("--json is not valid JSON: %v\n%s", err, res.stdout)
	}
	if !got.Valid || got.ChecksFailed != 0 || len(got.Errors) != 0 {
		t.Fatalf("report is not clean: %+v", got)
	}
	if got.SamplesAbsent {
		t.Fatalf("samples_absent = true, want false when a sidecar is supplied")
	}
	if got.ProofsVerified == 0 {
		t.Fatalf("proofs_verified = 0 for a 5-record pack, want non-zero")
	}
}

// TestCLIVerifyNoSidecarIsDocumentedPass pins the documented "bundle only" mode:
// without receipts the verifier attests to the signature and internal
// consistency only, reports samples_absent, and still exits 0. This is the
// actual behaviour and is asserted here so a change to it is a visible test
// failure rather than a silent contract drift.
func TestCLIVerifyNoSidecarIsDocumentedPass(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, _, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	res := runCLI(t, "verify", "--bundle", bundlePath, "--json")
	if res.code != 0 {
		t.Fatalf("verify without sidecar exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	var got verifyJSON
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("--json is not valid JSON: %v\n%s", err, res.stdout)
	}
	if !got.Valid || !got.SamplesAbsent {
		t.Fatalf("want valid=true samples_absent=true, got %+v", got)
	}

	human := runCLI(t, "verify", "--bundle", bundlePath)
	if human.code != 0 || !strings.Contains(human.stdout, "PASS") || !strings.Contains(human.stdout, "absent") {
		t.Fatalf("human no-sidecar output unexpected (exit %d):\nstdout:\n%s\nstderr:\n%s",
			human.code, human.stdout, human.stderr)
	}
}

// -----------------------------------------------------------------------------
// Tampered sidecar
// -----------------------------------------------------------------------------

// TestCLIVerifyDeletedSidecarLineFails removes the last record line. The Merkle
// root and committed count no longer match the receipts, so verify must fail
// closed with a report naming the cause.
func TestCLIVerifyDeletedSidecarLineFails(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	raw, err := os.ReadFile(samplesPath)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("sidecar has %d lines, want 5", len(lines))
	}
	if err := os.WriteFile(samplesPath, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write truncated sidecar: %v", err)
	}

	assertVerifyFails(t, bundlePath, samplesPath)
}

// TestCLIVerifySeveredSidecarLineFails cuts the final record line in half so the
// last line is no longer valid JSON: the loader must fail closed with exit 1 and
// no panic.
func TestCLIVerifySeveredSidecarLineFails(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	raw, err := os.ReadFile(samplesPath)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if len(raw) <= 20 {
		t.Fatalf("sidecar unexpectedly small: %d bytes", len(raw))
	}
	if err := os.WriteFile(samplesPath, raw[:len(raw)-20], 0o644); err != nil {
		t.Fatalf("write severed sidecar: %v", err)
	}

	assertVerifyFailsNoPanic(t, bundlePath, samplesPath)
}

// -----------------------------------------------------------------------------
// Tampered bundle
// -----------------------------------------------------------------------------

// TestCLIVerifyP99TamperFails bumps aggregate.p99_ns by one nanosecond. The value
// stays structurally plausible (p95 <= p99 still holds), so only the digest and
// the coordinator signature can catch it — exactly the property under test.
func TestCLIVerifyP99TamperFails(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	mutateBundle(t, bundlePath, func(b *attest.Bundle) { b.Aggregate.P99NS++ })

	assertVerifyFails(t, bundlePath, samplesPath)
}

// TestCLIVerifyCountTamperFails changes aggregate.count so the cross-sum against
// the workers no longer matches. The bundle is rejected even before any
// cryptographic check runs.
func TestCLIVerifyCountTamperFails(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	mutateBundle(t, bundlePath, func(b *attest.Bundle) { b.Aggregate.Count++ })

	assertVerifyFails(t, bundlePath, samplesPath)
}

// TestCLIVerifyKeySwapFails replaces the coordinator key named by the signature
// with a different, perfectly valid 64-hex key (the worker's). The bundle still
// parses and the key is well-formed, but the seal no longer verifies against it.
func TestCLIVerifyKeySwapFails(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	otherKey := attest.PublicKeyHex(worker.Public)
	mutateBundle(t, bundlePath, func(b *attest.Bundle) { b.Signature.Key = otherKey })

	assertVerifyFails(t, bundlePath, samplesPath)
}

// -----------------------------------------------------------------------------
// Argument robustness
// -----------------------------------------------------------------------------

// TestCLIVerifyExpectKeyWrongValidKeyFails pins a different but valid coordinator
// key. The pin must fail closed even though the bundle is internally consistent
// and correctly signed by its own key.
func TestCLIVerifyExpectKeyWrongValidKeyFails(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	other, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath, "--expect-key", attest.PublicKeyHex(other.Public))
	if res.code != 1 {
		t.Fatalf("verify with a wrong-but-valid --expect-key exit = %d, want 1\nstdout:\n%s\nstderr:\n%s",
			res.code, res.stdout, res.stderr)
	}
	if strings.Contains(res.stderr, "panic:") {
		t.Fatalf("panic on --expect-key mismatch:\n%s", res.stderr)
	}
}

// TestCLIVerifyNonexistentPathFailsExit1 checks a missing file is a clean exit 1,
// not a panic (which would surface as exit 2).
func TestCLIVerifyNonexistentPathFailsExit1(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	res := runCLI(t, "verify", "--bundle", missing)
	if res.code != 1 {
		t.Fatalf("verify missing bundle exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if strings.Contains(res.stderr, "panic:") {
		t.Fatalf("panic on missing file:\n%s", res.stderr)
	}
}

// TestCLIVerifyWrongFormatFails feeds valid JSON that is not a vpmp/v1 bundle.
// The document loads, so the failure must come from verification, not from
// parsing: exit 1 and no panic.
func TestCLIVerifyWrongFormatFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-bundle.json")
	body := `{"format":"vpmp/v0","tool":{"name":"x","version":"1"}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	res := runCLI(t, "verify", "--bundle", path)
	if res.code != 1 {
		t.Fatalf("verify wrong-format bundle exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if strings.Contains(res.stdout+res.stderr, "panic:") {
		t.Fatalf("panic on wrong format:\nstdout:\n%s\nstderr:\n%s", res.stdout, res.stderr)
	}
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// mutateBundle loads the bundle at path, applies fn, and writes it back in
// canonical form. Re-saving keeps the exact integer encodings, so the only
// difference from the original is the one fn introduced.
func mutateBundle(t *testing.T, path string, fn func(*attest.Bundle)) {
	t.Helper()
	b, err := attest.LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle(%s): %v", path, err)
	}
	fn(&b)
	if err := attest.SaveBundle(b, path); err != nil {
		t.Fatalf("SaveBundle(%s): %v", path, err)
	}
}

// assertVerifyFails runs verify over the pack with --json and requires exit 1
// with a machine-readable report that disagrees with the pack. Requiring a valid
// JSON report means a non-zero exit cannot be an incidental crash that happened
// to exit 1.
func assertVerifyFails(t *testing.T, bundlePath, samplesPath string) {
	t.Helper()
	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath, "--json")
	if res.code != 1 {
		t.Fatalf("verify exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	var got verifyJSON
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("fail-path --json is not valid JSON: %v\nstdout:\n%s\nstderr:\n%s", err, res.stdout, res.stderr)
	}
	if got.Valid {
		t.Fatalf("tampered pack reported valid=true: %+v", got)
	}
	if len(got.Errors) == 0 {
		t.Fatalf("tampered pack reported no errors")
	}
}

// assertVerifyFailsNoPanic is assertVerifyFails for inputs that may fail during
// loading, before a report is produced: it requires exit 1 and no panic text.
func assertVerifyFailsNoPanic(t *testing.T, bundlePath, samplesPath string) {
	t.Helper()
	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath)
	if res.code != 1 {
		t.Fatalf("verify exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if strings.Contains(res.stdout+res.stderr, "panic:") {
		t.Fatalf("panic on tampered input:\nstdout:\n%s\nstderr:\n%s", res.stdout, res.stderr)
	}
}
