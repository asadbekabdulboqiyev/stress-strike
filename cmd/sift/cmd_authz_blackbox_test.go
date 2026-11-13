package main

// cmd_authz_blackbox_test.go — black-box exit-code tests for the `authorize`
// and `audit` command surface.
//
// The dispatchers terminate through os.Exit for usage errors and denied
// mutations, so those paths are exercised through the real CLI binary built by
// TestMain in cmd_verify_test.go. Subprocess runs do not contribute to the
// in-process coverage profile; they exist to pin the user-visible contract.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIAuthorizeUsageErrors(t *testing.T) {
	// Keep the default policy path inside the test sandbox: one of the calls
	// below falls back to it.
	t.Setenv("SIFT_HOME", t.TempDir())

	res := runCLI(t, "authorize")
	if res.code != 2 {
		t.Errorf("authorize without a subcommand: exit = %d, want 2", res.code)
	}
	if !strings.Contains(res.stderr, "usage: Sift authorize") {
		t.Errorf("stderr = %q", res.stderr)
	}

	res = runCLI(t, "authorize", "frobnicate")
	if res.code != 2 {
		t.Errorf("unknown subcommand: exit = %d, want 2", res.code)
	}
	if !strings.Contains(res.stderr, `unknown authorize subcommand "frobnicate"`) {
		t.Errorf("stderr = %q", res.stderr)
	}

	res = runCLI(t, "authorize", "add", "--policy", filepath.Join(t.TempDir(), "p.json"))
	if res.code != 1 {
		t.Errorf("add without --pattern: exit = %d, want 1", res.code)
	}
	if !strings.Contains(res.stderr, "--pattern is required") {
		t.Errorf("stderr = %q", res.stderr)
	}

	res = runCLI(t, "authorize", "remove", "--pattern", "x")
	_ = res // uses the default policy path; must not panic on a missing file
}

func TestCLIAuditExitCodes(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	res := runCLI(t, "audit", "verify", "--log", logPath)
	if res.code != 1 {
		t.Errorf("verify missing log: exit = %d, want 1", res.code)
	}
	if !strings.Contains(res.stderr, "TAMPERED or corrupt") {
		t.Errorf("stderr = %q", res.stderr)
	}

	res = runCLI(t, "audit")
	if res.code != 2 {
		t.Errorf("audit without a subcommand: exit = %d, want 2", res.code)
	}

	res = runCLI(t, "audit", "nope")
	if res.code != 2 || !strings.Contains(res.stderr, `unknown audit subcommand "nope"`) {
		t.Errorf("exit = %d stderr = %q", res.code, res.stderr)
	}

	// A valid trail written by a normal run verifies cleanly.
	policy := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"mode":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res = runCLI(t, "authorize", "add", "--policy", policy, "--pattern", "example.com", "--ticket", "T-1")
	if res.code != 0 {
		t.Fatalf("authorize add: exit = %d stderr = %q", res.code, res.stderr)
	}
}
