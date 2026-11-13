package main

// cli_authz_inproc_test.go — in-process coverage for the `authorize` and
// `audit` subcommands in cmd_authz.go.
//
// These read/write policy and audit files, so they run against a throwaway
// SIFT_HOME and never touch ~/.Sift.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInprocAuthorizeDispatch(t *testing.T) {
	scanCLIHome(t)

	t.Run("no args exits 2", func(t *testing.T) {
		res := runCommandFn(t, func() { cmdAuthorize() }, "authorize")
		if res.code != 2 {
			t.Fatalf("authorize exit = %d, want 2 (stderr: %s)", res.code, res.stderr)
		}
	})

	t.Run("unknown subcommand exits 2", func(t *testing.T) {
		res := runCommandFn(t, func() { cmdAuthorize() }, "authorize", "frobnicate")
		if res.code != 2 {
			t.Fatalf("authorize frobnicate exit = %d, want 2", res.code)
		}
		if !strings.Contains(res.stderr, "unknown authorize subcommand") {
			t.Errorf("stderr = %q, want the unknown-subcommand notice", res.stderr)
		}
	})

	t.Run("help exits 0", func(t *testing.T) {
		res := runCommandFn(t, func() { cmdAuthorize() }, "authorize", "--help")
		if res.code != 0 {
			t.Fatalf("authorize --help exit = %d, want 0", res.code)
		}
		if !strings.Contains(res.stderr, "usage:") {
			t.Errorf("stderr = %q, want the usage text", res.stderr)
		}
	})
}

func TestInprocAuthorizeAddListVerify(t *testing.T) {
	home := scanCLIHome(t)
	policy := filepath.Join(home, "authz.json")

	t.Run("add", func(t *testing.T) {
		res := runCommandFn(t, func() { cmdAuthorize() }, "authorize", "add",
			"--pattern", "*.example.test", "--approver", "alice", "--ticket", "T-1",
			"--reason", "quarterly pen-test", "--policy", policy)
		if res.code != 0 {
			t.Fatalf("authorize add exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
		}
		if !strings.Contains(res.stdout, "added authorization: *.example.test") {
			t.Errorf("stdout = %q, want the added line", res.stdout)
		}
		if !strings.Contains(res.stdout, "policy: "+policy) {
			t.Errorf("stdout = %q, want the policy path", res.stdout)
		}
	})

	t.Run("add again replaces", func(t *testing.T) {
		res := runCommandFn(t, func() { cmdAuthorize() }, "authorize", "add",
			"--pattern", "*.example.test", "--approver", "bob", "--policy", policy)
		if res.code != 0 {
			t.Fatalf("authorize add (replace) exit = %d, want 0", res.code)
		}
		if !strings.Contains(res.stdout, "updated authorization") {
			t.Errorf("stdout = %q, want the updated line", res.stdout)
		}
	})

	t.Run("list", func(t *testing.T) {
		res := runCommandFn(t, func() { cmdAuthorize() }, "authorize", "list", "--policy", policy)
		if res.code != 0 {
			t.Fatalf("authorize list exit = %d, want 0", res.code)
		}
		if !strings.Contains(res.stdout, "*.example.test") {
			t.Errorf("stdout = %q, want the listed pattern", res.stdout)
		}
	})

	t.Run("verify empty policy", func(t *testing.T) {
		empty := filepath.Join(home, "empty.json")
		if err := os.WriteFile(empty, []byte(`{"rules":[]}`), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		res := runCommandFn(t, func() { cmdAuthorize() }, "authorize", "verify", "--policy", empty)
		if res.code != 0 {
			t.Fatalf("authorize verify exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
		}
	})
}

func TestInprocAuditShowVerify(t *testing.T) {
	home := scanCLIHome(t)

	t.Run("show missing log", func(t *testing.T) {
		missing := filepath.Join(home, "nope.jsonl")
		res := runCommandFn(t, func() { cmdAudit() }, "audit", "show", "--log", missing)
		if res.code != 0 {
			t.Fatalf("audit show exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
		}
		if !strings.Contains(res.stdout, "no audit log at "+missing) {
			t.Errorf("stdout = %q, want the missing-log notice", res.stdout)
		}
	})

	t.Run("verify missing log", func(t *testing.T) {
		missing := filepath.Join(home, "nope2.jsonl")
		res := runCommandFn(t, func() { cmdAudit() }, "audit", "verify", "--log", missing)
		if res.code != 1 {
			t.Fatalf("audit verify exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
		}
		// On Windows the reported error is localised ("The system cannot find the
		// file specified."), so assert on the path the tool was asked to verify.
		if !strings.Contains(res.stderr, missing) {
			t.Errorf("stderr = %q, want the missing-file error", res.stderr)
		}
	})

	t.Run("unknown subcommand exits 2", func(t *testing.T) {
		res := runCommandFn(t, func() { cmdAudit() }, "audit", "export")
		if res.code != 2 {
			t.Fatalf("audit export exit = %d, want 2", res.code)
		}
	})
}
