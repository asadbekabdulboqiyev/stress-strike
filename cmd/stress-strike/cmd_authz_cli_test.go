package main

// cmd_authz_cli_test.go — in-process coverage for the `authorize` and `audit`
// command surface in cmd_authz.go.
//
// The dispatchers (cmdAuthorize, cmdAudit) call os.Exit on missing/unknown
// subcommands, so only the branches that return normally are driven here.
// Exit-code behaviour is covered black-box through cliBin in
// cmd_authz_blackbox_test.go.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

// withArgs runs fn with os.Args set to argv and restores the original slice.
func withArgs(t *testing.T, argv []string, fn func()) {
	t.Helper()
	old := os.Args
	os.Args = argv
	defer func() { os.Args = old }()
	fn()
}

// captureCmd runs fn with stdout and stderr redirected and returns both
// streams.
func captureCmd(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	stdout = captureStream(t, &os.Stdout, func() {
		stderr = captureStderr(t, fn)
	})
	return stdout, stderr
}

func TestAuthorizeAddUpdatesAndListStates(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "nested", "authz.json")
	future := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	past := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)

	// New rule with an expiry, an approver and a ticket.
	stdout := captureStream(t, &os.Stdout, func() {
		authorizeAdd([]string{
			"--policy", policy,
			"--pattern", "example.com",
			"--approver", "ciso",
			"--ticket", "SEC-1",
			"--reason", "quarterly test",
			"--until", future.Format(time.RFC3339),
		})
	})
	for _, want := range []string{
		"added authorization: example.com",
		"(until " + future.Format(time.RFC3339) + ")",
		"ticket=SEC-1",
		"policy: " + policy,
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("add output missing %q: %q", want, stdout)
		}
	}

	// Re-adding the same pattern replaces it instead of appending.
	stdout = captureStream(t, &os.Stdout, func() {
		authorizeAdd([]string{"--policy", policy, "--pattern", "example.com", "--approver", "ciso", "--ticket", "SEC-2"})
	})
	if !strings.Contains(stdout, "updated authorization: example.com") {
		t.Errorf("second add should update: %q", stdout)
	}
	if strings.Contains(stdout, "(until") {
		t.Errorf("updated rule should have no expiry: %q", stdout)
	}

	// A second, already-expired rule.
	captureStream(t, &os.Stdout, func() {
		authorizeAdd([]string{"--policy", policy, "--pattern", "old.example", "--until", past.Format(time.RFC3339)})
	})

	// A third rule with neither expiry nor ticket: the optional suffixes stay off.
	stdout = captureStream(t, &os.Stdout, func() {
		authorizeAdd([]string{"--policy", policy, "--pattern", "plain.example"})
	})
	if strings.Contains(stdout, "ticket=") || strings.Contains(stdout, "(until") {
		t.Errorf("plain rule printed optional suffixes: %q", stdout)
	}

	pol, err := authz.LoadPolicy(policy)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if len(pol.Rules) != 3 {
		t.Fatalf("rules = %d, want 3 (%+v)", len(pol.Rules), pol.Rules)
	}
	if pol.Rules[0].Ticket != "SEC-2" || !pol.Rules[0].Until.IsZero() {
		t.Errorf("example.com rule was not replaced: %+v", pol.Rules[0])
	}

	stdout = captureStream(t, &os.Stdout, func() {
		authorizeList([]string{"--policy", policy})
	})
	for _, want := range []string{
		"policy: " + policy,
		"mode: permissive (allow_private=false)",
		"rules:",
		"example.com",
		"approver=ciso",
		"ticket=SEC-2",
		"EXPIRED " + past.Format(time.RFC3339),
		"approver=-",
		"ticket=-",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("list output missing %q: %q", want, stdout)
		}
	}

	stdout = captureStream(t, &os.Stdout, func() {
		authorizeVerify([]string{"--policy", policy})
	})
	if !strings.Contains(stdout, "is valid: mode=permissive, 3 rule(s)") {
		t.Errorf("verify output = %q", stdout)
	}
}

func TestAuthorizeListEmptyPolicyAndStrictMode(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "authz.json")

	// No file at all: LoadPolicyOrDefault returns the permissive default.
	stdout := captureStream(t, &os.Stdout, func() {
		authorizeList([]string{"--policy", policy})
	})
	if !strings.Contains(stdout, "rules: (none)") {
		t.Errorf("empty policy output = %q", stdout)
	}

	pol := authz.DefaultPolicy()
	pol.Mode = authz.ModeStrict
	pol.AllowPrivate = true
	if err := savePolicy(policy, pol); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	stdout = captureStream(t, &os.Stdout, func() {
		authorizeList([]string{"--policy", policy})
	})
	if !strings.Contains(stdout, "mode: strict (allow_private=true)") {
		t.Errorf("strict policy output = %q", stdout)
	}

	stdout = captureStream(t, &os.Stdout, func() {
		authorizeVerify([]string{"--policy", policy})
	})
	if !strings.Contains(stdout, "mode=strict, 0 rule(s)") {
		t.Errorf("strict verify output = %q", stdout)
	}
}

func TestAuthorizeRemove(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "authz.json")
	pol := authz.DefaultPolicy()
	pol.Rules = []authz.Rule{
		{Pattern: "a.example", Ticket: "1"},
		{Pattern: "b.example", Ticket: "2"},
		{Pattern: "a.example", Ticket: "3"},
	}
	if err := savePolicy(policy, pol); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	stdout := captureStream(t, &os.Stdout, func() {
		authorizeRemove([]string{"--policy", policy, "--pattern", "a.example"})
	})
	if !strings.Contains(stdout, `removed 2 rule(s) matching "a.example"`) {
		t.Errorf("remove output = %q", stdout)
	}

	pol, err := authz.LoadPolicy(policy)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if len(pol.Rules) != 1 || pol.Rules[0].Pattern != "b.example" {
		t.Fatalf("rules after remove = %+v", pol.Rules)
	}

	// Removing a pattern that is not present is a no-op, not an error.
	stdout = captureStream(t, &os.Stdout, func() {
		authorizeRemove([]string{"--policy", policy, "--pattern", "missing.example"})
	})
	if !strings.Contains(stdout, "removed 0 rule(s)") {
		t.Errorf("remove-missing output = %q", stdout)
	}
}

func TestCmdAuthorizeDispatch(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "authz.json")

	run := func(args ...string) (stdout, stderr string) {
		argv := append([]string{"Sift", "authorize"}, args...)
		withArgs(t, argv, func() {
			stdout, stderr = captureCmd(t, cmdAuthorize)
		})
		return stdout, stderr
	}

	if out, _ := run("add", "--policy", policy, "--pattern", "dispatch.example", "--ticket", "T-9"); !strings.Contains(out, "added authorization: dispatch.example") {
		t.Errorf("add dispatch output = %q", out)
	}
	for _, sub := range []string{"list", "ls"} {
		if out, _ := run(sub, "--policy", policy); !strings.Contains(out, "dispatch.example") {
			t.Errorf("%s dispatch output = %q", sub, out)
		}
	}
	if out, _ := run("verify", "--policy", policy); !strings.Contains(out, "1 rule(s)") {
		t.Errorf("verify dispatch output = %q", out)
	}
	if out, _ := run("remove", "--policy", policy, "--pattern", "dispatch.example"); !strings.Contains(out, "removed 1 rule(s)") {
		t.Errorf("remove dispatch output = %q", out)
	}
	if out, _ := run("rm", "--policy", policy, "--pattern", "dispatch.example"); !strings.Contains(out, "removed 0 rule(s)") {
		t.Errorf("rm dispatch output = %q", out)
	}
	for _, sub := range []string{"help", "--help", "-h"} {
		_, errOut := run(sub)
		if !strings.Contains(errOut, "usage: Sift authorize <add|list|remove|verify>") {
			t.Errorf("%s dispatch stderr = %q", sub, errOut)
		}
	}
}

func TestCmdAuditDispatch(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	recordAuthz(authz.Entry{
		Action: "run", Targets: []string{"https://example.com/"}, Class: "public", Allowed: true,
	}, logPath, "")
	recordAuthz(authz.Entry{
		Action: "pentest", Targets: []string{"http://10.0.0.1/"}, Class: "private", Allowed: false,
		Reason: "no authorization ticket",
	}, logPath, "")

	run := func(args ...string) (stdout, stderr string) {
		argv := append([]string{"Sift", "audit"}, args...)
		withArgs(t, argv, func() {
			stdout, stderr = captureCmd(t, cmdAudit)
		})
		return stdout, stderr
	}

	out, _ := run("show", "--log", logPath)
	for _, want := range []string{
		"audit log: " + logPath,
		"(2 record(s) shown)",
		"ALLOW",
		"DENY ",
		"pentest",
		"targets=http://10.0.0.1/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("show output missing %q: %q", want, out)
		}
	}

	out, _ = run("ls", "--log", logPath, "--limit", "1")
	if !strings.Contains(out, "(1 record(s) shown)") || strings.Contains(out, "ALLOW") {
		t.Errorf("limited show output = %q", out)
	}

	out, _ = run("show", "--log", logPath, "--limit", "0")
	if !strings.Contains(out, "(2 record(s) shown)") {
		t.Errorf("--limit 0 should show everything: %q", out)
	}

	out, _ = run("verify", "--log", logPath)
	if !strings.Contains(out, "OK: 2 record(s), hash chain intact") {
		t.Errorf("verify output = %q", out)
	}

	_, errOut := run("help")
	if !strings.Contains(errOut, "usage: Sift audit <show|verify>") {
		t.Errorf("audit help stderr = %q", errOut)
	}
}

func TestAuditShowMissingLog(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-audit.jsonl")
	stdout := captureStream(t, &os.Stdout, func() {
		auditShow([]string{"--log", missing})
	})
	if !strings.Contains(stdout, "no audit log at "+missing) {
		t.Errorf("missing-log output = %q", stdout)
	}
}

func TestScenarioTargets(t *testing.T) {
	if got := scenarioTargets(nil); got != nil {
		t.Fatalf("nil scenario targets = %v", got)
	}

	sc := &config.Scenario{
		BaseURL: "  https://a.example/  ",
		Steps: []config.Step{
			{URL: "https://b.example/x"},
			{URL: "https://a.example/"},     // duplicate of BaseURL
			{URL: "  https://b.example/x "}, // duplicate after trimming
			{URL: ""},
			{URL: "not-a-url"},
		},
	}
	got := scenarioTargets(sc)
	want := []string{"https://a.example/", "https://b.example/x"}
	if len(got) != len(want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("targets = %v, want %v", got, want)
		}
	}
}

func TestRunAuthorizeWithGate(t *testing.T) {
	// Pin the admin seam off: an unlock open on this machine would otherwise
	// replace the "rule=..." outcome with an admin-unlock bypass and fail the
	// assertions below for reasons unrelated to the code.
	noBypass := func() bool { return false }

	// No targets: the gate is a no-op and never writes an audit record.
	enforceAuthz(authz.OpLoadTest, nil, nil, gateOptions{adminBypass: noBypass})
	runAuthorizeWithGate(nil, authz.OpLoadTest, gateOptions{adminBypass: noBypass})

	dir := t.TempDir()
	g := gateOptions{
		policyPath:  filepath.Join(dir, "policy.json"),
		auditPath:   filepath.Join(dir, "audit.jsonl"),
		adminBypass: noBypass,
	}
	sc := &config.Scenario{
		BaseURL: "https://93.184.216.34/",
		Steps:   []config.Step{{URL: "https://93.184.216.34/health"}},
	}

	errOut := captureStderr(t, func() { runAuthorizeWithGate(sc, authz.OpLoadTest, g) })
	if !strings.Contains(errOut, "authorization: ok (class=public)") {
		t.Errorf("gate stderr = %q", errOut)
	}

	entries, err := authz.ReadAll(g.auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].Action != authz.OpLoadTest.String() || !entries[0].Allowed {
		t.Errorf("audit entry = %+v", entries[0])
	}
	if got := len(entries[0].Targets); got != 2 {
		t.Errorf("audit targets = %v", entries[0].Targets)
	}

	// An explicit matching rule makes the gate name the rule it used.
	pol := authz.DefaultPolicy()
	pol.Rules = []authz.Rule{{Pattern: "93.184.216.34", Approver: "ciso", Ticket: "SEC-9"}}
	if err := savePolicy(g.policyPath, pol); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	errOut = captureStderr(t, func() { runAuthorizeWithGate(sc, authz.OpLoadTest, g) })
	if !strings.Contains(errOut, "rule=93.184.216.34") {
		t.Errorf("gate stderr after rule = %q", errOut)
	}
}

func TestModeNameAndOrDash(t *testing.T) {
	if got := modeName(authz.ModeStrict); got != "strict" {
		t.Errorf("modeName(strict) = %q", got)
	}
	if got := modeName(authz.ModePermissive); got != "permissive" {
		t.Errorf("modeName(permissive) = %q", got)
	}
	if got := orDash(""); got != "-" {
		t.Errorf("orDash(\"\") = %q", got)
	}
	if got := orDash("value"); got != "value" {
		t.Errorf("orDash(value) = %q", got)
	}
}

func TestSavePolicyErrorBranches(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The parent of the policy path is a regular file: MkdirAll fails.
	if err := savePolicy(filepath.Join(file, "authz.json"), authz.DefaultPolicy()); err == nil {
		t.Error("savePolicy should fail when the parent is not a directory")
	}

	// The directory exists but is not writable: WriteFile fails.
	readOnly := filepath.Join(dir, "readonly")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX directory permissions — a 0500 directory is still writable")
	}
	if err := savePolicy(filepath.Join(readOnly, "authz.json"), authz.DefaultPolicy()); err == nil {
		t.Error("savePolicy should fail when the directory is read-only")
	}
}

func TestRecordAuthzWarnings(t *testing.T) {
	// Audit path whose parent is a file: Open fails.
	dir := t.TempDir()
	parent := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	errOut := captureStderr(t, func() {
		recordAuthz(authz.Entry{Action: "run"}, filepath.Join(parent, "audit.jsonl"), "")
	})
	if !strings.Contains(errOut, "warning: cannot write audit log") {
		t.Errorf("open failure stderr = %q", errOut)
	}

	// The webhook returns 500: the record is still written, a warning is printed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	logPath := filepath.Join(dir, "audit.jsonl")
	errOut = captureStderr(t, func() {
		recordAuthz(authz.Entry{Action: "run", Targets: []string{"https://example.com/"}}, logPath, srv.URL)
	})
	if !strings.Contains(errOut, "warning: audit webhook failed") {
		t.Errorf("webhook failure stderr = %q", errOut)
	}
	if n, err := authz.Verify(logPath); err != nil || n != 1 {
		t.Errorf("audit log after webhook failure: n=%d err=%v", n, err)
	}

	// A successful webhook keeps the output clean.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ok.Close()
	if errOut := captureStderr(t, func() {
		recordAuthz(authz.Entry{Action: "run"}, logPath, ok.URL)
	}); errOut != "" {
		t.Errorf("successful webhook wrote to stderr: %q", errOut)
	}
}
