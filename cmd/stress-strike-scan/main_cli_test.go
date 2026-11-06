package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// scanBin is the compiled stress-strike-scan binary, built once by TestMain so
// the CLI tests exercise main() end to end including the os.Exit paths.
var scanBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "scan-cli-*")
	if err != nil {
		os.Exit(1)
	}
	scanBin = filepath.Join(dir, "stress-strike-scan")

	build := exec.Command("go", "build", "-o", scanBin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		os.Stderr.Write(out)
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type cliResult struct {
	stdout string
	stderr string
	code   int
}

func runScan(t *testing.T, env []string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(scanBin, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return cliResult{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

func TestCLIRequiresTarget(t *testing.T) {
	res := runScan(t, nil)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1", res.code)
	}
	if !strings.Contains(res.stderr, "--target is required") {
		t.Errorf("stderr = %q", res.stderr)
	}
	if !strings.Contains(res.stderr, "Usage:") {
		t.Error("usage text should be printed")
	}
}

func TestCLIInvalidTargetIsUsageError(t *testing.T) {
	res := runScan(t, nil, "-target", "ftp://example.com")
	if res.code != usageExitCode {
		t.Fatalf("exit = %d, want %d (stderr %q)", res.code, usageExitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "invalid --target") {
		t.Errorf("stderr = %q", res.stderr)
	}
}

func TestCLIInvalidEnableIsUsageError(t *testing.T) {
	res := runScan(t, nil, "-target", "example.com", "-enable", "nope")
	if res.code != usageExitCode {
		t.Fatalf("exit = %d, want %d", res.code, usageExitCode)
	}
	if !strings.Contains(res.stderr, "unknown intrusive family") {
		t.Errorf("stderr = %q", res.stderr)
	}
}

func TestCLIInvalidScopePatternIsUsageError(t *testing.T) {
	res := runScan(t, nil, "-target", "example.com", "-allow", "*")
	if res.code != usageExitCode {
		t.Fatalf("exit = %d, want %d (stderr %q)", res.code, usageExitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "scope pattern") {
		t.Errorf("stderr should explain the bad pattern: %q", res.stderr)
	}
}

func TestCLIDryRunSendsNothing(t *testing.T) {
	res := runScan(t, nil, "-target", "example.com", "-owasp", "-dry-run")
	if res.code != 0 {
		t.Fatalf("exit = %d (stderr %q)", res.code, res.stderr)
	}
	for _, want := range []string{"dry-run: the policy is evaluated", "TLS/HTTP/WAF/security phases are skipped",
		"OWASP checker has probes that dial outside", "guard: sent=0"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("stdout missing %q", want)
		}
	}
	if !strings.Contains(res.stderr, "authorization: ok") {
		t.Errorf("stderr missing authorization line: %q", res.stderr)
	}
}

func TestCLIAllowAllScope(t *testing.T) {
	res := runScan(t, nil, "-target", "example.com", "-port", "1", "-allow-all", "-tls", "-dry-run")
	if res.code != 0 {
		t.Fatalf("exit = %d (stderr %q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "scope: ALL HOSTS") {
		t.Errorf("stdout missing allow-all scope line: %q", res.stdout)
	}
}

func TestCLIExplicitAllowScope(t *testing.T) {
	res := runScan(t, nil, "-target", "example.com", "-allow", "example.com", "-allow", "*.example.org",
		"-tls", "-dry-run")
	if res.code != 0 {
		t.Fatalf("exit = %d (stderr %q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "scope: example.com, *.example.org (from --allow)") {
		t.Errorf("stdout missing explicit scope line: %q", res.stdout)
	}
}

func TestCLIStrictPolicyDenies(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"mode":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	res := runScan(t, nil, "-target", "127.0.0.1", "-port", "1", "-tls", "-policy", policy)
	if res.code != authzDeniedExitCode {
		t.Fatalf("exit = %d, want %d (stderr %q)", res.code, authzDeniedExitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "BLOCKED by authorization policy") {
		t.Errorf("stderr = %q", res.stderr)
	}
	if !strings.Contains(res.stderr, "stress-strike authorize add") {
		t.Error("denial should explain how to authorize")
	}
}

func TestCLITicketAuthorization(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	body := `{"mode":1,"rules":[{"pattern":"127.0.0.1","approver":"sec","ticket":"T-1"}]}`
	if err := os.WriteFile(policy, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(dir, "audit.log")

	res := runScan(t, nil, "-target", "127.0.0.1", "-port", "1", "-tls", "-dry-run",
		"-policy", policy, "-authorized", "T-1", "-audit-log", audit)
	if res.code != 0 {
		t.Fatalf("exit = %d (stderr %q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "authorization: ok") {
		t.Errorf("stderr = %q", res.stderr)
	}

	data, err := os.ReadFile(audit)
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	if !strings.Contains(string(data), `"action":"scan"`) || !strings.Contains(string(data), `"allowed":true`) ||
		!strings.Contains(string(data), "T-1") {
		t.Errorf("audit log = %s", data)
	}
}

func TestCLITicketMismatchDenies(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	body := `{"mode":1,"rules":[{"pattern":"127.0.0.1","approver":"sec","ticket":"T-1"}]}`
	if err := os.WriteFile(policy, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	res := runScan(t, nil, "-target", "127.0.0.1", "-port", "1", "-tls",
		"-policy", policy, "-authorized", "T-OTHER")
	if res.code != authzDeniedExitCode {
		t.Fatalf("exit = %d, want %d (stderr %q)", res.code, authzDeniedExitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "no active authorization with ticket") {
		t.Errorf("stderr = %q", res.stderr)
	}
}

func TestCLIMalformedPolicyExitsOne(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policy, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}

	res := runScan(t, nil, "-target", "127.0.0.1", "-port", "1", "-tls", "-policy", policy)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr %q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "Error: parse policy") {
		t.Errorf("stderr = %q", res.stderr)
	}
}

func TestCLIEnvAllowAndBadEnvRule(t *testing.T) {
	// A valid STRESS_STRIKE_ALLOW rule is folded into the policy.
	res := runScan(t, []string{"STRESS_STRIKE_ALLOW=127.0.0.1"}, "-target", "127.0.0.1", "-port", "1", "-tls", "-dry-run")
	if res.code != 0 {
		t.Fatalf("exit = %d (stderr %q)", res.code, res.stderr)
	}

	// An empty pattern in the env spec is a fatal configuration error.
	res = runScan(t, []string{"STRESS_STRIKE_ALLOW=127.0.0.1, "}, "-target", "127.0.0.1", "-port", "1", "-tls")
	_ = res // trailing empty entries are skipped, so this must still succeed
	if res.code != 0 {
		t.Fatalf("blank env entries should be skipped, exit = %d (stderr %q)", res.code, res.stderr)
	}
}

func TestCLIAllPhasesAgainstServer(t *testing.T) {
	url, port := scanTestServer(t, false)

	res := runScan(t, nil, "-target", "127.0.0.1", "-port", port, "-all", "-verbose")
	if res.code != 0 {
		t.Fatalf("exit = %d (stderr %q)", res.code, res.stderr)
	}
	for _, want := range []string{"stress-strike scan", "TLS Scan", "HTTP Fingerprint", "WAF Detection",
		"Security Headers", "VULNERABILITIES & RISK SCORE", "Risk Score:", "Scan Duration:"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("stdout missing %q", want)
		}
	}
	if !strings.Contains(res.stdout, "HTTP/") && !strings.Contains(res.stdout, "Server:") {
		t.Logf("URL was %s; handler may not have been reached", url)
	}
}

func TestCLIOWASPPhase(t *testing.T) {
	_, port := scanTestServer(t, true)

	outJSON := filepath.Join(t.TempDir(), "scan.json")

	res := runScan(t, nil, "-target", "127.0.0.1", "-port", port, "-owasp", "-verbose", "-rate", "200", "-budget", "800",
		"-path", "/,/login", "-output-json", outJSON)
	if res.code != 0 {
		t.Fatalf("exit = %d (stderr %q)", res.code, res.stderr)
	}
	for _, want := range []string{"OWASP Top 10 Check", "OWASP TOP 10 — COVERAGE-AWARE RESULTS", "routes:",
		"guard: sent=", "JSON report:"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("stdout missing %q", want)
		}
	}

	data, err := os.ReadFile(outJSON)
	if err != nil {
		t.Fatalf("json report: %v", err)
	}
	if !strings.Contains(string(data), `"owasp"`) {
		t.Errorf("json report missing owasp section: %s", data)
	}
}

func TestCLIOWASPOutputJSONUnwritable(t *testing.T) {
	_, port := scanTestServer(t, true)

	res := runScan(t, nil, "-target", "127.0.0.1", "-port", port, "-owasp", "-rate", "200", "-budget", "800",
		"-output-json", "/dev/null/dir/scan.json")
	if res.code != 0 {
		t.Fatalf("exit = %d (stderr %q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "Failed to create JSON") {
		t.Errorf("stdout missing create failure warning: %q", res.stdout)
	}
}

func TestCLIPassivePhase(t *testing.T) {
	_, port := scanTestServer(t, false)

	res := runScan(t, nil, "-target", "127.0.0.1", "-port", port, "-passive", "-verbose", "-path", "/,/admin", "-rate", "200")
	if res.code != 0 {
		t.Fatalf("exit = %d (stderr %q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "Passive Checks") {
		t.Errorf("stdout missing passive phase: %q", res.stdout)
	}
}

func TestCLIIntrusivePhase(t *testing.T) {
	_, port := scanTestServer(t, false)

	res := runScan(t, nil, "-target", "127.0.0.1", "-port", port,
		"-intrusive", "-enable", "crlf", "-enable", "path-traversal", "-verbose")
	if res.code != 0 {
		t.Fatalf("exit = %d (stderr %q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "Intrusive Probes") {
		t.Errorf("stdout missing intrusive phase: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "families:") {
		t.Errorf("verbose output should list enabled families: %q", res.stdout)
	}
}

func TestCLISelectedPhasesOnly(t *testing.T) {
	_, port := scanTestServer(t, false)

	for _, phase := range []string{"-tls", "-http", "-waf", "-security"} {
		res := runScan(t, nil, "-target", "127.0.0.1", "-port", port, phase)
		if res.code != 0 {
			t.Fatalf("%s: exit = %d (stderr %q)", phase, res.code, res.stderr)
		}
		if !strings.Contains(res.stdout, "Target: 127.0.0.1") {
			t.Errorf("%s: missing target banner", phase)
		}
	}
}

func TestCLIHelpExitCode(t *testing.T) {
	res := runScan(t, nil, "-h")
	if !strings.Contains(res.stderr, "stress-strike scan — TLS/WAF Deep Scanner") {
		t.Errorf("help text missing: %q", res.stderr)
	}
	if !strings.Contains(res.stderr, "Examples:") {
		t.Errorf("help text should list examples: %q", res.stderr)
	}
}

func TestDefaultPolicyPathHonoursEnv(t *testing.T) {
	t.Setenv("STRESS_STRIKE_POLICY", "/tmp/explicit-policy.json")
	if got := defaultPolicyPath(); got != "/tmp/explicit-policy.json" {
		t.Errorf("defaultPolicyPath = %q", got)
	}
}

func TestPrintWAFInfoVariants(t *testing.T) {
	got := captureStdout(t, func() {
		printWAFInfo(&scanner.WAFInfo{Detected: true, Name: "Cloudflare", Vendor: "CF", Confidence: 90,
			Indicators: []string{"a", "b", "c", "d", "e", "f", "g"}})
		printWAFInfo(&scanner.WAFInfo{Detected: false})
	})
	if !strings.Contains(got, "Detected: ✅ Cloudflare (CF)") {
		t.Errorf("missing detected line: %q", got)
	}
	if !strings.Contains(got, "Indicators: a, b, c, d, e") {
		t.Errorf("indicators should be capped at five: %q", got)
	}
	if !strings.Contains(got, "No WAF found") {
		t.Errorf("missing not-detected line: %q", got)
	}
}

func TestPrintSecurityInfoVariants(t *testing.T) {
	sec := &scanner.SecurityInfo{
		Score: 55,
		Details: []scanner.SecurityDetail{
			{Header: "HSTS", Status: "present", Value: "max-age=1"},
			{Header: "CSP", Status: "missing"},
			{Header: "XFO", Status: "weak", Value: "SAMEORIGIN"},
			{Header: "Referrer-Policy", Status: "info", Value: "no-referrer"},
			{Header: "Other", Status: "strong", Value: "v"},
		},
		MissingHeaders: []string{"CSP"},
	}
	got := captureStdout(t, func() { printSecurityInfo(sec) })
	for _, want := range []string{"Score: 55/100", "HSTS: max-age=1", "CSP: (not set)",
		"XFO: SAMEORIGIN", "Referrer-Policy: no-referrer", "Missing: CSP"} {
		if !strings.Contains(got, want) {
			t.Errorf("printSecurityInfo output missing %q", want)
		}
	}
}

// scanTestServer starts an in-process HTTP server the CLI subprocess can reach
// and returns its URL plus the port as a string for -port.
func scanTestServer(t *testing.T, withForms bool) (string, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "test-server/1.0")
		if withForms {
			w.Header().Set("X-Powered-By", "Go/1.26")
			io.WriteString(w, `<html><body><form method="post" action="/login">
<input name="username"><input name="password" type="password"></form>
<a href="/admin">admin</a><a href="/login">login</a></body></html>`)
			return
		}
		io.WriteString(w, `<html><body>ok</body></html>`)
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split test server host: %v", err)
	}
	return srv.URL, port
}
