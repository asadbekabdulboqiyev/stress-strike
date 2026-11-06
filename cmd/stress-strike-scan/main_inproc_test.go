package main

import (
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runMain executes main() in-process with the given argv. Only paths that
// return normally may be used: main calls os.Exit on every error, which would
// kill the test binary. Exit-code behaviour is covered by the subprocess tests
// in main_cli_test.go.
func runMain(t *testing.T, args ...string) (stdout, stderr string) {
	t.Helper()

	oldArgs := os.Args
	oldStdout, oldStderr := os.Stdout, os.Stderr
	oldFlags := flag.CommandLine
	defer func() {
		os.Args = oldArgs
		os.Stdout, os.Stderr = oldStdout, oldStderr
		flag.CommandLine = oldFlags
	}()

	outFile, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatalf("temp stdout: %v", err)
	}
	errFile, err := os.CreateTemp(t.TempDir(), "stderr-*")
	if err != nil {
		t.Fatalf("temp stderr: %v", err)
	}

	os.Args = append([]string{"stress-strike-scan"}, args...)
	os.Stdout = outFile
	os.Stderr = errFile
	flag.CommandLine = flag.NewFlagSet("stress-strike-scan", flag.ContinueOnError)

	main()

	if err := outFile.Close(); err != nil {
		t.Fatalf("close stdout: %v", err)
	}
	if err := errFile.Close(); err != nil {
		t.Fatalf("close stderr: %v", err)
	}
	outBytes, err := os.ReadFile(outFile.Name())
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	errBytes, err := os.ReadFile(errFile.Name())
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(outBytes), string(errBytes)
}

// inprocTestServer starts a local HTTP server and returns the host, port and
// port string for the CLI flags.
func inprocTestServer(t *testing.T) (portStr string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "inproc/1.0")
		w.Header().Set("X-Powered-By", "Go")
		switch r.URL.Path {
		case "/robots.txt":
			w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
		default:
			w.Write([]byte(`<html><body><form action="/login" method="post">
<input name="username"><input name="password" type="password"></form>
<a href="/admin">a</a></body></html>`))
		}
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	return port
}

func TestMainTLSPhase(t *testing.T) {
	port := inprocTestServer(t)

	stdout, _ := runMain(t, "-target", "127.0.0.1", "-port", port, "-tls")
	for _, want := range []string{"stress-strike scan — Deep Security Scanner", "URL:    https://127.0.0.1",
		"scope: 127.0.0.1 (derived from --target", "TLS Scan", "VULNERABILITIES & RISK SCORE", "Risk Score:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q", want)
		}
	}
}

func TestMainAllPhases(t *testing.T) {
	port := inprocTestServer(t)

	stdout, _ := runMain(t, "-target", "127.0.0.1", "-port", port, "-all", "-verbose")
	for _, want := range []string{"HTTP Fingerprint", "WAF Detection", "Security Headers", "Scan Duration:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q", want)
		}
	}

	// Unreachable HTTP endpoint: the phase error branches print and continue.
	stdout, _ = runMain(t, "-target", "127.0.0.1", "-port", "1", "-http", "-waf", "-security")
	if !strings.Contains(stdout, "scan error") {
		t.Errorf("expected scan error lines, got %q", stdout)
	}
}

func TestMainOWASPPhase(t *testing.T) {
	port := inprocTestServer(t)
	outJSON := filepath.Join(t.TempDir(), "scan.json")

	stdout, _ := runMain(t, "-target", "127.0.0.1", "-port", port,
		"-owasp", "-verbose", "-rate", "200", "-budget", "800",
		"-path", "/,/login", "-output-json", outJSON)
	for _, want := range []string{"OWASP Top 10 Check", "routes:", "OWASP TOP 10 — COVERAGE-AWARE RESULTS",
		"guard: sent=", "JSON report:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q", want)
		}
	}
	if _, err := os.Stat(outJSON); err != nil {
		t.Fatalf("json report: %v", err)
	}
}

func TestMainOWASPDryRun(t *testing.T) {
	stdout, stderr := runMain(t, "-target", "127.0.0.1", "-port", "1", "-owasp", "-dry-run", "-verbose")
	if !strings.Contains(stdout, "dry-run: the policy is evaluated") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "authorization: ok") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestMainPassiveAndIntrusivePhases(t *testing.T) {
	port := inprocTestServer(t)

	stdout, _ := runMain(t, "-target", "127.0.0.1", "-port", port,
		"-passive", "-verbose", "-rate", "200", "-path", "/,/admin")
	if !strings.Contains(stdout, "Passive Checks") {
		t.Errorf("stdout missing passive phase: %q", stdout)
	}

	stdout, _ = runMain(t, "-target", "127.0.0.1", "-port", port,
		"-intrusive", "-enable", "crlf", "-verbose", "-rate", "200")
	if !strings.Contains(stdout, "Intrusive Probes") || !strings.Contains(stdout, "families:") {
		t.Errorf("stdout missing intrusive phase: %q", stdout)
	}

	// An empty --enable list leaves the intrusive phase off.
	stdout, _ = runMain(t, "-target", "127.0.0.1", "-port", port, "-intrusive", "-rate", "200")
	if strings.Contains(stdout, "Intrusive Probes") {
		t.Errorf("intrusive phase should not run with an empty --enable list: %q", stdout)
	}
}

func TestMainOutputJSONFailure(t *testing.T) {
	port := inprocTestServer(t)

	stdout, _ := runMain(t, "-target", "127.0.0.1", "-port", port, "-tls",
		"-output-json", "/dev/null/dir/scan.json")
	if !strings.Contains(stdout, "Failed to create JSON") {
		t.Errorf("stdout missing JSON failure warning: %q", stdout)
	}
}
