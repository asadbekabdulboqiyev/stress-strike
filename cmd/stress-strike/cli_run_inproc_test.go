package main

// cli_run_inproc_test.go — in-process coverage for `stress-strike run`.
//
// The load engine talks to a loopback httptest server, so the whole happy path
// (plan, run, report, save) executes for real without leaving the machine. One
// virtual user for one second keeps the suite fast.

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// runTestServer starts a loopback server that answers every request 200.
func runTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// deadLoopbackURL returns a loopback URL nothing listens on, so every
// request to it fails immediately (connection refused).
func deadLoopbackURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return fmt.Sprintf("http://127.0.0.1:%d/", port)
}

// runArgs builds the common flag set a load-test invocation needs so the
// authorization layer stays inside the throwaway home.
func runArgs(home string, extra ...string) []string {
	base := []string{
		"run",
		"--policy", filepath.Join(home, "authz.json"),
		"--audit-log", filepath.Join(home, "audit.jsonl"),
		"--allow-private",
	}
	return append(base, extra...)
}

func TestInprocRunHelpAndVersion(t *testing.T) {
	scanCLIHome(t)

	res := runCLIInProcess(t, "run", "--help")
	if res.code != 0 {
		t.Fatalf("help exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "stress-strike run") || !strings.Contains(res.stderr, "FLAGS") {
		t.Errorf("help text incomplete: %q", res.stderr)
	}

	res = runCLIInProcess(t, "run", "--version")
	if res.code != 0 {
		t.Fatalf("version exit = %d, want 0", res.code)
	}
	if !strings.Contains(res.stdout, "stress-strike v"+version) {
		t.Errorf("stdout = %q, want the version", res.stdout)
	}
}

func TestInprocRunUsageAndConfigErrors(t *testing.T) {
	home := scanCLIHome(t)
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no target", runArgs(home), 1, "either --config or --url is required"},
		{"missing config", runArgs(home, "--config", filepath.Join(home, "nope.yaml")), 1, "error:"},
		{"bad mode", runArgs(home, "--url", "http://127.0.0.1:1/", "--mode", "bogus"), 1, "invalid --mode"},
		{"bad tls fingerprint", runArgs(home, "--url", "http://127.0.0.1:1/", "--tls-fingerprint", "netscape"), 1, "unknown -tls-fingerprint"},
		{"bad header", runArgs(home, "--url", "http://127.0.0.1:1/", "--header", "no-equals"), 2, "header"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res := runCLIInProcess(t, tc.args...)
			if res.code != tc.code {
				t.Fatalf("exit = %d, want %d (stderr: %s)", res.code, tc.code, res.stderr)
			}
			if !strings.Contains(res.stderr, tc.want) {
				t.Errorf("stderr = %q, want %q", res.stderr, tc.want)
			}
		})
	}
}

func TestInprocRunHappyPath(t *testing.T) {
	home := scanCLIHome(t)
	reportDir := filepath.Join(t.TempDir(), "reports")
	srv := runTestServer(t)

	args := runArgs(home,
		"--url", srv.URL+"/health",
		"--users", "1",
		"--duration", "1",
		"--timeout", "2",
		"--quiet",
		"--pre-warm",
		"--pre-warm-conns", "1",
		"--timeline",
		"--report-dir", reportDir,
	)
	res := runCLIInProcess(t, args...)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	for _, want := range []string{"WARNING: stress-strike is a load testing tool", "stress-strike v" + version, "Reports written:"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, res.stderr)
		}
	}
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		t.Fatalf("read report dir: %v", err)
	}
	var json, txt, csv bool
	for _, e := range entries {
		switch filepath.Ext(e.Name()) {
		case ".json":
			json = true
		case ".txt":
			txt = true
		case ".csv":
			csv = true
		}
	}
	if !json || !txt || !csv {
		t.Errorf("reports: json=%v txt=%v csv=%v (want all three)", json, txt, csv)
	}
}

func TestInprocRunPacedWithCoordinatedOmission(t *testing.T) {
	home := scanCLIHome(t)
	srv := runTestServer(t)

	res := runCLIInProcess(t, runArgs(home,
		"--url", srv.URL,
		"--users", "1",
		"--duration", "1",
		"--target-rps", "20",
		"--coordinated-omission",
		"--no-http2",
		"--quiet",
		"--report-dir", t.TempDir(),
	)...)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
}

func TestInprocRunCoordinatedOmissionWarning(t *testing.T) {
	home := scanCLIHome(t)
	srv := runTestServer(t)

	res := runCLIInProcess(t, runArgs(home,
		"--url", srv.URL,
		"--users", "1",
		"--duration", "1",
		"--coordinated-omission",
		"--quiet",
		"--report-dir", t.TempDir(),
	)...)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "--coordinated-omission has no effect without pacing") {
		t.Errorf("stderr = %q, want the pacing warning", res.stderr)
	}
}

func TestInprocRunSLAFailureExitsTwo(t *testing.T) {
	home := scanCLIHome(t)
	srv := runTestServer(t)

	res := runCLIInProcess(t, runArgs(home,
		"--url", srv.URL,
		"--users", "1",
		"--duration", "1",
		"--quiet",
		"--expect-p99-ms", "0.000001",
		"--report-dir", t.TempDir(),
	)...)
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "SLA gate FAILED") {
		t.Errorf("stderr = %q, want the SLA gate message", res.stderr)
	}
}

func TestInprocRunAllRequestsFailExitsOne(t *testing.T) {
	home := scanCLIHome(t)
	// A port nothing listens on: every request fails, which the safety net
	// must surface as exit 1 instead of a green run.
	dead := deadLoopbackURL(t)

	res := runCLIInProcess(t, runArgs(home,
		"--url", dead,
		"--users", "1",
		"--duration", "1",
		"--timeout", "1",
		"--quiet",
		"--report-dir", t.TempDir(),
	)...)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "100% of requests failed") {
		t.Errorf("stderr = %q, want the unreachable-target warning", res.stderr)
	}
}

func TestInprocRunEvidenceBundle(t *testing.T) {
	home := scanCLIHome(t)
	srv := runTestServer(t)
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.json")

	res := runCLIInProcess(t, runArgs(home,
		"--url", srv.URL,
		"--users", "1",
		"--duration", "1",
		"--quiet",
		"--emit-bundle", bundle,
		"--bundle-worker", "test-worker",
		"--report-dir", filepath.Join(dir, "reports"),
	)...)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if !strings.Contains(string(data), "vpmp/v1") {
		t.Errorf("bundle = %q, want a vpmp/v1 document", data)
	}
	if _, err := os.Stat(strings.TrimSuffix(bundle, ".json") + ".samples.jsonl"); err != nil {
		t.Errorf("samples sidecar missing: %v", err)
	}
}

func TestInprocRunHelpers(t *testing.T) {
	// defaultWorkerID returns "hostname-pid".
	got := defaultWorkerID()
	if got == "" {
		t.Fatalf("defaultWorkerID = %q, want non-empty", got)
	}

	// coCorrectionGate: unpaced → message; paced steady/soak → empty.
	if msg := coCorrectionGate(&config.Scenario{}, 0); msg == "" {
		t.Errorf("coCorrectionGate(unpaced) = empty, want a message")
	}
	sc := &config.Scenario{Profile: config.Profile{Type: config.ProfileSteady}}
	if msg := coCorrectionGate(sc, 500); msg != "" {
		t.Errorf("coCorrectionGate(steady,paced) = %q, want empty", msg)
	}
	sc = &config.Scenario{Profile: config.Profile{Type: config.ProfileSpike}}
	if msg := coCorrectionGate(sc, 500); msg == "" {
		t.Errorf("coCorrectionGate(spike,paced) = empty, want a message")
	}

	// millisInterval formats the bounds.
	if got := millisInterval(0, 1_500_000_000); got != "[0.000ms, 1500.000ms]" {
		t.Errorf("millisInterval = %q", got)
	}
}
