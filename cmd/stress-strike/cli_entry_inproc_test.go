package main

// cli_entry_inproc_test.go — in-process coverage for the remaining command
// entry points in package main: demo-store, healthcheck, sub-binary dispatch,
// the dashboard mode and the interactive picker/CLI/wizard.
//
// Everything runs under cli_harness_test.go's driveCommand, so exitProcess and
// cliux.ExitProcess unwind into the test. Nothing leaves the machine: load
// tests target a loopback httptest server, the dashboard bind tests occupy a
// loopback port so ListenAndServe fails immediately, and PATH is emptied where
// a command would otherwise open a real browser.

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/dashboard"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
	prom "github.com/asadbekabdulboqiyev/sift/internal/metrics/exporter"
)

// okServer starts a loopback server that answers 200 to everything.
func okServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// unusedLoopbackURL returns a loopback URL whose port refuses every
// connection for as long as the test runs.
//
// The port is held by a listener that accepts and immediately resets the
// connection. Binding an ephemeral port, closing it and using the freed
// number has a race: another program on the host can take the port in the
// window before the first request, and then the "nothing is listening here"
// assumption is silently wrong.
func unusedLoopbackURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // the listener was closed by the test cleanup
			}
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return "http://" + ln.Addr().String() + "/"
}

// ── demo-store ────────────────────────────────────────────────────────────

func TestInprocDemoStoreHelp(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{"store", []string{"demo-store", "--help"}, "Sift demo-store — launch"},
		{"status", []string{"demo-store", "status", "--help"}, "demo-store status — report"},
		{"stop", []string{"demo-store", "stop", "--help"}, "demo-store stop — stop"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res := runCommandFn(t, cmdDemoStore, tc.argv...)
			if res.code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, tc.want) {
				t.Errorf("stderr = %q, want %q", res.stderr, tc.want)
			}
		})
	}
}

// TestInprocDemoStoreHelpPrinters exercises the three help renderers directly,
// which is the only way to reach the flag listings without the parse wrapper.
func TestInprocDemoStoreHelpPrinters(t *testing.T) {
	// A flag set with no flags still renders the fixed prose.
	fs := flag.NewFlagSet("demo-store", flag.ContinueOnError)
	res := runCommandFn(t, func() { printDemoStoreHelp(fs) }, "demo-store")
	if res.code != 0 || !strings.Contains(res.stderr, "Build the store binary with") {
		t.Fatalf("printDemoStoreHelp: code=%d stderr=%q", res.code, res.stderr)
	}
	res = runCommandFn(t, func() { printDemoStoreStatusHelp(fs) }, "demo-store")
	if res.code != 0 || !strings.Contains(res.stderr, "--json") {
		t.Fatalf("printDemoStoreStatusHelp: code=%d stderr=%q", res.code, res.stderr)
	}
	res = runCommandFn(t, func() { printDemoStoreStopHelp(fs) }, "demo-store")
	if res.code != 0 || !strings.Contains(res.stderr, "demo-store stop") {
		t.Fatalf("printDemoStoreStopHelp: code=%d stderr=%q", res.code, res.stderr)
	}
}

// ── healthcheck ───────────────────────────────────────────────────────────

func TestInprocHealthcheck(t *testing.T) {
	srv := okServer(t)

	t.Run("healthy", func(t *testing.T) {
		res := runCommandFn(t, cmdHealthcheck, "healthcheck", "-addr", srv.URL)
		if res.code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
		}
	})

	t.Run("unhealthy", func(t *testing.T) {
		res := runCommandFn(t, cmdHealthcheck, "healthcheck", "-addr", unusedLoopbackURL(t), "-timeout", "1")
		if res.code != 1 {
			t.Fatalf("exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
		}
		if !strings.Contains(res.stderr, "healthcheck:") {
			t.Errorf("stderr = %q, want a probe diagnostic", res.stderr)
		}
	})

	t.Run("usage", func(t *testing.T) {
		res := runCommandFn(t, cmdHealthcheck, "healthcheck", "-bogus")
		if res.code != 2 {
			t.Fatalf("exit = %d, want 2 (stderr: %s)", res.code, res.stderr)
		}
	})
}

// ── direct-dial JSON ──────────────────────────────────────────────────────

func TestInprocEmitScanDirectDialJSON(t *testing.T) {
	payload := map[string]any{"hosts": []string{"a.example"}, "ok": true}

	t.Run("no output requested", func(t *testing.T) {
		res := runCommandFn(t, func() {
			if err := emitScanDirectDialJSON("subdomain", "example.com", payload, &scanFlags{}); err != nil {
				t.Fatalf("emitScanDirectDialJSON: %v", err)
			}
		}, "subdomain")
		if res.code != 0 || res.stdout != "" {
			t.Fatalf("code=%d stdout=%q, want silent success", res.code, res.stdout)
		}
	})

	t.Run("stdout json", func(t *testing.T) {
		res := runCommandFn(t, func() {
			if err := emitScanDirectDialJSON("subdomain", "example.com", payload, &scanFlags{jsonOut: true}); err != nil {
				t.Fatalf("emitScanDirectDialJSON: %v", err)
			}
		}, "subdomain")
		if res.code != 0 {
			t.Fatalf("code = %d (stderr: %s)", res.code, res.stderr)
		}
		for _, want := range []string{`"command": "subdomain"`, `"scope_enforced": false`, `"result"`} {
			if !strings.Contains(res.stdout, want) {
				t.Errorf("stdout = %q, want %q", res.stdout, want)
			}
		}
	})

	t.Run("output file", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "result.json")
		res := runCommandFn(t, func() {
			if err := emitScanDirectDialJSON("portscan", "example.com", payload, &scanFlags{outputJSON: out}); err != nil {
				t.Fatalf("emitScanDirectDialJSON: %v", err)
			}
		}, "portscan")
		if res.code != 0 {
			t.Fatalf("code = %d (stderr: %s)", res.code, res.stderr)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read output: %v", err)
		}
		if !strings.Contains(string(data), `"target": "example.com"`) {
			t.Errorf("file = %q, want the envelope", data)
		}
	})
}

// ── sub-binary dispatch ───────────────────────────────────────────────────

// writeExecSibling drops a small shell script beside the test binary so
// runSubCommand's "sibling binary found" branch is exercised without building
// the real subcommands. Names are unique per test and removed afterwards.
func writeExecSibling(t *testing.T, name, script string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// Match the name runSubCommand looks for, which carries .exe on Windows.
	path := filepath.Join(filepath.Dir(exe), subBinaryName(name))
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write sibling %s: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
}

// skipUnlessPOSIXExec skips on Windows: these cases drive sibling discovery
// with `#!/bin/sh` scripts, and Windows can only execute PE images, not scripts
// with an interpreter line. The Windows half of the same logic — the ".exe"
// suffix that runSubCommand must look for — is covered by
// TestSubBinaryNameWindowsSuffix.
func skipUnlessPOSIXExec(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sibling dispatch is driven by /bin/sh scripts; Windows needs real PE binaries")
	}
}

func TestSubBinaryNameSuffix(t *testing.T) {
	want := "Sift-scan"
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	if got := subBinaryName("Sift-scan"); got != want {
		t.Errorf("subBinaryName = %q, want %q", got, want)
	}
}

func TestInprocRunSubCommandSibling(t *testing.T) {
	skipUnlessPOSIXExec(t)

	writeExecSibling(t, "Sift-test-ok", "#!/bin/sh\nexit 0\n")
	res := runCommandFn(t, func() { runSubCommand("Sift-test-ok", []string{"--flag"}) }, "x")
	if res.code != 0 {
		t.Fatalf("sibling success: exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}

	writeExecSibling(t, "Sift-test-fail", "#!/bin/sh\nexit 7\n")
	res = runCommandFn(t, func() { runSubCommand("Sift-test-fail", nil) }, "x")
	if res.code != 7 {
		t.Fatalf("sibling failure: exit = %d, want 7 (stderr: %s)", res.code, res.stderr)
	}
}

// TestInprocRunSubCommandGoFallback replaces `go` on PATH: the missing sibling
// falls through to `go run`, which the stub answers without compiling anything.
func TestInprocRunSubCommandGoFallback(t *testing.T) {
	skipUnlessPOSIXExec(t)
	dir := t.TempDir()
	goStub := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte(goStub), 0o755); err != nil {
		t.Fatalf("write go stub: %v", err)
	}
	t.Setenv("PATH", dir)

	res := runCommandFn(t, func() { runSubCommand("Sift-no-such-subcommand-xyz", nil) }, "x")
	if res.code != 0 {
		t.Fatalf("fallback success: exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}

	if err := os.WriteFile(filepath.Join(dir, "go"), []byte("#!/bin/sh\nexit 4\n"), 0o755); err != nil {
		t.Fatalf("rewrite go stub: %v", err)
	}
	res = runCommandFn(t, func() { runSubCommand("Sift-no-such-subcommand-xyz", nil) }, "x")
	if res.code != 4 {
		t.Fatalf("fallback failure: exit = %d, want 4 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "Build with: go build") {
		t.Errorf("stderr = %q, want the build hint", res.stderr)
	}
}

// TestInprocSubCommandWrappers drives the five one-line dispatchers. Each
// finds the sibling script it names, so the real sub-binaries are never built.
func TestInprocSubCommandWrappers(t *testing.T) {
	skipUnlessPOSIXExec(t)
	cases := []struct {
		name string
		fn   func()
	}{
		{"Sift-replay", cmdReplay},
		{"Sift-scan", cmdScan},
		{"Sift-dashboard", cmdDashboard},
		{"Sift-master", cmdMaster},
		{"Sift-worker", cmdWorker},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			writeExecSibling(t, tc.name, "#!/bin/sh\nexit 0\n")
			res := runCommandFn(t, tc.fn, tc.name, "--help")
			if res.code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
			}
		})
	}
}

// ── dashboard mode ────────────────────────────────────────────────────────

func TestInprocRunWithDashboardRefusesOpenBind(t *testing.T) {
	sc, err := quickScenario("t", "http://127.0.0.1:1/", "GET", "", headerFlags{},
		"steady", 1, 1, 0, 0, 0, 0, 0, 0, 0, 2, true)
	if err != nil {
		t.Fatalf("quickScenario: %v", err)
	}

	t.Run("non-loopback without auth", func(t *testing.T) {
		res := runCommandFn(t, func() {
			runWithDashboard(sc, "0.0.0.0:0", t.TempDir(), dashboard.AuthOptions{})
		}, "dashboard")
		if res.code != 1 {
			t.Fatalf("exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
		}
		if !strings.Contains(res.stderr, "FATAL") {
			t.Errorf("stderr = %q, want the auth refusal", res.stderr)
		}
	})

	t.Run("bind failure", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("listen: %v", err)
		}
		addr := ln.Addr().String()
		t.Cleanup(func() { _ = ln.Close() })

		res := runCommandFn(t, func() {
			runWithDashboard(sc, addr, t.TempDir(), dashboard.AuthOptions{})
		}, "dashboard")
		if res.code != 1 {
			t.Fatalf("exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
		}
		if !strings.Contains(res.stderr, "dashboard server failed") {
			t.Errorf("stderr = %q, want the bind error", res.stderr)
		}
		if !strings.Contains(res.stdout, "Sift dashboard") {
			t.Errorf("stdout = %q, want the banner", res.stdout)
		}
	})
}

func TestInprocDashboardTelemetryHelpers(t *testing.T) {
	srv := okServer(t)
	sc, err := quickScenario("t", srv.URL, "GET", "", headerFlags{},
		"steady", 1, 1, 0, 0, 0, 0, 0, 0, 0, 2, true)
	if err != nil {
		t.Fatalf("quickScenario: %v", err)
	}
	eng, err := engine.New(sc)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	t.Run("no telemetry yet", func(t *testing.T) {
		if _, ok := engineTelemetry(eng); ok {
			t.Fatal("engineTelemetry reported telemetry before Run")
		}
		snap := snapshotFromTelemetry(eng, sc)
		if snap == nil || snap.ActiveUsers != sc.Profile.Users {
			t.Fatalf("snapshot = %+v, want the idle default", snap)
		}
	})

	t.Run("live run", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = eng.Run(ctx, engine.RunOptions{Out: io.Discard, Quiet: true})
		}()
		deadline := time.Now().Add(3 * time.Second)
		for eng.Telemetry() == nil && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if eng.Telemetry() == nil {
			cancel()
			<-done
			t.Skip("engine telemetry never became available")
		}
		if _, ok := engineTelemetry(eng); !ok {
			t.Error("engineTelemetry = false during a live run")
		}
		snap := snapshotFromTelemetry(eng, sc)
		if snap == nil || snap.StatusCodes == nil {
			t.Fatalf("snapshot = %+v, want a live snapshot", snap)
		}
		cancel()
		<-done
	})
}

func TestInprocStreamTelemetry(t *testing.T) {
	srv := okServer(t)
	sc, err := quickScenario("t", srv.URL, "GET", "", headerFlags{},
		"steady", 1, 1, 0, 0, 0, 0, 0, 0, 0, 2, true)
	if err != nil {
		t.Fatalf("quickScenario: %v", err)
	}
	eng, err := engine.New(sc)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	t.Run("nil metrics", func(t *testing.T) {
		stop := make(chan struct{})
		go func() {
			time.Sleep(550 * time.Millisecond)
			close(stop)
		}()
		streamTelemetry(dashboard.NewServer(), eng, sc, nil, stop)
	})

	t.Run("with metrics", func(t *testing.T) {
		stop := make(chan struct{})
		go func() {
			time.Sleep(550 * time.Millisecond)
			close(stop)
		}()
		streamTelemetry(dashboard.NewServer(), eng, sc, prom.NewMetrics(), stop)
	})
}

// ── interactive mode ──────────────────────────────────────────────────────

// withHistoryFile points the wizard's last-run persistence at a temp file.
func withHistoryFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "last-run.json")
	prev := historyFilePath
	historyFilePath = func() string { return path }
	t.Cleanup(func() { historyFilePath = prev })
	return path
}

func TestInprocInteractivePickerQuit(t *testing.T) {
	res := driveCommand(t, "0\n", interactivePicker)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "Bye.") {
		t.Errorf("stdout = %q, want the goodbye", res.stdout)
	}
}

func TestInprocInteractiveCLIEmptyURL(t *testing.T) {
	scanCLIHome(t)
	// "1" routes the picker to the CLI, the blank line leaves the URL empty.
	res := driveCommand(t, "1\n\n", interactivePicker)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "target URL is required") {
		t.Errorf("stdout = %q, want the URL error", res.stdout)
	}
}

func TestInprocInteractiveCLIRun(t *testing.T) {
	scanCLIHome(t)
	t.Chdir(t.TempDir())
	withHistoryFile(t)
	srv := okServer(t)

	stdin := "1\n" + srv.URL + "\n1\n1\n"
	res := driveCommand(t, stdin, interactivePicker)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr tail: %s)", res.code, tail(res.stderr, 1200))
	}
	if !strings.Contains(res.stdout, "Running load test") {
		t.Errorf("stdout = %q, want the run notice", res.stdout)
	}
	if !strings.Contains(res.stderr, "Reports written:") {
		t.Errorf("stderr = %q, want the reports notice", res.stderr)
	}
}

func TestInprocInteractiveWizardExpertRun(t *testing.T) {
	scanCLIHome(t)
	t.Chdir(t.TempDir())
	withHistoryFile(t)
	srv := okServer(t)

	// Expert flow: mode 2, URL, GET, no headers, 1 user, 1s, steady profile,
	// unlimited RPS, 1s timeout, no keep-alive, no capture, no gate, name,
	// confirm.
	lines := []string{
		"2", srv.URL, "", "", "1", "1", "1", "0", "1", "n", "0", "n", "e2e", "y",
	}
	stdin := strings.Join(lines, "\n") + "\n"

	res := driveCommand(t, stdin, func() {
		interactiveWizard(bufio.NewReader(os.Stdin))
	})
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr tail: %s)", res.code, tail(res.stderr, 1200))
	}
	if !strings.Contains(res.stdout, "Running load test") {
		t.Errorf("stdout = %q, want the run notice", res.stdout)
	}
	if !strings.Contains(res.stderr, "Reports written:") {
		t.Errorf("stderr = %q, want the reports notice", res.stderr)
	}
}

func TestInprocInteractiveWizardCanceled(t *testing.T) {
	scanCLIHome(t)
	t.Chdir(t.TempDir())
	withHistoryFile(t)

	// Guided mode, valid URL, then "n" at the confirmation prompt.
	stdin := "1\nhttp://127.0.0.1:1/\nn\n"
	res := driveCommand(t, stdin, func() {
		interactiveWizard(bufio.NewReader(os.Stdin))
	})
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "Setup canceled.") {
		t.Errorf("stderr = %q, want the cancellation notice", res.stderr)
	}
}

func TestInprocInteractiveDashboard(t *testing.T) {
	scanCLIHome(t)
	t.Chdir(t.TempDir())
	history := withHistoryFile(t)
	srv := okServer(t)

	data, err := json.Marshal(lastRun{Name: "x", URL: srv.URL, VUsers: 1, Duration: 1})
	if err != nil {
		t.Fatalf("marshal history: %v", err)
	}
	if err := os.WriteFile(history, data, 0o600); err != nil {
		t.Fatalf("write history: %v", err)
	}

	// interactiveDashboard hard-codes 127.0.0.1:8888. Occupy it so the
	// dashboard's ListenAndServe fails immediately instead of blocking.
	ln, err := net.Listen("tcp", "127.0.0.1:8888")
	if err != nil {
		t.Skipf("127.0.0.1:8888 unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	t.Setenv("PATH", "") // openBrowser must not launch a real browser

	res := runCommandFn(t, func() {
		interactiveDashboard(bufio.NewReader(strings.NewReader("")))
	}, "dashboard")
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "dashboard server failed") {
		t.Errorf("stderr = %q, want the bind error", res.stderr)
	}
}

func TestInprocInteractiveDashboardNoURL(t *testing.T) {
	scanCLIHome(t)
	withHistoryFile(t) // empty history

	res := runCommandFn(t, func() {
		interactiveDashboard(bufio.NewReader(strings.NewReader("")))
	}, "dashboard")
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "target URL is required") {
		t.Errorf("stdout = %q, want the URL error", res.stdout)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

// tail returns at most n trailing bytes, so a failure message stays readable.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
