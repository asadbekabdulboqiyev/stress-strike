package main

// cmd_scan_cli_test.go — black-box end-to-end tests for the standalone scanner
// commands (fuzz, dirbust, jwt, graphql, websocket, crawl, subdomain,
// portscan, sslscan) and the demo-store status/stop subcommands.
//
// The command entry points call os.Exit, so — like cmd_verify_test.go — these
// tests build the real executable once (via the shared TestMain harness in
// cmd_verify_test.go) and drive it as a subprocess. That exercises exactly what
// a user runs: dispatch, the authorization gate, the probe gate, and the
// output shapes.
//
// Network isolation: every case either stops at the authorization gate, at the
// probe gate under --dry-run, or is a pure offline analysis (jwt). No case
// reaches the network, so these tests are hermetic.

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// A public IP literal keeps the authorization gate on its permissive default
// (class=public, no ticket, no DNS) while nothing is ever dialed: each case is
// refused by the probe gate under --dry-run. The metadata address is the
// canonical credential-theft path the policy must always refuse.
const (
	cliPublicIP   = "93.184.216.34"
	cliMetadataIP = "169.254.169.254"
)

// scanCLIEnv points the CLI's authorization state (policy + audit log) at a
// throwaway directory. exec.Command inherits os.Environ(), so t.Setenv reaches
// the subprocess.
func scanCLIEnv(t *testing.T) {
	t.Helper()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())
}

// runCLIStdin is runCLI with stdin fed from a string, for the `jwt` stdin path.
func runCLIStdin(t *testing.T, stdin string, args ...string) cliResult {
	t.Helper()
	if cliBuildErr != nil {
		t.Fatalf("CLI build failed: %v", cliBuildErr)
	}
	if cliBin == "" {
		t.Fatal("CLI binary was not built")
	}
	cmd := exec.Command(cliBin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return cliResult{stdout: out.String(), stderr: errb.String(), code: code}
}

var scannerCommands = []string{
	"fuzz", "dirbust", "jwt", "graphql", "websocket", "crawl", "subdomain", "portscan", "sslscan",
}

// TestScannerCommandHelpDispatches proves every scanner command is wired into
// main()'s dispatch and renders its own help.
func TestScannerCommandHelpDispatches(t *testing.T) {
	scanCLIEnv(t)
	for _, c := range scannerCommands {
		c := c
		t.Run(c, func(t *testing.T) {
			res := runCLI(t, c, "--help")
			if res.code != 0 {
				t.Fatalf("%s --help exit = %d, want 0\nstderr: %s", c, res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, "stress-strike "+c) {
				t.Errorf("%s --help did not print its header\nstderr: %s", c, res.stderr)
			}
		})
	}
}

// TestFullHelpListsScanners guards the top-level help against drifting out of
// sync with the dispatch switch.
func TestFullHelpListsScanners(t *testing.T) {
	res := runCLI(t, "--help")
	if res.code != 0 {
		t.Fatalf("--help exit = %d, want 0", res.code)
	}
	if !strings.Contains(res.stderr, "INDIVIDUAL SCANNERS") {
		t.Errorf("full help is missing the INDIVIDUAL SCANNERS section")
	}
	for _, c := range scannerCommands {
		if !strings.Contains(res.stderr, c) {
			t.Errorf("full help does not list %q", c)
		}
	}
}

// TestGatedScannersDryRunSendsNothing is the core safety property: under
// --dry-run a gated scanner evaluates policy but sends nothing, and the gate's
// own counter says so (sent=0). The scanner-level counters can count attempts,
// but the gate is the honest signal about what left the machine.
func TestGatedScannersDryRunSendsNothing(t *testing.T) {
	scanCLIEnv(t)
	cases := []struct {
		name string
		args []string
	}{
		{"fuzz", []string{"fuzz", "--target", "https://" + cliPublicIP + "/", "--path", "/", "--mutations", "5", "--concurrency", "1", "--dry-run"}},
		{"dirbust", []string{"dirbust", "--target", "https://" + cliPublicIP + "/", "--dry-run"}},
		{"graphql", []string{"graphql", "--target", "https://" + cliPublicIP + "/graphql", "--dry-run"}},
		{"crawl", []string{"crawl", "--target", "https://" + cliPublicIP + "/", "--pages", "1", "--dry-run"}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			res := runCLI(t, c.args...)
			if res.code != 0 {
				t.Fatalf("exit = %d, want 0\nstderr: %s", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, "sent=0") {
				t.Errorf("gate must report sent=0 under --dry-run\nstderr: %s", res.stderr)
			}
			if !strings.Contains(res.stderr, "dry-run") {
				t.Errorf("expected a dry-run disclosure\nstderr: %s", res.stderr)
			}
		})
	}
}

// TestDirectDialScannersDryRunSkip proves the scanners that bypass the probe
// gate refuse to run at all under --dry-run: a dry run may never open a socket.
func TestDirectDialScannersDryRunSkip(t *testing.T) {
	scanCLIEnv(t)
	cases := []struct {
		name   string
		args   []string
		marker string
	}{
		{"subdomain", []string{"subdomain", "--target", cliPublicIP, "--dry-run"}, "dry-run: subdomain would run"},
		{"portscan", []string{"portscan", "--target", cliPublicIP, "--dry-run"}, "dry-run: portscan would run"},
		{"sslscan", []string{"sslscan", "--target", cliPublicIP, "--dry-run"}, "dry-run: sslscan would run"},
		{"websocket", []string{"websocket", "--url", "ws://" + cliPublicIP + "/", "--dry-run"}, "dry-run: websocket would run"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			res := runCLI(t, c.args...)
			if res.code != 0 {
				t.Fatalf("exit = %d, want 0\nstderr: %s", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, c.marker) {
				t.Errorf("missing dry-run skip disclosure %q\nstderr: %s", c.marker, res.stderr)
			}
			if res.stdout != "" {
				t.Errorf("a skipped dry run must produce no result, got stdout: %s", res.stdout)
			}
		})
	}
}

// TestScannerGateBlocksMetadata proves the authorization gate is wired ahead of
// every probe: the cloud-metadata address is refused for every gated scanner
// and the process exits 3 (authorization denied), not 1 (runtime error).
func TestScannerGateBlocksMetadata(t *testing.T) {
	scanCLIEnv(t)
	cases := [][]string{
		{"fuzz", "--target", "http://" + cliMetadataIP + "/", "--path", "/"},
		{"dirbust", "--target", "http://" + cliMetadataIP + "/"},
		{"graphql", "--target", "http://" + cliMetadataIP + "/graphql"},
		{"crawl", "--target", "http://" + cliMetadataIP + "/"},
		{"subdomain", "--target", cliMetadataIP},
		{"portscan", "--target", cliMetadataIP},
		{"sslscan", "--target", cliMetadataIP},
		{"websocket", "--url", "ws://" + cliMetadataIP + "/"},
	}
	for _, args := range cases {
		args := args
		t.Run(args[0], func(t *testing.T) {
			res := runCLI(t, args...)
			if res.code != authzDeniedExitCode {
				t.Fatalf("exit = %d, want %d\nstderr: %s", res.code, authzDeniedExitCode, res.stderr)
			}
			if !strings.Contains(res.stderr, "BLOCKED by authorization policy") {
				t.Errorf("expected an authorization denial\nstderr: %s", res.stderr)
			}
		})
	}
}

// TestJWTCliRedactsToken proves the token never appears on any output stream,
// in either the JSON or the human report. A JWT is a bearer credential; the
// company rule is that user tokens are never logged.
func TestJWTCliRedactsToken(t *testing.T) {
	scanCLIEnv(t)
	const token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.UNIQUESIGMARKER"

	for _, args := range [][]string{
		{"jwt", "--token", token, "--json"},
		{"jwt", "--token", token},
	} {
		res := runCLI(t, args...)
		if res.code != 0 {
			t.Fatalf("%v exit = %d, want 0\nstderr: %s", args, res.code, res.stderr)
		}
		combined := res.stdout + res.stderr
		if strings.Contains(combined, token) || strings.Contains(combined, "UNIQUESIGMARKER") {
			t.Fatalf("CLI leaked the token for %v\nstdout: %s\nstderr: %s", args, res.stdout, res.stderr)
		}
	}
}

// TestJWTCliReadsStdin covers the pipe-a-token path, which keeps the token out
// of the shell history and the process table.
func TestJWTCliReadsStdin(t *testing.T) {
	scanCLIEnv(t)
	const token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.UNIQUESIGMARKER"
	res := runCLIStdin(t, token+"\n", "jwt", "--json")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr: %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, `"valid": true`) {
		t.Errorf("expected a decoded report on stdout, got: %s", res.stdout)
	}
	if strings.Contains(res.stdout, "UNIQUESIGMARKER") {
		t.Fatalf("stdin path leaked the token: %s", res.stdout)
	}
}

// TestJWTCliNoInputIsHonest verifies that a missing token is a clear error, not
// a hang waiting on a TTY the operator did not mean to type into. A subprocess
// with no stdin gets the null device, which reads as non-empty input.
func TestJWTCliNoInputIsHonest(t *testing.T) {
	scanCLIEnv(t)
	res := runCLI(t, "jwt")
	if res.code != 1 {
		t.Errorf("exit = %d, want 1\nstderr: %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "no token provided") {
		t.Errorf("expected an actionable message\nstderr: %s", res.stderr)
	}
}

// TestScannerJSONKeepsStdoutMachineOnly proves the machine-readable contract:
// with --json, stdout carries only the JSON result and the gate stats go to
// stderr.
func TestScannerJSONKeepsStdoutMachineOnly(t *testing.T) {
	scanCLIEnv(t)
	res := runCLI(t, "dirbust", "--target", "https://"+cliPublicIP+"/", "--dry-run", "--json")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr: %s", res.code, res.stderr)
	}
	trimmed := strings.TrimSpace(res.stdout)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		t.Errorf("--json stdout is not a JSON object:\n%s", res.stdout)
	}
	if strings.Contains(res.stdout, "probes:") {
		t.Errorf("gate stats must go to stderr, not stdout:\n%s", res.stdout)
	}
}

// TestScannerOutputJSONFileMode proves --output-json writes a 0600 file and
// leaves the human summary on stdout.
func TestScannerOutputJSONFileMode(t *testing.T) {
	scanCLIEnv(t)
	path := t.TempDir() + "/dirbust.json"
	res := runCLI(t, "dirbust", "--target", "https://"+cliPublicIP+"/", "--dry-run", "--output-json", path)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr: %s", res.code, res.stderr)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("output file not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("output file mode = %o, want 600", perm)
	}
	if !strings.Contains(res.stdout, "dirbust:") {
		t.Errorf("human summary missing from stdout: %s", res.stdout)
	}
}

// TestScannerUnknownFlagExitsTwo pins the usage-error convention (exit 2) for
// the new commands, matching the rest of the CLI.
func TestScannerUnknownFlagExitsTwo(t *testing.T) {
	scanCLIEnv(t)
	res := runCLI(t, "fuzz", "--target", "example.com", "--path", "/", "--nope")
	if res.code != 2 {
		t.Errorf("exit = %d, want 2\nstderr: %s", res.code, res.stderr)
	}
}

// TestDemoStoreStatusCLI covers the status subcommand, including the honest
// "managed=false" from a fresh process.
func TestDemoStoreStatusCLI(t *testing.T) {
	scanCLIEnv(t)
	res := runCLI(t, "demo-store", "status", "--url", "http://127.0.0.1:1")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr: %s", res.code, res.stderr)
	}
	for _, want := range []string{"demo-store:", "running:    false", "managed:    false"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("status output missing %q\nstdout: %s", want, res.stdout)
		}
	}

	res = runCLI(t, "demo-store", "status", "--url", "http://127.0.0.1:1", "--json")
	if res.code != 0 {
		t.Fatalf("--json exit = %d, want 0\nstderr: %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, `"running"`) {
		t.Errorf("--json status missing fields:\n%s", res.stdout)
	}
}

// TestDemoStoreStopCLI covers stop's honest no-op from a standalone process: it
// never kills a store it did not launch.
func TestDemoStoreStopCLI(t *testing.T) {
	scanCLIEnv(t)
	res := runCLI(t, "demo-store", "stop", "--url", "http://127.0.0.1:1")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr: %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "nothing to stop") {
		t.Errorf("stop output = %q, want a no-op notice", res.stdout)
	}
}

// TestDemoStoreSubcommandHelp proves the two new subcommands have their own
// help and do not fall through to launching the store.
func TestDemoStoreSubcommandHelp(t *testing.T) {
	scanCLIEnv(t)
	for _, sub := range []string{"status", "stop"} {
		res := runCLI(t, "demo-store", sub, "--help")
		if res.code != 0 {
			t.Fatalf("demo-store %s --help exit = %d, want 0\nstderr: %s", sub, res.code, res.stderr)
		}
		if !strings.Contains(res.stderr, "demo-store "+sub) {
			t.Errorf("demo-store %s --help missing its header\nstderr: %s", sub, res.stderr)
		}
	}
}
