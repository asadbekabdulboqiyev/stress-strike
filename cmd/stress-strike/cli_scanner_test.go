package main

// cli_scanner_test.go — in-process coverage for the standalone scanner
// commands (fuzz, dirbust, jwt, graphql, websocket, crawl, subdomain,
// portscan, sslscan).
//
// Every case stays off the network: it stops at the authorization gate (exit
// 3), at the probe gate under --dry-run (exit 0, nothing sent), or is a pure
// offline analysis (jwt). Public IP literals keep the authorization layer on
// its permissive default without a DNS lookup; the metadata address is the
// canonical credential-theft path the policy must always refuse.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Public and private IP literals: no DNS, deterministic classification.
const (
	inprocPublicIP    = "93.184.216.34"
	inprocPrivateIP   = "10.11.12.13"
	inprocMetadataURL = "http://169.254.169.254/latest/meta-data/"
)

func TestInprocMainDispatch(t *testing.T) {
	scanCLIHome(t)

	t.Run("help exits 0", func(t *testing.T) {
		res := runCLIInProcess(t, "help")
		if res.code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
		}
		if !strings.Contains(res.stderr, "Sift") {
			t.Errorf("help output missing the program name: %q", res.stderr)
		}
		if !strings.Contains(res.stderr, "portscan") {
			t.Errorf("help output missing the command list: %q", res.stderr)
		}
	})

	for _, alts := range [][]string{{"--help"}, {"-h"}} {
		if res := runCLIInProcess(t, alts...); res.code != 0 {
			t.Errorf("%v: exit = %d, want 0", alts, res.code)
		}
	}

	for _, v := range []string{"version", "--version", "-v"} {
		res := runCLIInProcess(t, v)
		if res.code != 0 {
			t.Fatalf("%s: exit = %d, want 0", v, res.code)
		}
		if !strings.Contains(res.stdout, "Sift v") {
			t.Errorf("%s: stdout = %q, want a version line", v, res.stdout)
		}
	}

	t.Run("unknown command exits 2", func(t *testing.T) {
		res := runCLIInProcess(t, "definitely-not-a-command")
		if res.code != 2 {
			t.Fatalf("exit = %d, want 2", res.code)
		}
		joined := res.stdout + res.stderr
		if !strings.Contains(joined, "unknown command") {
			t.Errorf("output = %q, want an unknown-command message", joined)
		}
		if !strings.Contains(joined, "help") {
			t.Errorf("output = %q, want the command listing hint", joined)
		}
	})
}

// gatedScanners are the commands whose probes route through the Guard; --dry-run
// therefore makes them evaluate the policy and send nothing.
var gatedScanners = []string{"crawl", "dirbust", "fuzz", "graphql"}

func TestInprocScannerHelp(t *testing.T) {
	scanCLIHome(t)
	for _, cmd := range scannerCommands {
		cmd := cmd
		t.Run(cmd, func(t *testing.T) {
			res := runCLIInProcess(t, cmd, "--help")
			if res.code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, "Sift "+cmd) {
				t.Errorf("help text does not name the command: %q", res.stderr)
			}
			if !strings.Contains(res.stderr, "FLAGS") {
				t.Errorf("help text has no flag section: %q", res.stderr)
			}
		})
	}
}

func TestInprocScannerUnknownFlag(t *testing.T) {
	scanCLIHome(t)
	for _, cmd := range scannerCommands {
		cmd := cmd
		t.Run(cmd, func(t *testing.T) {
			res := runCLIInProcess(t, cmd, "--no-such-flag")
			if res.code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr: %s)", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, "no-such-flag") {
				t.Errorf("stderr = %q, want the offending flag named", res.stderr)
			}
		})
	}
}

func TestInprocGatedUsageErrors(t *testing.T) {
	scanCLIHome(t)
	for _, cmd := range gatedScanners {
		cmd := cmd
		t.Run(cmd, func(t *testing.T) {
			// fuzz validates its own required flags before the gate, so every
			// case carries the minimum path it needs.
			base := []string{cmd}
			if cmd == "fuzz" {
				base = append(base, "--path", "/")
			}
			cases := []struct {
				name string
				args []string
				want string
			}{
				{"missing target", []string{cmd}, "--target is required"},
				{"non-http scheme", []string{cmd, "--target", "ftp://example.test"}, "http://"},
				{"missing host", []string{cmd, "--target", "http://"}, "host"},
				{"embedded credentials", []string{cmd, "--target", "http://user:pass@example.test"}, "credentials"},
				{"negative rate", append(base, "--target", inprocPublicIP, "--rate", "-1"), "policy"},
				{"negative budget", append(base, "--target", inprocPublicIP, "--budget", "-2"), "policy"},
				{"malformed allow pattern", append(base, "--target", inprocPublicIP, "--allow", "["), "policy"},
			}
			for _, tc := range cases {
				res := runCLIInProcess(t, tc.args...)
				if res.code != 2 {
					t.Errorf("%s: exit = %d, want 2 (stderr: %s)", tc.name, res.code, res.stderr)
					continue
				}
				if !strings.Contains(res.stderr, tc.want) {
					t.Errorf("%s: stderr = %q, want %q", tc.name, res.stderr, tc.want)
				}
			}
		})
	}
}

func TestInprocGatedAuthzDenied(t *testing.T) {
	scanCLIHome(t)
	for _, cmd := range gatedScanners {
		cmd := cmd
		t.Run(cmd, func(t *testing.T) {
			args := []string{cmd, "--target", "http://" + inprocPrivateIP + "/"}
			if cmd == "fuzz" {
				args = append(args, "--path", "/")
			}
			res := runCLIInProcess(t, args...)
			if res.code != authzDeniedExitCode {
				t.Fatalf("exit = %d, want %d (stderr: %s)", res.code, authzDeniedExitCode, res.stderr)
			}
			joined := res.stdout + res.stderr
			if !strings.Contains(joined, "BLOCKED by authorization policy") {
				t.Errorf("output = %q, want the policy refusal", joined)
			}
			if !strings.Contains(joined, "--allow-private") {
				t.Errorf("output = %q, want the remediation hint", joined)
			}
		})
	}
}

func TestInprocGatedMetadataDenied(t *testing.T) {
	scanCLIHome(t)
	for _, cmd := range gatedScanners {
		cmd := cmd
		t.Run(cmd, func(t *testing.T) {
			// --allow-private must not open the metadata endpoint.
			args := []string{cmd, "--target", inprocMetadataURL, "--allow-private"}
			if cmd == "fuzz" {
				args = append(args, "--path", "/")
			}
			res := runCLIInProcess(t, args...)
			if res.code != authzDeniedExitCode {
				t.Fatalf("exit = %d, want %d (stderr: %s)", res.code, authzDeniedExitCode, res.stderr)
			}
		})
	}
}

func TestInprocGatedDryRun(t *testing.T) {
	scanCLIHome(t)
	cases := []struct {
		cmd    string
		args   []string
		expect []string
	}{
		{"crawl", []string{"--target", "https://" + inprocPublicIP, "--depth", "0", "--pages", "0", "--concurrency", "0", "--timeout", "0"}, []string{"crawl:", "pages:"}},
		{"dirbust", []string{"--target", "https://" + inprocPublicIP, "--path", "/admin", "--path", ".env"}, []string{"dirbust:", "found:"}},
		{"fuzz", []string{"--target", "https://" + inprocPublicIP, "--path", "search", "--path", "/item/{id}", "--mutations", "1", "--concurrency", "1", "--method", "GET", "--timeout", "1"}, []string{"fuzz:", "paths:"}},
		{"graphql", []string{"--target", "https://" + inprocPublicIP + "/graphql"}, []string{"graphql:", "reachable:"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.cmd, func(t *testing.T) {
			args := append([]string{tc.cmd}, tc.args...)
			args = append(args, "--dry-run")
			res := runCLIInProcess(t, args...)
			if res.code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, "dry-run: probe policy is evaluated, nothing is sent") {
				t.Errorf("stderr = %q, want the dry-run notice", res.stderr)
			}
			if !strings.Contains(res.stderr, "refused=") {
				t.Errorf("stderr = %q, want the gate counters", res.stderr)
			}
			for _, want := range tc.expect {
				if !strings.Contains(res.stdout, want) {
					t.Errorf("stdout = %q, want %q", res.stdout, want)
				}
			}
		})
	}
}

func TestInprocGatedDryRunJSON(t *testing.T) {
	scanCLIHome(t)
	cases := [][]string{
		{"crawl", "--target", "https://" + inprocPublicIP, "--dry-run", "--json"},
		{"dirbust", "--target", "https://" + inprocPublicIP, "--dry-run", "--json"},
		{"fuzz", "--target", "https://" + inprocPublicIP, "--path", "/", "--mutations", "1", "--dry-run", "--json"},
		{"graphql", "--target", "https://" + inprocPublicIP + "/gql", "--dry-run", "--json"},
	}
	for _, args := range cases {
		args := args
		t.Run(args[0], func(t *testing.T) {
			res := runCLIInProcess(t, args...)
			if res.code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
			}
			if !strings.Contains(res.stdout, "{") {
				t.Fatalf("stdout = %q, want a JSON document", res.stdout)
			}
			// The scan itself must not print its human summary in JSON mode.
			if strings.Contains(res.stdout, args[0]+": ") {
				t.Errorf("stdout mixes the human summary into JSON: %q", res.stdout)
			}
		})
	}
}

func TestInprocOutputJSONFile(t *testing.T) {
	home := scanCLIHome(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "result.json")

	res := runCLIInProcess(t, "graphql", "--target", "https://"+inprocPublicIP+"/gql", "--dry-run", "--output-json", out)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	// --output-json alone still prints the human summary to stdout.
	if !strings.Contains(res.stdout, "graphql:") {
		t.Errorf("stdout = %q, want the human summary", res.stdout)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(data), `"endpoint"`) {
		t.Errorf("output file = %q, want the JSON result", data)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if runtime.GOOS != "windows" {
		// POSIX permission bits do not exist on Windows: the mode is
		// reported as 0666 and only the read-only bit is meaningful.
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %o, want 600", perm)
		}
	}
	// The audit log went into the throwaway home, not the real one.
	if entries, err := os.ReadDir(home); err != nil {
		t.Fatalf("read home: %v", err)
	} else if len(entries) == 0 {
		t.Error("no audit log was written to STRESS_STRIKE_HOME")
	}
}

func TestInprocOutputJSONFileError(t *testing.T) {
	scanCLIHome(t)
	res := runCLIInProcess(t, "graphql", "--target", "https://"+inprocPublicIP+"/gql", "--dry-run", "--output-json", filepath.Join(t.TempDir(), "missing", "x.json"))
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "write ") {
		t.Errorf("stderr = %q, want a write error", res.stderr)
	}
}

func TestInprocCrawlFlagDefaults(t *testing.T) {
	scanCLIHome(t)
	res := runCLIInProcess(t, "crawl", "--target", "https://"+inprocPublicIP, "--offsite", "--dry-run")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "offsite:   true") {
		t.Errorf("stdout = %q, want offsite honoured", res.stdout)
	}
}

func TestInprocFuzzUsageErrors(t *testing.T) {
	scanCLIHome(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"missing path", []string{"fuzz", "--target", inprocPublicIP}, "--path is required"},
		{"zero mutations", []string{"fuzz", "--target", inprocPublicIP, "--path", "/", "--mutations", "0"}, "mutations"},
		{"zero concurrency", []string{"fuzz", "--target", inprocPublicIP, "--path", "/", "--concurrency", "0"}, "concurrency"},
		{"zero timeout", []string{"fuzz", "--target", inprocPublicIP, "--path", "/", "--timeout", "0"}, "timeout"},
	}
	for _, tc := range cases {
		res := runCLIInProcess(t, tc.args...)
		if res.code != 2 {
			t.Errorf("%s: exit = %d, want 2 (stderr: %s)", tc.name, res.code, res.stderr)
			continue
		}
		if !strings.Contains(res.stderr, tc.want) {
			t.Errorf("%s: stderr = %q, want %q", tc.name, res.stderr, tc.want)
		}
	}
}

func TestInprocFuzzNormalizePaths(t *testing.T) {
	home := scanCLIHome(t)
	res := runCLIInProcess(t, "fuzz", "--target", "https://"+inprocPublicIP,
		"--path", "/dup", "--path", "dup", "--path", "https://evil.test/x", "--path", " ", "--path", "a/b",
		"--mutations", "1", "--dry-run")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	_ = home
	if !strings.Contains(res.stdout, "paths:       2") {
		t.Errorf("stdout = %q, want two normalised paths (deduped, scheme dropped, blank skipped)", res.stdout)
	}
}

func TestInprocDirectDialUsageErrors(t *testing.T) {
	scanCLIHome(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"subdomain missing target", []string{"subdomain"}, "--target is required"},
		{"portscan missing target", []string{"portscan"}, "--target is required"},
		{"sslscan missing target", []string{"sslscan"}, "--target is required"},
		{"websocket missing url", []string{"websocket"}, "--url is required"},

		{"subdomain bad scheme", []string{"subdomain", "--target", "ftp://x.test"}, "http://"},
		{"portscan bad scheme", []string{"portscan", "--target", "ftp://x.test"}, "http://"},
		{"sslscan bad scheme", []string{"sslscan", "--target", "ftp://x.test"}, "http://"},

		{"portscan non-numeric port", []string{"portscan", "--target", inprocPublicIP, "--ports", "80,abc"}, "must be a number"},
		{"portscan out of range", []string{"portscan", "--target", inprocPublicIP, "--ports", "70000"}, "out of range"},

		{"websocket bad url", []string{"websocket", "--url", "://nope"}, "invalid WebSocket URL"},
		{"websocket wrong scheme", []string{"websocket", "--url", "https://example.test/ws"}, "ws:// or wss://"},
	}
	for _, tc := range cases {
		res := runCLIInProcess(t, tc.args...)
		if res.code != 2 {
			t.Errorf("%s: exit = %d, want 2 (stderr: %s)", tc.name, res.code, res.stderr)
			continue
		}
		if !strings.Contains(res.stderr, tc.want) {
			t.Errorf("%s: stderr = %q, want %q", tc.name, res.stderr, tc.want)
		}
	}
}

func TestInprocDirectDialAuthzDenied(t *testing.T) {
	scanCLIHome(t)
	cases := [][]string{
		{"subdomain", "--target", inprocPrivateIP},
		{"portscan", "--target", inprocPrivateIP},
		{"sslscan", "--target", inprocPrivateIP},
		{"websocket", "--url", "ws://" + inprocPrivateIP + "/socket"},
	}
	for _, args := range cases {
		res := runCLIInProcess(t, args...)
		if res.code != authzDeniedExitCode {
			t.Errorf("%v: exit = %d, want %d (stderr: %s)", args, res.code, authzDeniedExitCode, res.stderr)
			continue
		}
		if !strings.Contains(res.stderr, "BLOCKED by authorization policy") {
			t.Errorf("%v: stderr = %q, want the policy refusal", args, res.stderr)
		}
	}
}

func TestInprocDirectDialDryRun(t *testing.T) {
	scanCLIHome(t)
	cases := [][]string{
		{"subdomain", "--target", "https://" + inprocPublicIP},
		{"portscan", "--target", "https://" + inprocPublicIP, "--ports", "80,443,8080"},
		{"sslscan", "--target", "https://" + inprocPublicIP},
		{"sslscan", "--target", "http://" + inprocPublicIP},
		{"websocket", "--url", "wss://" + inprocPublicIP + "/socket"},
	}
	for _, args := range cases {
		args := append(append([]string{}, args...), "--dry-run")
		res := runCLIInProcess(t, args...)
		if res.code != 0 {
			t.Errorf("%v: exit = %d, want 0 (stderr: %s)", args, res.code, res.stderr)
			continue
		}
		if !strings.Contains(res.stderr, "nothing is sent") {
			t.Errorf("%v: stderr = %q, want the dry-run notice", args, res.stderr)
		}
		if !strings.Contains(res.stderr, "dials "+string(args[0])) {
			// The direct-dial note names the command that will dial.
			if !strings.Contains(res.stderr, args[0]+" dials ") {
				t.Errorf("%v: stderr = %q, want the direct-dial honesty note", args, res.stderr)
			}
		}
	}
}

func TestInprocDirectDialDryRunJSON(t *testing.T) {
	scanCLIHome(t)
	for _, name := range []string{"subdomain", "portscan", "sslscan", "websocket"} {
		name := name
		t.Run(name, func(t *testing.T) {
			args := []string{name, "--dry-run", "--json"}
			switch name {
			case "websocket":
				args = append(args, "--url", "wss://"+inprocPublicIP+"/socket")
			default:
				args = append(args, "--target", "https://"+inprocPublicIP)
			}
			res := runCLIInProcess(t, args...)
			if res.code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
			}
			for _, want := range []string{`"command": "` + name + `"`, `"skipped": true`, `"scope_enforced": false`} {
				if !strings.Contains(res.stdout, want) {
					t.Errorf("stdout = %q, want %q", res.stdout, want)
				}
			}
		})
	}
}
