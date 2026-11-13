package main

// cmd_scan_shared_test.go — unit tests for the plumbing every standalone
// scanner command shares (fuzz, dirbust, jwt, graphql, websocket, crawl,
// subdomain, portscan, sslscan).
//
// The command entry points call os.Exit, so they cannot be driven in-process.
// These tests therefore target the pure helpers in cmd_scan_shared.go and the
// per-command helpers, and the black-box end-to-end coverage lives in
// cmd_scan_cli_test.go. The one safety invariant worth pinning at this level —
// that the CLI's JWT view can never carry the raw token — is checked here.

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
)

// captureStream swaps a package-global *os.File (os.Stdout / os.Stderr) for a
// pipe while fn runs and returns everything written to it. fmt reads the
// variable at call time, so reassigning the variable redirects the output.
func captureStream(t *testing.T, target **os.File, fn func()) string {
	t.Helper()
	old := *target
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	*target = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	*target = old
	out := <-done
	_ = r.Close()
	return out
}

func TestValidateScanTarget(t *testing.T) {
	ok := []struct {
		in         string
		wantHost   string
		wantScheme string
	}{
		{"example.com", "example.com", "https"}, // bare host gets https
		{"https://example.com/x", "example.com", "https"},
		{"http://example.com:8080", "example.com", "http"},
		{"  example.com  ", "example.com", "https"}, // whitespace trimmed
	}
	for _, c := range ok {
		u, err := validateScanTarget(c.in)
		if err != nil {
			t.Errorf("validateScanTarget(%q) error: %v", c.in, err)
			continue
		}
		if u.Hostname() != c.wantHost || u.Scheme != c.wantScheme {
			t.Errorf("validateScanTarget(%q) = %s://%s, want %s://%s",
				c.in, u.Scheme, u.Hostname(), c.wantScheme, c.wantHost)
		}
	}

	bad := []string{
		"",                            // empty
		"ftp://example.com",           // non-http scheme
		"https://user:pw@example.com", // embedded credentials
		"https://",                    // no host
		"://example.com",              // unparseable
	}
	for _, in := range bad {
		if _, err := validateScanTarget(in); err == nil {
			t.Errorf("validateScanTarget(%q) = nil error, want an error", in)
		}
	}

	// The fragment is dropped so it never reaches a probe.
	u, err := validateScanTarget("https://example.com/a#frag")
	if err != nil {
		t.Fatal(err)
	}
	if u.Fragment != "" {
		t.Errorf("fragment = %q, want it dropped", u.Fragment)
	}
}

func TestScanScopeHostBracketsIPv6(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com", "example.com"},
		{"https://example.com:8443", "example.com"}, // port dropped, host kept
		{"https://[::1]:8080", "[::1]"},             // IPv6 bracketed
		{"http://10.0.0.1", "10.0.0.1"},
	}
	for _, c := range cases {
		u, err := validateScanTarget(c.in)
		if err != nil {
			t.Fatalf("validateScanTarget(%q): %v", c.in, err)
		}
		if got := scanScopeHost(u); got != c.want {
			t.Errorf("scanScopeHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestScanScopeResolution(t *testing.T) {
	u, err := validateScanTarget("https://example.com/x")
	if err != nil {
		t.Fatal(err)
	}

	// Default: the operator's own host, any port.
	sf := &scanFlags{}
	if got := scanScope(u, sf); !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Errorf("default scanScope = %v, want [example.com]", got)
	}
	if got := scanScopeLabel(u, sf); got != "example.com" {
		t.Errorf("default label = %q, want example.com", got)
	}

	// Explicit --allow entries win over the host default.
	sf = &scanFlags{allow: stringListFlags{"a.com", "b.com"}}
	if got := scanScope(u, sf); !reflect.DeepEqual(got, []string{"a.com", "b.com"}) {
		t.Errorf("scanScope = %v, want [a.com b.com]", got)
	}
	if got := scanScopeLabel(u, sf); got != "a.com, b.com" {
		t.Errorf("label = %q, want \"a.com, b.com\"", got)
	}

	// --allow-all: an empty allowlist and a single "*" marker in the result.
	sf = &scanFlags{allowAll: true}
	if got := scanScope(u, sf); got != nil {
		t.Errorf("allow-all scanScope = %v, want nil", got)
	}
	if got := scanScopeOut(u, sf); !reflect.DeepEqual(got, []string{"* (allow-all)"}) {
		t.Errorf("allow-all scanScopeOut = %v, want [* (allow-all)]", got)
	}
	if got := scanScopeLabel(u, sf); got != "* (allow-all)" {
		t.Errorf("allow-all label = %q, want \"* (allow-all)\"", got)
	}
}

func TestBuildScanGuard(t *testing.T) {
	u, err := validateScanTarget("https://example.com")
	if err != nil {
		t.Fatal(err)
	}

	g, err := buildScanGuard(u, &scanFlags{}, false, scanner.DefaultTimeout)
	if err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	cfg := g.Config()
	if !reflect.DeepEqual(cfg.Allow, []string{"example.com"}) {
		t.Errorf("guard allow = %v, want [example.com]", cfg.Allow)
	}
	if cfg.Intrusive {
		t.Error("intrusive must default to off")
	}
	if cfg.DryRun {
		t.Error("dry-run must default to off")
	}

	// The intrusive opt-in and allow-all are propagated to the Guard.
	if g, err := buildScanGuard(u, &scanFlags{}, true, scanner.DefaultTimeout); err != nil {
		t.Fatalf("intrusive guard: %v", err)
	} else if !g.Config().Intrusive {
		t.Error("intrusive flag was not propagated")
	}
	if g, err := buildScanGuard(u, &scanFlags{allowAll: true}, false, scanner.DefaultTimeout); err != nil {
		t.Fatalf("allow-all guard: %v", err)
	} else if !g.Config().AllowAll {
		t.Error("allow-all flag was not propagated")
	}

	// A bad policy is a configuration error caught before any probe.
	bad := []struct {
		name string
		sf   *scanFlags
	}{
		{"too many pattern fields", &scanFlags{allow: stringListFlags{"a b c"}}},
		{"malformed wildcard", &scanFlags{allow: stringListFlags{"*."}}},
		{"negative rate", &scanFlags{rate: -1}},
		{"negative budget", &scanFlags{budget: -1}},
	}
	for _, c := range bad {
		if _, err := buildScanGuard(u, c.sf, false, scanner.DefaultTimeout); err == nil {
			t.Errorf("buildScanGuard(%s) = nil error, want an error", c.name)
		}
	}
}

func TestScanGateNote(t *testing.T) {
	if got := scanGateNote(scanner.GuardStats{}); got != "" {
		t.Errorf("clean stats note = %q, want \"\"", got)
	}
	got := scanGateNote(scanner.GuardStats{RequestsRefused: 3, RefusedOutOfScope: 1, RefusedDryRun: 2})
	if !strings.Contains(got, "refused 3") || !strings.Contains(got, "dry-run=2") {
		t.Errorf("note = %q, want it to mention 3 refusals and dry-run=2", got)
	}
}

func TestPrintScanGateStats(t *testing.T) {
	out := captureStream(t, &os.Stderr, func() {
		printScanGateStats(scanner.GuardStats{RequestsSent: 5, RequestsRefused: 2, BytesRead: 42})
	})
	if !strings.Contains(out, "sent=5") || !strings.Contains(out, "refused=2") || !strings.Contains(out, "read=42B") {
		t.Errorf("gate stats line = %q, want sent/refused/read counters", out)
	}
}

func TestEmitScanJSONNoFlagsIsNoop(t *testing.T) {
	out := captureStream(t, &os.Stdout, func() {
		if err := emitScanJSON(map[string]any{"a": 1}, &scanFlags{}); err != nil {
			t.Fatalf("emitScanJSON: %v", err)
		}
	})
	if out != "" {
		t.Errorf("no output flags must print nothing, got %q", out)
	}
}

func TestEmitScanJSONToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	out := captureStream(t, &os.Stdout, func() {
		if err := emitScanJSON(map[string]any{"a": float64(1)}, &scanFlags{outputJSON: path}); err != nil {
			t.Fatalf("emitScanJSON: %v", err)
		}
	})
	if out != "" {
		t.Errorf("--output-json alone must not touch stdout, got %q", out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(data), `"a": 1`) {
		t.Errorf("file content = %q, want the JSON result", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		// POSIX permission bits do not exist on Windows: the mode is
		// reported as 0666 and only the read-only bit is meaningful.
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("output file mode = %o, want 600 (never world-readable)", perm)
		}
	}
}

func TestEmitScanJSONToStdout(t *testing.T) {
	out := captureStream(t, &os.Stdout, func() {
		if err := emitScanJSON(map[string]any{"a": float64(1)}, &scanFlags{jsonOut: true}); err != nil {
			t.Fatalf("emitScanJSON: %v", err)
		}
	})
	if !strings.Contains(out, `"a": 1`) {
		t.Errorf("--json stdout = %q, want the JSON result", out)
	}
}

func TestEmitScanJSONBothTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	out := captureStream(t, &os.Stdout, func() {
		if err := emitScanJSON(map[string]any{"a": float64(1)}, &scanFlags{jsonOut: true, outputJSON: path}); err != nil {
			t.Fatalf("emitScanJSON: %v", err)
		}
	})
	if !strings.Contains(out, `"a": 1`) {
		t.Errorf("stdout = %q, want the JSON result", out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file was not written: %v", err)
	}
}

func TestScanDryRunSkip(t *testing.T) {
	// Not a dry run: no skip, nothing printed.
	out := captureStream(t, &os.Stderr, func() {
		skip, err := scanDryRunSkip("fuzz", "host", &scanFlags{})
		if err != nil {
			t.Errorf("scanDryRunSkip unexpected error: %v", err)
		}
		if skip {
			t.Error("scanDryRunSkip must be false without --dry-run")
		}
	})
	if out != "" {
		t.Errorf("non-dry-run must print nothing, got %q", out)
	}

	// Dry run: skip is requested and the intent is announced.
	out = captureStream(t, &os.Stderr, func() {
		skip, err := scanDryRunSkip("subdomain", "example.com", &scanFlags{dryRun: true})
		if err != nil {
			t.Errorf("scanDryRunSkip unexpected error: %v", err)
		}
		if !skip {
			t.Error("scanDryRunSkip must be true with --dry-run")
		}
	})
	if !strings.Contains(out, "dry-run: subdomain would run") {
		t.Errorf("dry-run disclosure = %q, want it to name the scanner and target", out)
	}
}

func TestCompactJSON(t *testing.T) {
	if got := compactJSON(nil); got != "null" {
		t.Errorf("compactJSON(nil) = %q, want null", got)
	}
	// json.Marshal sorts object keys, so the output is deterministic.
	if got := compactJSON(map[string]any{"b": float64(2), "a": "x"}); got != `{"a":"x","b":2}` {
		t.Errorf("compactJSON = %q, want {\"a\":\"x\",\"b\":2}", got)
	}
}

func TestFuzzNormalizePaths(t *testing.T) {
	got := fuzzNormalizePaths([]string{"item", "/x", "http://evil/x", "", "/x", "  /y  ", "/"})
	want := []string{"/item", "/x", "/y", "/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fuzzNormalizePaths = %v, want %v", got, want)
	}
	if got := fuzzNormalizePaths(nil); len(got) != 0 {
		t.Errorf("fuzzNormalizePaths(nil) = %v, want empty", got)
	}
}

func TestParsePortList(t *testing.T) {
	if got, err := parsePortList(""); got != nil || err != nil {
		t.Errorf("parsePortList(\"\") = %v, %v; want nil, nil (built-in list)", got, err)
	}
	good := []struct {
		in   string
		want []int
	}{
		{"80,443", []int{80, 443}},
		{"80,80,443", []int{80, 443}},  // duplicates dropped, order kept
		{" 80 , 443 ", []int{80, 443}}, // whitespace tolerated
		{"80,,443", []int{80, 443}},    // empty segment skipped
	}
	for _, c := range good {
		got, err := parsePortList(c.in)
		if err != nil {
			t.Errorf("parsePortList(%q) error: %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parsePortList(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, in := range []string{"80,abc", "0", "-1", "65536", "70000"} {
		if _, err := parsePortList(in); err == nil {
			t.Errorf("parsePortList(%q) = nil error, want an error", in)
		}
	}
}

func TestOneLine(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"hello\r\nworld", 0, "hello"}, // first line only
		{"  spaced  \n", 0, "spaced"},  // trimmed
		{"abcdef", 3, "abc…"},          // truncated with an ellipsis
		{"short", 80, "short"},         // short lines pass through
	}
	for _, c := range cases {
		if got := oneLine(c.in, c.max); got != c.want {
			t.Errorf("oneLine(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}

func TestResolveJWTInput(t *testing.T) {
	// --token wins over everything and is trimmed.
	if tok, err := resolveJWTInput("  a.b.c  ", ""); err != nil || tok != "a.b.c" {
		t.Errorf("token flag = %q, %v; want a.b.c", tok, err)
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "tok.txt")
	if err := os.WriteFile(file, []byte("  x.y.z \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// --file is read and trimmed.
	if tok, err := resolveJWTInput("", file); err != nil || tok != "x.y.z" {
		t.Errorf("file input = %q, %v; want x.y.z", tok, err)
	}
	// --token still wins when a file is also given.
	if tok, err := resolveJWTInput("t.k.1", file); err != nil || tok != "t.k.1" {
		t.Errorf("token precedence = %q, %v; want t.k.1", tok, err)
	}

	// An empty file and a missing file are both errors.
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveJWTInput("", empty); err == nil {
		t.Error("empty file must be an error")
	}
	if _, err := resolveJWTInput("", filepath.Join(dir, "nope.txt")); err == nil {
		t.Error("missing file must be an error")
	}
}

// TestJWTReportNeverCarriesToken pins the safety invariant behind the CLI's
// jwtReport view: a JWT is a bearer credential, so the CLI report must never
// regain a token field. The underlying scanner.JWTResult echoes the token, and
// that is exactly why the CLI replaces it with this redacted view.
func TestJWTReportNeverCarriesToken(t *testing.T) {
	rt := reflect.TypeOf(jwtReport{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if strings.EqualFold(f.Name, "Token") || tag == "token" {
			t.Fatalf("jwtReport field %q would leak the token into logs and JSON", f.Name)
		}
	}

	const token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.UNIQUESIGMARKER"
	res := scanner.AnalyzeJWT(token)
	report := jwtReport{
		Valid:         res.Valid,
		AlgoConfusion: res.AlgoConfusion,
		Header:        res.Header,
		Payload:       res.Payload,
		Issues:        res.Issues,
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), token) || strings.Contains(string(data), "UNIQUESIGMARKER") {
		t.Fatalf("report leaked the token: %s", data)
	}

	// Document why the view exists: the raw result does echo it.
	if raw, err := json.Marshal(res); err != nil {
		t.Fatal(err)
	} else if !strings.Contains(string(raw), token) {
		t.Log("note: scanner.JWTResult no longer echoes the token; the view may be re-examined")
	}
}
