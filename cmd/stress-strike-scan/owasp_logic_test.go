package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// captureStdout redirects os.Stdout for the duration of fn and returns what it
// wrote, so printer tests do not spam the test log.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()

	fn()
	w.Close()
	os.Stdout = old
	out := <-done
	r.Close()
	return out
}

// captureStderrScan is the stderr variant used by the authz warning paths.
func captureStderrScan(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()

	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()

	fn()
	w.Close()
	os.Stderr = old
	out := <-done
	r.Close()
	return out
}

func TestStringSliceFlag(t *testing.T) {
	var s stringSliceFlag
	var nilFlag *stringSliceFlag
	if got := nilFlag.String(); got != "" {
		t.Errorf("nil String() = %q, want empty", got)
	}
	if got := s.String(); got != "" {
		t.Errorf("empty String() = %q, want empty", got)
	}
	if err := s.Set("one"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Set("two"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := s.String(); got != "one,two" {
		t.Errorf("String() = %q, want one,two", got)
	}
}

func TestMapOWASPStatus(t *testing.T) {
	cases := []struct {
		computed string
		covered  int
		findings int
		want     string
	}{
		{"PASS", 3, 0, "PASS"},
		{"WARNING", 2, 0, "WARNING"},
		{"FAIL", 1, 0, "FAIL"},
		{"PASS", 0, 0, statusNotTested},
		{"PASS", 0, 2, "FAIL"},
		{"WARNING", 0, 1, "FAIL"},
	}
	for _, tc := range cases {
		if got := mapOWASPStatus(tc.computed, tc.covered, tc.findings); got != tc.want {
			t.Errorf("mapOWASPStatus(%q,%d,%d) = %q, want %q",
				tc.computed, tc.covered, tc.findings, got, tc.want)
		}
	}
}

func TestStatusRankAndWorse(t *testing.T) {
	if statusRank("FAIL") != 3 || statusRank("WARNING") != 2 || statusRank("PASS") != 1 {
		t.Error("statusRank ordering is wrong")
	}
	if statusRank("") != 0 || statusRank(statusNotTested) != 0 {
		t.Error("empty and NOT TESTED must rank 0")
	}

	if got := worseStatus("", "PASS"); got != "PASS" {
		t.Errorf("worseStatus('',PASS) = %q", got)
	}
	if got := worseStatus("FAIL", "WARNING"); got != "FAIL" {
		t.Errorf("worseStatus(FAIL,WARNING) = %q", got)
	}
	if got := worseStatus("WARNING", "FAIL"); got != "FAIL" {
		t.Errorf("worseStatus(WARNING,FAIL) = %q", got)
	}
	if got := worseStatus("PASS", ""); got != "PASS" {
		t.Errorf("worseStatus(PASS,'') = %q", got)
	}
}

func TestEscalateStatus(t *testing.T) {
	if got := escalateStatus("PASS", statusNotTested); got != "PASS" {
		t.Errorf("a no-severity target must not change PASS, got %q", got)
	}
	if got := escalateStatus(statusNotTested, "FAIL"); got != "FAIL" {
		t.Errorf("NOT TESTED must yield to conclusive evidence, got %q", got)
	}
	if got := escalateStatus("PASS", "WARNING"); got != "WARNING" {
		t.Errorf("escalate PASS→WARNING = %q", got)
	}
	if got := escalateStatus("FAIL", "WARNING"); got != "FAIL" {
		t.Errorf("escalate must never weaken FAIL, got %q", got)
	}
}

func TestFabricatesFindings(t *testing.T) {
	if fabricatesFindings("A03", 5, []string{"x"}) {
		t.Error("covered findings are evidence, not fabrication")
	}
	if fabricatesFindings("A03", 0, nil) {
		t.Error("no findings cannot be fabricated")
	}
	if fabricatesFindings("A02", 0, []string{"x"}) {
		t.Error("A02 is not in the fabricated list")
	}
	if fabricatesFindings("A05", 0, []string{"x"}) {
		t.Error("A05 must keep findings: its probes dial outside the gate")
	}
	for _, id := range []string{"A03", "A07", "A10"} {
		if !fabricatesFindings(id, 0, []string{"x"}) {
			t.Errorf("%s with zero coverage should be treated as fabricated", id)
		}
	}
}

func TestTLSSignatureBad(t *testing.T) {
	if tlsSignatureBad(nil) {
		t.Error("nil TLSInfo cannot be bad")
	}
	if tlsSignatureBad(&scanner.TLSInfo{Version: "TLS 1.3"}) {
		t.Error("TLS 1.3 is not a bad signature")
	}
	if !tlsSignatureBad(&scanner.TLSInfo{Version: "TLS 1.0"}) {
		t.Error("TLS 1.0 is a bad signature")
	}
	if !tlsSignatureBad(&scanner.TLSInfo{Version: "TLS 1.1"}) {
		t.Error("TLS 1.1 is a bad signature")
	}
	if !tlsSignatureBad(&scanner.TLSInfo{Version: "TLS 1.3", Certificate: &scanner.CertInfo{IsExpired: true}}) {
		t.Error("an expired certificate is a bad signature")
	}
}

func TestSecurityHeaderEvidence(t *testing.T) {
	sec := &scanner.SecurityInfo{MissingHeaders: []string{"X-Frame-Options"}}
	if got := securityHeaderEvidence(sec, nil); len(got) != 1 || got[0] != "X-Frame-Options" {
		t.Errorf("dedicated phase evidence = %v", got)
	}

	if got := securityHeaderEvidence(nil, nil); got != nil {
		t.Errorf("nil inputs = %v, want nil", got)
	}

	httpInfo := &scanner.HTTPInfo{Headers: map[string]string{
		"Strict-Transport-Security": "max-age=31536000",
		"content-security-policy":   "default-src 'self'", // case-insensitive match
	}}
	got := securityHeaderEvidence(nil, httpInfo)
	want := []string{"X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"}
	if len(got) != len(want) {
		t.Fatalf("fallback evidence = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("fallback evidence[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNotTestedIDs(t *testing.T) {
	if got := notTestedIDs(nil); got != nil {
		t.Errorf("nil export = %v, want nil", got)
	}
	out := &owaspExport{Categories: map[string]*owaspCategoryResult{
		"A01": {ID: "A01", Status: "PASS"},
		"A03": {ID: "A03", Status: statusNotTested},
		"A09": {ID: "A09", Status: statusNotTested},
	}}
	got := notTestedIDs(out)
	if len(got) != 2 || got[0] != "A03" || got[1] != "A09" {
		t.Errorf("notTestedIDs = %v, want [A03 A09] in order", got)
	}
}

func TestOnlyIntrusive(t *testing.T) {
	if onlyIntrusive(nil) {
		t.Error("empty list = false")
	}
	if !onlyIntrusive([]string{"A03", "A10"}) {
		t.Error("all-intrusive list should be true")
	}
	if onlyIntrusive([]string{"A03", "A02"}) {
		t.Error("a non-intrusive id must make it false")
	}
}

func TestNotTestedReason(t *testing.T) {
	base := scanner.GuardStats{}
	if got := notTestedReason([]string{"A03"}, false, false, base); !strings.Contains(got, "--intrusive") {
		t.Errorf("intrusive-off reason = %q", got)
	}
	if got := notTestedReason([]string{"A03"}, true, false, scanner.GuardStats{RefusedIntrusive: 1}); !strings.Contains(got, "--intrusive") {
		t.Errorf("refused-intrusive reason = %q", got)
	}
	if got := notTestedReason([]string{"A01"}, true, true, base); !strings.Contains(got, "dry-run") {
		t.Errorf("dry-run reason = %q", got)
	}
	if got := notTestedReason([]string{"A01"}, true, false, scanner.GuardStats{RefusedOutOfScope: 1}); !strings.Contains(got, "out of scope") {
		t.Errorf("out-of-scope reason = %q", got)
	}
	if got := notTestedReason([]string{"A01"}, true, false, scanner.GuardStats{RefusedBudget: 1}); !strings.Contains(got, "budget") {
		t.Errorf("budget reason = %q", got)
	}
	if got := notTestedReason([]string{"A01"}, true, false, scanner.GuardStats{RefusedRate: 1}); !strings.Contains(got, "rate limit") {
		t.Errorf("rate reason = %q", got)
	}
	if got := notTestedReason([]string{"A01"}, true, false, base); !strings.Contains(got, "no probe reached the server") {
		t.Errorf("fallback reason = %q", got)
	}
}

func TestPrintOWASP(t *testing.T) {
	captureStdout(t, func() { printOWASP(nil, false) })

	out := &owaspExport{Categories: map[string]*owaspCategoryResult{
		"A01": {
			ID: "A01", Name: "Broken Access Control", Status: "FAIL", Score: 40, ProbesCovered: 2,
			Findings: []string{"IDOR found", "no finding remediation"}, Remediation: []string{"add checks"},
		},
		"A02": {ID: "A02", Name: "Cryptographic Failures", Status: statusNotTested, Score: 100},
	}}
	got := captureStdout(t, func() { printOWASP(out, true) })
	for _, want := range []string{"OWASP TOP 10", "A01 Broken Access Control: FAIL", "probes answered: 2",
		"IDOR found", "fix: add checks", "no finding remediation", "A02", statusNotTested} {
		if !strings.Contains(got, want) {
			t.Errorf("printOWASP output missing %q", want)
		}
	}

	// Non-verbose must omit the per-category detail.
	got = captureStdout(t, func() { printOWASP(out, false) })
	if strings.Contains(got, "probes answered") {
		t.Error("non-verbose output should not include probe counts")
	}
}

func TestPrintGuardStats(t *testing.T) {
	got := captureStdout(t, func() {
		printGuardStats(scanner.GuardStats{RequestsSent: 5, RequestsRefused: 2, RefusedOutOfScope: 1, BytesRead: 100})
	})
	if !strings.Contains(got, "guard: sent=5") || !strings.Contains(got, "bytes-read=100") {
		t.Errorf("printGuardStats output = %q", got)
	}

	got = captureStdout(t, func() {
		printGuardStats(scanner.GuardStats{DryRunChecked: 7})
	})
	if !strings.Contains(got, "dry-run-checked=7") {
		t.Errorf("dry-run counter missing: %q", got)
	}
}

func TestPrintProbeFindings(t *testing.T) {
	got := captureStdout(t, func() { printProbeFindings(nil, false) })
	if !strings.Contains(got, "no findings") {
		t.Errorf("empty output = %q", got)
	}

	vulns := []scanner.Vulnerability{
		{ID: "V1", Title: "SQLi", Severity: "critical", Category: "injection", URL: "https://x/y", Parameter: "id", Evidence: "err", Remediation: "parameterize"},
		{ID: "V2", Title: "XSS", Severity: "high", Category: "injection"},
		{ID: "V3", Title: "Leak", Severity: "medium", Category: "disclosure"},
		{ID: "V4", Title: "Banner", Severity: "low", Category: "info"},
		{ID: "V5", Title: "Note", Severity: "info", Category: "info"},
		{ID: "V6", Title: "Weird", Severity: "unknown", Category: "other"},
	}
	got = captureStdout(t, func() { printProbeFindings(vulns, true) })
	for _, want := range []string{"[CRITICAL] SQLi", "url: https://x/y", "parameter: id", "evidence: err",
		"fix: parameterize", "[HIGH] XSS", "[MEDIUM] Leak", "[LOW] Banner", "[INFO] Note", "[UNKNOWN] Weird"} {
		if !strings.Contains(got, want) {
			t.Errorf("printProbeFindings output missing %q", want)
		}
	}
}

func TestIntrusiveFamilyNames(t *testing.T) {
	names := intrusiveFamilyNames()
	if len(names) != len(intrusiveFamilyList) {
		t.Fatalf("len(names) = %d, want %d", len(names), len(intrusiveFamilyList))
	}
	if names[0] != "crlf" || names[len(names)-1] != "write-methods" {
		t.Errorf("unexpected order: %v", names)
	}
}

func TestParseEnable(t *testing.T) {
	opts, enabled, err := parseEnable([]string{" CRLF ", "", "boolean-sqli", "time-sqli", "path-traversal", "ssrf", "write-methods"})
	if err != nil {
		t.Fatalf("parseEnable: %v", err)
	}
	if len(enabled) != 6 {
		t.Errorf("enabled = %v, want 6 families", enabled)
	}
	if !opts.CRLFInjection || !opts.BooleanSQLi || !opts.TimeBasedSQLi || !opts.PathTraversal || !opts.SSRFIndicators || !opts.WriteMethodProbes {
		t.Errorf("not all options set: %+v", opts)
	}
	if enabled[0] != "crlf" {
		t.Errorf("names should be normalized, got %v", enabled)
	}

	if _, _, err := parseEnable([]string{"nope"}); err == nil {
		t.Error("unknown family should be a usage error")
	} else if !strings.Contains(err.Error(), "valid names are") {
		t.Errorf("error should list valid names: %v", err)
	}

	opts, enabled, err = parseEnable(nil)
	if err != nil || len(enabled) != 0 {
		t.Errorf("nil input = (%+v, %v, %v)", opts, enabled, err)
	}
}

func TestTargetBaseURL(t *testing.T) {
	cases := []struct {
		target  string
		port    int
		want    string
		wantErr bool
	}{
		{"", 443, "", true},
		{"   ", 443, "", true},
		{"example.com", 443, "https://example.com", false},
		{"example.com", 8443, "https://example.com:8443", false},
		{"example.com", 0, "", true},
		{"example.com", 70000, "", true},
		{"example.com:8080", 443, "https://example.com:8080", false},
		{"example.com:notaport", 443, "", true},
		{"example.com:0", 443, "", true},
		{"https://example.com/path", 443, "https://example.com/path", false},
		{"http://example.com", 443, "http://example.com", false},
		{"ftp://example.com", 443, "", true},
		{"https://", 443, "", true},
		{"https://user:pass@example.com", 443, "", true},
		{"2001:db8::1", 443, "https://[2001:db8::1]", false},
		{"[2001:db8::1]", 443, "https://[2001:db8::1]", false},
		{"[2001:db8::1]:8443", 443, "https://[2001:db8::1]:8443", false},
	}
	for _, tc := range cases {
		got, err := targetBaseURL(tc.target, tc.port)
		if tc.wantErr {
			if err == nil {
				t.Errorf("targetBaseURL(%q,%d) = %q, want error", tc.target, tc.port, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("targetBaseURL(%q,%d) error: %v", tc.target, tc.port, err)
			continue
		}
		if got != tc.want {
			t.Errorf("targetBaseURL(%q,%d) = %q, want %q", tc.target, tc.port, got, tc.want)
		}
	}
}

func TestDerivedScopePattern(t *testing.T) {
	if got, err := derivedScopePattern("https://example.com:8443/x"); err != nil || got != "example.com" {
		t.Errorf("derivedScopePattern = (%q,%v)", got, err)
	}
	if got, err := derivedScopePattern("https://[2001:db8::1]:443"); err != nil || got != "[2001:db8::1]" {
		t.Errorf("IPv6 derivedScopePattern = (%q,%v)", got, err)
	}
	if _, err := derivedScopePattern("https:///nohost"); err == nil {
		t.Error("expected error when the URL has no host")
	}
}

func TestParsePathList(t *testing.T) {
	got := parsePathList(" /one , two,,/three ")
	want := []string{"/one", "/two", "/three"}
	if len(got) != len(want) {
		t.Fatalf("parsePathList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parsePathList[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if got := parsePathList(""); len(got) != 0 {
		t.Errorf("empty input = %v", got)
	}
}

func TestOWASPBaseURLs(t *testing.T) {
	got := owaspBaseURLs("https://example.com", nil)
	if len(got) != 1 || got[0] != "https://example.com" {
		t.Errorf("no paths = %v", got)
	}

	got = owaspBaseURLs("https://example.com/root?x=1", []string{"/a", "/b?q=2"})
	if len(got) != 2 || got[0] != "https://example.com/a" || got[1] != "https://example.com/b?q=2" {
		t.Errorf("expanded = %v", got)
	}

	if got := owaspBaseURLs("://bad", []string{"/a"}); len(got) != 1 || got[0] != "://bad" {
		t.Errorf("unparsable origin = %v", got)
	}

	if got := owaspBaseURLs("https://example.com", []string{"%zz"}); len(got) != 1 || got[0] != "https://example.com" {
		t.Errorf("all-invalid paths should fall back to the origin, got %v", got)
	}
}

func TestGatedPhaseSkipReason(t *testing.T) {
	if got := gatedPhaseSkipReason(false); got != "" {
		t.Errorf("non-dry-run reason = %q, want empty", got)
	}
	if got := gatedPhaseSkipReason(true); !strings.Contains(got, "OWASP") {
		t.Errorf("dry-run reason = %q", got)
	}
}

func TestApplyOWASPEvidenceDowngrades(t *testing.T) {
	applyOWASPEvidenceDowngrades(nil, nil, nil, nil) // must not panic

	out := &owaspExport{Categories: map[string]*owaspCategoryResult{
		"A02": {ID: "A02", Status: statusNotTested},
		"A05": {ID: "A05", Status: "PASS"},
	}}
	applyOWASPEvidenceDowngrades(out, &scanner.TLSInfo{Version: "TLS 1.0"}, nil, nil)
	if out.Categories["A02"].Status != "FAIL" {
		t.Errorf("A02 = %q, want FAIL from the deprecated TLS version", out.Categories["A02"].Status)
	}

	// Fewer than three missing headers is a warning, three or more a fail.
	applyOWASPEvidenceDowngrades(out, nil, &scanner.SecurityInfo{MissingHeaders: []string{"a"}}, nil)
	if out.Categories["A05"].Status != "WARNING" {
		t.Errorf("A05 with one missing header = %q, want WARNING", out.Categories["A05"].Status)
	}
	out.Categories["A05"].Status = "PASS"
	applyOWASPEvidenceDowngrades(out, nil, &scanner.SecurityInfo{MissingHeaders: []string{"a", "b", "c"}}, nil)
	if out.Categories["A05"].Status != "FAIL" {
		t.Errorf("A05 with three missing headers = %q, want FAIL", out.Categories["A05"].Status)
	}

	// An already-worse status is never weakened.
	out.Categories["A02"].Status = "FAIL"
	applyOWASPEvidenceDowngrades(out, &scanner.TLSInfo{Version: "TLS 1.3"}, nil, nil)
	if out.Categories["A02"].Status != "FAIL" {
		t.Errorf("A02 weakened to %q", out.Categories["A02"].Status)
	}

	// Header evidence via the raw HTTP map when the security phase did not run.
	out2 := &owaspExport{Categories: map[string]*owaspCategoryResult{"A05": {ID: "A05", Status: statusNotTested}}}
	applyOWASPEvidenceDowngrades(out2, nil, nil, &scanner.HTTPInfo{Headers: map[string]string{}})
	if out2.Categories["A05"].Status != "FAIL" {
		t.Errorf("A05 from raw headers = %q, want FAIL (five missing)", out2.Categories["A05"].Status)
	}
}

func TestRecordScanAuthz(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/audit.log"
	recordScanAuthz(authz.Entry{
		Action:  authz.OpScan.String(),
		Targets: []string{"https://example.com"},
		Class:   "public",
		Allowed: true,
		Rule:    "example.com",
		Reason:  "covered by authorization",
		Version: version,
	}, path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("audit log not written: %v", err)
	}
	if !strings.Contains(string(data), `"action":"scan"`) {
		t.Errorf("audit log = %q", data)
	}

	// An unwritable path warns instead of failing. A regular file standing in
	// for a directory is unwritable on every platform; "/dev/null/..." only
	// fails on Unix, and Windows silently creates it under the drive root.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	out := captureStderrScan(t, func() {
		recordScanAuthz(authz.Entry{Action: "scan"}, filepath.Join(blocker, "audit.log"))
	})
	if !strings.Contains(out, "warning: cannot write audit log") {
		t.Errorf("expected a warning, got %q", out)
	}
}
