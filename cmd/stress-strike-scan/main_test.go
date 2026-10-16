package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

func TestCalculateVulnsNone(t *testing.T) {
	r := &scanner.ScanResult{
		TLS: &scanner.TLSInfo{Version: "TLS 1.3", IsSecure: true, Certificate: &scanner.CertInfo{IsExpired: false, IsSelfSigned: false}},
		Security: &scanner.SecurityInfo{
			Score: 90,
			Details: []scanner.SecurityDetail{
				{Header: "strict-transport-security", Status: "present"},
			},
		},
		HTTP: &scanner.HTTPInfo{CORS: &scanner.CORSInfo{AllowOrigin: "https://app.example.com", IsPermissive: false}},
	}
	vulns := calculateVulns(r)
	if len(vulns) != 0 {
		t.Fatalf("expected no vulns, got %+v", vulns)
	}
}

func TestCalculateVulnsTLS(t *testing.T) {
	r := &scanner.ScanResult{
		TLS: &scanner.TLSInfo{
			Version:     "TLS 1.0",
			IsSecure:    false,
			Certificate: &scanner.CertInfo{IsExpired: true, IsSelfSigned: true, NotAfter: time.Now().Add(-24 * time.Hour)},
		},
	}
	vulns := calculateVulns(r)
	ids := make(map[string]bool)
	for _, v := range vulns {
		ids[v.ID] = true
	}
	for _, want := range []string{"TLS-001", "TLS-002", "TLS-003"} {
		if !ids[want] {
			t.Errorf("missing vuln %s in %v", want, ids)
		}
	}
	// TLS-001 must be critical severity.
	for _, v := range vulns {
		if v.ID == "TLS-001" && v.Severity != "critical" {
			t.Errorf("TLS-001 severity = %q, want critical", v.Severity)
		}
	}
}

func TestCalculateVulnsSecurityHeaders(t *testing.T) {
	r := &scanner.ScanResult{
		Security: &scanner.SecurityInfo{
			Score:          40,
			MissingHeaders: []string{"x-frame-options", "content-security-policy"},
		},
	}
	vulns := calculateVulns(r)
	if len(vulns) != 2 {
		t.Fatalf("expected 2 header vulns, got %d: %+v", len(vulns), vulns)
	}
	ids := map[string]bool{vulns[0].ID: true, vulns[1].ID: true}
	if !ids["SEC-XFRAMEOPTIONS"] || !ids["SEC-CONTENTSECURITYPOLICY"] {
		t.Errorf("unexpected header vuln IDs: %v", ids)
	}
	for _, v := range vulns {
		if v.Severity != "medium" {
			t.Errorf("header vuln severity = %q, want medium", v.Severity)
		}
	}
}

func TestCalculateVulnsPermissiveCORS(t *testing.T) {
	r := &scanner.ScanResult{
		HTTP: &scanner.HTTPInfo{CORS: &scanner.CORSInfo{AllowOrigin: "*", IsPermissive: true}},
	}
	vulns := calculateVulns(r)
	if len(vulns) != 1 || vulns[0].ID != "CORS-001" {
		t.Fatalf("expected CORS-001 vuln, got %+v", vulns)
	}
}

func TestCalculateRiskScoreClean(t *testing.T) {
	r := &scanner.ScanResult{
		TLS: &scanner.TLSInfo{Version: "TLS 1.3", IsSecure: true},
	}
	if got := calculateRiskScore(r); got != 100 {
		t.Errorf("clean scan risk score = %d, want 100", got)
	}
}

func TestCalculateRiskScoreNilEverything(t *testing.T) {
	if got := calculateRiskScore(&scanner.ScanResult{}); got != 100 {
		t.Errorf("nil-sections risk score = %d, want 100", got)
	}
}

func TestCalculateRiskScoreTLSFlags(t *testing.T) {
	cases := []struct {
		name string
		r    *scanner.ScanResult
		want int
	}{
		{
			name: "insecure only",
			r:    &scanner.ScanResult{TLS: &scanner.TLSInfo{Version: "TLS 1.2", IsSecure: false}},
			want: 80,
		},
		{
			name: "insecure + expired",
			r: &scanner.ScanResult{TLS: &scanner.TLSInfo{
				Version:     "TLS 1.2",
				IsSecure:    false,
				Certificate: &scanner.CertInfo{IsExpired: true},
			}},
			want: 50,
		},
		{
			name: "insecure + expired + self-signed + TLS 1.0",
			r: &scanner.ScanResult{TLS: &scanner.TLSInfo{
				Version:     "TLS 1.0",
				IsSecure:    false,
				Certificate: &scanner.CertInfo{IsExpired: true, IsSelfSigned: true},
			}},
			want: 20, // 100 - 20 - 30 - 15 - 15
		},
	}
	for _, c := range cases {
		if got := calculateRiskScore(c.r); got != c.want {
			t.Errorf("%s: risk score = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestCalculateRiskScoreSecurityDeduction(t *testing.T) {
	r := &scanner.ScanResult{Security: &scanner.SecurityInfo{Score: 0}}
	if got := calculateRiskScore(r); got != 80 { // 100 - (100-0)/5
		t.Errorf("security score 0 -> risk = %d, want 80", got)
	}
	r = &scanner.ScanResult{Security: &scanner.SecurityInfo{Score: 75}}
	if got := calculateRiskScore(r); got != 95 { // 100 - (100-75)/5 = 95
		t.Errorf("security score 75 -> risk = %d, want 95", got)
	}
}

func TestCalculateRiskScoreClampsToZero(t *testing.T) {
	r := &scanner.ScanResult{
		TLS: &scanner.TLSInfo{Version: "TLS 1.0", IsSecure: false, Certificate: &scanner.CertInfo{IsExpired: true, IsSelfSigned: true}}, // -80
		Vulns: []scanner.Vuln{
			{ID: "X1", Severity: "critical"}, // -25
			{ID: "X2", Severity: "critical"}, // -25
			{ID: "X3", Severity: "high"},     // -15
		},
	}
	if got := calculateRiskScore(r); got != 0 {
		t.Errorf("risk score = %d, want clamped 0", got)
	}
}

func TestMin(t *testing.T) {
	if got := min(3, 5); got != 3 {
		t.Errorf("min(3,5) = %d", got)
	}
	if got := min(5, 3); got != 3 {
		t.Errorf("min(5,3) = %d", got)
	}
	if got := min(4, 4); got != 4 {
		t.Errorf("min(4,4) = %d", got)
	}
}

// ── status mapping (coverage honesty) ───────────────────────────────────────

func TestMapOWASPStatus(t *testing.T) {
	cases := []struct {
		name     string
		computed string
		covered  int
		findings int
		want     string
	}{
		{"covered and clean is PASS", "PASS", 3, 0, "PASS"},
		{"covered warning stands", "WARNING", 2, 0, "WARNING"},
		{"covered failure stands", "FAIL", 1, 0, "FAIL"},
		{"uncovered clean is NOT TESTED", "PASS", 0, 0, statusNotTested},
		{"uncovered empty is NOT TESTED", "", 0, 0, statusNotTested},
		{"uncovered with findings is FAIL", "FAIL", 0, 2, "FAIL"},
		{"uncovered WARNING with findings is escalated to FAIL", "WARNING", 0, 1, "FAIL"},
		{"uncovered PASS with findings is FAIL, never PASS", "PASS", 0, 1, "FAIL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mapOWASPStatus(c.computed, c.covered, c.findings); got != c.want {
				t.Errorf("mapOWASPStatus(%q, %d, %d) = %q, want %q",
					c.computed, c.covered, c.findings, got, c.want)
			}
		})
	}
}

func TestMapOWASPStatusNeverUpgradesToPass(t *testing.T) {
	// Exhaustive over the small input space: a zero-coverage category must
	// never come back as PASS, whatever the checker computed.
	for _, computed := range []string{"", "PASS", "WARNING", "FAIL", statusNotTested} {
		for _, findings := range []int{0, 1, 5} {
			if got := mapOWASPStatus(computed, 0, findings); got == "PASS" {
				t.Errorf("zero coverage (computed=%q, findings=%d) returned PASS", computed, findings)
			}
		}
	}
}

func TestFabricatesFindings(t *testing.T) {
	cases := []struct {
		name     string
		id       string
		covered  int
		findings []string
		want     bool
	}{
		{"gated-clean intrusive category with a finding is fabricated", "A07", 0, []string{"f"}, true},
		{"injection category with a finding is fabricated", "A03", 0, []string{"f"}, true},
		{"ssrf category with a finding is fabricated", "A10", 0, []string{"f"}, true},
		{"A05 is not treated as fabricated (it dials outside the gate)", "A05", 0, []string{"f"}, false},
		{"a non-intrusive category is never fabricated", "A01", 0, []string{"f"}, false},
		{"real coverage makes a finding trustworthy", "A07", 4, []string{"f"}, false},
		{"no findings means nothing to drop", "A07", 0, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := fabricatesFindings(c.id, c.covered, c.findings); got != c.want {
				t.Errorf("fabricatesFindings(%q, %d, %v) = %v, want %v",
					c.id, c.covered, c.findings, got, c.want)
			}
		})
	}
}

func TestGatedPhaseSkipReason(t *testing.T) {
	if got := gatedPhaseSkipReason(false); got != "" {
		t.Errorf("gatedPhaseSkipReason(false) = %q, want empty", got)
	}
	if got := gatedPhaseSkipReason(true); got == "" {
		t.Error("gatedPhaseSkipReason(true) = \"\", want a non-empty reason")
	}
}

// ── target / scope helpers ──────────────────────────────────────────────────

func TestTargetBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		port    int
		want    string
		wantErr bool
	}{
		{"bare host defaults to https", "example.com", 443, "https://example.com", false},
		{"non-default port is appended", "example.com", 8443, "https://example.com:8443", false},
		{"explicit scheme is preserved", "http://example.com", 443, "http://example.com", false},
		{"scheme and path are preserved", "https://example.com/app", 443, "https://example.com/app", false},
		{"host with explicit port wins over --port", "example.com:8080", 443, "https://example.com:8080", false},
		{"bracketed IPv6 keeps brackets", "[::1]", 443, "https://[::1]", false},
		{"bare IPv6 gets bracketed", "::1", 443, "https://[::1]", false},
		{"empty target is rejected", "", 443, "", true},
		{"non-http scheme is rejected", "ftp://example.com", 443, "", true},
		{"userinfo is rejected", "http://user:pass@example.com", 443, "", true},
		{"port zero is rejected", "example.com", 0, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := targetBaseURL(c.target, c.port)
			if c.wantErr {
				if err == nil {
					t.Fatalf("targetBaseURL(%q, %d) = %q, want error", c.target, c.port, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("targetBaseURL(%q, %d) unexpected error: %v", c.target, c.port, err)
			}
			if got != c.want {
				t.Errorf("targetBaseURL(%q, %d) = %q, want %q", c.target, c.port, got, c.want)
			}
		})
	}
}

func TestDerivedScopePattern(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		want    string
		wantErr bool
	}{
		{"host only, no port", "https://example.com", "example.com", false},
		{"port is dropped", "https://example.com:8443", "example.com", false},
		{"subdomain is kept whole", "http://sub.example.com/path", "sub.example.com", false},
		{"IPv6 is bracketed", "https://[::1]:8443", "[::1]", false},
		{"expanded IPv6 is bracketed", "https://[2001:db8::1]", "[2001:db8::1]", false},
		{"hostless URL is rejected", "https://", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := derivedScopePattern(c.baseURL)
			if c.wantErr {
				if err == nil {
					t.Fatalf("derivedScopePattern(%q) = %q, want error", c.baseURL, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("derivedScopePattern(%q) unexpected error: %v", c.baseURL, err)
			}
			if got != c.want {
				t.Errorf("derivedScopePattern(%q) = %q, want %q", c.baseURL, got, c.want)
			}
		})
	}
}

// ── --enable parsing ────────────────────────────────────────────────────────

func TestParseEnableValidNames(t *testing.T) {
	opts, enabled, err := parseEnable([]string{
		"crlf", "boolean-sqli", "time-sqli", "path-traversal", "ssrf", "write-methods",
	})
	if err != nil {
		t.Fatalf("parseEnable unexpected error: %v", err)
	}
	if !opts.CRLFInjection || !opts.BooleanSQLi || !opts.TimeBasedSQLi ||
		!opts.PathTraversal || !opts.SSRFIndicators || !opts.WriteMethodProbes {
		t.Errorf("not every family flag was set: %+v", opts)
	}
	if len(enabled) != 6 {
		t.Errorf("enabled = %v, want 6 names", enabled)
	}
}

func TestParseEnableNormalizesCaseAndSpace(t *testing.T) {
	_, enabled, err := parseEnable([]string{" CRLF ", "Path-Traversal"})
	if err != nil {
		t.Fatalf("parseEnable unexpected error: %v", err)
	}
	want := []string{"crlf", "path-traversal"}
	if len(enabled) != len(want) {
		t.Fatalf("enabled = %v, want %v", enabled, want)
	}
	for i := range want {
		if enabled[i] != want[i] {
			t.Errorf("enabled[%d] = %q, want %q", i, enabled[i], want[i])
		}
	}
}

func TestParseEnableUnknownNameErrors(t *testing.T) {
	_, _, err := parseEnable([]string{"crlf", "not-a-family"})
	if err == nil {
		t.Fatal("parseEnable with an unknown family returned no error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not-a-family") {
		t.Errorf("error %q does not name the offending value", msg)
	}
	for _, valid := range intrusiveFamilyNames() {
		if !strings.Contains(msg, valid) {
			t.Errorf("error %q does not list the valid name %q", msg, valid)
		}
	}
}

func TestParseEnableEmptyValuesAreIgnored(t *testing.T) {
	opts, enabled, err := parseEnable([]string{"", "  "})
	if err != nil {
		t.Fatalf("parseEnable unexpected error: %v", err)
	}
	if len(enabled) != 0 {
		t.Errorf("enabled = %v, want none", enabled)
	}
	if opts != (scanner.IntrusiveOptions{}) {
		t.Errorf("opts = %+v, want the zero value", opts)
	}
}

// ── --path parsing ──────────────────────────────────────────────────────────

func TestParsePathList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"leading slashes preserved", "/a,/b", []string{"/a", "/b"}},
		{"missing slashes are added", "a, b", []string{"/a", "/b"}},
		{"empty input yields nothing", "", nil},
		{"blank entries are dropped", "/, ,/x", []string{"/", "/x"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parsePathList(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("parsePathList(%q) = %v, want %v", c.in, got, c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Errorf("parsePathList(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
				}
			}
		})
	}
}

// ── loopback integration (gate in front of the OWASP checker) ────────────────

// loopbackGuard builds a Guard scoped to the httptest loopback host with a
// high rate and budget so a test never waits on the limiter.
func loopbackGuard(t *testing.T, dryRun bool) *scanner.Guard {
	t.Helper()
	g, err := scanner.NewGuard(scanner.GuardConfig{
		Allow:       []string{"127.0.0.1"},
		Intrusive:   false,
		RPS:         50000,
		MaxRequests: 100000,
		DryRun:      dryRun,
	})
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	return g
}

func TestRunOWASPScanNonIntrusiveLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	defer srv.Close()

	g := loopbackGuard(t, false)
	out := runOWASPScan([]string{srv.URL}, g, nil, nil, nil)

	// A03/A07/A10 are intrusive and have no probe outside the gate: with the
	// opt-in off not a single payload was sent, so not one of them produced
	// real evidence. A07's checker still emits a "no brute force protection"
	// finding even though its twenty login attempts were all refused, so this
	// also proves the provenance rule drops that fabricated finding.
	// A05 is deliberately excluded: it genuinely dials local service ports
	// outside the gate, which can add a real finding on a developer box.
	for _, id := range []string{"A03", "A07", "A10"} {
		cat := out.Categories[id]
		if cat == nil {
			t.Fatalf("category %s missing from the report", id)
		}
		if cat.Status != statusNotTested {
			t.Errorf("%s status = %q, want %q", id, cat.Status, statusNotTested)
		}
		if cat.ProbesCovered != 0 {
			t.Errorf("%s probes_covered = %d, want 0", id, cat.ProbesCovered)
		}
		if len(cat.Findings) != 0 {
			t.Errorf("%s kept %d findings with no coverage: %v", id, len(cat.Findings), cat.Findings)
		}
	}

	// Global invariant: nothing may ever be reported PASS without coverage.
	for id, cat := range out.Categories {
		if cat.Status == "PASS" && cat.ProbesCovered == 0 {
			t.Errorf("%s reported PASS with zero probe coverage", id)
		}
	}

	if out.Guard.RequestsSent == 0 {
		t.Errorf("the gate sent no probe at all: %+v", out.Guard)
	}
	if out.Guard.RefusedIntrusive == 0 {
		t.Errorf("the gate recorded no intrusive refusal: %+v", out.Guard)
	}
}

func TestRunOWASPScanDryRunSendsNothing(t *testing.T) {
	// Function-level property: when runOWASPScan is handed a dry-run Guard, the
	// gate sends nothing and no category may read PASS. main() additionally
	// skips the gated phases under --dry-run (see gatedPhaseSkipReason), but
	// this keeps the mapping honest even if that changes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	g := loopbackGuard(t, true)
	out := runOWASPScan([]string{srv.URL}, g, nil, nil, nil)

	if out.Guard.RequestsSent != 0 {
		t.Errorf("dry-run sent %d requests through the gate, want 0", out.Guard.RequestsSent)
	}
	if out.Guard.DryRunChecked == 0 {
		t.Errorf("dry-run recorded no policy evaluation: %+v", out.Guard)
	}
	for id, cat := range out.Categories {
		if cat.Status == "PASS" {
			t.Errorf("%s reported PASS under dry-run: %+v", id, cat)
		}
		if cat.ProbesCovered != 0 {
			t.Errorf("%s has %d covered probes under dry-run, want 0", id, cat.ProbesCovered)
		}
	}
}
