package scanner

// Tests for the passive check family. They are written entirely against the
// Requester seam: passiveFakeRequester answers from memory, so no socket is ever
// opened and no Guard is constructed. Every assertion is about behaviour that a
// reviewer can reproduce by reading the fake's routes.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// In-memory Requester
// ---------------------------------------------------------------------------

// passiveFakeRequester is a Requester that answers from a handler. It records
// every request line and Host override so a test can prove what was NOT fetched.
type passiveFakeRequester struct {
	handler   func(*http.Request) (*http.Response, error)
	refuse    error
	panicOnDo bool

	mu       sync.Mutex
	requests []string
	hosts    []string
	// canaryChannels records where a Host-header canary actually appeared:
	// the rewritten req.Host and the X-Forwarded-Host header value.
	canaryChannels []string
	// plainRequests records ordinary fetches only (no Host rewrite, no
	// X-Forwarded-Host), so a test can count page probes without counting the
	// host-header probes that target the same URLs.
	plainRequests []string
}

func (f *passiveFakeRequester) Check(_ context.Context, _ string, _ string, intrusive bool) error {
	if intrusive {
		return ErrIntrusiveDisabled
	}
	return f.refuse
}

func (f *passiveFakeRequester) Do(req *http.Request) (*http.Response, error) {
	if f.panicOnDo {
		panic("passiveFakeRequester: Do panicked on purpose")
	}
	f.mu.Lock()
	f.requests = append(f.requests, req.URL.String())
	f.hosts = append(f.hosts, req.Host)
	// http.NewRequest sets req.Host from the URL, so an override is visible as
	// req.Host differing from req.URL.Host. Ordinary page fetches have no
	// override and no forwarded-host header.
	hostOverridden := req.Host != "" && req.Host != req.URL.Host
	if !hostOverridden && req.Header.Get("X-Forwarded-Host") == "" {
		f.plainRequests = append(f.plainRequests, req.URL.String())
	}
	if hostOverridden {
		f.canaryChannels = append(f.canaryChannels, req.Host)
	}
	for _, v := range req.Header.Values("X-Forwarded-Host") {
		if v != "" {
			f.canaryChannels = append(f.canaryChannels, v)
		}
	}
	f.mu.Unlock()
	if f.handler == nil {
		return passiveTestResponse(404, nil, ""), nil
	}
	return f.handler(req)
}

// fetched returns a copy of the recorded request URLs.
func (f *passiveFakeRequester) fetched() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// requested reports whether any request URL contains the needle.
func (f *passiveFakeRequester) requested(needle string) bool {
	for _, raw := range f.fetched() {
		if strings.Contains(raw, needle) {
			return true
		}
	}
	return false
}

// canarySent reports whether the canary appeared in a rewritten Host header or
// an X-Forwarded-Host value.
func (f *passiveFakeRequester) canarySent(canary string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range f.canaryChannels {
		if strings.Contains(v, canary) {
			return true
		}
	}
	return false
}

// countPlainURL counts ordinary fetches (no host override) whose URL is exactly
// the given string.
func (f *passiveFakeRequester) countPlainURL(exact string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, raw := range f.plainRequests {
		if raw == exact {
			n++
		}
	}
	return n
}

// countPlainContaining counts ordinary fetches whose URL contains the needle.
func (f *passiveFakeRequester) countPlainContaining(needle string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, raw := range f.plainRequests {
		if strings.Contains(raw, needle) {
			n++
		}
	}
	return n
}

// countContaining counts recorded request URLs containing the needle.
func (f *passiveFakeRequester) countContaining(needle string) int {
	n := 0
	for _, raw := range f.fetched() {
		if strings.Contains(raw, needle) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

// passiveHeader builds a header with as many repeated keys as the test needs
// (Set-Cookie is the reason this takes a flat key/value list).
func passiveHeader(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

// passiveTestResponse mirrors what a Requester returns: a status, a header map
// and a body. The header is copied so two responses never share a map.
func passiveTestResponse(status int, header http.Header, body string) *http.Response {
	out := http.Header{}
	for key, values := range header {
		for _, value := range values {
			out.Add(key, value)
		}
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     out,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// passiveRoute is one fixed answer.
type passiveRoute struct {
	status int
	header http.Header
	body   string
}

// passiveStaticSite answers every path with the same route.
func passiveStaticSite(route passiveRoute) *passiveFakeRequester {
	return &passiveFakeRequester{handler: func(*http.Request) (*http.Response, error) {
		return passiveTestResponse(route.status, route.header, route.body), nil
	}}
}

// passiveSite routes exact paths and falls back for everything else. The
// fallback is what the soft-404 controls and any unlisted probe see.
func passiveSite(fallback passiveRoute, routes map[string]passiveRoute) *passiveFakeRequester {
	return &passiveFakeRequester{handler: func(req *http.Request) (*http.Response, error) {
		if route, ok := routes[req.URL.Path]; ok {
			return passiveTestResponse(route.status, route.header, route.body), nil
		}
		return passiveTestResponse(fallback.status, fallback.header, fallback.body), nil
	}}
}

// passiveHTMLRoute is the common "an HTML page" route.
func passiveHTMLRoute(body string) passiveRoute {
	return passiveRoute{status: 200, header: passiveHeader("Content-Type", "text/html; charset=utf-8"), body: body}
}

// passiveNotFoundRoute is the plain 404 most tests use as a fallback.
func passiveNotFoundRoute() passiveRoute {
	return passiveRoute{status: 404, header: passiveHeader("Content-Type", "text/plain"), body: "not found"}
}

// ---------------------------------------------------------------------------
// Scan orchestration helpers
// ---------------------------------------------------------------------------

// passiveScan builds a scanner through the public constructor and runs it once.
func passiveScan(t *testing.T, baseURL string, req Requester, opts PassiveOptions) ([]Vulnerability, []PassiveProbeNote) {
	t.Helper()
	scanner, err := NewPassiveScanner(baseURL, req, opts)
	if err != nil {
		t.Fatalf("NewPassiveScanner(%q) returned an error: %v", baseURL, err)
	}
	findings := scanner.ScanAll(context.Background())
	return findings, scanner.Notes()
}

// passiveWithCheck returns the findings that carry one check ID.
func passiveWithCheck(findings []Vulnerability, checkID string) []Vulnerability {
	var out []Vulnerability
	for _, v := range findings {
		if strings.HasPrefix(v.ID, checkID) {
			out = append(out, v)
		}
	}
	return out
}

// passiveHasCheck reports whether any finding carries the check ID.
func passiveHasCheck(findings []Vulnerability, checkID string) bool {
	return len(passiveWithCheck(findings, checkID)) > 0
}

// passiveFind returns the first finding for a check ID and parameter.
func passiveFind(findings []Vulnerability, checkID, parameter string) (Vulnerability, bool) {
	for _, v := range findings {
		if strings.HasPrefix(v.ID, checkID) && v.Parameter == parameter {
			return v, true
		}
	}
	return Vulnerability{}, false
}

// passiveURLsEndingWith reports how many findings have a URL ending in suffix.
func passiveURLsEndingWith(findings []Vulnerability, suffix string) int {
	n := 0
	for _, v := range findings {
		if strings.HasSuffix(v.URL, suffix) {
			n++
		}
	}
	return n
}

// passiveTestPage is a small HTML page with a title, so the soft-404 baseline
// can compare titles when it needs to.
func passiveTestPage(title, extra string) string {
	return "<!doctype html><html><head><title>" + title + "</title></head><body>" + extra + "</body></html>"
}

// ---------------------------------------------------------------------------
// Constructor: fail closed
// ---------------------------------------------------------------------------

func TestPassiveNewScannerFailsClosed(t *testing.T) {
	ok := &passiveFakeRequester{}
	cases := []struct {
		name    string
		baseURL string
		req     Requester
		paths   []string
		wantErr bool
	}{
		{name: "nil requester", baseURL: "https://example.com", req: nil, wantErr: true},
		{name: "empty url", baseURL: "", req: ok, wantErr: true},
		{name: "blank url", baseURL: "   ", req: ok, wantErr: true},
		{name: "no scheme is not guessed", baseURL: "example.com", req: ok, wantErr: true},
		{name: "scheme without slashes", baseURL: "example.com/app", req: ok, wantErr: true},
		{name: "non http scheme", baseURL: "ftp://example.com", req: ok, wantErr: true},
		{name: "file scheme", baseURL: "file:///etc/passwd", req: ok, wantErr: true},
		{name: "no host", baseURL: "http://", req: ok, wantErr: true},
		{name: "userinfo", baseURL: "https://user:pass@example.com", req: ok, wantErr: true},
		{name: "space in host", baseURL: "http://exa mple.com/", req: ok, wantErr: true},
		{name: "path with scheme", baseURL: "https://example.com", req: ok, paths: []string{"http://evil.example/x"}, wantErr: true},
		{name: "protocol relative path", baseURL: "https://example.com", req: ok, paths: []string{"//evil.example/x"}, wantErr: true},
		{name: "backslash in path", baseURL: "https://example.com", req: ok, paths: []string{"/\\evil.example"}, wantErr: true},
		{name: "newline in path", baseURL: "https://example.com", req: ok, paths: []string{"/a\nb"}, wantErr: true},
		{name: "not root relative", baseURL: "https://example.com", req: ok, paths: []string{"app/dashboard"}, wantErr: true},
		{name: "http base is accepted", baseURL: "http://example.com", req: ok, wantErr: false},
		{name: "https base with path and query", baseURL: "https://example.com/app?x=1", req: ok, wantErr: false},
		{name: "empty path entry is the root", baseURL: "https://example.com", req: ok, paths: []string{"", "   "}, wantErr: false},
		{name: "root relative path entry", baseURL: "https://example.com", req: ok, paths: []string{"/app", "/search?q=1"}, wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner, err := NewPassiveScanner(tc.baseURL, tc.req, PassiveOptions{Paths: tc.paths})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewPassiveScanner(%q) accepted an input it must refuse", tc.baseURL)
				}
				if scanner != nil {
					t.Fatalf("NewPassiveScanner(%q) returned a scanner together with an error", tc.baseURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewPassiveScanner(%q) rejected a valid input: %v", tc.baseURL, err)
			}
			if scanner == nil {
				t.Fatalf("NewPassiveScanner(%q) returned a nil scanner and no error", tc.baseURL)
			}
		})
	}
}

func TestPassiveEmptyPathEntryProbesRoot(t *testing.T) {
	fake := passiveSite(passiveNotFoundRoute(), nil)
	if _, _ = passiveScan(t, "https://example.com", fake, PassiveOptions{Paths: []string{"", "   "}}); true {
		// Both entries normalize to "/" and dedup, so exactly one ordinary page
		// fetch targets the site root.
		if got := fake.countPlainURL("https://example.com/"); got != 1 {
			t.Fatalf("expected exactly one page fetch to the site root, got %d: %v", got, fake.fetched())
		}
	}
}

func TestPassivePathsAreCapped(t *testing.T) {
	paths := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		paths = append(paths, fmt.Sprintf("/capped%d", i))
	}
	fake := passiveSite(passiveNotFoundRoute(), nil)
	_, _ = passiveScan(t, "https://example.com", fake, PassiveOptions{Paths: paths})
	if got := fake.countPlainContaining("/capped"); got != passiveMaxPaths {
		t.Fatalf("expected the page set to be capped at %d ordinary fetches, got %d", passiveMaxPaths, got)
	}
}

// ---------------------------------------------------------------------------
// Soft-404 baseline
// ---------------------------------------------------------------------------

func TestPassiveSoft404RejectsExactControlBody(t *testing.T) {
	// Every path, including /Dockerfile, answers with one and the same body.
	// The artifact signature would match, so only the baseline can stop it.
	const body = "FROM alpine:3.19\n"
	fake := passiveStaticSite(passiveRoute{status: 200, header: passiveHeader("Content-Type", "text/plain"), body: body})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	if passiveHasCheck(findings, passiveCheckIDArtifact) {
		t.Fatalf("a soft-404 body identical to the control was reported as an artifact: %+v", passiveWithCheck(findings, passiveCheckIDArtifact))
	}
	if !fake.requested("/Dockerfile") {
		t.Fatalf("the artifact probe never ran, so the test proved nothing: %v", fake.fetched())
	}
}

func TestPassiveSoft404BaselineRejectsAndSpares(t *testing.T) {
	control := passiveTestPage("Page not found", strings.Repeat("x", 400))
	baseline := &passiveSoft404Baseline{
		ok:      true,
		hashes:  map[string]struct{}{passiveBodyHash([]byte(control)): {}},
		samples: []passiveSoft404Sample{{status: 404, length: len(control), title: "Page not found"}},
	}

	hashExact := passiveMakeResponse(404, passiveHeader("Content-Type", "text/html"), control)
	if !baseline.rejects(hashExact) {
		t.Fatal("an identical control body at the control status must be rejected")
	}

	sameHashWrongStatus := passiveMakeResponse(200, passiveHeader("Content-Type", "text/html"), control)
	if baseline.rejects(sameHashWrongStatus) {
		t.Fatal("a body hash match at a different status must not be rejected: 200 is not the 404 the control saw")
	}

	onePercent := passiveTestPage("Page not found", strings.Repeat("x", 405))
	sameTitle := passiveMakeResponse(404, passiveHeader("Content-Type", "text/html"), onePercent)
	if !baseline.rejects(sameTitle) {
		t.Fatal("a body within the length tolerance with the same normalized title must be rejected")
	}

	titledDifferently := passiveTestPage("Completely different", strings.Repeat("x", 400))
	if baseline.rejects(passiveMakeResponse(404, passiveHeader("Content-Type", "text/html"), titledDifferently)) {
		t.Fatal("a different title must not be rejected, even at a similar length")
	}

	untitled := passiveMakeResponse(404, passiveHeader("Content-Type", "text/html"), "<html><body>"+strings.Repeat("x", 400)+"</body></html>")
	if baseline.rejects(untitled) {
		t.Fatal("an empty title must never satisfy the title comparison: two untitled files must not be conflated")
	}

	farOff := passiveTestPage("Page not found", strings.Repeat("x", 4000))
	if baseline.rejects(passiveMakeResponse(404, passiveHeader("Content-Type", "text/html"), farOff)) {
		t.Fatal("a body far outside the length tolerance must not be rejected")
	}

	if (&passiveSoft404Baseline{ok: false, hashes: map[string]struct{}{}}).rejects(hashExact) {
		t.Fatal("a baseline that could not be built must reject nothing")
	}
	var nilBaseline *passiveSoft404Baseline
	if nilBaseline.rejects(hashExact) {
		t.Fatal("a nil baseline must reject nothing")
	}
	if baseline.rejects(nil) {
		t.Fatal("a nil response must not be rejected")
	}
}

func TestPassiveWithinPercentBoundaries(t *testing.T) {
	cases := []struct {
		a, b int
		pct  int
		want bool
	}{
		{a: 100, b: 100, pct: 2, want: true},
		{a: 102, b: 100, pct: 2, want: true},
		{a: 103, b: 100, pct: 2, want: false},
		{a: 98, b: 100, pct: 2, want: true},
		{a: 97, b: 100, pct: 2, want: false},
		{a: 0, b: 0, pct: 2, want: true},
		{a: 1, b: 0, pct: 2, want: false},
	}
	for _, tc := range cases {
		if got := passiveWithinPercent(tc.a, tc.b, tc.pct); got != tc.want {
			t.Errorf("passiveWithinPercent(%d, %d, %d) = %v, want %v", tc.a, tc.b, tc.pct, got, tc.want)
		}
	}
}

// passiveMakeResponse builds a passiveResponse the way passiveFetch would, so a
// unit test can exercise a check's decision without a Requester.
func passiveMakeResponse(status int, header http.Header, body string) *passiveResponse {
	resp := &passiveResponse{rawURL: "https://example.com/probe", status: status, header: header, body: []byte(body)}
	if passiveLooksHTML(header.Get("Content-Type"), resp.body) {
		resp.html = passiveParseHTML(resp.body)
		resp.html.isHTML = true
	}
	return resp
}

// ---------------------------------------------------------------------------
// Security headers, CSP, clickjacking, HSTS
// ---------------------------------------------------------------------------

func TestPassiveMissingHeadersAndClickjacking(t *testing.T) {
	fake := passiveStaticSite(passiveHTMLRoute(passiveTestPage("Home", "<h1>home</h1>")))
	findings, _ := passiveScan(t, "http://example.com", fake, PassiveOptions{})

	for _, parameter := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"} {
		if _, ok := passiveFind(findings, passiveCheckIDHeaders, parameter); !ok {
			t.Errorf("expected a %s finding on a bare response", parameter)
		}
	}
	if _, ok := passiveFind(findings, passiveCheckIDClickjack, "X-Frame-Options"); !ok {
		t.Error("expected a clickjacking finding when neither X-Frame-Options nor frame-ancestors is present")
	}
	if passiveHasCheck(findings, passiveCheckIDHSTS) {
		t.Error("HSTS must not be reported on an http base: the header cannot be delivered over a plaintext first hop")
	}
	if passiveHasCheck(findings, passiveCheckIDCSP) {
		t.Errorf("with no CSP header at all, CSP analysis has nothing to quote and must stay silent: %+v", passiveWithCheck(findings, passiveCheckIDCSP))
	}
}

func TestPassiveHSTSOnlyOnHTTPSBase(t *testing.T) {

	httpFake := passiveStaticSite(passiveHTMLRoute(passiveTestPage("Home", "<h1>home</h1>")))
	httpFindings, _ := passiveScan(t, "http://example.com", httpFake, PassiveOptions{})
	if passiveHasCheck(httpFindings, passiveCheckIDHSTS) {
		t.Error("HSTS must not be flagged on an http base")
	}

	httpsFake := passiveStaticSite(passiveHTMLRoute(passiveTestPage("Home", "<h1>home</h1>")))
	httpsFindings, _ := passiveScan(t, "https://example.com", httpsFake, PassiveOptions{})
	got, ok := passiveFind(httpsFindings, passiveCheckIDHSTS, "Strict-Transport-Security")
	if !ok {
		t.Fatal("expected an HSTS finding on an https base without the header")
	}
	if got.Severity != "medium" {
		t.Errorf("missing HSTS severity = %q, want medium", got.Severity)
	}

	shortFake := passiveStaticSite(passiveRoute{status: 200, header: passiveHeader(
		"Content-Type", "text/html; charset=utf-8",
		"Strict-Transport-Security", "max-age=600",
	), body: passiveTestPage("Home", "<h1>home</h1>")})
	shortFindings, _ := passiveScan(t, "https://example.com", shortFake, PassiveOptions{})
	if got, ok := passiveFind(shortFindings, passiveCheckIDHSTS, "Strict-Transport-Security"); !ok || got.Severity != "low" {
		t.Errorf("expected a low-severity finding for max-age=600, got %+v (found=%v)", got, ok)
	}

	goodFake := passiveStaticSite(passiveRoute{status: 200, header: passiveHeader(
		"Content-Type", "text/html; charset=utf-8",
		"Strict-Transport-Security", "max-age=31536000; includeSubDomains",
	), body: passiveTestPage("Home", "<h1>home</h1>")})
	goodFindings, _ := passiveScan(t, "https://example.com", goodFake, PassiveOptions{})
	if passiveHasCheck(goodFindings, passiveCheckIDHSTS) {
		t.Errorf("a one-year max-age with includeSubDomains must not be flagged: %+v", passiveWithCheck(goodFindings, passiveCheckIDHSTS))
	}
}

func TestPassiveCSPWeaknesses(t *testing.T) {
	cases := []struct {
		name         string
		header       http.Header
		wantParam    string
		wantSeverity string
	}{
		{
			name:         "wildcard script source",
			header:       passiveHeader("Content-Type", "text/html", "Content-Security-Policy", "default-src *; object-src 'none'"),
			wantParam:    "default-src",
			wantSeverity: "medium",
		},
		{
			name:         "unsafe-inline without nonce",
			header:       passiveHeader("Content-Type", "text/html", "Content-Security-Policy", "script-src 'self' 'unsafe-inline'; object-src 'none'"),
			wantParam:    "script-src",
			wantSeverity: "medium",
		},
		{
			name:         "unsafe-eval",
			header:       passiveHeader("Content-Type", "text/html", "Content-Security-Policy", "script-src 'self' 'unsafe-eval'; object-src 'none'"),
			wantParam:    "script-src",
			wantSeverity: "medium",
		},
		{
			name:         "report only only",
			header:       passiveHeader("Content-Type", "text/html", "Content-Security-Policy-Report-Only", "default-src 'self'"),
			wantParam:    "Content-Security-Policy-Report-Only",
			wantSeverity: "medium",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := passiveStaticSite(passiveRoute{status: 200, header: tc.header, body: passiveTestPage("Home", "<h1>home</h1>")})
			findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
			got, ok := passiveFind(findings, passiveCheckIDCSP, tc.wantParam)
			if !ok {
				t.Fatalf("expected a CSP finding with parameter %q, got %+v", tc.wantParam, passiveWithCheck(findings, passiveCheckIDCSP))
			}
			if got.Severity != tc.wantSeverity {
				t.Errorf("severity = %q, want %q", got.Severity, tc.wantSeverity)
			}
		})
	}
}

func TestPassiveCSPGoodPolicyIsQuiet(t *testing.T) {
	fake := passiveStaticSite(passiveRoute{status: 200, header: passiveHeader(
		"Content-Type", "text/html",
		"Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
	), body: passiveTestPage("Home", "<h1>home</h1>")})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	if passiveHasCheck(findings, passiveCheckIDCSP) {
		t.Errorf("a strict policy must produce no CSP finding: %+v", passiveWithCheck(findings, passiveCheckIDCSP))
	}
	if passiveHasCheck(findings, passiveCheckIDClickjack) {
		t.Errorf("frame-ancestors 'none' must satisfy the clickjacking check: %+v", passiveWithCheck(findings, passiveCheckIDClickjack))
	}
}

func TestPassiveClickjackingCases(t *testing.T) {
	cases := []struct {
		name         string
		header       http.Header
		wantParam    string
		wantSeverity string
		wantQuiet    bool
	}{
		{
			name:      "DENY is enough",
			header:    passiveHeader("Content-Type", "text/html", "X-Frame-Options", "DENY"),
			wantQuiet: true,
		},
		{
			name:         "permissive frame-ancestors beats DENY",
			header:       passiveHeader("Content-Type", "text/html", "X-Frame-Options", "DENY", "Content-Security-Policy", "frame-ancestors *"),
			wantParam:    "frame-ancestors",
			wantSeverity: "medium",
		},
		{
			name:         "ALLOW-FROM is dead",
			header:       passiveHeader("Content-Type", "text/html", "X-Frame-Options", "ALLOW-FROM https://partner.example"),
			wantParam:    "X-Frame-Options",
			wantSeverity: "medium",
		},
		{
			name:         "unrecognised value",
			header:       passiveHeader("Content-Type", "text/html", "X-Frame-Options", "banana"),
			wantParam:    "X-Frame-Options",
			wantSeverity: "low",
		},
		{
			name:         "no protection at all",
			header:       passiveHeader("Content-Type", "text/html"),
			wantParam:    "X-Frame-Options",
			wantSeverity: "medium",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := passiveStaticSite(passiveRoute{status: 200, header: tc.header, body: passiveTestPage("Home", "<h1>home</h1>")})
			findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
			if tc.wantQuiet {
				if passiveHasCheck(findings, passiveCheckIDClickjack) {
					t.Fatalf("expected no clickjacking finding: %+v", passiveWithCheck(findings, passiveCheckIDClickjack))
				}
				return
			}
			got, ok := passiveFind(findings, passiveCheckIDClickjack, tc.wantParam)
			if !ok {
				t.Fatalf("expected a clickjacking finding with parameter %q, got %+v", tc.wantParam, passiveWithCheck(findings, passiveCheckIDClickjack))
			}
			if got.Severity != tc.wantSeverity {
				t.Errorf("severity = %q, want %q", got.Severity, tc.wantSeverity)
			}
		})
	}
}

func TestPassiveFrameAncestorsPlusXFOIsInfoOnly(t *testing.T) {
	fake := passiveStaticSite(passiveRoute{status: 200, header: passiveHeader(
		"Content-Type", "text/html",
		"X-Frame-Options", "DENY",
		"Content-Security-Policy", "default-src 'self'; object-src 'none'",
	), body: passiveTestPage("Home", "<h1>home</h1>")})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	got, ok := passiveFind(findings, passiveCheckIDCSP, "frame-ancestors")
	if !ok {
		t.Fatalf("expected an informational frame-ancestors note: %+v", passiveWithCheck(findings, passiveCheckIDCSP))
	}
	if got.Severity != "info" {
		t.Errorf("frame-ancestors note severity = %q, want info", got.Severity)
	}
	if passiveHasCheck(findings, passiveCheckIDClickjack) {
		t.Errorf("X-Frame-Options DENY plus a valid policy must not be a clickjacking finding: %+v", passiveWithCheck(findings, passiveCheckIDClickjack))
	}
}

// ---------------------------------------------------------------------------
// Cookies and prefixes
// ---------------------------------------------------------------------------

func TestPassiveCookieAttributesAndRedaction(t *testing.T) {
	header := passiveHeader(
		"Content-Type", "text/html",
		"Set-Cookie", "sid=SUPERSECRETSESSIONVALUE",
		"Set-Cookie", "theme=dark; SameSite=None",
		"Set-Cookie", "csrf=1; HttpOnly; Secure; SameSite=Lax",
	)
	fake := passiveStaticSite(passiveRoute{status: 200, header: header, body: passiveTestPage("Home", "<h1>home</h1>")})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})

	if _, ok := passiveFind(findings, passiveCheckIDCookie, "sid"); !ok {
		t.Errorf("expected a finding for the session cookie: %+v", passiveWithCheck(findings, passiveCheckIDCookie))
	}
	none, ok := passiveFind(findings, passiveCheckIDCookie, "theme")
	if !ok {
		t.Fatalf("expected a SameSite=None-without-Secure finding for theme: %+v", passiveWithCheck(findings, passiveCheckIDCookie))
	}
	if none.Severity != "high" {
		t.Errorf("SameSite=None without Secure severity = %q, want high", none.Severity)
	}
	if !strings.Contains(none.Title, "SameSite=None") {
		t.Errorf("unexpected finding title %q", none.Title)
	}
	if got, ok := passiveFind(findings, passiveCheckIDCookie, "csrf"); ok {
		t.Errorf("a cookie with HttpOnly, Secure and SameSite=Lax must not be flagged, got %+v", got)
	}

	for _, v := range passiveWithCheck(findings, passiveCheckIDCookie) {
		if strings.Contains(v.Evidence, "SUPERSECRETSESSIONVALUE") {
			t.Fatalf("evidence leaked the cookie value: %q", v.Evidence)
		}
		if !strings.Contains(v.Evidence, "<redacted len=") {
			t.Errorf("cookie evidence should carry the length-redaction marker: %q", v.Evidence)
		}
	}
}

func TestPassiveCookiePrefixes(t *testing.T) {
	header := passiveHeader(
		"Content-Type", "text/html",
		"Set-Cookie", "__Host-brokenpath=1; Secure; Path=/app",
		"Set-Cookie", "__Secure-insecure=1",
		"Set-Cookie", "__Secure-good=1; Secure",
		"Set-Cookie", "__Host-good=1; Secure; Path=/",
	)
	fake := passiveStaticSite(passiveRoute{status: 200, header: header, body: passiveTestPage("Home", "<h1>home</h1>")})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})

	got := passiveWithCheck(findings, passiveCheckIDPrefix)
	if len(got) != 2 {
		t.Fatalf("expected exactly two prefix violations, got %d: %+v", len(got), got)
	}
	byParam := map[string]bool{}
	for _, v := range got {
		byParam[v.Parameter] = true
	}
	if !byParam["__Host-brokenpath"] || !byParam["__Secure-insecure"] {
		t.Errorf("wrong cookies flagged: %+v", got)
	}

	httpFake := passiveStaticSite(passiveRoute{status: 200, header: header, body: passiveTestPage("Home", "<h1>home</h1>")})
	httpFindings, _ := passiveScan(t, "http://example.com", httpFake, PassiveOptions{})
	for _, v := range passiveWithCheck(httpFindings, passiveCheckIDPrefix) {
		if v.Parameter == "__Secure-insecure" {
			t.Error("a __Secure- prefix must not be flagged on an http base, where Secure cannot be set at all")
		}
	}
}

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

// passiveTestJWT builds an unsigned JWS-shaped token from two JSON objects. It
// exists so a test can prove what the decoder reads without shipping a real key.
func passiveTestJWT(t *testing.T, header, payload string) string {
	t.Helper()
	enc := func(raw string) string { return base64.RawURLEncoding.EncodeToString([]byte(raw)) }
	return enc(header) + "." + enc(payload) + "."
}

func TestPassiveJWTAlgorithmAndExpiry(t *testing.T) {
	weak := passiveTestJWT(t, `{"alg":"none","typ":"JWT"}`, `{"sub":"1"}`)
	strong := passiveTestJWT(t, `{"alg":"HS256","typ":"JWT"}`, `{"sub":"2","exp":4102444800}`)
	body := passiveTestPage("Home", `<div data-a="`+weak+`" data-b="`+strong+`">x</div>`)
	fake := passiveStaticSite(passiveHTMLRoute(body))
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})

	algFindings := passiveWithCheck(findings, passiveCheckIDJWTAlg)
	if len(algFindings) != 1 {
		t.Fatalf("expected exactly one alg=none finding, got %d: %+v", len(algFindings), algFindings)
	}
	if algFindings[0].Severity != "high" {
		t.Errorf("alg=none severity = %q, want high", algFindings[0].Severity)
	}
	if !strings.Contains(algFindings[0].Evidence, "confidence=heuristic") {
		t.Errorf("alg=none must be heuristic, since acceptance was never tested: %q", algFindings[0].Evidence)
	}

	expFindings := passiveWithCheck(findings, passiveCheckIDJWTExp)
	if len(expFindings) != 1 {
		t.Fatalf("expected exactly one missing-exp finding (only the token without exp), got %d: %+v", len(expFindings), expFindings)
	}
	if expFindings[0].Severity != "low" {
		t.Errorf("missing exp severity = %q, want low", expFindings[0].Severity)
	}

	// The token itself must never appear anywhere: only its SHA-256 may.
	for _, v := range findings {
		if strings.Contains(v.Evidence, weak) || strings.Contains(v.Evidence, strong) {
			t.Fatalf("evidence leaked a raw JWT: %q", v.Evidence)
		}
	}
	sum := sha256.Sum256([]byte(weak))
	if !strings.Contains(algFindings[0].Evidence, hex.EncodeToString(sum[:])) {
		t.Errorf("alg=none evidence should carry the token SHA-256: %q", algFindings[0].Evidence)
	}
}

func TestPassiveJWTMixedAlgorithms(t *testing.T) {
	hs := passiveTestJWT(t, `{"alg":"HS256"}`, `{"sub":"1","exp":4102444800}`)
	rs := passiveTestJWT(t, `{"alg":"RS256"}`, `{"sub":"2","exp":4102444800}`)
	body := passiveTestPage("Home", `<p>`+hs+`</p><p>`+rs+`</p>`)
	fake := passiveStaticSite(passiveHTMLRoute(body))
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	if !passiveHasCheck(findings, passiveCheckIDJWTCrypto) {
		t.Fatalf("expected a mixed-algorithm finding: %+v", passiveWithCheck(findings, passiveCheckIDJWTCrypto))
	}
	if passiveHasCheck(findings, passiveCheckIDJWTAlg) {
		t.Errorf("neither token uses none: %+v", passiveWithCheck(findings, passiveCheckIDJWTAlg))
	}

	// One family alone is normal and must stay silent.
	onlyHS := passiveStaticSite(passiveHTMLRoute(passiveTestPage("Home", `<p>`+hs+`</p>`)))
	hsFindings, _ := passiveScan(t, "https://example.com", onlyHS, PassiveOptions{})
	if passiveHasCheck(hsFindings, passiveCheckIDJWTCrypto) {
		t.Errorf("a single HS256 token must not be reported as mixed: %+v", passiveWithCheck(hsFindings, passiveCheckIDJWTCrypto))
	}
}

// ---------------------------------------------------------------------------
// Cache-Control
// ---------------------------------------------------------------------------

func TestPassiveCacheControlCases(t *testing.T) {
	cases := []struct {
		name         string
		cacheControl string
		cookie       bool
		path         string
		wantParam    string
		wantSeverity string
	}{
		{name: "public with cookie is high", cacheControl: "public, max-age=3600", cookie: true, wantParam: "Cache-Control", wantSeverity: "high"},
		{name: "long max-age with cookie is high", cacheControl: "max-age=86400", cookie: true, wantParam: "Cache-Control", wantSeverity: "high"},
		{name: "no-cache only is low", cacheControl: "no-cache", cookie: true, wantParam: "Cache-Control", wantSeverity: "low"},
		{name: "absent with cookie is medium", cacheControl: "", cookie: true, wantParam: "Cache-Control", wantSeverity: "medium"},
		{name: "no-store is clean", cacheControl: "no-store, private", cookie: true},
		{name: "private with short max-age is clean", cacheControl: "private, max-age=60", cookie: true},
		{name: "absent on a sensitive path is clean", cacheControl: "", path: "/admin"},
		{name: "sensitive path with public is medium", cacheControl: "public, max-age=600", path: "/admin", wantParam: "Cache-Control", wantSeverity: "medium"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := passiveHeader("Content-Type", "text/html")
			if tc.cacheControl != "" {
				header.Set("Cache-Control", tc.cacheControl)
			}
			if tc.cookie {
				header.Set("Set-Cookie", "sid=abc")
			}
			route := passiveRoute{status: 200, header: header, body: passiveTestPage("Home", "<h1>home</h1>")}
			path := tc.path
			if path == "" {
				path = "/"
			}
			fake := passiveSite(passiveNotFoundRoute(), map[string]passiveRoute{path: route})
			findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{Paths: []string{path}})

			if tc.wantParam == "" {
				if passiveHasCheck(findings, passiveCheckIDCache) {
					t.Fatalf("expected no cache finding: %+v", passiveWithCheck(findings, passiveCheckIDCache))
				}
				return
			}
			got, ok := passiveFind(findings, passiveCheckIDCache, tc.wantParam)
			if !ok {
				t.Fatalf("expected a cache finding: %+v", passiveWithCheck(findings, passiveCheckIDCache))
			}
			if got.Severity != tc.wantSeverity {
				t.Errorf("severity = %q, want %q", got.Severity, tc.wantSeverity)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Host header canary
// ---------------------------------------------------------------------------

func TestPassiveHostHeaderCanary(t *testing.T) {
	locRoute := func(status int, header http.Header, body string) passiveRoute {
		return passiveRoute{status: status, header: header, body: body}
	}
	normal := locRoute(200, passiveHTMLRoute(passiveTestPage("Home", "<h1>home</h1>")).header, passiveTestPage("Home", "<h1>home</h1>"))
	fake := &passiveFakeRequester{handler: func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Host == passiveHostCanary:
			return passiveTestResponse(302, passiveHeader("Location", "https://"+passiveHostCanary+"/login?token=abcdefghij"), ""), nil
		case req.Header.Get("X-Forwarded-Host") == passiveHostCanary:
			return passiveTestResponse(200, passiveHTMLRoute(passiveTestPage("Home", "<h1>home</h1>")).header, passiveTestPage("Home", `<a href="https://`+passiveHostCanary+`/reset?token=12345678ab">reset</a>`)), nil
		default:
			return passiveTestResponse(normal.status, normal.header, normal.body), nil
		}
	}}
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})

	direct, ok := passiveFind(findings, passiveCheckIDHost, "Host")
	if !ok {
		t.Fatalf("expected a Host canary finding: %+v", passiveWithCheck(findings, passiveCheckIDHost))
	}
	if direct.Severity != "high" {
		t.Errorf("a token-context Location reflection must be high, got %q (%s)", direct.Severity, direct.Evidence)
	}
	if !strings.Contains(direct.Evidence, "False-positive check:") {
		t.Errorf("evidence must explain what to doubt: %q", direct.Evidence)
	}

	forwarded, ok := passiveFind(findings, passiveCheckIDHost, "X-Forwarded-Host")
	if !ok {
		t.Fatalf("expected an X-Forwarded-Host finding: %+v", passiveWithCheck(findings, passiveCheckIDHost))
	}
	if forwarded.Severity != "medium" {
		t.Errorf("a token-context body reflection must be medium, got %q", forwarded.Severity)
	}
	if !fake.canarySent(passiveHostCanary) {
		t.Error("the canary never reached a request, so the reflection cannot be attributed")
	}
}

func TestPassiveHostHeaderQuietWhenNotReflected(t *testing.T) {
	fake := passiveStaticSite(passiveHTMLRoute(passiveTestPage("Home", "<h1>home</h1>")))
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	if passiveHasCheck(findings, passiveCheckIDHost) {
		t.Fatalf("a site that ignores the Host header must produce no finding: %+v", passiveWithCheck(findings, passiveCheckIDHost))
	}
}

func TestPassiveHostHeaderPlainBodyReflectionIsInfo(t *testing.T) {
	fake := &passiveFakeRequester{handler: func(req *http.Request) (*http.Response, error) {
		if req.Host == passiveHostCanary || req.Header.Get("X-Forwarded-Host") == passiveHostCanary {
			return passiveTestResponse(200, passiveHTMLRoute("").header, passiveTestPage("Home", "welcome to "+passiveHostCanary)), nil
		}
		return passiveTestResponse(200, passiveHTMLRoute("").header, passiveTestPage("Home", "<h1>home</h1>")), nil
	}}
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	got := passiveWithCheck(findings, passiveCheckIDHost)
	if len(got) == 0 {
		t.Fatal("expected a body reflection finding")
	}
	for _, v := range got {
		if v.Severity != "info" {
			t.Errorf("a plain body reflection must stay informational, got %q: %s", v.Severity, v.Evidence)
		}
	}
}

// ---------------------------------------------------------------------------
// Metafiles
// ---------------------------------------------------------------------------

func TestPassiveMetafilesRobotsAndSecurityTxt(t *testing.T) {
	robots := "User-agent: *\nDisallow: /admin\nDisallow: /private\nAllow: /\nSitemap: https://example.com/sitemap.xml\n"
	fake := passiveSite(passiveNotFoundRoute(), map[string]passiveRoute{
		"/robots.txt": {status: 200, header: passiveHeader("Content-Type", "text/plain"), body: robots},
	})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	if got, ok := passiveFind(findings, passiveCheckIDMeta, "robots.txt"); !ok {
		t.Errorf("expected a robots.txt finding: %+v", passiveWithCheck(findings, passiveCheckIDMeta))
	} else if !strings.Contains(got.Evidence, "/admin") {
		t.Errorf("robots evidence should quote the advertised path: %q", got.Evidence)
	}
	if _, ok := passiveFind(findings, passiveCheckIDMeta, "security.txt"); !ok {
		t.Errorf("expected a missing security.txt finding: %+v", passiveWithCheck(findings, passiveCheckIDMeta))
	}

	clean := passiveSite(passiveNotFoundRoute(), map[string]passiveRoute{
		"/robots.txt": {status: 200, header: passiveHeader("Content-Type", "text/plain"), body: "User-agent: *\nAllow: /\n"},
		"/.well-known/security.txt": {status: 200, header: passiveHeader("Content-Type", "text/plain"),
			body: "Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\nCanonical: https://example.com/.well-known/security.txt\n"},
	})
	cleanFindings, _ := passiveScan(t, "https://example.com", clean, PassiveOptions{})
	if passiveHasCheck(cleanFindings, passiveCheckIDMeta) {
		t.Errorf("a permissive robots.txt and a complete security.txt must be quiet: %+v", passiveWithCheck(cleanFindings, passiveCheckIDMeta))
	}
}

func TestPassiveMetafilesHTMLetAtFixedPathIsNotMetafile(t *testing.T) {
	// A themed 200 page at /robots.txt must not be read as a robots file.
	fake := passiveStaticSite(passiveHTMLRoute(passiveTestPage("Oops", "<h1>404</h1>Page not found, but styled")))
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	if got, ok := passiveFind(findings, passiveCheckIDMeta, "robots.txt"); ok {
		t.Errorf("an HTML page at /robots.txt was reported as a robots file: %s", got.Evidence)
	}
}

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

func TestPassiveArtifactFlagsSignatureAndSkipsForbidden(t *testing.T) {
	fake := passiveSite(passiveNotFoundRoute(), map[string]passiveRoute{
		"/Dockerfile": {status: 200, header: passiveHeader("Content-Type", "text/plain"), body: "FROM golang:1.22\nCOPY . /app\n"},
		"/id_rsa":     {status: 403, header: passiveHeader("Content-Type", "text/plain"), body: "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n"},
	})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})

	got, ok := passiveFind(findings, passiveCheckIDArtifact, "/Dockerfile")
	if !ok {
		t.Fatalf("expected a Dockerfile finding: %+v", passiveWithCheck(findings, passiveCheckIDArtifact))
	}
	if !strings.Contains(got.Evidence, "confidence=high") {
		t.Errorf("artifact confidence should be high (signature plus baseline): %q", got.Evidence)
	}
	if !strings.Contains(got.Evidence, "FROM golang:1.22") {
		t.Errorf("artifact evidence should quote the matched signature: %q", got.Evidence)
	}
	if got.Severity != "medium" {
		t.Errorf("artifact severity = %q, want medium", got.Severity)
	}
	if passiveURLsEndingWith(findings, "/id_rsa") != 0 {
		t.Errorf("a 403 response is the correct answer and must never be reported as a leak: %+v", passiveWithCheck(findings, passiveCheckIDArtifact))
	}
}

func TestPassiveArtifactIgnoresHTMLAndEmptyBodies(t *testing.T) {
	fake := passiveSite(passiveNotFoundRoute(), map[string]passiveRoute{
		"/.env":          {status: 200, header: passiveHeader("Content-Type", "text/html"), body: passiveTestPage("Home", "A=1 B=2")},
		"/composer.json": {status: 200, header: passiveHeader("Content-Type", "text/plain"), body: "{}\n"},
		"/index.php.bak": {status: 200, header: passiveHeader("Content-Type", "text/plain"), body: "<h1>hello</h1>"},
	})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	got := passiveWithCheck(findings, passiveCheckIDArtifact)
	for _, v := range got {
		if strings.HasSuffix(v.URL, "/.env") {
			t.Errorf("an HTML document at /.env is the site's own page, not a dotenv file: %s", v.Evidence)
		}
		if strings.HasSuffix(v.URL, "/composer.json") {
			t.Errorf("a composer.json without a require block must not match: %s", v.Evidence)
		}
		if strings.HasSuffix(v.URL, "/index.php.bak") {
			t.Errorf("an HTML body must not be read as backed-up PHP source: %s", v.Evidence)
		}
	}
}

func TestPassiveArtifactBinarySignatures(t *testing.T) {
	fake := passiveSite(passiveNotFoundRoute(), map[string]passiveRoute{
		"/.DS_Store": {status: 200, header: passiveHeader("Content-Type", "application/octet-stream"), body: "Bud1\x00\x00\x00\x08\x00\x00\x00\x08"},
		"/Thumbs.db": {status: 200, header: passiveHeader("Content-Type", "application/octet-stream"), body: "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00"},
	})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	got := passiveWithCheck(findings, passiveCheckIDArtifact)
	if len(got) != 2 {
		t.Fatalf("expected two binary-signature findings, got %d: %+v", len(got), got)
	}
	for _, v := range got {
		if v.Severity != "low" {
			t.Errorf("%s severity = %q, want low (a directory listing leaks names, not secrets)", v.URL, v.Severity)
		}
	}
}

// ---------------------------------------------------------------------------
// Source maps
// ---------------------------------------------------------------------------

func TestPassiveSourceMapsAreSameHostOnly(t *testing.T) {
	const mapBody = `{"version":3,"sources":["src/app.ts"],"mappings":"AAAA,BBBB"}`
	fake := passiveSite(passiveNotFoundRoute(), map[string]passiveRoute{
		"/":           passiveHTMLRoute(passiveTestPage("Home", "<script src=\"/app.js\"></script>")),
		"/app.js":     {status: 200, header: passiveHeader("Content-Type", "application/javascript"), body: "console.log(1)"},
		"/app.js.map": {status: 200, header: passiveHeader("Content-Type", "application/json"), body: mapBody},
		"/lib.js":     {status: 200, header: passiveHeader("Content-Type", "application/javascript"), body: "console.log(2)"},
	})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})

	got := passiveWithCheck(findings, passiveCheckIDSrcMap)
	if len(got) != 1 {
		t.Fatalf("expected exactly one source-map finding (the same-host one), got %d: %+v", len(got), got)
	}
	if !strings.HasSuffix(got[0].URL, "example.com/app.js.map") {
		t.Errorf("unexpected source-map URL %q", got[0].URL)
	}
	if fake.requested("cdn.example.net") {
		t.Errorf("a third-party host must never be probed for a source map: %v", fake.fetched())
	}
}

func TestPassiveSourceMapNeedsSourceMapJSON(t *testing.T) {
	fake := passiveSite(passiveNotFoundRoute(), map[string]passiveRoute{
		"/":           passiveHTMLRoute(passiveTestPage("Home", "<script src=\"/app.js\"></script>")),
		"/app.js":     {status: 200, header: passiveHeader("Content-Type", "application/javascript"), body: "console.log(1)"},
		"/app.js.map": {status: 200, header: passiveHeader("Content-Type", "application/json"), body: `{"ok":true,"items":[1,2]}`},
	})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	if passiveHasCheck(findings, passiveCheckIDSrcMap) {
		t.Fatalf("JSON without the source-map keys must not be reported: %+v", passiveWithCheck(findings, passiveCheckIDSrcMap))
	}
}

// ---------------------------------------------------------------------------
// Mixed content and Subresource Integrity
// ---------------------------------------------------------------------------

func TestPassiveMixedContentAndSRI(t *testing.T) {
	body := passiveTestPage("Home", strings.Join([]string{
		`<script src="http://cdn.example.net/a.js"></script>`,
		`<script src="https://cdn.example.net/b.js"></script>`,
		`<script src="https://cdn.example.net/c.js" integrity="sha384-abc" crossorigin="anonymous"></script>`,
		`<script src="/local.js"></script>`,
		`<link rel="stylesheet" href="https://cdn.example.net/d.css">`,
	}, ""))
	fake := passiveStaticSite(passiveHTMLRoute(body))
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})

	mixed := passiveWithCheck(findings, passiveCheckIDMixed)
	if len(mixed) != 1 {
		t.Fatalf("expected exactly one mixed-content finding, got %d: %+v", len(mixed), mixed)
	}
	if !strings.Contains(mixed[0].Parameter, "a.js") {
		t.Errorf("unexpected mixed-content resource %q", mixed[0].Parameter)
	}
	if mixed[0].Severity != "medium" {
		t.Errorf("mixed content severity = %q, want medium", mixed[0].Severity)
	}

	sri := passiveWithCheck(findings, passiveCheckIDSRI)
	if len(sri) != 2 {
		t.Fatalf("expected two SRI findings (the script and the stylesheet), got %d: %+v", len(sri), sri)
	}
	for _, v := range sri {
		if strings.Contains(v.Parameter, "c.js") {
			t.Errorf("a pinned resource must not be reported: %+v", v)
		}
		if strings.Contains(v.Parameter, "local.js") {
			t.Errorf("a same-origin resource must not be reported: %+v", v)
		}
		if v.Severity != "low" {
			t.Errorf("SRI severity = %q, want low", v.Severity)
		}
	}

	// On an http base there is no downgrade to report.
	httpFake := passiveStaticSite(passiveHTMLRoute(body))
	httpFindings, _ := passiveScan(t, "http://example.com", httpFake, PassiveOptions{})
	if passiveHasCheck(httpFindings, passiveCheckIDMixed) {
		t.Errorf("mixed content must not be reported on an http page: %+v", passiveWithCheck(httpFindings, passiveCheckIDMixed))
	}
}

// ---------------------------------------------------------------------------
// Information leakage
// ---------------------------------------------------------------------------

func TestPassiveBannersAndCommentSecrets(t *testing.T) {
	header := passiveHeader(
		"Content-Type", "text/html",
		"Server", "nginx/1.24.0",
		"X-Powered-By", "PHP/8.1.2",
	)
	body := passiveTestPage("Home", "<!-- debug: api_key=SECRETVALUE123 --><h1>home</h1>")
	fake := passiveStaticSite(passiveRoute{status: 200, header: header, body: body})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})

	server, ok := passiveFind(findings, passiveCheckIDBanner, "Server")
	if !ok {
		t.Fatalf("expected a Server banner finding: %+v", passiveWithCheck(findings, passiveCheckIDBanner))
	}
	if server.Severity != "low" {
		t.Errorf("a versioned banner severity = %q, want low", server.Severity)
	}
	if !strings.Contains(server.Evidence, "confidence=informational") {
		t.Errorf("hygiene findings must be informational: %q", server.Evidence)
	}

	comment, ok := passiveFind(findings, passiveCheckIDComment, "HTML comment")
	if !ok {
		t.Fatalf("expected a comment-secret finding: %+v", passiveWithCheck(findings, passiveCheckIDComment))
	}
	if comment.Severity != "low" {
		t.Errorf("comment secret severity = %q, want low", comment.Severity)
	}
	if strings.Contains(comment.Evidence, "SECRETVALUE123") {
		t.Fatalf("comment evidence leaked the secret: %q", comment.Evidence)
	}
	if !strings.Contains(comment.Evidence, "<redacted>") {
		t.Errorf("comment evidence should mark the redaction: %q", comment.Evidence)
	}
}

func TestPassiveCommentWithoutSecretIsQuiet(t *testing.T) {
	for _, comment := range []string{
		"<!-- TODO: tidy this up -->",
		"<!-- renders in three columns -->",
		"<!-- analytics placeholder -->",
	} {
		body := passiveTestPage("Home", comment+"<h1>home</h1>")
		fake := passiveStaticSite(passiveHTMLRoute(body))
		findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
		if passiveHasCheck(findings, passiveCheckIDComment) {
			t.Errorf("comment %q must not be reported as a secret: %+v", comment, passiveWithCheck(findings, passiveCheckIDComment))
		}
	}
}

// ---------------------------------------------------------------------------
// Verbose errors
// ---------------------------------------------------------------------------

func TestPassiveVerboseErrorOnBaselineControl(t *testing.T) {
	stack := "<html><body><h1>Error</h1>\njava.lang.NullPointerException\n\tat com.example.App.run(App.java:42)\n</body></html>"
	fake := passiveStaticSite(passiveRoute{status: 500, header: passiveHeader("Content-Type", "text/html"), body: stack})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
	got := passiveWithCheck(findings, passiveCheckIDError)
	if len(got) == 0 {
		t.Fatalf("expected a verbose-error finding from the error page")
	}
	first := got[0]
	if first.Severity != "medium" {
		t.Errorf("verbose error severity = %q, want medium", first.Severity)
	}
	if !strings.Contains(first.Evidence, "java-stack-trace") {
		t.Errorf("evidence should name the marker that matched: %q", first.Evidence)
	}
	if !strings.Contains(first.Evidence, "confidence=heuristic") {
		t.Errorf("a body pattern is heuristic, not proof: %q", first.Evidence)
	}

	quietFake := passiveStaticSite(passiveRoute{status: 404, header: passiveHeader("Content-Type", "text/plain"), body: "Not Found"})
	quietFindings, _ := passiveScan(t, "https://example.com", quietFake, PassiveOptions{})
	if passiveHasCheck(quietFindings, passiveCheckIDError) {
		t.Errorf("a plain 404 must not look like a stack trace: %+v", passiveWithCheck(quietFindings, passiveCheckIDError))
	}
}

func TestPassiveVerboseErrorsSampledPerMarker(t *testing.T) {
	bodies := map[string]string{
		"php-fatal-error":    "<html><body>Fatal error: Uncaught Error: boom in /var/www/index.php:12</body></html>",
		"python-traceback":   "<html><body>\nTraceback (most recent call last):\n  File \"app.py\", line 1, in <module>\n</body></html>",
		"mysql-syntax-error": "<html><body>SQLSTATE[42000]: Syntax error or access violation</body></html>",
	}
	for marker, body := range bodies {
		t.Run(marker, func(t *testing.T) {
			fake := passiveStaticSite(passiveRoute{status: 500, header: passiveHeader("Content-Type", "text/html"), body: body})
			findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{})
			found := false
			for _, v := range passiveWithCheck(findings, passiveCheckIDError) {
				if v.Parameter == marker {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected a %s finding, got %+v", marker, passiveWithCheck(findings, passiveCheckIDError))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A deliberately broken site, used to pin global invariants
// ---------------------------------------------------------------------------

// passiveTestAllCheckIDs is the complete check inventory. The rich-site test
// asserts every one of them fires at least once, so a check that stops
// emitting (or a constant that drifts) fails a test instead of silently
// disappearing from reports.
var passiveTestAllCheckIDs = []string{
	passiveCheckIDHeaders,
	passiveCheckIDCSP,
	passiveCheckIDClickjack,
	passiveCheckIDHSTS,
	passiveCheckIDCookie,
	passiveCheckIDPrefix,
	passiveCheckIDJWTAlg,
	passiveCheckIDJWTExp,
	passiveCheckIDJWTCrypto,
	passiveCheckIDCache,
	passiveCheckIDHost,
	passiveCheckIDMeta,
	passiveCheckIDArtifact,
	passiveCheckIDSrcMap,
	passiveCheckIDMixed,
	passiveCheckIDSRI,
	passiveCheckIDBanner,
	passiveCheckIDComment,
	passiveCheckIDError,
}

// passiveCheckIDOf strips the numeric suffix from a finding ID.
func passiveCheckIDOf(v Vulnerability) string {
	if i := strings.LastIndex(v.ID, "-"); i > 0 {
		return v.ID[:i]
	}
	return v.ID
}

// passiveRichSite answers a small site that is broken in every way this family
// looks for. It is the fixture for the invariant tests.
func passiveRichSite(t *testing.T) *passiveFakeRequester {
	t.Helper()
	weak := passiveTestJWT(t, `{"alg":"none","typ":"JWT"}`, `{"sub":"1"}`)
	symmetric := passiveTestJWT(t, `{"alg":"HS256","typ":"JWT"}`, `{"sub":"3","exp":4102444800}`)
	asymmetric := passiveTestJWT(t, `{"alg":"RS256","typ":"JWT"}`, `{"sub":"2","exp":4102444800}`)
	home := passiveTestPage("Home", strings.Join([]string{
		`<script src="/app.js"></script>`,
		`<script src="http://cdn.example.net/a.js"></script>`,
		`<script src="https://cdn.example.net/b.js"></script>`,
		`<!-- debug: password=Hunter2Hunter -->`,
		`<p>` + weak + `</p><p>` + symmetric + `</p><p>` + asymmetric + `</p>`,
	}, ""))
	routes := map[string]passiveRoute{
		"/": {
			status: 200,
			header: passiveHeader(
				"Content-Type", "text/html; charset=utf-8",
				"Content-Security-Policy", "default-src *",
				"Cache-Control", "public, max-age=7200",
				"Set-Cookie", "sid=RICHVALUE",
				"Server", "nginx/1.2.3",
			),
			body: home,
		},
		"/admin": {
			status: 200,
			header: passiveHeader(
				"Content-Type", "text/html; charset=utf-8",
				"Set-Cookie", "__Host-admin=1; Path=/admin",
			),
			body: passiveTestPage("Admin", "<h1>admin</h1>"),
		},
		"/robots.txt": {status: 200, header: passiveHeader("Content-Type", "text/plain"), body: "User-agent: *\nDisallow: /admin\n"},
		"/Dockerfile": {status: 200, header: passiveHeader("Content-Type", "text/plain"), body: "FROM alpine:3.19\n"},
		"/app.js":     {status: 200, header: passiveHeader("Content-Type", "application/javascript"), body: "console.log(1)"},
		"/app.js.map": {status: 200, header: passiveHeader("Content-Type", "application/json"),
			body: `{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}`},
	}
	// The fallback is what the soft-404 controls see, and it leaks a stack trace.
	fallback := passiveRoute{status: 404, header: passiveHeader("Content-Type", "text/plain"),
		body: "Fatal error: uncaught Error in /srv/app/index.php:12"}
	return &passiveFakeRequester{handler: func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Host == passiveHostCanary:
			return passiveTestResponse(302, passiveHeader("Location", "https://"+passiveHostCanary+"/login?reset=abcdefghij"), ""), nil
		case req.Header.Get("X-Forwarded-Host") == passiveHostCanary:
			return passiveTestResponse(200, passiveHTMLRoute("home").header, "welcome to "+passiveHostCanary), nil
		}
		if route, ok := routes[req.URL.Path]; ok {
			return passiveTestResponse(route.status, route.header, route.body), nil
		}
		return passiveTestResponse(fallback.status, fallback.header, fallback.body), nil
	}}
}

func TestPassiveRichSiteFindingsAreWellFormed(t *testing.T) {
	fake := passiveRichSite(t)
	findings, notes := passiveScan(t, "https://example.com", fake, PassiveOptions{Paths: []string{"/", "/admin"}})
	if len(findings) < 12 {
		t.Fatalf("the rich fixture should produce a substantial report, got %d findings", len(findings))
	}

	seen := map[string]bool{}
	ids := map[string]bool{}
	for _, v := range findings {
		checkID := passiveCheckIDOf(v)
		seen[checkID] = true

		if v.ID == "" || checkID == v.ID {
			t.Errorf("finding ID %q does not carry a check prefix", v.ID)
		}
		if ids[v.ID] {
			t.Errorf("duplicate finding ID %q", v.ID)
		}
		ids[v.ID] = true

		switch v.Severity {
		case "info", "low", "medium", "high":
		default:
			t.Errorf("%s has an unknown severity %q", v.ID, v.Severity)
		}
		if v.CVSS != passiveCVSSFor(v.Severity) {
			t.Errorf("%s severity %q carries CVSS %v, want %v", v.ID, v.Severity, v.CVSS, passiveCVSSFor(v.Severity))
		}
		if !strings.HasPrefix(v.Evidence, "confidence=") {
			t.Fatalf("%s evidence does not lead with a confidence level: %q", v.ID, v.Evidence)
		}
		level := strings.TrimPrefix(strings.SplitN(v.Evidence, ";", 2)[0], "confidence=")
		if !passiveConfidenceLevels[level] {
			t.Errorf("%s uses confidence %q, which is not in the vocabulary", v.ID, level)
		}
		if !strings.Contains(v.Evidence, "False-positive check: ") {
			t.Errorf("%s evidence has no false-positive note: %q", v.ID, v.Evidence)
		}
		for field, value := range map[string]string{
			"Title": v.Title, "CWE": v.CWE, "Category": v.Category,
			"Impact": v.Impact, "Remediation": v.Remediation, "URL": v.URL,
		} {
			if strings.TrimSpace(value) == "" {
				t.Errorf("%s has an empty %s", v.ID, field)
			}
		}
		if len(v.References) == 0 {
			t.Errorf("%s carries no references", v.ID)
		}
		parsed, err := url.Parse(v.URL)
		if err != nil {
			t.Errorf("%s has an unparseable URL %q", v.ID, v.URL)
			continue
		}
		if !strings.EqualFold(parsed.Host, "example.com") {
			t.Errorf("%s points at a foreign host %q", v.ID, parsed.Host)
		}
		if passiveSeverityRank(v.Severity) >= 5 {
			t.Errorf("%s has a severity that ranks as unknown", v.ID)
		}
	}

	for _, id := range passiveTestAllCheckIDs {
		if !seen[id] {
			t.Errorf("check %s produced no finding on the rich fixture", id)
		}
	}

	for _, note := range notes {
		if note.Err == "" {
			t.Errorf("note without an error message: %+v", note)
		}
	}
}

func TestPassiveFindingsAreSortedBySeverity(t *testing.T) {
	fake := passiveRichSite(t)
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{Paths: []string{"/", "/admin"}})
	if len(findings) < 2 {
		t.Fatalf("need at least two findings, got %d", len(findings))
	}
	for i := 1; i < len(findings); i++ {
		prev, cur := findings[i-1], findings[i]
		if passiveSeverityRank(prev.Severity) > passiveSeverityRank(cur.Severity) {
			t.Fatalf("finding %d (%s) is more severe than %d (%s): not sorted", i-1, prev.Severity, i, cur.Severity)
		}
	}
}

func TestPassiveSortIsDeterministic(t *testing.T) {
	key := func(v Vulnerability) string {
		return v.Severity + "|" + v.URL + "|" + v.Title + "|" + v.Parameter
	}

	first, _ := passiveScan(t, "https://example.com", passiveRichSite(t), PassiveOptions{Paths: []string{"/", "/admin"}})
	second, _ := passiveScan(t, "https://example.com", passiveRichSite(t), PassiveOptions{Paths: []string{"/", "/admin"}})
	if len(first) != len(second) {
		t.Fatalf("two identical scans returned %d and %d findings", len(first), len(second))
	}
	for i := range first {
		if key(first[i]) != key(second[i]) {
			t.Fatalf("finding %d differs between runs:\n  %s\n  %s", i, key(first[i]), key(second[i]))
		}
	}
}

func TestPassiveDedupIsPerCheckAndURL(t *testing.T) {
	// The same cross-origin script twice is one finding, not two.
	// The same banner on two paths is two findings, because the URL differs.
	dup := passiveTestPage("Home", `<script src="https://cdn.example.net/b.js"></script><script src="https://cdn.example.net/b.js"></script>`)
	header := passiveHeader("Content-Type", "text/html; charset=utf-8", "Server", "nginx/1.2.3")
	fake := passiveSite(passiveNotFoundRoute(), map[string]passiveRoute{
		"/":     {status: 200, header: header, body: dup},
		"/home": {status: 200, header: header, body: dup},
	})
	findings, _ := passiveScan(t, "https://example.com", fake, PassiveOptions{Paths: []string{"/", "/home"}})

	if got := passiveWithCheck(findings, passiveCheckIDSRI); len(got) != 2 {
		t.Errorf("expected one SRI finding per path, got %d: %+v", len(got), got)
	}
	banner := passiveWithCheck(findings, passiveCheckIDBanner)
	var serverBanners int
	for _, v := range banner {
		if v.Parameter == "Server" {
			serverBanners++
		}
	}
	if serverBanners != 2 {
		t.Errorf("expected the same banner on two paths to stay two findings, got %d", serverBanners)
	}
}

// ---------------------------------------------------------------------------
// Probe notes, refusals and panic safety
// ---------------------------------------------------------------------------

func TestPassiveRefusalsBecomeNotes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{name: "out of scope", err: ErrOutOfScope, want: "ErrOutOfScope"},
		{name: "budget", err: fmt.Errorf("guard: %w", ErrBudgetExhausted), want: "ErrBudgetExhausted"},
		{name: "rate limit", err: ErrRateLimited, want: "ErrRateLimited"},
		{name: "dry run", err: ErrDryRun, want: "ErrDryRun"},
		{name: "unknown", err: errors.New("dial tcp: connection refused"), want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &passiveFakeRequester{refuse: tc.err}
			findings, notes := passiveScan(t, "https://example.com", fake, PassiveOptions{})
			if len(findings) != 0 {
				t.Fatalf("a refused scan produced findings: %+v", findings)
			}
			if len(notes) == 0 {
				t.Fatalf("a refusal must be recorded as a note")
			}
			for _, note := range notes {
				if note.Sentinel != tc.want {
					t.Errorf("note sentinel = %q, want %q (%+v)", note.Sentinel, tc.want, note)
				}
			}
			if fake.requested("example.com") {
				t.Error("a refused probe must not reach Do")
			}
		})
	}
}

func TestPassiveScanAllSurvivesPanickingRequester(t *testing.T) {
	fake := &passiveFakeRequester{panicOnDo: true}
	scanner, err := NewPassiveScanner("https://example.com", fake, PassiveOptions{})
	if err != nil {
		t.Fatalf("NewPassiveScanner: %v", err)
	}
	var findings []Vulnerability
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ScanAll let a panic escape: %v", r)
			}
		}()
		findings = scanner.ScanAll(context.Background())
	}()
	if len(findings) != 0 {
		t.Fatalf("a panicking requester should produce no findings, got %+v", findings)
	}
	notes := scanner.Notes()
	if len(notes) == 0 {
		t.Fatal("the recovered panics should be recorded as notes")
	}
	found := false
	for _, note := range notes {
		if strings.Contains(note.Err, "panic") {
			found = true
		}
	}
	if !found {
		t.Errorf("no note mentions the panic: %+v", notes)
	}
}

func TestPassiveScanAllToleratesNilAndCancelledContext(t *testing.T) {
	fake := passiveStaticSite(passiveHTMLRoute(passiveTestPage("Home", "<h1>home</h1>")))
	scanner, err := NewPassiveScanner("https://example.com", fake, PassiveOptions{})
	if err != nil {
		t.Fatalf("NewPassiveScanner: %v", err)
	}
	if findings := scanner.ScanAll(nil); len(findings) == 0 {
		t.Error("a nil context must behave like context.Background()")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	before := len(fake.fetched())
	if findings := scanner.ScanAll(cancelled); len(findings) != 0 {
		t.Errorf("a cancelled context must produce no findings, got %+v", findings)
	}
	if len(fake.fetched()) != before {
		t.Error("a cancelled context must not issue new probes")
	}
}

func TestPassiveNilScannerIsSafe(t *testing.T) {
	var scanner *PassiveScanner
	if findings := scanner.ScanAll(context.Background()); findings != nil {
		t.Errorf("a nil scanner must return nil, got %+v", findings)
	}
	if notes := scanner.Notes(); notes != nil {
		t.Errorf("a nil scanner must return no notes, got %+v", notes)
	}
}
