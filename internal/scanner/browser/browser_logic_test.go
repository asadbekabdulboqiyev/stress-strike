package browser

// browser_logic_test.go — the browser package's pure logic plus one real-browser
// smoke test.
//
// This package was silently dead: New() ran its probe on the plain timeout
// context instead of the chromedp context, so every call failed with "invalid
// context", and ctx() cancelled the allocator before the caller used it. The
// crawler's JS-rendering path and the OAuth deep-login path therefore never
// worked. The smoke test below starts a real Chromium to prove the fix; it
// skips when no browser is installed.

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestExtractEndpointsPerFormParams(t *testing.T) {
	html := `
<form action="/search" method="GET">
  <input name="q">
  <input name="page">
</form>
<form method="POST" action="/api/submit">
  <input name="token">
  <input name="data">
</form>`

	endpoints := ExtractEndpoints(html, "https://example.com")

	byURL := make(map[string]Endpoint)
	for _, ep := range endpoints {
		byURL[ep.URL] = ep
	}

	search, ok := byURL["https://example.com/search"]
	if !ok {
		t.Fatal("expected /search form")
	}
	if !equalStrings(search.Params, []string{"q", "page"}) {
		t.Errorf("search params = %v, want [q page]", search.Params)
	}

	submit, ok := byURL["https://example.com/api/submit"]
	if !ok {
		t.Fatal("expected /api/submit form")
	}
	if !equalStrings(submit.Params, []string{"token", "data"}) {
		t.Errorf("submit params = %v, want [token data] — a form must not inherit another form's inputs", submit.Params)
	}
	if submit.Method != "POST" {
		t.Errorf("submit method = %q, want POST (attribute order must not matter)", submit.Method)
	}
}

// TestExtractEndpointsDedupIsPerMethod: a link and a GET form for the same URL
// are one endpoint; a link and a POST form are two.
func TestExtractEndpointsDedupIsPerMethod(t *testing.T) {
	html := `<a href="/transfer">Transfer</a><form action="/transfer" method="POST"></form>`
	endpoints := ExtractEndpoints(html, "https://example.com")

	if len(endpoints) != 2 {
		t.Fatalf("endpoints = %v, want a GET link and a POST form", endpoints)
	}
	methods := map[string]bool{}
	for _, ep := range endpoints {
		methods[ep.Method] = true
	}
	if !methods["GET"] || !methods["POST"] {
		t.Errorf("methods = %v, want both GET and POST", methods)
	}
}

func TestExtractEndpointsUnterminatedFormDoesNotLeak(t *testing.T) {
	html := `<form action="/one"><input name="a"><form action="/two"><input name="b"></form>`
	endpoints := ExtractEndpoints(html, "https://example.com")

	for _, ep := range endpoints {
		if ep.URL == "https://example.com/one" {
			if len(ep.Params) != 1 || ep.Params[0] != "a" {
				t.Errorf("/one params = %v, want [a]", ep.Params)
			}
		}
	}
}

func TestExtractEndpointsAttributeShapes(t *testing.T) {
	html := `<form action='/single' method=post><input name=unquoted required></form>`
	endpoints := ExtractEndpoints(html, "https://example.com")

	if len(endpoints) != 1 {
		t.Fatalf("endpoints = %v, want one", endpoints)
	}
	ep := endpoints[0]
	if ep.URL != "https://example.com/single" {
		t.Errorf("url = %q, want single-quoted action resolved", ep.URL)
	}
	if ep.Method != "POST" {
		t.Errorf("method = %q, want POST from an unquoted attribute", ep.Method)
	}
	if !equalStrings(ep.Params, []string{"unquoted"}) {
		t.Errorf("params = %v, want [unquoted]", ep.Params)
	}
}

func TestParseTagAttrs(t *testing.T) {
	attrs := parseTagAttrs(`<form action="/a" method="POST" novalidate class='x y'>`)
	if attrs["action"] != "/a" {
		t.Errorf("action = %q", attrs["action"])
	}
	if attrs["method"] != "POST" {
		t.Errorf("method = %q", attrs["method"])
	}
	if attrs["class"] != "x y" {
		t.Errorf("class = %q", attrs["class"])
	}
	if _, ok := attrs["novalidate"]; !ok {
		t.Error("a value-less attribute should still be recorded")
	}
	if _, ok := attrs["form"]; ok {
		t.Error("the tag name must not become an attribute")
	}
}

func TestLoginSucceeded(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		successMatch string
		want         bool
	}{
		{"explicit match found", "<h1>Welcome, Asad</h1>", "Welcome", true},
		{"explicit match missing", "<h1>Login</h1>", "Welcome", false},
		{"heuristic: still on login page", "<h2>Sign in</h2><input name=password>", "", false},
		{"heuristic: password field left", "<input type=password>", "", false},
		{"heuristic: moved on", "<h1>Dashboard</h1><p>Your reports</p>", "", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := loginSucceeded(c.body, c.successMatch); got != c.want {
				t.Errorf("loginSucceeded(%q, %q) = %v, want %v", c.body, c.successMatch, got, c.want)
			}
		})
	}
}

// --- real-browser smoke test -------------------------------------------------

// chromeInstalled reports whether a Chrome/Chromium binary the allocator can
// find is present. CI installs Chrome; a machine without one skips.
func chromeInstalled() bool {
	candidates := []string{
		"google-chrome",
		"google-chrome-stable",
		"chromium",
		"chromium-browser",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil && p != "" {
			return true
		}
		if _, err := os.Stat(c); err == nil {
			return true
		}
	}
	return false
}

// TestNewAndPageRealBrowser proves the context wiring end to end: without it,
// New() fails with "invalid context" and Page() cancels the allocator before
// navigating.
func TestNewAndPageRealBrowser(t *testing.T) {
	if !chromeInstalled() {
		t.Skip("no Chrome/Chromium binary on this machine")
	}

	b, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if b == nil {
		t.Fatal("New returned nil without an error")
	}

	html, err := b.Page("data:text/html,<h1>rendered</h1>", 20*time.Second)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if !strings.Contains(html, "rendered") {
		t.Errorf("rendered HTML = %q, want it to contain the heading text", html)
	}
}

func TestEnsureAvailable(t *testing.T) {
	if !chromeInstalled() {
		t.Skip("no Chrome/Chromium binary on this machine")
	}
	if err := EnsureAvailable(); err != nil {
		t.Fatalf("EnsureAvailable: %v", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
