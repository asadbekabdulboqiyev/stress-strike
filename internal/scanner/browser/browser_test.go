package browser

import (
	"testing"
)

func TestExtractEndpoints(t *testing.T) {
	html := `
<html>
<body>
<a href="/about">About</a>
<a href="https://example.com/login">Login</a>
<a href="mailto:test@example.com">Email</a>
<a href="javascript:void(0)">JS Link</a>
<form action="/search" method="GET">
<input name="q">
<input name="page">
</form>
<form action="/api/submit" method="POST">
<input name="token">
<input name="data">
</form>
</body>
</html>
`

	endpoints := ExtractEndpoints(html, "https://example.com")

	// Should find links and forms
	byURL := make(map[string]Endpoint)
	for _, ep := range endpoints {
		byURL[ep.URL] = ep
	}

	// Check about link
	if _, ok := byURL["https://example.com/about"]; !ok {
		t.Error("expected /about link")
	}

	// Check login link
	if _, ok := byURL["https://example.com/login"]; !ok {
		t.Error("expected login link")
	}

	// Check GET search form
	searchEp, ok := byURL["https://example.com/search"]
	if !ok {
		t.Error("expected /search form")
	}
	if searchEp.Method != "GET" {
		t.Errorf("expected GET method, got %s", searchEp.Method)
	}
	foundQ := false
	for _, p := range searchEp.Params {
		if p == "q" {
			foundQ = true
		}
	}
	if !foundQ {
		t.Error("expected 'q' param in search form")
	}

	// Check POST submit form
	submitEp, ok := byURL["https://example.com/api/submit"]
	if !ok {
		t.Error("expected /api/submit form")
	}
	if submitEp.Method != "POST" {
		t.Errorf("expected POST method, got %s", submitEp.Method)
	}

	// Should NOT include mailto or javascript links
	if _, ok := byURL["mailto:test@example.com"]; ok {
		t.Error("should not include mailto link")
	}
	if _, ok := byURL["javascript:void(0)"]; ok {
		t.Error("should not include javascript link")
	}
}

func TestExtractEndpointsRelativeURLs(t *testing.T) {
	html := `<a href="/page">Page</a><a href="../sibling">Sibling</a>`
	endpoints := ExtractEndpoints(html, "https://example.com/dir/")

	byURL := make(map[string]bool)
	for _, ep := range endpoints {
		byURL[ep.URL] = true
	}

	if !byURL["https://example.com/page"] {
		t.Error("expected absolute /page URL")
	}
	if !byURL["https://example.com/sibling"] {
		t.Error("expected resolved sibling URL")
	}
}

func TestExtractEndpointsDedup(t *testing.T) {
	html := `<a href="/page">Page</a><a href="/page">Page again</a>`
	endpoints := ExtractEndpoints(html, "https://example.com")
	if len(endpoints) != 1 {
		t.Errorf("expected 1 deduplicated endpoint, got %d", len(endpoints))
	}
}

func TestExtractEndpointsEmpty(t *testing.T) {
	endpoints := ExtractEndpoints("", "https://example.com")
	if len(endpoints) != 0 {
		t.Errorf("expected 0 endpoints for empty HTML, got %d", len(endpoints))
	}
}
