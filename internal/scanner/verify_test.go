package scanner

// verify_test.go covers the false-positive verifier with per-class httptest
// mock servers: SQLi (error + boolean), XSS (raw vs escaped), traversal,
// open redirect, deterministic header/cookie/info re-checks, dead targets,
// and the Annotate no-mutation contract.

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ConfidenceBadge
// ---------------------------------------------------------------------------

func TestVerifConfidenceBadge(t *testing.T) {
	cases := map[Confidence]string{
		ConfConfirmed:    "[VERIFIED]",
		ConfProbable:     "[PROBABLE]",
		ConfPossible:     "[UNVERIFIED]",
		Confidence(""):   "[UNVERIFIED]",
		Confidence("??"): "[UNVERIFIED]",
	}
	for in, want := range cases {
		if got := ConfidenceBadge(in); got != want {
			t.Errorf("ConfidenceBadge(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// SQL injection
// ---------------------------------------------------------------------------

func TestVerifSQLiErrorBasedConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") || strings.Contains(id, `"`) {
			fmt.Fprint(w, "Warning: mysqli_fetch_array() expects parameter 1, "+
				"SQLSTATE[42000]: Syntax error or access violation")
			return
		}
		fmt.Fprint(w, "<html>catalog page ok</html>")
	}))
	defer srv.Close()

	v := NewVerifier(2 * time.Second)
	vuln := Vulnerability{
		CWE:       "CWE-89",
		URL:       srv.URL + "/item?id=" + url.QueryEscape(`' OR 1=1--`),
		Parameter: "id",
		Evidence:  "Payload triggered SQL error response",
		PoC:       "GET /item?id=' OR 1=1--",
	}
	got := v.Check(srv.URL, vuln)
	if got.Confidence != ConfConfirmed {
		t.Fatalf("SQLi error page graded %q, want confirmed (evidence: %s)", got.Confidence, got.Evidence)
	}
	if got.Evidence == "" {
		t.Fatal("confirmed verdict must explain why")
	}
}

func TestVerifSQLiBooleanDifferentialProbable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		switch {
		case strings.Contains(id, "AND 1=2"):
			fmt.Fprint(w, "<html>zero results empty list</html>")
		case strings.Contains(id, "AND 1=1"):
			fmt.Fprint(w, "<html>one result admin panel visible</html>")
		default:
			fmt.Fprint(w, "<html>home neutral page</html>")
		}
	}))
	defer srv.Close()

	v := NewVerifier(2 * time.Second)
	vuln := Vulnerability{
		CWE:       "CWE-89",
		URL:       srv.URL + "/list?id=" + url.QueryEscape("7 AND 1=1"),
		Parameter: "id",
		Evidence:  "Boolean behaviour suspected",
	}
	got := v.Check(srv.URL, vuln)
	if got.Confidence != ConfProbable {
		t.Fatalf("boolean differential graded %q, want probable (evidence: %s)", got.Confidence, got.Evidence)
	}
}

func TestVerifSQLiUnreproduciblePossible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>static welcome page</html>")
	}))
	defer srv.Close()

	v := NewVerifier(2 * time.Second)
	vuln := Vulnerability{
		CWE:       "CWE-89",
		URL:       srv.URL + "/?id=" + url.QueryEscape("' UNION SELECT NULL--"),
		Parameter: "id",
		Evidence:  "Scanner matched a generic 'syntax' word",
	}
	got := v.Check(srv.URL, vuln)
	if got.Confidence != ConfPossible {
		t.Fatalf("unreproducible SQLi graded %q, want possible (evidence: %s)", got.Confidence, got.Evidence)
	}
}

// ---------------------------------------------------------------------------
// XSS
// ---------------------------------------------------------------------------

func TestVerifXSSRawReflectionConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html>search results for: %s</html>", r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	v := NewVerifier(2 * time.Second)
	vuln := Vulnerability{
		CWE:       "CWE-79",
		URL:       srv.URL + "/search?q=" + url.QueryEscape(`<script>alert(1)</script>`),
		Parameter: "q",
		Evidence:  "Reflected payload found in response body",
	}
	got := v.Check(srv.URL, vuln)
	if got.Confidence != ConfConfirmed {
		t.Fatalf("raw reflection graded %q, want confirmed (evidence: %s)", got.Confidence, got.Evidence)
	}
}

func TestVerifXSSEscapedReflectionDowngraded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html>search results for: %s</html>", html.EscapeString(r.URL.Query().Get("q")))
	}))
	defer srv.Close()

	v := NewVerifier(2 * time.Second)
	vuln := Vulnerability{
		CWE:       "CWE-79",
		URL:       srv.URL + "/search?q=" + url.QueryEscape(`<script>alert(1)</script>`),
		Parameter: "q",
		Evidence:  "Reflected payload found in response body",
	}
	got := v.Check(srv.URL, vuln)
	if got.Confidence == ConfConfirmed {
		t.Fatalf("HTML-encoded reflection must NOT be confirmed (evidence: %s)", got.Evidence)
	}
	if got.Confidence != ConfPossible {
		t.Fatalf("escaped reflection graded %q, want downgraded to possible (evidence: %s)", got.Confidence, got.Evidence)
	}
	if !strings.Contains(got.Evidence, "encoded") && !strings.Contains(got.Evidence, "&lt;") {
		t.Errorf("evidence should mention encoding, got: %s", got.Evidence)
	}
}

// ---------------------------------------------------------------------------
// Path traversal
// ---------------------------------------------------------------------------

func TestVerifTraversalConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		if strings.Contains(f, "..") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/usr/sbin/nologin")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	v := NewVerifier(2 * time.Second)
	vuln := Vulnerability{
		CWE:      "CWE-22",
		URL:      srv.URL + "/view?file=" + url.QueryEscape("../../../etc/passwd"),
		Evidence: "Payload returned system file content",
	}
	got := v.Check(srv.URL, vuln)
	if got.Confidence != ConfConfirmed {
		t.Fatalf("traversal with passwd content graded %q, want confirmed (evidence: %s)", got.Confidence, got.Evidence)
	}
}

// ---------------------------------------------------------------------------
// Open redirect
// ---------------------------------------------------------------------------

func TestVerifOpenRedirectConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("next") != "" {
			w.Header().Set("Location", "//evil.com/account")
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "<html>login page</html>")
	}))
	defer srv.Close()

	v := NewVerifier(2 * time.Second)
	vuln := Vulnerability{
		CWE:       "CWE-601",
		URL:       srv.URL + "/login?next=" + url.QueryEscape("//evil.com/account"),
		Parameter: "next",
		Evidence:  "Parameter caused redirect off-site",
	}
	got := v.Check(srv.URL, vuln)
	if got.Confidence != ConfConfirmed {
		t.Fatalf("external redirect graded %q, want confirmed (evidence: %s)", got.Confidence, got.Evidence)
	}
}

// ---------------------------------------------------------------------------
// Deterministic classes
// ---------------------------------------------------------------------------

func TestVerifMissingHeaderRecheckConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>hello</html>") // deliberately no security headers
	}))
	defer srv.Close()

	v := NewVerifier(2 * time.Second)
	vuln := Vulnerability{
		CWE:      "CWE-693",
		URL:      srv.URL,
		Title:    "Missing/Weak Security Header: Strict-Transport-Security",
		Evidence: "Missing HSTS header - allows HTTP downgrade attacks and SSL stripping",
	}
	got := v.Check(srv.URL, vuln)
	if got.Confidence != ConfConfirmed {
		t.Fatalf("absent header claim graded %q, want confirmed (evidence: %s)", got.Confidence, got.Evidence)
	}
}

func TestVerifMissingHeaderFixedDowngraded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff") // condition has been fixed
		fmt.Fprint(w, "<html>hello</html>")
	}))
	defer srv.Close()

	v := NewVerifier(2 * time.Second)
	vuln := Vulnerability{
		CWE:      "CWE-16",
		URL:      srv.URL,
		Title:    "Missing/Weak Security Header: X-Content-Type-Options",
		Evidence: "Missing X-Content-Type-Options - MIME type sniffing possible",
	}
	got := v.Check(srv.URL, vuln)
	if got.Confidence != ConfPossible {
		t.Fatalf("fixed header finding graded %q, want possible (evidence: %s)", got.Confidence, got.Evidence)
	}
}

func TestVerifCookieFlagRecheckConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/"}) // no Secure flag
		fmt.Fprint(w, "<html>dashboard</html>")
	}))
	defer srv.Close()

	v := NewVerifier(2 * time.Second)
	vuln := Vulnerability{
		CWE:       "CWE-614",
		URL:       srv.URL,
		Title:     "Cookie 'sid' Missing Secure Flag",
		Parameter: "sid",
		Evidence:  "Cookie 'sid' set without Secure flag",
	}
	got := v.Check(srv.URL, vuln)
	if got.Confidence != ConfConfirmed {
		t.Fatalf("cookie flag claim graded %q, want confirmed (evidence: %s)", got.Confidence, got.Evidence)
	}
}

func TestVerifInfoDisclosureRecheckConfirmed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "APP_KEY=base64keyhere\nDB_PASSWORD=hunter2\n")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v := NewVerifier(2 * time.Second)
	vuln := Vulnerability{
		CWE:      "CWE-200",
		URL:      srv.URL + "/.env",
		Title:    "Exposed .env File",
		Evidence: "HTTP 200 at /.env with content matching 'DB_PASSWORD='",
	}
	got := v.Check(srv.URL, vuln)
	if got.Confidence != ConfConfirmed {
		t.Fatalf(".env disclosure graded %q, want confirmed (evidence: %s)", got.Confidence, got.Evidence)
	}
}

// ---------------------------------------------------------------------------
// Network failure handling
// ---------------------------------------------------------------------------

func TestVerifUnreachableTargetPossible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	target := srv.URL
	srv.Close() // target is now dead

	v := NewVerifier(2 * time.Second)
	got := v.Check(target, Vulnerability{CWE: "CWE-79", URL: target + "/?q=x", Parameter: "q"})
	if got.Confidence != ConfPossible {
		t.Fatalf("dead target graded %q, want possible (never silently dropped)", got.Confidence)
	}
	if !strings.Contains(strings.ToLower(got.Evidence), "unreachab") {
		t.Errorf("evidence should note the verification was unreachable, got: %s", got.Evidence)
	}
}

// ---------------------------------------------------------------------------
// Other classes
// ---------------------------------------------------------------------------

func TestVerifCommandInjectionSignatureProbable(t *testing.T) {
	v := NewVerifier(2 * time.Second)

	withSig := Vulnerability{
		CWE:      "CWE-78",
		URL:      "http://127.0.0.1:1/ping?host=x",
		PoC:      "GET /ping?host=;id -> uid=33(root) gid=33(root)",
		Evidence: "Command output observed",
	}
	if got := v.Check("", withSig); got.Confidence != ConfProbable {
		t.Fatalf("command-output signature graded %q, want probable (evidence: %s)", got.Confidence, got.Evidence)
	}

	plain := Vulnerability{CWE: "CWE-918", URL: "http://127.0.0.1:1/fetch?url=x"}
	if got := v.Check("", plain); got.Confidence != ConfPossible {
		t.Fatalf("plain SSRF heuristic graded %q, want possible (evidence: %s)", got.Confidence, got.Evidence)
	}
}

// ---------------------------------------------------------------------------
// Annotate
// ---------------------------------------------------------------------------

func TestVerifAnnotateDoesNotMutateInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>hello</html>") // no security headers -> HSTS claim verifies
	}))
	defer srv.Close()

	input := []Vulnerability{
		{
			CWE:      "CWE-693",
			URL:      srv.URL,
			Title:    "Missing/Weak Security Header: Strict-Transport-Security",
			Evidence: "Missing HSTS header - allows HTTP downgrade attacks and SSL stripping",
		},
		{
			CWE:      "CWE-999",
			URL:      srv.URL,
			Title:    "Exotic Heuristic Finding",
			Evidence: "original evidence text",
		},
	}

	// Deep-copy input titles/evidence so we can prove no mutation happened.
	before := make([]Vulnerability, len(input))
	copy(before, input)

	v := NewVerifier(2 * time.Second)
	out := v.Annotate(srv.URL, input)

	if len(out) != len(input) {
		t.Fatalf("Annotate returned %d findings, want %d", len(out), len(input))
	}

	want0 := "[VERIFIED] Missing/Weak Security Header: Strict-Transport-Security"
	if out[0].Title != want0 {
		t.Errorf("out[0].Title = %q, want %q", out[0].Title, want0)
	}
	want1 := "[UNVERIFIED] Exotic Heuristic Finding"
	if out[1].Title != want1 {
		t.Errorf("out[1].Title = %q, want %q", out[1].Title, want1)
	}
	if !strings.Contains(out[0].Evidence, "verification:") {
		t.Errorf("out[0].Evidence not enriched: %q", out[0].Evidence)
	}

	for i := range input {
		if !reflect.DeepEqual(input[i], before[i]) {
			t.Fatalf("input element %d was mutated:\nbefore: %+v\nafter:  %+v", i, before[i], input[i])
		}
	}
}
