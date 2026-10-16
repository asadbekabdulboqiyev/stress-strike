package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// owaspTestServer returns a Server whose policy and audit trail live in a
// throwaway directory, so a test can never read the operator's real policy or
// write into their real ~/.stress-strike audit log.
func owaspTestServer(t *testing.T) *Server {
	t.Helper()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())
	t.Setenv("STRESS_STRIKE_POLICY", "")
	t.Setenv("STRESS_STRIKE_ALLOW", "")
	t.Setenv("STRESS_STRIKE_AUDIT_LOG", "")
	return NewServer()
}

func owaspPost(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/owasp/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleOWASPScan(rec, req)
	return rec
}

func owaspDecode(t *testing.T, rec *httptest.ResponseRecorder) OWASPScanResult {
	t.Helper()
	var out OWASPScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, rec.Body.String())
	}
	return out
}

// --- status mapping ---------------------------------------------------------

// The whole honesty of the feature rests on this function: nothing may turn a
// category we never tested into a PASS.
func TestOWASPStatusNeverManufacturesPass(t *testing.T) {
	cases := []struct {
		checkerStatus string
		coverage      int
		want          string
	}{
		{"", 0, "NOT TESTED"},
		{"", 7, "NOT TESTED"},
		{"PASS", 0, "NOT TESTED"},
		{"FAIL", 0, "NOT TESTED"},
		{"WARNING", 0, "NOT TESTED"},
		{"NOT TESTED", 9, "NOT TESTED"}, // explicit refusal beats coverage
		{"PASS", 1, "PASS"},
		{"FAIL", 1, "FAIL"},
		{"WARNING", 1, "WARNING"},
	}
	for _, c := range cases {
		got := owaspStatus(c.checkerStatus, c.coverage)
		if got != c.want {
			t.Errorf("owaspStatus(%q, %d) = %q, want %q", c.checkerStatus, c.coverage, got, c.want)
		}
	}

	// Property, not just examples: no input combination may yield PASS unless
	// the checker itself said PASS and a probe actually reached the server.
	checkerStatuses := []string{"", "PASS", "FAIL", "WARNING", "NOT TESTED", "nonsense"}
	for _, status := range checkerStatuses {
		for coverage := 0; coverage <= 3; coverage++ {
			got := owaspStatus(status, coverage)
			if got == "PASS" && (status != "PASS" || coverage <= 0) {
				t.Fatalf("owaspStatus(%q, %d) = PASS, which is manufactured", status, coverage)
			}
			if got != "PASS" && got != "FAIL" && got != "WARNING" && got != "NOT TESTED" {
				t.Fatalf("owaspStatus(%q, %d) = %q, not a known status", status, coverage, got)
			}
		}
	}
}

func TestOWASPWorstStatus(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		{"", "PASS", "PASS"},
		{"PASS", "FAIL", "FAIL"},
		{"FAIL", "WARNING", "FAIL"},
		{"WARNING", "PASS", "WARNING"},
		{"FAIL", "FAIL", "FAIL"},
		{"PASS", "PASS", "PASS"},
	}
	for _, c := range cases {
		if got := owaspWorstStatus(c.a, c.b); got != c.want {
			t.Errorf("owaspWorstStatus(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
		// Merging is symmetric: scanning paths in either order gives the same verdict.
		if got := owaspWorstStatus(c.b, c.a); got != c.want {
			t.Errorf("owaspWorstStatus(%q, %q) = %q, want %q (not symmetric)", c.b, c.a, got, c.want)
		}
	}
}

func TestOWASPGrade(t *testing.T) {
	cases := map[int]string{0: "F", 59: "F", 60: "D", 70: "C", 80: "B", 90: "A", 100: "A"}
	for score, want := range cases {
		if got := owaspGrade(score); got != want {
			t.Errorf("owaspGrade(%d) = %q, want %q", score, got, want)
		}
	}
}

func TestOWASPSplitConfidence(t *testing.T) {
	cases := []struct {
		in             string
		wantConfidence string
		wantRest       string
	}{
		{"confidence=confirmed; server echoed payload", "confirmed", "server echoed payload"},
		{"confidence=heuristic; only", "heuristic", "only"},
		{"confidence=high", "high", ""},
		{"no prefix here", "", "no prefix here"},
		{"", "", ""},
	}
	for _, c := range cases {
		conf, rest := owaspSplitConfidence(c.in)
		if conf != c.wantConfidence || rest != c.wantRest {
			t.Errorf("owaspSplitConfidence(%q) = (%q, %q), want (%q, %q)",
				c.in, conf, rest, c.wantConfidence, c.wantRest)
		}
	}
}

func TestOWASPToFinding(t *testing.T) {
	f := owaspToFinding(scanner.Vulnerability{
		ID:        "PSV-001",
		Severity:  "high",
		Title:     "Missing security headers",
		Parameter: "X-Frame-Options",
		CWE:       "CWE-693",
		Evidence:  "confidence=high; response lacked X-Frame-Options on /login",
	})
	if f.Confidence != "high" {
		t.Errorf("Confidence = %q, want %q", f.Confidence, "high")
	}
	if strings.HasPrefix(f.Evidence, "confidence=") {
		t.Errorf("Evidence still carries the prefix: %q", f.Evidence)
	}
	if f.Evidence != "response lacked X-Frame-Options on /login" {
		t.Errorf("Evidence = %q, observation lost", f.Evidence)
	}
	if f.Title != "Missing security headers" || f.CWE != "CWE-693" {
		t.Errorf("title/CWE not carried through: %+v", f)
	}
}

// --- input validation -------------------------------------------------------

func TestOWASPValidateTarget(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // expected normalized URL, "" means error expected
	}{
		{"bare host gets https", "example.com", "https://example.com"},
		{"https kept", "https://example.com", "https://example.com"},
		{"http kept", "http://example.com:8080", "http://example.com:8080"},
		{"whitespace trimmed", "  https://example.com  ", "https://example.com"},
		{"fragment dropped", "https://example.com/a#frag", "https://example.com/a"},
		{"port kept", "https://example.com:8443/app", "https://example.com:8443/app"},
		{"empty", "", ""},
		{"only spaces", "   ", ""},
		{"ftp rejected", "ftp://example.com", ""},
		{"file rejected", "file:///etc/passwd", ""},
		{"gopher rejected", "gopher://example.com", ""},
		{"no host", "https://", ""},
		{"credentials rejected", "https://user:pass@example.com", ""},
		{"garbage", "http://exa mple.com/%zz", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := owaspValidateTarget(c.in)
			if c.want == "" {
				if err == nil {
					t.Fatalf("owaspValidateTarget(%q) = %q, want an error", c.in, u)
				}
				return
			}
			if err != nil {
				t.Fatalf("owaspValidateTarget(%q): %v", c.in, err)
			}
			if u.String() != c.want {
				t.Errorf("owaspValidateTarget(%q) = %q, want %q", c.in, u, c.want)
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				t.Errorf("scheme %q escaped the http/https allow-list", u.Scheme)
			}
		})
	}
}

func TestOWASPValidatePaths(t *testing.T) {
	got, err := owaspValidatePaths(nil)
	if err != nil || got != nil {
		t.Fatalf("nil paths = (%v, %v), want (nil, nil)", got, err)
	}

	got, err = owaspValidatePaths([]string{"/", "/login", " /admin ", "/", "/admin"})
	if err != nil {
		t.Fatalf("valid paths: %v", err)
	}
	want := []string{"/", "/login", "/admin"}
	if len(got) != len(want) {
		t.Fatalf("dedup/trim produced %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("paths[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	for _, bad := range []struct {
		name  string
		paths []string
	}{
		{"relative", []string{"admin"}},
		{"absolute URL", []string{"https://evil.example/x"}},
		{"scheme smuggled", []string{"/ok", "http://evil.example"}},
		{"too many", make([]string, owaspMaxPaths+1)},
	} {
		t.Run(bad.name, func(t *testing.T) {
			if _, err := owaspValidatePaths(bad.paths); err == nil {
				t.Fatalf("owaspValidatePaths(%v) accepted, want an error", bad.paths)
			}
		})
	}
}

func TestOWASPValidateFlags(t *testing.T) {
	// Defaults: zero means "use the default", and the defaults must satisfy the
	// very rule they are checked against.
	rps, budget, timeout, err := owaspValidateFlags(&OWASPScanRequest{})
	if err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
	if rps != scanner.DefaultRPS {
		t.Errorf("default rps = %v, want %v", rps, scanner.DefaultRPS)
	}
	if budget != owaspDefaultBudget {
		t.Errorf("default budget = %d, want %d", budget, owaspDefaultBudget)
	}
	if timeout <= 0 || timeout > owaspMaxTimeout*1e9 {
		t.Errorf("default timeout = %v, out of range", timeout)
	}
	if float64(budget)/rps > owaspMaxScanSeconds {
		t.Fatalf("the defaults themselves exceed the %gs cap", owaspMaxScanSeconds)
	}

	for _, bad := range []struct {
		name string
		req  OWASPScanRequest
	}{
		{"negative rate", OWASPScanRequest{Rate: -1}},
		{"rate above max", OWASPScanRequest{Rate: owaspMaxRate + 1}},
		{"zero budget rejected as negative", OWASPScanRequest{Budget: -5}},
		{"budget above max", OWASPScanRequest{Budget: owaspMaxBudget + 1}},
		{"negative timeout", OWASPScanRequest{TimeoutSec: -1}},
		{"timeout above max", OWASPScanRequest{TimeoutSec: owaspMaxTimeout + 1}},
		// budget/rate = 2000s at rate 1: refused rather than held open.
		{"slow combination", OWASPScanRequest{Rate: 1, Budget: owaspMaxBudget}},
	} {
		t.Run(bad.name, func(t *testing.T) {
			if _, _, _, err := owaspValidateFlags(&bad.req); err == nil {
				t.Fatalf("owaspValidateFlags(%+v) accepted, want an error", bad.req)
			}
		})
	}

	// The fastest allowed combination must still be inside the cap.
	if _, _, _, err := owaspValidateFlags(&OWASPScanRequest{Rate: 20, Budget: owaspMaxBudget}); err != nil {
		t.Errorf("rate 20 with max budget rejected: %v", err)
	}
}

func TestOWASPFamilyOptions(t *testing.T) {
	all, err := owaspFamilyOptions(true, nil)
	if err != nil {
		t.Fatalf("all families: %v", err)
	}
	if !all.CRLFInjection || !all.BooleanSQLi || !all.TimeBasedSQLi ||
		!all.PathTraversal || !all.SSRFIndicators || !all.WriteMethodProbes {
		t.Fatalf("intrusive with no family list must enable every family: %+v", all)
	}

	one, err := owaspFamilyOptions(true, []string{"crlf"})
	if err != nil {
		t.Fatalf("single family: %v", err)
	}
	if !one.CRLFInjection {
		t.Error("crlf not enabled")
	}
	if one.BooleanSQLi || one.TimeBasedSQLi || one.PathTraversal ||
		one.SSRFIndicators || one.WriteMethodProbes {
		t.Errorf("selecting one family enabled others: %+v", one)
	}

	// Selecting a family is itself intrusive, so the caller may do it without
	// passing intrusive:true; the handler turns the request offensive either way.
	partial, err := owaspFamilyOptions(false, []string{"ssrf", "write-methods"})
	if err != nil {
		t.Fatalf("family list without intrusive flag: %v", err)
	}
	if !partial.SSRFIndicators || !partial.WriteMethodProbes {
		t.Errorf("selected families missing: %+v", partial)
	}
	if partial.CRLFInjection || partial.BooleanSQLi || partial.TimeBasedSQLi || partial.PathTraversal {
		t.Errorf("unselected families enabled: %+v", partial)
	}

	if _, err := owaspFamilyOptions(true, []string{"nope"}); err == nil {
		t.Error("unknown family accepted, want an error")
	}
	if _, err := owaspFamilyOptions(true, []string{"crlf", "bogus"}); err == nil {
		t.Error("family list with a bogus entry accepted, want an error")
	}
}

func TestOWASPScopeHost(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://example.com/app", "example.com"},
		{"https://example.com:8443/", "example.com"}, // bare host matches any port
		{"http://127.0.0.1:8080/", "127.0.0.1"},
		{"http://[::1]:8080/", "[::1]"}, // bracketed so the parser sees one host
	}
	for _, c := range cases {
		u, err := owaspValidateTarget(c.raw)
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if got := owaspScopeHost(u); got != c.want {
			t.Errorf("owaspScopeHost(%s) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestOWASPDedupe(t *testing.T) {
	got := dedupe([]string{"a", "", "b", "a", "b", "c"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("dedupe = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedupe[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if dedupe(nil) != nil {
		t.Error("dedupe(nil) should stay nil")
	}
	if out := dedupe([]string{"only"}); len(out) != 1 || out[0] != "only" {
		t.Errorf("dedupe single = %v", out)
	}
}

// --- request handling -------------------------------------------------------

func TestOWASPScanRouteRegistered(t *testing.T) {
	s := owaspTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/owasp/scan", strings.NewReader(""))
	rec := httptest.NewRecorder()
	s.serveApp(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Fatal("/api/owasp/scan is not registered in serveApp")
	}
	// An empty body reaches the handler and fails validation there — which is
	// exactly the proof that the route is wired, not served as a 404/405.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body = %d, want 400 from the handler (got %s)", rec.Code, rec.Body.String())
	}
}

func TestOWASPScanRejectsBadRequests(t *testing.T) {
	s := owaspTestServer(t)

	t.Run("GET refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/owasp/scan", nil)
		rec := httptest.NewRecorder()
		s.handleOWASPScan(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET = %d, want 405", rec.Code)
		}
	})

	t.Run("cross-origin refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/owasp/scan",
			strings.NewReader(`{"target":"https://example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		s.handleOWASPScan(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("cross-origin POST = %d, want 403", rec.Code)
		}
	})

	t.Run("unknown field refused", func(t *testing.T) {
		rec := owaspPost(t, s, `{"target":"https://example.com","sneaky":true}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unknown field = %d, want 400", rec.Code)
		}
	})

	t.Run("bad scheme refused", func(t *testing.T) {
		rec := owaspPost(t, s, `{"target":"file:///etc/passwd"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("file:// target = %d, want 400", rec.Code)
		}
	})

	t.Run("bad family refused", func(t *testing.T) {
		rec := owaspPost(t, s, `{"target":"https://example.com","intrusive":true,"enable":["rm -rf"]}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unknown family = %d, want 400", rec.Code)
		}
	})

	t.Run("errors are JSON, not plain text", func(t *testing.T) {
		rec := owaspPost(t, s, `{`)
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("Content-Type = %q, want application/json", ct)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("error body is not JSON: %v (%s)", err, rec.Body.String())
		}
		if body["ok"] != false {
			t.Errorf("error body ok = %v, want false", body["ok"])
		}
	})
}

func TestOWASPScanDeniedRecordsAudit(t *testing.T) {
	s := owaspTestServer(t)

	// 169.254.169.254 is cloud metadata: always denied, and it needs no DNS, so
	// the refusal is deterministic and no packet leaves the machine.
	rec := owaspPost(t, s, `{"target":"http://169.254.169.254/"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("metadata target = %d, want 403\nbody: %s", rec.Code, rec.Body.String())
	}

	var deny struct {
		OK     bool   `json:"ok"`
		Denied bool   `json:"denied"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &deny); err != nil {
		t.Fatalf("decode deny: %v", err)
	}
	if deny.OK || !deny.Denied {
		t.Fatalf("body = %+v, want ok=false denied=true", deny)
	}
	// The reason must name the target it refused, so the operator can tell
	// which of their inputs was the problem.
	if !strings.Contains(deny.Reason, "169.254.169.254") {
		t.Errorf("reason %q never names the refused target", deny.Reason)
	}

	// The refusal must be on the trail — a denied scan that leaves no record is
	// an invisible scan.
	logPath := filepath.Join(os.Getenv("STRESS_STRIKE_HOME"), "audit.jsonl")
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("audit log not written: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("audit log has %d lines, want exactly the one decision", len(lines))
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("audit entry is not JSON: %v", err)
	}
	if entry["allowed"] != false {
		t.Errorf("audit allowed = %v, want false", entry["allowed"])
	}
	if entry["class"] == nil || entry["class"] == "" {
		t.Errorf("audit entry lost the target class: %v", entry)
	}
	if entry["hash"] == nil || entry["hash"] == "" {
		t.Errorf("audit entry is not hash-chained: %v", entry)
	}
	if entry["action"] != "scan" {
		t.Errorf("audit action = %v, want scan", entry["action"])
	}
}

func TestOWASPScanIntrusiveNeedsTicket(t *testing.T) {
	s := owaspTestServer(t)

	// Loopback is allowed for an ordinary scan, so this isolates the rule that
	// makes a scan offensive: intrusive probes need an approval ticket.
	rec := owaspPost(t, s, `{"target":"http://127.0.0.1:9/","intrusive":true}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("intrusive without ticket = %d, want 403\nbody: %s", rec.Code, rec.Body.String())
	}

	var deny struct {
		Denied bool   `json:"denied"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &deny); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !deny.Denied {
		t.Fatal("intrusive scan without a ticket was allowed")
	}
	if !strings.Contains(deny.Reason, "ticket") {
		t.Errorf("reason %q never mentions the ticket requirement", deny.Reason)
	}

	// Asking for a single family is still offensive.
	rec = owaspPost(t, s, `{"target":"http://127.0.0.1:9/","enable":["crlf"]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("family list without a ticket = %d, want 403", rec.Code)
	}

	// And a bogus ticket does not satisfy the requirement.
	rec = owaspPost(t, s, `{"target":"http://127.0.0.1:9/","intrusive":true,"authorized":"FAKE-1"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bogus ticket = %d, want 403", rec.Code)
	}
}

func TestOWASPScanDryRunSendsNothing(t *testing.T) {
	s := owaspTestServer(t)

	// A listener that would fail the test if it were ever contacted.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rec := owaspPost(t, s, `{"target":"`+srv.URL+`","dryRun":true,"rate":50,"timeoutSec":5}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry run = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	res := owaspDecode(t, rec)

	if !res.DryRun {
		t.Error("response does not echo dryRun")
	}
	if hits != 0 {
		t.Fatalf("dry run contacted the server %d time(s)", hits)
	}
	if res.Gate.RequestsSent != 0 {
		t.Errorf("gate sent %d requests in dry run", res.Gate.RequestsSent)
	}
	if res.Gate.RefusedDryRun == 0 {
		t.Errorf("gate refused nothing in dry run: %+v", res.Gate)
	}

	// Nothing was tested, so nothing may be claimed.
	if res.Tested != 0 {
		t.Errorf("tested = %d, want 0 in a dry run", res.Tested)
	}
	if res.Score != 0 || res.Grade != "" {
		t.Errorf("dry run produced a score/grade (%d, %q); that is manufactured confidence",
			res.Score, res.Grade)
	}
	for _, c := range res.Categories {
		if c.Status != "NOT TESTED" {
			t.Errorf("category %s = %q in a dry run, want NOT TESTED", c.ID, c.Status)
		}
	}
	if !res.NotesContain("Dry run") {
		t.Error("no note explains that nothing was sent")
	}
}

// NotesContain is a small helper for the assertions above.
func (r OWASPScanResult) NotesContain(needle string) bool {
	for _, n := range r.Notes {
		if strings.Contains(n, needle) {
			return true
		}
	}
	return false
}

// --- the real thing ---------------------------------------------------------

func TestOWASPScanAgainstLoopback(t *testing.T) {
	s := owaspTestServer(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "test-harness/1.0")
		_, _ = w.Write([]byte(
			`<html><body><h1>hello</h1><form action="/login" method="post"></form></body></html>`))
	}))
	defer srv.Close()

	body := `{"target":"` + srv.URL + `","passive":true,"rate":50,"timeoutSec":5}`
	rec := owaspPost(t, s, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	res := owaspDecode(t, rec)

	if !res.OK {
		t.Fatal("ok = false on a successful scan")
	}
	if res.Target != srv.URL {
		t.Errorf("target = %q, want %q", res.Target, srv.URL)
	}

	// Scope defaults to the host the operator typed — nothing else.
	if len(res.Scope) != 1 || res.Scope[0] != "127.0.0.1" {
		t.Errorf("scope = %v, want exactly [127.0.0.1]", res.Scope)
	}
	if res.Intrusive {
		t.Error("intrusive came back true although it was not requested")
	}

	if len(res.Categories) != 10 {
		t.Fatalf("categories = %d, want all 10 of the OWASP Top 10", len(res.Categories))
	}
	if res.Total != 10 {
		t.Errorf("total = %d, want 10", res.Total)
	}

	// Every status must be one of the four honest values, and the tested count
	// must agree with them.
	tested := 0
	for _, c := range res.Categories {
		switch c.Status {
		case "PASS", "WARNING", "FAIL":
			tested++
		case "NOT TESTED":
		default:
			t.Errorf("category %s = %q, not a known status", c.ID, c.Status)
		}
		if c.Name == "" || c.ID == "" {
			t.Errorf("category with an empty id/name: %+v", c)
		}
	}
	if res.Tested != tested {
		t.Errorf("tested = %d, but %d categories are not NOT TESTED", res.Tested, tested)
	}
	if tested == 0 {
		t.Fatal("nothing was tested against a server that answers on every path")
	}

	// Nothing may leave the scope the operator typed. Refusals are expected and
	// honest: with intrusive probes off, the checker still *attempts* A03/A05/
	// A07/A10 and the gate turns each one down, which is what makes those
	// categories NOT TESTED instead of a quiet pass.
	if res.Gate.RequestsSent == 0 {
		t.Error("gate sent no requests, so the scan never happened")
	}
	if res.Gate.RefusedOutOfScope != 0 {
		t.Errorf("gate let %d probe(s) out of scope: %+v", res.Gate.RefusedOutOfScope, res.Gate)
	}
	if res.Gate.RefusedIntrusive == 0 {
		t.Error("gate refused no intrusive probe although intrusive was off")
	}
	if res.Gate.BytesRead == 0 {
		t.Error("bytesRead = 0 although the server answered")
	}

	// The passive findings, if any, must carry their confidence pulled out of
	// the evidence prefix — never left inside it.
	for _, f := range res.Findings {
		if strings.HasPrefix(f.Evidence, "confidence=") {
			t.Errorf("finding %s still has the confidence prefix in Evidence: %q", f.ID, f.Evidence)
		}
		if f.Severity == "" || f.Title == "" {
			t.Errorf("finding missing severity or title: %+v", f)
		}
	}

	// One scan at a time: the semaphore must be free again after this one.
	if cap(s.owaspSem) != 1 {
		t.Errorf("owaspSem cap = %d, want 1", cap(s.owaspSem))
	}
	select {
	case s.owaspSem <- struct{}{}:
		<-s.owaspSem
	default:
		t.Error("owaspSem was not released after the scan")
	}
}

func TestOWASPScanSecondCallIsRefused(t *testing.T) {
	s := owaspTestServer(t)

	// Occupy the single scan slot, as a scan in flight would.
	s.owaspSem <- struct{}{}
	defer func() { <-s.owaspSem }()

	rec := owaspPost(t, s, `{"target":"https://example.com"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("concurrent scan = %d, want 409", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	msg, _ := body["error"].(string)
	if !strings.Contains(msg, "already running") {
		t.Errorf("error %q does not say a scan is already running", msg)
	}
}

func TestOWASPScanResolvesCLIPolicyPath(t *testing.T) {
	// A policy on disk must be honoured, not skipped: resolving a different
	// path than the CLI does would be silently fail-open — the operator writes
	// an approval, and the dashboard never reads it. Strict mode is written as
	// its numeric value because authz.Mode is an int with no custom unmarshaler.
	dir := t.TempDir()
	t.Setenv("STRESS_STRIKE_HOME", dir)
	t.Setenv("STRESS_STRIKE_ALLOW", "")
	t.Setenv("STRESS_STRIKE_AUDIT_LOG", "")

	if err := os.WriteFile(filepath.Join(dir, "authz.json"), []byte(`{"mode":1}`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	s := NewServer()

	// Loopback is allowed by the default permissive policy (see
	// TestOWASPScanAgainstLoopback), so a refusal here can only come from the
	// strict policy that was just written.
	rec := owaspPost(t, s, `{"target":"http://127.0.0.1:9/"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("metadata target with an on-disk policy = %d, want 403", rec.Code)
	}

	// The audit trail must land next to the policy, in the same home.
	if _, err := os.Stat(filepath.Join(dir, "audit.jsonl")); err != nil {
		t.Errorf("audit log not written to %s: %v", dir, err)
	}
}
