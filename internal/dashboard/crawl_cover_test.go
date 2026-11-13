package dashboard

// crawl_cover_test.go — coverage for the crawler control plane (crawl.go).
//
// The crawl endpoint has a dry-run knob, so validation and scope/precedence
// branches stay offline; one small real crawl runs against a loopback
// httptest server to exercise discovery, the round tripper and the report.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
)

func crawlPost(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/crawl/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleCrawlScan(rec, req)
	return rec
}

func crawlDecode(t *testing.T, rec *httptest.ResponseRecorder) CrawlScanResult {
	t.Helper()
	var out CrawlScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, rec.Body.String())
	}
	return out
}

func TestCrawlValidateFlags(t *testing.T) {
	tests := []struct {
		name      string
		req       CrawlScanRequest
		wantRPS   float64
		wantBudg  int64
		wantTO    time.Duration
		wantError string
	}{
		{
			name:     "defaults",
			req:      CrawlScanRequest{},
			wantRPS:  scanner.DefaultRPS,
			wantBudg: crawlDefaultBudget,
			wantTO:   10 * time.Second,
		},
		{
			name:     "explicit values",
			req:      CrawlScanRequest{Rate: 50, Budget: 500, Timeout: 30},
			wantRPS:  50,
			wantBudg: 500,
			wantTO:   30 * time.Second,
		},
		{name: "rate low", req: CrawlScanRequest{Rate: 0.5}, wantError: "rate must be between"},
		{name: "rate high", req: CrawlScanRequest{Rate: 51}, wantError: "rate must be between"},
		{name: "budget low", req: CrawlScanRequest{Budget: -1}, wantError: "budget must be between"},
		{name: "budget high", req: CrawlScanRequest{Budget: 2001}, wantError: "budget must be between"},
		{name: "timeout low", req: CrawlScanRequest{Timeout: -1}, wantError: "timeout must be between"},
		{name: "timeout high", req: CrawlScanRequest{Timeout: 31}, wantError: "timeout must be between"},
		{name: "slow combination", req: CrawlScanRequest{Rate: 10, Budget: 2000}, wantError: "budget/rate is 200s"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rps, budget, timeout, err := crawlValidateFlags(&tc.req)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rps != tc.wantRPS || budget != tc.wantBudg || timeout != tc.wantTO {
				t.Errorf("got %v/%d/%v, want %v/%d/%v",
					rps, budget, timeout, tc.wantRPS, tc.wantBudg, tc.wantTO)
			}
		})
	}
}

func TestCrawlGateAndAudit(t *testing.T) {
	t.Setenv("SIFT_HOME", t.TempDir())
	t.Setenv("SIFT_POLICY", "")
	t.Setenv("SIFT_ALLOW", "")
	t.Setenv("SIFT_AUDIT_LOG", "")

	// OpScan: a public target is allowed without a ticket.
	out, err := crawlGate("https://93.184.216.34/")
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if !out.Allowed {
		t.Errorf("public crawl target denied: %+v", out)
	}

	out, err = crawlGate("http://169.254.169.254/")
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if out.Allowed {
		t.Error("metadata crawl target was allowed")
	}

	if err := crawlAudit(authz.Entry{Action: authz.OpScan.String(), Targets: []string{"https://93.184.216.34/"}, Allowed: true}); err != nil {
		t.Fatalf("crawlAudit: %v", err)
	}
	if n, err := authz.Verify(filepath.Join(os.Getenv("SIFT_HOME"), "audit.jsonl")); err != nil || n != 1 {
		t.Errorf("audit verify: n=%d err=%v", n, err)
	}
}

func TestCrawlScanRejectsBadRequests(t *testing.T) {
	t.Run("GET refused", func(t *testing.T) {
		s := owaspTestServer(t)
		req := httptest.NewRequest(http.MethodGet, "/api/crawl/scan", nil)
		rec := httptest.NewRecorder()
		s.handleCrawlScan(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET = %d, want 405", rec.Code)
		}
	})

	t.Run("cross-origin refused", func(t *testing.T) {
		s := owaspTestServer(t)
		req := httptest.NewRequest(http.MethodPost, "/api/crawl/scan",
			strings.NewReader(`{"target":"https://example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		s.handleCrawlScan(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("cross-origin = %d, want 403", rec.Code)
		}
	})

	t.Run("concurrent scan refused", func(t *testing.T) {
		s := owaspTestServer(t)
		s.owaspSem <- struct{}{}
		defer func() { <-s.owaspSem }()
		if rec := crawlPost(t, s, `{"target":"https://example.com"}`); rec.Code != http.StatusConflict {
			t.Fatalf("busy = %d, want 409", rec.Code)
		}
	})

	tests := []struct {
		name string
		body string
	}{
		{"malformed JSON", `{`},
		{"unknown field", `{"target":"https://example.com","bogus":1}`},
		{"missing target", `{}`},
		{"non-http scheme", `{"target":"file:///etc/passwd"}`},
		{"rate below one", `{"target":"https://example.com","rate":0.5}`},
		{"rate above cap", `{"target":"https://example.com","rate":51}`},
		{"budget above cap", `{"target":"https://example.com","budget":2001}`},
		{"timeout above cap", `{"target":"https://example.com","timeoutSec":31}`},
		{"budget over rate cap", `{"target":"https://example.com","rate":10,"budget":2000}`},
		{"invalid scope", `{"target":"https://example.com","allow":[""]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := owaspTestServer(t)
			rec := crawlPost(t, s, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 400\nbody: %s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCrawlScanDeniedRecordsAudit(t *testing.T) {
	s := owaspTestServer(t)

	rec := crawlPost(t, s, `{"target":"http://169.254.169.254/"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("metadata target = %d, want 403\nbody: %s", rec.Code, rec.Body.String())
	}
	var deny struct {
		Denied bool   `json:"denied"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &deny); err != nil {
		t.Fatalf("decode deny: %v", err)
	}
	if !deny.Denied || !strings.Contains(deny.Reason, "169.254.169.254") {
		t.Errorf("deny = %+v", deny)
	}

	entries, err := authz.ReadAll(filepath.Join(os.Getenv("SIFT_HOME"), "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(entries) != 1 || entries[0].Allowed || entries[0].Action != authz.OpScan.String() {
		t.Errorf("audit entries = %+v", entries)
	}
}

func TestCrawlScanAuditUnavailableDeniesSafely(t *testing.T) {
	s := owaspTestServer(t)
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIFT_AUDIT_LOG", filepath.Join(blocker, "audit.jsonl"))

	rec := crawlPost(t, s, `{"target":"http://169.254.169.254/"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("deny with broken audit = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "audit log unavailable") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestCrawlScanAllowedButAuditBrokenFailsClosed(t *testing.T) {
	s := owaspTestServer(t)
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIFT_AUDIT_LOG", filepath.Join(blocker, "audit.jsonl"))

	rec := crawlPost(t, s, `{"target":"https://93.184.216.34/","dryRun":true}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("allowed with broken audit = %d, want 500\nbody: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "cannot record the authorization decision") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestCrawlScanPolicyError(t *testing.T) {
	s := owaspTestServer(t)
	if err := os.WriteFile(filepath.Join(os.Getenv("SIFT_HOME"), "authz.json"),
		[]byte(`{"mode":`), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := crawlPost(t, s, `{"target":"https://93.184.216.34/"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("corrupt policy = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "authorization policy error") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestCrawlScanDryRunClampsAndAllowAll(t *testing.T) {
	s := owaspTestServer(t)

	// Large knobs are clamped rather than rejected; the dry run keeps it offline.
	rec := crawlPost(t, s, `{
		"target":"http://127.0.0.1:9/",
		"dryRun":true,
		"allowAll":true,
		"offsite":true,
		"depth":99,
		"pages":9999,
		"concurrency":99,
		"rate":50,
		"budget":50,
		"timeoutSec":5
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry run = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	res := crawlDecode(t, rec)

	if !res.DryRun || !res.Offsite {
		t.Errorf("flags = dryRun:%v offsite:%v", res.DryRun, res.Offsite)
	}
	if len(res.Scope) != 1 || res.Scope[0] != "* (allow-all)" {
		t.Errorf("scope = %v, want the allow-all marker", res.Scope)
	}
	if res.Gate.RequestsSent != 0 {
		t.Errorf("dry run sent %d request(s)", res.Gate.RequestsSent)
	}
	if res.Gate.RefusedDryRun == 0 {
		t.Errorf("dry run refused nothing: %+v", res.Gate)
	}
	for _, want := range []string{"Dry run", "Offsite links are allowed"} {
		found := false
		for _, n := range res.Notes {
			if strings.Contains(n, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("notes missing %q: %v", want, res.Notes)
		}
	}

	// Zero values take the documented defaults and the host scope.
	rec = crawlPost(t, s, `{"target":"http://127.0.0.1:9/","dryRun":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("defaults dry run = %d, want 200", rec.Code)
	}
	res = crawlDecode(t, rec)
	if len(res.Scope) != 1 || res.Scope[0] != "127.0.0.1" {
		t.Errorf("default scope = %v, want [127.0.0.1]", res.Scope)
	}
}

func TestCrawlScanAgainstLoopback(t *testing.T) {
	s := owaspTestServer(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			_, _ = fmt.Fprint(w, `<html><body>
				<a href="/about">about</a>
				<a href="/search?q=x">search</a>
				<a href="https://elsewhere.example/">offsite</a>
			</body></html>`)
		default:
			_, _ = fmt.Fprint(w, `<html><body>page</body></html>`)
		}
	}))
	defer srv.Close()

	rec := crawlPost(t, s, `{
		"target":"`+srv.URL+`/",
		"depth":2,
		"pages":10,
		"concurrency":2,
		"rate":50,
		"budget":50,
		"timeoutSec":5
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("crawl = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	res := crawlDecode(t, rec)

	if !res.OK || res.DryRun {
		t.Errorf("flags = ok:%v dryRun:%v", res.OK, res.DryRun)
	}
	if res.Pages == 0 {
		t.Error("crawl fetched no pages")
	}
	if res.Gate.RequestsSent == 0 {
		t.Errorf("gate sent no requests: %+v", res.Gate)
	}
	if res.DurationSec < 0 {
		t.Errorf("duration = %v", res.DurationSec)
	}
	if len(res.Discovered) == 0 || res.Endpoints != len(res.Discovered) {
		t.Errorf("discovered = %d, endpoints = %d", len(res.Discovered), res.Endpoints)
	}
	for _, ep := range res.Discovered {
		if ep.URL == "" || ep.Method == "" || ep.Kind == "" {
			t.Errorf("incomplete endpoint: %+v", ep)
		}
		// Offsite links must never be followed by default.
		if strings.Contains(ep.URL, "elsewhere.example") {
			t.Errorf("offsite endpoint was followed: %+v", ep)
		}
	}
}

func TestCrawlScanEncodeFailure(t *testing.T) {
	s := owaspTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/crawl/scan",
		strings.NewReader(`{"target":"http://127.0.0.1:9/","dryRun":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := &failingWriter{}
	s.handleCrawlScan(w, req)
	if got := w.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	select {
	case s.owaspSem <- struct{}{}:
		<-s.owaspSem
	default:
		t.Error("owaspSem was not released after an encode failure")
	}
}

func TestCrawlDenyEncodeFailure(t *testing.T) {
	s := owaspTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/crawl/scan",
		strings.NewReader(`{"target":"http://169.254.169.254/"}`))
	req.Header.Set("Content-Type", "application/json")
	w := &failingWriter{}
	s.handleCrawlScan(w, req)
	if got := w.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("deny Content-Type = %q, want application/json", got)
	}
}

func TestCrawlScanRefusalsAreExplained(t *testing.T) {
	s := owaspTestServer(t)

	// The allowlist names a different host, so every hop is refused before it
	// is sent and the response must explain the refusals.
	rec := crawlPost(t, s, `{
		"target":"http://127.0.0.1:9/",
		"allow":["other.example"],
		"rate":50,
		"budget":20,
		"timeoutSec":5
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("refused crawl = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	res := crawlDecode(t, rec)
	if res.Gate.RequestsRefused == 0 || res.Gate.RefusedOutOfScope == 0 {
		t.Fatalf("gate refused nothing: %+v", res.Gate)
	}
	found := false
	for _, n := range res.Notes {
		if strings.Contains(n, "Gate refused") && strings.Contains(n, "out-of-scope") {
			found = true
		}
	}
	if !found {
		t.Errorf("refusals are not explained: %v", res.Notes)
	}
}
