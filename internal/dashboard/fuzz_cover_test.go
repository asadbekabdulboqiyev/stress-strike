package dashboard

// fuzz_cover_test.go — coverage for the fuzz control plane (fuzz.go).
//
// The fuzz endpoint has no dry-run knob, so validation refusals run before any
// request and the one successful campaign runs against a loopback httptest
// server with a tiny mutation budget.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
)

func fuzzPost(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/fuzz/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleFuzzScan(rec, req)
	return rec
}

func fuzzDecode(t *testing.T, rec *httptest.ResponseRecorder) FuzzScanResult {
	t.Helper()
	var out FuzzScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, rec.Body.String())
	}
	return out
}

func TestFuzzValidateFlags(t *testing.T) {
	tests := []struct {
		name      string
		req       FuzzScanRequest
		wantRPS   float64
		wantBudg  int64
		wantTO    time.Duration
		wantError string
	}{
		{
			name:     "defaults",
			req:      FuzzScanRequest{},
			wantRPS:  scanner.DefaultRPS,
			wantBudg: fuzzDefaultBudget,
			wantTO:   10 * time.Second,
		},
		{
			name:     "explicit values",
			req:      FuzzScanRequest{Rate: 50, Budget: 500, Timeout: 30},
			wantRPS:  50,
			wantBudg: 500,
			wantTO:   30 * time.Second,
		},
		{name: "rate low", req: FuzzScanRequest{Rate: 0.5}, wantError: "rate must be between"},
		{name: "rate high", req: FuzzScanRequest{Rate: 51}, wantError: "rate must be between"},
		{name: "budget low", req: FuzzScanRequest{Budget: -1}, wantError: "budget must be between"},
		{name: "budget high", req: FuzzScanRequest{Budget: 2001}, wantError: "budget must be between"},
		{name: "timeout low", req: FuzzScanRequest{Timeout: -1}, wantError: "timeout must be between"},
		{name: "timeout high", req: FuzzScanRequest{Timeout: 31}, wantError: "timeout must be between"},
		{name: "slow combination", req: FuzzScanRequest{Rate: 10, Budget: 2000}, wantError: "budget/rate is 200s"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rps, budget, timeout, err := fuzzValidateFlags(&tc.req)
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

func TestFuzzValidatePaths(t *testing.T) {
	if got, err := fuzzValidatePaths(nil); err != nil || got != nil {
		t.Errorf("nil paths = %v, %v", got, err)
	}

	if _, err := fuzzValidatePaths(make([]string, fuzzMaxPaths+1)); err == nil ||
		!strings.Contains(err.Error(), "at most") {
		t.Errorf("too many paths err = %v", err)
	}

	got, err := fuzzValidatePaths([]string{"  ", "/a", "b", "https://evil.example/x", "/a", "/b/"})
	if err != nil {
		t.Fatalf("validate paths: %v", err)
	}
	want := []string{"/a", "/b", "/b/"}
	if len(got) != len(want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("paths = %v, want %v", got, want)
		}
	}
}

func TestFuzzGateAndAudit(t *testing.T) {
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())
	t.Setenv("STRESS_STRIKE_POLICY", "")
	t.Setenv("STRESS_STRIKE_ALLOW", "")
	t.Setenv("STRESS_STRIKE_AUDIT_LOG", "")

	// OpScan (not OpPentest): a public target is allowed by the default policy
	// without a ticket.
	out, err := fuzzGate("https://93.184.216.34/", "")
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if !out.Allowed {
		t.Errorf("public fuzz target denied: %+v", out)
	}

	// Metadata stays denied even without a ticket.
	out, err = fuzzGate("http://169.254.169.254/", "")
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if out.Allowed {
		t.Error("metadata fuzz target was allowed")
	}

	if err := fuzzAudit(authz.Entry{Action: authz.OpScan.String(), Targets: []string{"https://93.184.216.34/"}, Allowed: true}); err != nil {
		t.Fatalf("fuzzAudit: %v", err)
	}
	if n, err := authz.Verify(filepath.Join(os.Getenv("STRESS_STRIKE_HOME"), "audit.jsonl")); err != nil || n != 1 {
		t.Errorf("audit verify: n=%d err=%v", n, err)
	}
}

func TestFuzzScanRejectsBadRequests(t *testing.T) {
	t.Run("GET refused", func(t *testing.T) {
		s := owaspTestServer(t)
		req := httptest.NewRequest(http.MethodGet, "/api/fuzz/scan", nil)
		rec := httptest.NewRecorder()
		s.handleFuzzScan(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET = %d, want 405", rec.Code)
		}
	})

	t.Run("cross-origin refused", func(t *testing.T) {
		s := owaspTestServer(t)
		req := httptest.NewRequest(http.MethodPost, "/api/fuzz/scan",
			strings.NewReader(`{"target":"https://example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		s.handleFuzzScan(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("cross-origin = %d, want 403", rec.Code)
		}
	})

	t.Run("concurrent scan refused", func(t *testing.T) {
		s := owaspTestServer(t)
		s.owaspSem <- struct{}{}
		defer func() { <-s.owaspSem }()
		if rec := fuzzPost(t, s, `{"target":"https://example.com"}`); rec.Code != http.StatusConflict {
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
		{"too many paths", `{"target":"https://example.com","paths":[` + manyPaths(fuzzMaxPaths+1) + `]}`},
		{"rate below one", `{"target":"https://example.com","rate":0.5}`},
		{"rate above cap", `{"target":"https://example.com","rate":51}`},
		{"budget above cap", `{"target":"https://example.com","budget":2001}`},
		{"timeout above cap", `{"target":"https://example.com","timeoutSec":31}`},
		{"budget over rate cap", `{"target":"https://example.com","rate":10,"budget":2000}`},
		{"invalid scope", `{"target":"https://example.com","allow":[""]}`},
		{"no paths", `{"target":"https://example.com"}`},
		{"no paths with clamped mutations", `{"target":"https://example.com","mutations":5000}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := owaspTestServer(t)
			rec := fuzzPost(t, s, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 400\nbody: %s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestFuzzScanDeniedRecordsAudit(t *testing.T) {
	s := owaspTestServer(t)

	rec := fuzzPost(t, s, `{"target":"http://169.254.169.254/","paths":["/a"]}`)
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

	entries, err := authz.ReadAll(filepath.Join(os.Getenv("STRESS_STRIKE_HOME"), "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(entries) != 1 || entries[0].Allowed || entries[0].Action != authz.OpScan.String() {
		t.Errorf("audit entries = %+v", entries)
	}
}

func TestFuzzScanAuditUnavailableDeniesSafely(t *testing.T) {
	s := owaspTestServer(t)
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STRESS_STRIKE_AUDIT_LOG", filepath.Join(blocker, "audit.jsonl"))

	rec := fuzzPost(t, s, `{"target":"http://169.254.169.254/","paths":["/a"]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("deny with broken audit = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "audit log unavailable") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestFuzzScanAllowedButAuditBrokenFailsClosed(t *testing.T) {
	s := owaspTestServer(t)
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STRESS_STRIKE_AUDIT_LOG", filepath.Join(blocker, "audit.jsonl"))

	rec := fuzzPost(t, s, `{"target":"https://93.184.216.34/","paths":["/a"]}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("allowed with broken audit = %d, want 500\nbody: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "cannot record the authorization decision") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestFuzzScanPolicyError(t *testing.T) {
	s := owaspTestServer(t)
	if err := os.WriteFile(filepath.Join(os.Getenv("STRESS_STRIKE_HOME"), "authz.json"),
		[]byte(`{"mode":`), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := fuzzPost(t, s, `{"target":"https://93.184.216.34/","paths":["/a"]}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("corrupt policy = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "authorization policy error") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestFuzzScanAgainstLoopback(t *testing.T) {
	s := owaspTestServer(t)

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rec := fuzzPost(t, s, `{
		"target":"`+srv.URL+`",
		"paths":["/a","b"],
		"mutations":5,
		"concurrency":2,
		"rate":50,
		"budget":100,
		"timeoutSec":5
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("fuzz scan = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	res := fuzzDecode(t, rec)

	if !res.OK {
		t.Error("ok = false on a successful scan")
	}
	if len(res.Scope) != 1 || res.Scope[0] != "127.0.0.1" {
		t.Errorf("scope = %v, want [127.0.0.1]", res.Scope)
	}
	if hits.Load() == 0 {
		t.Error("fuzzer never contacted the loopback server")
	}
	if res.Gate.RequestsSent == 0 {
		t.Errorf("gate sent no requests: %+v", res.Gate)
	}
	// Sent counts mutated probes; the gate also counts the baseline requests,
	// so it must be at least as large, never smaller.
	if res.Sent == 0 {
		t.Error("fuzzer reported no mutated probes")
	}
	if res.Sent > int(res.Gate.RequestsSent) {
		t.Errorf("sent = %d exceeds gate sent = %d", res.Sent, res.Gate.RequestsSent)
	}
}

func TestFuzzScanAllowAll(t *testing.T) {
	s := owaspTestServer(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rec := fuzzPost(t, s, `{
		"target":"`+srv.URL+`",
		"paths":["/a"],
		"allowAll":true,
		"mutations":2,
		"concurrency":1,
		"rate":50,
		"budget":50,
		"timeoutSec":5
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("allow-all fuzz = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	res := fuzzDecode(t, rec)
	if len(res.Scope) != 1 || res.Scope[0] != "* (allow-all)" {
		t.Errorf("scope = %v, want the allow-all marker", res.Scope)
	}
}

func TestFuzzScanRefusedNotesAreExplained(t *testing.T) {
	s := owaspTestServer(t)

	// The scope names a different host, so the gate refuses every probe. The
	// fuzzer still finishes (nothing is sent) and the refusal is explained.
	rec := fuzzPost(t, s, `{
		"target":"http://127.0.0.1:9/",
		"paths":["/a"],
		"allow":["other.example"],
		"mutations":2,
		"concurrency":1,
		"rate":50,
		"budget":20,
		"timeoutSec":5
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("refused fuzz = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	res := fuzzDecode(t, rec)
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
		t.Errorf("refusals are not explained in the notes: %v", res.Notes)
	}
}
