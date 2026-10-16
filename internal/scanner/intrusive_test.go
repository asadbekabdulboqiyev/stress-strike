package scanner

// Black-box tests for the intrusive web-vulnerability probes in intrusive.go.
//
// Every test runs against a loopback httptest server (or a Guard that refuses
// before the network is touched). Nothing here reaches an external host: the
// only "outside" origins the probes know about are the RFC 2606 reserved,
// non-resolving ss-canary.invalid and loopback addresses on a closed port.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── shared plumbing ──────────────────────────────────────────────────────────

// intrusiveTestRPS keeps the Guard's token bucket out of the way: these tests
// exercise probe logic, not rate limiting, and the default limiter would turn a
// scan of a few dozen requests into a multi-second one.
const intrusiveTestRPS = 50000

// intrusiveRecord is one request that reached a test server.
type intrusiveRecord struct {
	method string
	host   string
	url    string // r.URL.String(): path and query only, no scheme or host
	body   string
}

// intrusiveRecorder wraps a handler and remembers every request, so a test can
// assert what was sent, what was NOT sent, and how much work a scan did.
type intrusiveRecorder struct {
	mu   sync.Mutex
	recs []intrusiveRecord
}

func (rec *intrusiveRecorder) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := ""
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			body = string(raw)
			// Restore it: some handlers (and the probe's own form carriers)
			// still need to parse the body.
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		rec.mu.Lock()
		rec.recs = append(rec.recs, intrusiveRecord{
			method: r.Method,
			host:   r.Host,
			url:    r.URL.String(),
			body:   body,
		})
		rec.mu.Unlock()
		next(w, r)
	}
}

func (rec *intrusiveRecorder) count() int {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return len(rec.recs)
}

func (rec *intrusiveRecorder) list() []intrusiveRecord {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	out := make([]intrusiveRecord, len(rec.recs))
	copy(out, rec.recs)
	return out
}

func (rec *intrusiveRecorder) methods() []string {
	out := []string{}
	for _, r := range rec.list() {
		out = append(out, r.method)
	}
	return out
}

func (rec *intrusiveRecorder) ofMethod(method string) []intrusiveRecord {
	out := []intrusiveRecord{}
	for _, r := range rec.list() {
		if r.method == method {
			out = append(out, r)
		}
	}
	return out
}

// intrusiveGuard builds a Guard with a fast limiter, so policy never becomes
// the reason a test is slow. Callers set Allow/Intrusive explicitly.
func intrusiveGuard(t *testing.T, cfg GuardConfig) *Guard {
	t.Helper()
	if cfg.RPS <= 0 {
		cfg.RPS = intrusiveTestRPS
	}
	if cfg.Burst <= 0 {
		cfg.Burst = int(intrusiveTestRPS)
	}
	return mustGuard(t, cfg)
}

// intrusiveGuardAllowAll is the Requester every happy-path test uses: the whole
// loopback range is in scope and the intrusive gate is open.
func intrusiveGuardAllowAll(t *testing.T) *Guard {
	t.Helper()
	return intrusiveGuard(t, GuardConfig{AllowAll: true, Intrusive: true})
}

func intrusiveScanner(t *testing.T, base string, opts IntrusiveOptions) *IntrusiveScanner {
	t.Helper()
	s, err := NewIntrusiveScanner(base, intrusiveGuardAllowAll(t), opts)
	if err != nil {
		t.Fatalf("NewIntrusiveScanner(%q): %v", base, err)
	}
	return s
}

// intrusiveAllFamilies is the option set that turns every probe on.
func intrusiveAllFamilies() IntrusiveOptions {
	return IntrusiveOptions{
		CRLFInjection:     true,
		BooleanSQLi:       true,
		TimeBasedSQLi:     true,
		PathTraversal:     true,
		SSRFIndicators:    true,
		WriteMethodProbes: true,
	}
}

// ── test targets ─────────────────────────────────────────────────────────────

// intrusiveSink is one deliberately vulnerable target that produces a signal
// for every probe family. The family-isolation tests enable a single family at
// a time and assert that nothing from the other families appears.
func intrusiveSink() http.HandlerFunc {
	var mu sync.Mutex
	stored := map[string]bool{}
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			// A write method answered with a plain 200 OK: the probe must read
			// that as "accepted", not as "method not supported".
			mu.Lock()
			stored[r.URL.Path] = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		case http.MethodDelete:
			mu.Lock()
			delete(stored, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/"+intrusiveWritePathPrefix) {
			mu.Lock()
			exists := stored[r.URL.Path]
			mu.Unlock()
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, "not found")
				return
			}
			io.WriteString(w, "created")
			return
		}
		// SSRF: a URL-shaped value changes the outcome.
		for _, name := range []string{"next", "url"} {
			if strings.HasPrefix(r.URL.Query().Get(name), "http://") {
				w.WriteHeader(http.StatusBadGateway)
				io.WriteString(w, "connection refused: dial tcp 127.0.0.1:1")
				return
			}
		}
		id := r.URL.Query().Get("id")
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			id = r.PostFormValue("id")
		}
		if id != "" {
			// The CRLF carrier sink: the decoded value is echoed with CR and LF
			// intact, so the injected control characters survive into the body.
			io.WriteString(w, "you searched for "+id+"\n")
		}
		switch {
		case strings.Contains(id, "1=1"):
			io.WriteString(w, strings.Repeat("A", 4000))
		case strings.Contains(id, "1=2"):
			io.WriteString(w, strings.Repeat("B", 40))
		}
		if strings.Contains(r.URL.Path+" "+r.URL.RawQuery, "etc/passwd") {
			io.WriteString(w, intrusivePasswdSignature+"root:/root:/bin/bash\n")
		}
		io.WriteString(w, "ok")
	}
}

// intrusiveWriteTarget is a configurable in-memory resource server used only by
// the write-method tests.
type intrusiveWriteTarget struct {
	putStatus    int  // status the PUT answers with
	storeOnPut   bool // whether the PUT makes the path readable afterwards
	deleteStatus int  // status the DELETE answers with
	getStatus    int  // status a GET answers with when the path is absent

	mu     sync.Mutex
	stored map[string]bool
}

func newIntrusiveWriteTarget(putStatus int, storeOnPut bool, deleteStatus, getStatus int) *intrusiveWriteTarget {
	return &intrusiveWriteTarget{
		putStatus:    putStatus,
		storeOnPut:   storeOnPut,
		deleteStatus: deleteStatus,
		getStatus:    getStatus,
		stored:       map[string]bool{},
	}
}

func (s *intrusiveWriteTarget) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			s.mu.Lock()
			if s.storeOnPut {
				s.stored[r.URL.Path] = true
			}
			status := s.putStatus
			s.mu.Unlock()
			w.WriteHeader(status)
			return
		case http.MethodDelete:
			s.mu.Lock()
			delete(s.stored, r.URL.Path)
			status := s.deleteStatus
			s.mu.Unlock()
			w.WriteHeader(status)
			return
		}
		s.mu.Lock()
		exists := s.stored[r.URL.Path]
		status := s.getStatus
		s.mu.Unlock()
		if exists {
			io.WriteString(w, "created")
			return
		}
		w.WriteHeader(status)
		io.WriteString(w, "not found")
	}
}

func (s *intrusiveWriteTarget) leftOver() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.stored)
}

// ── construction ─────────────────────────────────────────────────────────────

func TestNewIntrusiveScannerFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		base    string
		noReq   bool
		wantErr bool
	}{
		{"nil requester", "http://127.0.0.1/", true, true},
		{"empty url", "", false, true},
		{"whitespace url", "   ", false, true},
		{"unparsable url", "http://[::1", false, true},
		{"no host", "notaurl", false, true},
		{"scheme relative", "//127.0.0.1/", false, true},
		{"userinfo", "https://user:pass@127.0.0.1/", false, true},
		{"ftp scheme", "ftp://127.0.0.1/", false, true},
		{"file scheme", "file:///etc/passwd", false, true},
		{"valid http", "http://127.0.0.1:8080/base?q=1", false, false},
		{"valid https", "https://127.0.0.1/", false, false},
		{"valid with fragment", "http://127.0.0.1/base#anchor", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := intrusiveGuardAllowAll(t)
			var req Requester = g
			if tc.noReq {
				req = nil
			}
			s, err := NewIntrusiveScanner(tc.base, req, IntrusiveOptions{CRLFInjection: true})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewIntrusiveScanner(%q) succeeded, want an error (fail closed)", tc.base)
				}
				if s != nil {
					t.Errorf("scanner must be nil when construction fails, got %+v", s)
				}
			} else {
				if err != nil {
					t.Fatalf("NewIntrusiveScanner(%q): unexpected error: %v", tc.base, err)
				}
				if s == nil {
					t.Fatal("scanner must not be nil")
				}
				if got := s.Enabled(); len(got) != 1 || got[0] != intrusiveProbeCRLF {
					t.Errorf("Enabled() = %v, want [%s]", got, intrusiveProbeCRLF)
				}
			}
			// The constructor must never touch the network or the policy layer.
			if got := g.Stats().RequestsSent; got != 0 {
				t.Errorf("constructor sent %d requests, want 0", got)
			}
			if got := g.Stats().RequestsRefused; got != 0 {
				t.Errorf("constructor made %d policy checks, want 0", got)
			}
		})
	}
}

func TestNewIntrusiveScannerDefaultsAndCaps(t *testing.T) {
	s := intrusiveScanner(t, "http://127.0.0.1/base/", IntrusiveOptions{})
	if s.opts.MaxParams != intrusiveDefaultMaxParams {
		t.Errorf("MaxParams = %d, want the default %d", s.opts.MaxParams, intrusiveDefaultMaxParams)
	}
	if s.opts.MaxEndpoints != intrusiveDefaultMaxEndpoints {
		t.Errorf("MaxEndpoints = %d, want the default %d", s.opts.MaxEndpoints, intrusiveDefaultMaxEndpoints)
	}
	if s.timeFloor != intrusiveTimeFloor {
		t.Errorf("timeFloor = %v, want %v", s.timeFloor, intrusiveTimeFloor)
	}
	if s.budget != intrusiveMaxTotalRequests {
		t.Errorf("budget = %d, want %d", s.budget, intrusiveMaxTotalRequests)
	}
	if s.timeBudget != intrusiveTimeMaxRequests {
		t.Errorf("timeBudget = %d, want %d", s.timeBudget, intrusiveTimeMaxRequests)
	}
	if got := s.Enabled(); len(got) != 0 {
		t.Errorf("Enabled() = %v with no options set, want an empty list", got)
	}

	explicit := intrusiveScanner(t, "http://127.0.0.1/", IntrusiveOptions{MaxParams: 1, MaxEndpoints: 2})
	if explicit.opts.MaxParams != 1 || explicit.opts.MaxEndpoints != 2 {
		t.Errorf("explicit caps were not honoured: MaxParams=%d MaxEndpoints=%d",
			explicit.opts.MaxParams, explicit.opts.MaxEndpoints)
	}

	negative := intrusiveScanner(t, "http://127.0.0.1/", IntrusiveOptions{MaxParams: -3, MaxEndpoints: -9})
	if negative.opts.MaxParams != intrusiveDefaultMaxParams || negative.opts.MaxEndpoints != intrusiveDefaultMaxEndpoints {
		t.Errorf("non-positive caps must fall back to the defaults, got MaxParams=%d MaxEndpoints=%d",
			negative.opts.MaxParams, negative.opts.MaxEndpoints)
	}

	// A fragment is never sent and must not survive into any built request.
	frag := intrusiveScanner(t, "http://127.0.0.1/base#anchor", IntrusiveOptions{})
	if frag.base.Fragment != "" || strings.Contains(frag.base.String(), "anchor") {
		t.Errorf("the fragment survived into the base URL: %q", frag.base.String())
	}
}

func TestIntrusiveEnabledList(t *testing.T) {
	all := intrusiveAllFamilies()
	wantAll := []string{
		intrusiveProbeCRLF,
		intrusiveProbeBooleanSQLi,
		intrusiveProbeTimeSQLi,
		intrusiveProbeTraversal,
		intrusiveProbeSSRF,
		intrusiveProbeWriteMethod,
	}

	cases := []struct {
		name string
		opts IntrusiveOptions
		want []string
	}{
		{"none", IntrusiveOptions{}, []string{}},
		{"crlf only", IntrusiveOptions{CRLFInjection: true}, []string{intrusiveProbeCRLF}},
		{"boolean only", IntrusiveOptions{BooleanSQLi: true}, []string{intrusiveProbeBooleanSQLi}},
		{"time only", IntrusiveOptions{TimeBasedSQLi: true}, []string{intrusiveProbeTimeSQLi}},
		{"traversal only", IntrusiveOptions{PathTraversal: true}, []string{intrusiveProbeTraversal}},
		{"ssrf only", IntrusiveOptions{SSRFIndicators: true}, []string{intrusiveProbeSSRF}},
		{"write only", IntrusiveOptions{WriteMethodProbes: true}, []string{intrusiveProbeWriteMethod}},
		{"all", all, wantAll},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := intrusiveScanner(t, "http://127.0.0.1/", tc.opts)
			got := s.Enabled()
			if len(got) != len(tc.want) {
				t.Fatalf("Enabled() = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("Enabled() = %v, want %v (order is part of the contract)", got, tc.want)
				}
			}
		})
	}

	t.Run("nil receiver", func(t *testing.T) {
		var nilScanner *IntrusiveScanner
		if got := nilScanner.Enabled(); len(got) != 0 {
			t.Errorf("a nil scanner must report no enabled families, got %v", got)
		}
		// ScanAll on a nil scanner must not panic either.
		if got := nilScanner.ScanAll(context.Background()); len(got) != 0 {
			t.Errorf("a nil scanner must return no findings, got %d", len(got))
		}
	})
}

// ── default-off behaviour ────────────────────────────────────────────────────

func TestIntrusiveScanAllNothingEnabled(t *testing.T) {
	rec := &intrusiveRecorder{}
	srv := httptest.NewServer(rec.wrap(intrusiveSink()))
	defer srv.Close()

	s := intrusiveScanner(t, srv.URL+"/?id=1&next=/target", IntrusiveOptions{})
	findings := s.ScanAll(context.Background())
	if findings == nil {
		t.Error("ScanAll returned nil, want an empty slice")
	}
	if len(findings) != 0 {
		t.Errorf("ScanAll returned %d findings with every family off, want 0", len(findings))
	}
	if got := rec.count(); got != 0 {
		t.Errorf("the server saw %d requests with every family off, want 0", got)
	}
}

func TestIntrusiveRefusedWhenGateClosed(t *testing.T) {
	scan := func(t *testing.T, g *Guard) (int, int64, int64) {
		t.Helper()
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(intrusiveSink()))
		defer srv.Close()

		s, err := NewIntrusiveScanner(srv.URL+"/?id=1&next=/target", g, intrusiveAllFamilies())
		if err != nil {
			t.Fatalf("NewIntrusiveScanner: %v", err)
		}
		findings := s.ScanAll(context.Background())
		return len(findings), int64(rec.count()), g.Stats().RequestsSent
	}

	t.Run("host not in scope", func(t *testing.T) {
		// AllowAll is false and Allow is empty: every Check is out of scope.
		g := intrusiveGuard(t, GuardConfig{Intrusive: true})
		findings, seen, sent := scan(t, g)
		if findings != 0 {
			t.Errorf("out-of-scope scan reported %d findings, want 0", findings)
		}
		if seen != 0 || sent != 0 {
			t.Errorf("out-of-scope scan reached the server: server=%d guard=%d, want 0", seen, sent)
		}
		if got := g.Stats().RefusedOutOfScope; got == 0 {
			t.Error("the Guard did not record an out-of-scope refusal")
		}
	})

	t.Run("intrusive gate off", func(t *testing.T) {
		g := intrusiveGuard(t, GuardConfig{AllowAll: true})
		findings, seen, sent := scan(t, g)
		if findings != 0 {
			t.Errorf("scan with the intrusive gate closed reported %d findings, want 0", findings)
		}
		if seen != 0 || sent != 0 {
			t.Errorf("intrusive-refused scan reached the server: server=%d guard=%d, want 0", seen, sent)
		}
		if got := g.Stats().RefusedIntrusive; got == 0 {
			t.Error("the Guard did not record an intrusive refusal")
		}
	})

	t.Run("dry run", func(t *testing.T) {
		g := intrusiveGuard(t, GuardConfig{AllowAll: true, Intrusive: true, DryRun: true})
		findings, seen, sent := scan(t, g)
		if findings != 0 {
			t.Errorf("dry-run scan reported %d findings, want 0", findings)
		}
		if seen != 0 || sent != 0 {
			t.Errorf("dry-run scan reached the server: server=%d guard=%d, want 0", seen, sent)
		}
		if got := g.Stats().DryRunChecked; got == 0 {
			t.Error("the Guard did not record a dry-run check")
		}
	})
}

// ── probe 1: CRLF / response splitting ───────────────────────────────────────

func TestIntrusiveCRLFInjection(t *testing.T) {
	const payload = intrusiveCRLFSuffix // "%0d%0aX-SS-Canary:1"

	t.Run("reflected control characters are a heuristic finding", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := r.URL.Query().Get("q")
			if v == "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			io.WriteString(w, "you searched for "+v)
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=hello", IntrusiveOptions{CRLFInjection: true})
		findings := s.ScanAll(context.Background())
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1 (the value is echoed with CR/LF intact)", len(findings))
		}
		v := findings[0]
		if v.Severity != "medium" {
			t.Errorf("Severity = %q, want medium (reflection is not a demonstrated split)", v.Severity)
		}
		if v.Parameter != "q" {
			t.Errorf("Parameter = %q, want q", v.Parameter)
		}
		if !strings.HasPrefix(v.Evidence, "confidence="+intrusiveConfidenceHeuristic) {
			t.Errorf("Evidence = %q, want a confidence=heuristic prefix", v.Evidence)
		}
		if !strings.Contains(v.Evidence, "reflection indicator") {
			t.Errorf("Evidence should say it is only a reflection indicator: %q", v.Evidence)
		}
	})

	t.Run("stripping CR and LF prevents the false positive", func(t *testing.T) {
		// A target that removes the control characters but still echoes the
		// value must NOT be reported: the marker text alone is not a signal.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := strings.NewReplacer("\r", "", "\n", "").Replace(r.URL.Query().Get("q"))
			io.WriteString(w, "you searched for "+v)
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=hello", IntrusiveOptions{CRLFInjection: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("CR/LF-stripping target reported %d findings, want 0", len(findings))
		}
	})

	t.Run("percent-encoding the value prevents the false positive", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The correct remediation: the value is re-encoded before output,
			// so no control character reaches the response.
			io.WriteString(w, "you searched for "+urlQueryEscapeForTest(r.URL.Query().Get("q")))
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=hello", IntrusiveOptions{CRLFInjection: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("encoding target reported %d findings, want 0", len(findings))
		}
	})

	t.Run("no reflection at all prevents the false positive", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=hello", IntrusiveOptions{CRLFInjection: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("non-reflecting target reported %d findings, want 0", len(findings))
		}
	})

	t.Run("a materialised response header is confirmed", func(t *testing.T) {
		// The target decodes the payload and puts the injected value into a
		// response header. Go's server cannot emit a raw CRLF inside a header
		// value (it sanitises it), so the wire-observable result of a real
		// response split is modelled here by materialising the header line the
		// injected sequence asked for.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.RawQuery, intrusiveCRLFMarker) {
				w.Header().Set(intrusiveCRLFCanaryName, "1")
			}
			io.WriteString(w, "ok")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=hello", IntrusiveOptions{CRLFInjection: true})
		findings := s.ScanAll(context.Background())
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1 (the response carries the canary header)", len(findings))
		}
		v := findings[0]
		if v.Severity != "high" {
			t.Errorf("Severity = %q, want high for a confirmed header", v.Severity)
		}
		if !strings.HasPrefix(v.Evidence, "confidence="+intrusiveConfidenceConfirmed) {
			t.Errorf("Evidence = %q, want a confidence=confirmed prefix", v.Evidence)
		}
		if !strings.Contains(v.PoC, payload) {
			t.Errorf("PoC should name the injected payload %q: %q", payload, v.PoC)
		}
	})

	t.Run("a split Location header is confirmed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Two Location headers is exactly what an injected CRLF+Location
			// produces on the wire.
			w.Header().Add("Location", "/redirected")
			w.Header().Add("Location", intrusiveCRLFMarker+": 1")
			w.WriteHeader(http.StatusFound)
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=hello", IntrusiveOptions{CRLFInjection: true})
		findings := s.ScanAll(context.Background())
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1 for the split Location header", len(findings))
		}
		if findings[0].Severity != "high" {
			t.Errorf("Severity = %q, want high", findings[0].Severity)
		}
		if !strings.HasPrefix(findings[0].Evidence, "confidence="+intrusiveConfidenceConfirmed) {
			t.Errorf("Evidence = %q, want a confidence=confirmed prefix", findings[0].Evidence)
		}
	})

	t.Run("a single Location header is not a split", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/only-one")
			w.WriteHeader(http.StatusFound)
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=hello", IntrusiveOptions{CRLFInjection: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("single-Location response reported %d findings, want 0", len(findings))
		}
	})

	t.Run("the header carrier is deliberately not used", func(t *testing.T) {
		// Documented limitation: the probe never injects into a request header,
		// because Go's transport refuses a CRLF in a header value. A target that
		// only reflects a *request header* into a response header therefore is
		// not found by this probe, and this test pins that behaviour so the
		// omission stays visible.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if echoed := r.Header.Get("X-Ss-Probe"); echoed != "" {
				w.Header().Set("X-Ss-Echo", echoed)
			}
			io.WriteString(w, "ok")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=hello", IntrusiveOptions{CRLFInjection: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("header-reflection target reported %d findings, want 0 (the header carrier is a known omission)", len(findings))
		}
	})

	t.Run("AllowPost adds a form carrier and nothing else", func(t *testing.T) {
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
			v := r.URL.Query().Get("q")
			if r.Method == http.MethodPost {
				_ = r.ParseForm()
				v = r.PostFormValue("q")
			}
			io.WriteString(w, "you searched for "+v)
		}))
		defer srv.Close()

		off := intrusiveScanner(t, srv.URL+"/?q=hello", IntrusiveOptions{CRLFInjection: true})
		if got := len(off.ScanAll(context.Background())); got != 1 {
			t.Errorf("AllowPost=false produced %d findings, want 1 (GET carrier only)", got)
		}
		for _, r := range rec.list() {
			if r.method != http.MethodGet {
				t.Errorf("AllowPost=false sent a %s request, want GET only", r.method)
			}
		}

		before := rec.count()
		on := intrusiveScanner(t, srv.URL+"/?q=hello", IntrusiveOptions{CRLFInjection: true, AllowPost: true})
		if got := len(on.ScanAll(context.Background())); got != 2 {
			t.Errorf("AllowPost=true produced %d findings, want 2 (GET and form carriers)", got)
		}
		var posts int
		for _, r := range rec.list()[before:] {
			if r.method == http.MethodPost {
				posts++
				if !strings.Contains(r.body, intrusiveCRLFSuffix) {
					t.Errorf("POST carrier body %q does not carry the injected sequence", r.body)
				}
			}
		}
		if posts != 1 {
			t.Errorf("AllowPost=true sent %d POST requests, want exactly 1", posts)
		}
	})
}

// ── probe 2: boolean-based SQLi ──────────────────────────────────────────────

func TestIntrusiveBooleanSQLi(t *testing.T) {
	sizeFor := func(v string) int {
		switch {
		case strings.Contains(v, "1=1"):
			return 400
		case strings.Contains(v, "1=2"):
			return 40
		}
		return 120
	}

	t.Run("a true/false length differential is reported", func(t *testing.T) {
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, strings.Repeat("x", sizeFor(r.URL.Query().Get("q"))))
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=1", IntrusiveOptions{BooleanSQLi: true})
		findings := s.ScanAll(context.Background())
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		v := findings[0]
		if v.Title != "Boolean-based SQL injection indicator" {
			t.Errorf("Title = %q", v.Title)
		}
		if v.Severity != "high" || v.Parameter != "q" {
			t.Errorf("Severity/Parameter = %q/%q, want high/q", v.Severity, v.Parameter)
		}
		if !strings.HasPrefix(v.Evidence, "confidence="+intrusiveConfidenceHeuristic) {
			t.Errorf("Evidence = %q, want a confidence=heuristic prefix (a differential is not proof)", v.Evidence)
		}
		if !strings.Contains(v.Evidence, "control did not differ") {
			t.Errorf("Evidence must name the benign control: %q", v.Evidence)
		}
		if !strings.Contains(v.Evidence, intrusiveSQLiQuoteTrue) || !strings.Contains(v.Evidence, intrusiveSQLiNumTrue) {
			t.Errorf("Evidence should list both payload pairs: %q", v.Evidence)
		}
		// Exactly the two payload pairs plus the mandatory control pair.
		if got := rec.count(); got != intrusiveSQLiRequests {
			t.Errorf("sent %d requests, want %d (2 pairs + the control pair)", got, intrusiveSQLiRequests)
		}
	})

	t.Run("a stable target is not reported", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, strings.Repeat("x", 120))
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=1", IntrusiveOptions{BooleanSQLi: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("stable target reported %d findings, want 0", len(findings))
		}
	})

	t.Run("a noisy target is suppressed by the control", func(t *testing.T) {
		// The response size alternates on every request regardless of input, so
		// the true/false pairs differ AND the benign control pair differs. The
		// control must veto the finding.
		var n int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			size := 40
			if atomic.AddInt32(&n, 1)%2 == 1 {
				size = 400
			}
			io.WriteString(w, strings.Repeat("x", size))
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=1", IntrusiveOptions{BooleanSQLi: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("non-deterministic target reported %d findings, want 0 (the control must veto)", len(findings))
		}
	})

	t.Run("a disabled family sends nothing", func(t *testing.T) {
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, strings.Repeat("x", sizeFor(r.URL.Query().Get("q"))))
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=1", IntrusiveOptions{CRLFInjection: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("got %d findings from another family, want 0", len(findings))
		}
		for _, r := range rec.list() {
			if strings.Contains(r.url, "1%3D2") || strings.Contains(r.url, "1=2") {
				t.Errorf("a boolean payload was sent with the family off: %s", r.url)
			}
		}
	})
}

// ── probe 3: time-based SQLi ─────────────────────────────────────────────────

func TestIntrusiveTimeBasedSQLi(t *testing.T) {
	// The handler is slow for every request (so the baseline is stable and the
	// jitter check has room), and much slower for the sleep-shaped value. Real
	// sleeps of two seconds are never used in a test.
	const (
		baseDelay  = 30 * time.Millisecond
		sleepDelay = 300 * time.Millisecond
	)
	slowHandler := func(w http.ResponseWriter, r *http.Request) {
		delay := baseDelay
		if strings.Contains(r.URL.Query().Get("q"), "SLEEP(2)") {
			delay = sleepDelay
		}
		time.Sleep(delay)
		io.WriteString(w, "ok")
	}

	t.Run("a sleep-shaped delay is reported", func(t *testing.T) {
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(slowHandler))
		defer srv.Close()

		// Prime the connection pool so the baseline is not polluted by TCP and
		// TLS-free setup on the first sample.
		if resp, err := http.Get(srv.URL + "/?q=warmup"); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		mark := rec.count()

		s := intrusiveScanner(t, srv.URL+"/?q=1", IntrusiveOptions{TimeBasedSQLi: true})
		// Only the detection floor is lowered. What is SENT stays SLEEP(2).
		s.timeFloor = 50 * time.Millisecond

		findings := s.ScanAll(context.Background())
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1 (only the MySQL sleep family is triggered by the handler)", len(findings))
		}
		v := findings[0]
		if v.Title != "Time-based SQL injection indicator" || v.Severity != "high" || v.Parameter != "q" {
			t.Errorf("Title/Severity/Parameter = %q/%q/%q", v.Title, v.Severity, v.Parameter)
		}
		if !strings.HasPrefix(v.Evidence, "confidence="+intrusiveConfidenceHeuristic) {
			t.Errorf("Evidence = %q, want a confidence=heuristic prefix", v.Evidence)
		}
		if !strings.Contains(v.Evidence, intrusiveSleepMySQL) {
			t.Errorf("Evidence should name the payload that delayed the response: %q", v.Evidence)
		}
		if !strings.Contains(v.Evidence, "hard-capped at 2s") {
			t.Errorf("Evidence must state the 2s cap on what was sent: %q", v.Evidence)
		}

		// Bounded work: 3 baseline samples + 3 repeats per payload family.
		wantRequests := intrusiveTimeBaselineN + 2*intrusiveTimeRepeats
		if got := rec.count() - mark; got != wantRequests {
			t.Errorf("the time probe sent %d requests, want %d", got, wantRequests)
		}

		// Safety: only the hard-capped 2s literals may ever leave the process.
		var sawMySQL, sawPostgres bool
		for _, r := range rec.list() {
			switch {
			case strings.Contains(r.url, "SLEEP%282%29"):
				sawMySQL = true
			case strings.Contains(r.url, "pg_sleep%282%29"):
				sawPostgres = true
			case strings.Contains(r.url, "SLEEP%28") || strings.Contains(r.url, "pg_sleep%28"):
				t.Errorf("a sleep payload other than the capped 2s literal was sent: %s", r.url)
			}
		}
		if !sawMySQL || !sawPostgres {
			t.Errorf("both capped sleep payloads should have been attempted: mysql=%v postgres=%v", sawMySQL, sawPostgres)
		}
	})

	t.Run("uniform latency is not reported", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(baseDelay)
			io.WriteString(w, "ok")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=1", IntrusiveOptions{TimeBasedSQLi: true})
		s.timeFloor = 50 * time.Millisecond
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("uniform-latency target reported %d findings, want 0", len(findings))
		}
	})

	t.Run("a disabled family sends nothing", func(t *testing.T) {
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(slowHandler))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=1", IntrusiveOptions{CRLFInjection: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("got %d findings from another family, want 0", len(findings))
		}
		for _, r := range rec.list() {
			if strings.Contains(r.url, "SLEEP") || strings.Contains(r.url, "pg_sleep") {
				t.Errorf("a sleep payload was sent with the family off: %s", r.url)
			}
		}
	})

	t.Run("the per-family request cap is enforced", func(t *testing.T) {
		// The time-based family has its own cap, independent of the whole-scan
		// budget, so a target with many endpoints and parameters cannot make it
		// run away. Three parameters are enough to overrun a cap that is only
		// checked but never spent.
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?a=1&b=2&c=3", IntrusiveOptions{TimeBasedSQLi: true})
		_ = s.ScanAll(context.Background())
		got := rec.count()
		if got == 0 {
			t.Fatal("the time-based probe sent nothing at all")
		}
		if got > intrusiveTimeMaxRequests {
			t.Errorf("the time-based probe sent %d requests, over its cap of %d", got, intrusiveTimeMaxRequests)
		}
	})
}

// ── probe 4: path traversal ──────────────────────────────────────────────────

func TestIntrusivePathTraversal(t *testing.T) {
	t.Run("a signature match is reported without the body", func(t *testing.T) {
		const body = "root:x:0:0:root:/root:/bin/bash"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path+" "+r.URL.RawQuery, "etc/passwd") {
				io.WriteString(w, body+"\n")
				return
			}
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "not found")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?id=1", IntrusiveOptions{PathTraversal: true})
		findings := s.ScanAll(context.Background())
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1 (one signature per endpoint)", len(findings))
		}
		v := findings[0]
		if v.Title != "Path traversal signature matched: /etc/passwd" {
			t.Errorf("Title = %q", v.Title)
		}
		if v.Severity != "high" {
			t.Errorf("Severity = %q, want high", v.Severity)
		}
		if !strings.HasPrefix(v.Evidence, "confidence="+intrusiveConfidenceConfirmed) {
			t.Errorf("Evidence = %q, want a confidence=confirmed prefix", v.Evidence)
		}
		// Safety rule: a traversal response body never reaches a finding.
		for _, field := range []struct{ name, value string }{
			{"Evidence", v.Evidence},
			{"PoC", v.PoC},
			{"Impact", v.Impact},
			{"Remediation", v.Remediation},
		} {
			if strings.Contains(field.value, intrusivePasswdSignature) {
				t.Errorf("%s leaks the signature bytes: %q", field.name, field.value)
			}
			if strings.Contains(field.value, "/bin/bash") || strings.Contains(field.value, "/root:/root") {
				t.Errorf("%s leaks file content: %q", field.name, field.value)
			}
		}
		if !strings.Contains(v.Evidence, "body is deliberately withheld") {
			t.Errorf("Evidence should state that the body is withheld: %q", v.Evidence)
		}
	})

	t.Run("a 404 target is not reported", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "not found")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?id=1", IntrusiveOptions{PathTraversal: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("404 target reported %d findings, want 0", len(findings))
		}
	})

	t.Run("a target that echoes signatures is suppressed by the canary", func(t *testing.T) {
		// This handler returns the passwd signature for every path, including
		// the canary file that cannot exist. Nothing here proves traversal, and
		// the suppression sweep must veto it.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, intrusivePasswdSignature+"root:/root:/bin/bash\n")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?id=1", IntrusiveOptions{PathTraversal: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("signature-echoing target reported %d findings, want 0", len(findings))
		}
	})

	t.Run("a disabled family sends nothing", func(t *testing.T) {
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?id=1", IntrusiveOptions{CRLFInjection: true})
		_ = s.ScanAll(context.Background())
		for _, r := range rec.list() {
			if strings.Contains(r.url, "etc/passwd") || strings.Contains(r.url, "passive-canary") {
				t.Errorf("a traversal payload was sent with the family off: %s", r.url)
			}
		}
	})
}

// ── probe 5: SSRF indicators ─────────────────────────────────────────────────

func TestIntrusiveSSRFIndicators(t *testing.T) {
	t.Run("a differential on a URL-shaped parameter is reported", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Query().Get("target"), "http://") {
				w.WriteHeader(http.StatusBadGateway)
				io.WriteString(w, "could not resolve host")
				return
			}
			io.WriteString(w, "ok")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?target=/local", IntrusiveOptions{SSRFIndicators: true})
		findings := s.ScanAll(context.Background())
		if len(findings) == 0 {
			t.Fatal("no findings; the canary URL changed the response while the control did not")
		}
		for _, v := range findings {
			if v.Title != "SSRF indicator in a URL-shaped parameter" {
				t.Errorf("Title = %q", v.Title)
			}
			if v.Severity != "medium" || v.Parameter != "target" {
				t.Errorf("Severity/Parameter = %q/%q", v.Severity, v.Parameter)
			}
			if !strings.HasPrefix(v.Evidence, "confidence="+intrusiveConfidenceHeuristic) {
				t.Errorf("Evidence = %q, want a confidence=heuristic prefix", v.Evidence)
			}
			if !strings.Contains(v.Evidence, intrusiveSSRFCanaryHost) {
				t.Errorf("Evidence should name the reserved canary host: %q", v.Evidence)
			}
			if !strings.Contains(v.Evidence, "same-length control") {
				t.Errorf("Evidence must name the mandatory control: %q", v.Evidence)
			}
			// Safety rule: never point a probe at a link-local metadata IP.
			for _, field := range []string{v.Evidence, v.PoC} {
				if strings.Contains(field, "169.254.169.254") {
					t.Errorf("a finding mentions the cloud metadata IP: %q", field)
				}
			}
		}
	})

	t.Run("a uniform target is not reported", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?target=/local", IntrusiveOptions{SSRFIndicators: true})
		if findings := s.ScanAll(context.Background()); len(findings) != 0 {
			t.Errorf("uniform target reported %d findings, want 0", len(findings))
		}
	})

	t.Run("a non-URL-shaped parameter is never touched", func(t *testing.T) {
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?q=1", IntrusiveOptions{SSRFIndicators: true})
		findings := s.ScanAll(context.Background())
		if len(findings) != 0 {
			t.Errorf("got %d findings for a parameter name that is not URL-shaped, want 0", len(findings))
		}
		if got := rec.count(); got != 0 {
			t.Errorf("a non-URL-shaped parameter caused %d requests, want 0", got)
		}
	})

	t.Run("the parameter-name filter is the documented set", func(t *testing.T) {
		for _, name := range []string{"url", "next", "target", "redirect", "callback", "NEXT", "Image"} {
			if !intrusiveSSRFParamRe.MatchString(name) {
				t.Errorf("%q should be treated as URL-shaped", name)
			}
		}
		for _, name := range []string{"q", "id", "search", "sql", "page"} {
			if intrusiveSSRFParamRe.MatchString(name) {
				t.Errorf("%q must not be treated as URL-shaped", name)
			}
		}
	})
}

// ── probe 6: write methods ───────────────────────────────────────────────────

func TestIntrusiveWriteMethodProbes(t *testing.T) {
	scan := func(t *testing.T, target *intrusiveWriteTarget) (*intrusiveRecorder, []Vulnerability) {
		t.Helper()
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(target.handler()))
		t.Cleanup(srv.Close)

		s := intrusiveScanner(t, srv.URL+"/", IntrusiveOptions{WriteMethodProbes: true})
		return rec, s.ScanAll(context.Background())
	}

	t.Run("an accepted PUT is confirmed, verified and cleaned up", func(t *testing.T) {
		target := newIntrusiveWriteTarget(http.StatusOK, true, http.StatusNoContent, http.StatusNotFound)
		rec, findings := scan(t, target)

		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		v := findings[0]
		if v.Severity != "high" {
			t.Errorf("Severity = %q, want high for a created resource", v.Severity)
		}
		if !strings.HasPrefix(v.Evidence, "confidence="+intrusiveConfidenceConfirmed) {
			t.Errorf("Evidence = %q, want a confidence=confirmed prefix", v.Evidence)
		}
		if !strings.Contains(v.Evidence, "residual side effect") {
			t.Errorf("Evidence must state the residual side effect: %q", v.Evidence)
		}
		if !strings.Contains(v.Evidence, "cleanup attempted: yes (DELETE returned 204)") {
			t.Errorf("Evidence must report the successful cleanup: %q", v.Evidence)
		}

		// Exactly GET (prove absent), PUT, GET (verify), DELETE (clean up).
		wantMethods := []string{http.MethodGet, http.MethodPut, http.MethodGet, http.MethodDelete}
		gotMethods := rec.methods()
		if len(gotMethods) != len(wantMethods) {
			t.Fatalf("methods = %v, want %v", gotMethods, wantMethods)
		}
		for i := range wantMethods {
			if gotMethods[i] != wantMethods[i] {
				t.Fatalf("methods = %v, want %v", gotMethods, wantMethods)
			}
		}

		puts := rec.ofMethod(http.MethodPut)
		if len(puts) != 1 {
			t.Fatalf("PUT requests = %d, want 1", len(puts))
		}
		// Bounded write: an empty body, on a random path, and nothing else.
		if puts[0].body != "" {
			t.Errorf("the PUT carried a body %q, want an empty body", puts[0].body)
		}
		path := puts[0].url
		if !strings.HasPrefix(path, "/"+intrusiveWritePathPrefix) || !strings.HasSuffix(path, ".txt") {
			t.Errorf("PUT path = %q, want a random path under %q", path, "/"+intrusiveWritePathPrefix)
		}
		for _, del := range rec.ofMethod(http.MethodDelete) {
			if del.url != path {
				t.Errorf("the DELETE touched %q but the PUT created %q", del.url, path)
			}
		}
		if got := target.leftOver(); got != 0 {
			t.Errorf("%d canary resources were left behind, want 0", got)
		}

		// The path is random per run, so a second scan cannot collide.
		_, findings2 := scan(t, newIntrusiveWriteTarget(http.StatusOK, true, http.StatusNoContent, http.StatusNotFound))
		if len(findings2) != 1 {
			t.Fatalf("second scan got %d findings, want 1", len(findings2))
		}
		if findings2[0].URL == v.URL {
			t.Errorf("both runs used the same random path %q; the path must be random per run", v.URL)
		}
	})

	t.Run("a PUT rejected with 405 is not a finding and sends no DELETE", func(t *testing.T) {
		target := newIntrusiveWriteTarget(http.StatusMethodNotAllowed, false, http.StatusNoContent, http.StatusNotFound)
		rec, findings := scan(t, target)
		if len(findings) != 0 {
			t.Errorf("got %d findings when the PUT was refused, want 0", len(findings))
		}
		if got := rec.methods(); len(got) != 2 || got[0] != http.MethodGet || got[1] != http.MethodPut {
			t.Errorf("methods = %v, want [GET PUT] with no DELETE", got)
		}
		if len(rec.ofMethod(http.MethodDelete)) != 0 {
			t.Error("a DELETE was sent even though nothing was created")
		}
	})

	t.Run("an existing path is never written to", func(t *testing.T) {
		target := newIntrusiveWriteTarget(http.StatusOK, true, http.StatusNoContent, http.StatusOK)
		rec, findings := scan(t, target)
		if len(findings) != 0 {
			t.Errorf("got %d findings when the path already existed, want 0", len(findings))
		}
		if got := rec.methods(); len(got) != 1 || got[0] != http.MethodGet {
			t.Errorf("methods = %v, want a single GET precondition check", got)
		}
	})

	t.Run("an accepted PUT that creates nothing is reported honestly", func(t *testing.T) {
		target := newIntrusiveWriteTarget(http.StatusOK, false, http.StatusMethodNotAllowed, http.StatusNotFound)
		rec, findings := scan(t, target)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		v := findings[0]
		if v.Severity != "medium" {
			t.Errorf("Severity = %q, want medium when nothing became readable", v.Severity)
		}
		if !strings.HasPrefix(v.Evidence, "confidence="+intrusiveConfidenceHigh) {
			t.Errorf("Evidence = %q, want a confidence=high prefix", v.Evidence)
		}
		if !strings.Contains(v.Evidence, "cleanup attempted: yes but it FAILED") {
			t.Errorf("Evidence must report the failed cleanup: %q", v.Evidence)
		}
		if len(rec.ofMethod(http.MethodDelete)) != 1 {
			t.Error("cleanup must be attempted even when the PUT created nothing readable")
		}
	})

	t.Run("a disabled family sends nothing", func(t *testing.T) {
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		}))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/", IntrusiveOptions{PathTraversal: true})
		_ = s.ScanAll(context.Background())
		for _, r := range rec.list() {
			if r.method != http.MethodGet {
				t.Errorf("a %s request was sent with the write family off", r.method)
			}
		}
	})
}

// ── bounds, ordering and redirect safety ─────────────────────────────────────

func TestIntrusiveRespectsBudget(t *testing.T) {
	scan := func(t *testing.T, cfg GuardConfig) (int, int) {
		t.Helper()
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(intrusiveSink()))
		defer srv.Close()

		g := intrusiveGuard(t, cfg)
		s, err := NewIntrusiveScanner(srv.URL+"/?id=1&next=/target&url=/target2", g, intrusiveAllFamilies())
		if err != nil {
			t.Fatalf("NewIntrusiveScanner: %v", err)
		}
		findings := s.ScanAll(context.Background())
		return rec.count(), len(findings)
	}

	full, _ := scan(t, GuardConfig{AllowAll: true, Intrusive: true})
	capped, _ := scan(t, GuardConfig{AllowAll: true, Intrusive: true, MaxRequests: 2})
	if capped > 2 {
		t.Errorf("the scan sent %d requests against a budget of 2", capped)
	}
	if capped >= full {
		t.Errorf("the budget did not stop the scan early: capped=%d full=%d", capped, full)
	}
}

func TestIntrusiveNeverFollowsRedirects(t *testing.T) {
	rec := &intrusiveRecorder{}
	srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, r *http.Request) {
		// A redirect to a host that is not in scope. The Guard refuses to
		// follow redirects (CheckRedirect returns ErrUseLastResponse), so this
		// 3xx must be treated as a final response.
		http.Redirect(w, r, "http://evil.example/landing", http.StatusFound)
	}))
	defer srv.Close()

	s := intrusiveScanner(t, srv.URL+"/?id=1&next=/target", IntrusiveOptions{
		CRLFInjection:     true,
		BooleanSQLi:       true,
		PathTraversal:     true,
		SSRFIndicators:    true,
		WriteMethodProbes: true,
	})
	findings := s.ScanAll(context.Background())
	if len(findings) != 0 {
		for _, v := range findings {
			t.Errorf("unexpected finding from a bare redirect: %q (%q)", v.Title, v.Evidence)
		}
	}
	if rec.count() == 0 {
		t.Fatal("the probe never reached the loopback server")
	}
	// Every request that reached the server was addressed to it: nothing was
	// re-issued against the redirect target.
	wantHost := strings.TrimPrefix(srv.URL, "http://")
	for _, r := range rec.list() {
		if r.host != wantHost {
			t.Errorf("a request was addressed to Host=%q, want %q", r.host, wantHost)
		}
	}
}

func TestIntrusiveSinkFamilyIsolation(t *testing.T) {
	families := []struct {
		name      string
		opts      IntrusiveOptions
		titleLike string
	}{
		{intrusiveProbeCRLF, IntrusiveOptions{CRLFInjection: true, AllowPost: true}, "CRLF"},
		{intrusiveProbeBooleanSQLi, IntrusiveOptions{BooleanSQLi: true}, "Boolean-based SQL injection indicator"},
		{intrusiveProbeTraversal, IntrusiveOptions{PathTraversal: true}, "Path traversal signature matched:"},
		{intrusiveProbeSSRF, IntrusiveOptions{SSRFIndicators: true}, "SSRF indicator in a URL-shaped parameter"},
		{intrusiveProbeWriteMethod, IntrusiveOptions{WriteMethodProbes: true}, "HTTP write method"},
	}

	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			rec := &intrusiveRecorder{}
			srv := httptest.NewServer(rec.wrap(intrusiveSink()))
			defer srv.Close()

			s := intrusiveScanner(t, srv.URL+"/?id=1&next=/target&url=/target2", fam.opts)
			findings := s.ScanAll(context.Background())
			if len(findings) == 0 {
				t.Fatalf("%s: the sink carries this signal but the probe reported nothing", fam.name)
			}
			for _, v := range findings {
				if !strings.HasPrefix(v.Title, fam.titleLike) {
					t.Errorf("%s: a finding from another family leaked in: %q", fam.name, v.Title)
				}
				if !strings.HasPrefix(v.Evidence, "confidence=") {
					t.Errorf("%s: Evidence is missing the confidence prefix: %q", fam.name, v.Evidence)
				}
				if v.Title == "" || v.Severity == "" || v.Category == "" || v.URL == "" ||
					v.Parameter == "" || v.Impact == "" || v.Remediation == "" || v.PoC == "" || len(v.References) == 0 {
					t.Errorf("%s: a finding is missing a required field: %+v", fam.name, v)
				}
				if !strings.HasPrefix(v.ID, intrusiveIDPrefix+"-") {
					t.Errorf("%s: ID = %q, want the %s prefix", fam.name, v.ID, intrusiveIDPrefix)
				}
			}
		})
	}

	t.Run("all families together", func(t *testing.T) {
		rec := &intrusiveRecorder{}
		srv := httptest.NewServer(rec.wrap(intrusiveSink()))
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?id=1&next=/target&url=/target2", intrusiveAllFamilies())
		findings := s.ScanAll(context.Background())

		seen := map[string]bool{}
		for _, v := range findings {
			switch {
			case strings.HasPrefix(v.Title, "CRLF"):
				seen[intrusiveProbeCRLF] = true
			case v.Title == "Boolean-based SQL injection indicator":
				seen[intrusiveProbeBooleanSQLi] = true
			case strings.HasPrefix(v.Title, "Path traversal signature matched:"):
				seen[intrusiveProbeTraversal] = true
			case v.Title == "SSRF indicator in a URL-shaped parameter":
				seen[intrusiveProbeSSRF] = true
			case strings.HasPrefix(v.Title, "HTTP write method"):
				seen[intrusiveProbeWriteMethod] = true
			}
		}
		for _, name := range []string{
			intrusiveProbeCRLF, intrusiveProbeBooleanSQLi, intrusiveProbeTraversal,
			intrusiveProbeSSRF, intrusiveProbeWriteMethod,
		} {
			if !seen[name] {
				t.Errorf("the %s family reported nothing against a sink that carries its signal", name)
			}
		}
		// The whole-scan budget is a hard bound on what can reach the target.
		if got := rec.count(); got > intrusiveMaxTotalRequests {
			t.Errorf("the scan sent %d requests, over the %d whole-scan allowance", got, intrusiveMaxTotalRequests)
		}
	})
}

func TestIntrusiveFindingsAreDeterministic(t *testing.T) {
	run := func() []string {
		srv := httptest.NewServer(intrusiveSink())
		defer srv.Close()

		s := intrusiveScanner(t, srv.URL+"/?id=1&next=/target&url=/target2", IntrusiveOptions{
			CRLFInjection:  true,
			BooleanSQLi:    true,
			PathTraversal:  true,
			SSRFIndicators: true,
			AllowPost:      true,
		})
		sig := []string{}
		for _, v := range s.ScanAll(context.Background()) {
			// URL and PoC are excluded: they legitimately carry the random
			// control tokens and the random per-run port.
			sig = append(sig, strings.Join([]string{v.Title, v.Severity, v.Category, v.Parameter}, "|"))
		}
		return sig
	}

	first, second := run(), run()
	if len(first) == 0 {
		t.Fatal("the detector returned nothing to compare")
	}
	if len(first) != len(second) {
		t.Fatalf("run 1 produced %d findings, run 2 produced %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("finding %d differs between runs:\n  %s\n  %s", i, first[i], second[i])
		}
	}
}

// urlQueryEscapeForTest percent-encodes a value the way a correctly fixed
// target would before putting it into a header or a body, so a test can model
// a non-vulnerable responder without importing net/url into its signature.
func urlQueryEscapeForTest(v string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\r' || c == '\n' {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
