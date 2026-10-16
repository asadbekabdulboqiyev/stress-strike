package scanner

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func guardNaN() float64 { return math.NaN() }
func guardInf() float64 { return math.Inf(1) }
func guardMustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// Guard is the Requester every probe depends on; this assertion makes a
// signature drift a build failure, not a runtime surprise.
var _ Requester = (*Guard)(nil)

func mustGuard(t *testing.T, cfg GuardConfig) *Guard {
	t.Helper()
	g, err := NewGuard(cfg)
	if err != nil {
		t.Fatalf("NewGuard(%+v): %v", cfg, err)
	}
	return g
}

func TestNewGuardValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  GuardConfig
		ok   bool
	}{
		{"zero value is valid", GuardConfig{}, true},
		{"nan rps", GuardConfig{RPS: guardNaN()}, false},
		{"inf rps", GuardConfig{RPS: guardInf()}, false},
		{"negative rps", GuardConfig{RPS: -1}, false},
		{"absurd rps", GuardConfig{RPS: defaultMaxRPS + 1}, false},
		{"negative burst", GuardConfig{Burst: -1}, false},
		{"negative budget", GuardConfig{MaxRequests: -1}, false},
		{"negative timeout", GuardConfig{Timeout: -time.Second}, false},
		{"negative body cap", GuardConfig{MaxBodyBytes: -1}, false},
		{"empty pattern entry", GuardConfig{Allow: []string{"   "}}, false},
		{"too many fields", GuardConfig{Allow: []string{"a b c"}}, false},
		{"path not absolute", GuardConfig{Allow: []string{"example.com api"}}, false},
		{"path in netloc", GuardConfig{Allow: []string{"example.com/api"}}, false},
		{"unclosed bracket", GuardConfig{Allow: []string{"[::1"}}, false},
		{"non-numeric port", GuardConfig{Allow: []string{"example.com:http"}}, false},
		{"port too big", GuardConfig{Allow: []string{"example.com:99999"}}, false},
		{"bare star", GuardConfig{Allow: []string{"*"}}, false},
		{"star not leading", GuardConfig{Allow: []string{"foo.*.com"}}, false},
		{"wildcard ok", GuardConfig{Allow: []string{"*.example.com"}}, true},
		{"ipv6 with port ok", GuardConfig{Allow: []string{"[::1]:8080"}}, true},
		{"cidr with path ok", GuardConfig{Allow: []string{"10.0.0.0/8 /internal"}}, true},
		{"rps default", GuardConfig{RPS: 0}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGuard(tc.cfg)
			if tc.ok && err != nil {
				t.Fatalf("expected ok, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestNewGuardDefaults(t *testing.T) {
	g := mustGuard(t, GuardConfig{})
	if g.cfg.RPS != DefaultRPS {
		t.Errorf("RPS = %v, want %v", g.cfg.RPS, DefaultRPS)
	}
	if g.cfg.Burst != DefaultRPS {
		t.Errorf("Burst = %d, want %d", g.cfg.Burst, DefaultRPS)
	}
	if g.cfg.MaxRequests != DefaultMaxRequests {
		t.Errorf("MaxRequests = %d, want %d", g.cfg.MaxRequests, DefaultMaxRequests)
	}
	if g.cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", g.cfg.Timeout, DefaultTimeout)
	}
	if g.cfg.MaxBodyBytes != DefaultProbeLimit {
		t.Errorf("MaxBodyBytes = %d, want %d", g.cfg.MaxBodyBytes, DefaultProbeLimit)
	}
}

func TestCheckFailClosedEmptyAllowlist(t *testing.T) {
	g := mustGuard(t, GuardConfig{})
	err := g.Check(context.Background(), "GET", "http://example.com/", false)
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("empty allowlist must refuse everything, got %v", err)
	}
	if g.Stats().RefusedOutOfScope != 1 {
		t.Errorf("RefusedOutOfScope = %d, want 1", g.Stats().RefusedOutOfScope)
	}
}

func TestCheckScopeMatching(t *testing.T) {
	cfg := GuardConfig{Allow: []string{
		"exact.test",
		"*.wild.test",
		"10.0.0.0/8",
		"192.168.1.5",
		"port.test:8443",
		"path.test /api",
		"172.16.0.0/12 /internal",
	}}
	g := mustGuard(t, cfg)
	ctx := context.Background()

	allowed := []string{
		"https://exact.test/",
		"https://exact.test/anything?q=1",
		"https://sub.wild.test/",
		"https://deep.sub.wild.test/",
		"http://10.0.0.1/",
		"http://10.255.255.254/",
		"http://192.168.1.5/",
		"https://port.test:8443/x",
		"http://path.test/api",
		"http://path.test/api/v1/users",
		"http://172.16.5.5/internal",
		"http://172.16.5.5/internal/x",
	}
	for _, u := range allowed {
		if err := g.Check(ctx, "GET", u, false); err != nil {
			t.Errorf("Check(%s) = %v, want allowed", u, err)
		}
	}

	refused := []string{
		"https://evil.test/",           // not listed
		"https://wild.test/",           // apex of a wildcard is excluded
		"https://11.0.0.1/",            // outside CIDR
		"http://192.168.1.6/",          // neighbouring IP
		"https://port.test/",           // wrong effective port (443 vs 8443)
		"https://port.test:9443/",      // wrong explicit port
		"http://path.test/apix",        // segment-aware: no /apix
		"http://path.test/",            // outside the path prefix
		"http://172.16.5.5/other",      // path prefix on a CIDR entry (outside /internal)
		"ftp://exact.test/",            // non-http(s) scheme
		"http://user:pass@exact.test/", // userinfo
		"http://exact.test:99999/",     // invalid port
		"http:///",                     // empty host
	}
	for _, u := range refused {
		if err := g.Check(ctx, "GET", u, false); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("Check(%s) = %v, want ErrOutOfScope", u, err)
		}
	}
}

func TestCheckEffectivePortSchemeDefault(t *testing.T) {
	g := mustGuard(t, GuardConfig{Allow: []string{"https.test:443", "http.test:80"}})
	ctx := context.Background()
	if err := g.Check(ctx, "GET", "https://https.test/", false); err != nil {
		t.Errorf("https default port 443 should match: %v", err)
	}
	if err := g.Check(ctx, "GET", "http://http.test/", false); err != nil {
		t.Errorf("http default port 80 should match: %v", err)
	}
	if err := g.Check(ctx, "GET", "https://https.test:80/", false); !errors.Is(err, ErrOutOfScope) {
		t.Errorf("https on port 80 should not match a :443 entry, got %v", err)
	}
}

func TestCheckAllowAllStillStructural(t *testing.T) {
	g := mustGuard(t, GuardConfig{AllowAll: true})
	ctx := context.Background()
	if err := g.Check(ctx, "GET", "https://anything.example/x", false); err != nil {
		t.Errorf("AllowAll should permit a valid http(s) target: %v", err)
	}
	// Structural refusals survive AllowAll.
	for _, u := range []string{
		"ftp://anything.example/",
		"http://user:pw@anything.example/",
		"http://anything.example:70000/",
		"http:///",
	} {
		if err := g.Check(ctx, "GET", u, false); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("AllowAll must still refuse %s structurally, got %v", u, err)
		}
	}
}

func TestCheckIntrusiveGate(t *testing.T) {
	ctx := context.Background()

	off := mustGuard(t, GuardConfig{AllowAll: true})
	if err := off.Check(ctx, "GET", "http://t.test/", true); !errors.Is(err, ErrIntrusiveDisabled) {
		t.Fatalf("intrusive probe with gate off = %v, want ErrIntrusiveDisabled", err)
	}
	if err := off.Check(ctx, "GET", "http://t.test/", false); err != nil {
		t.Fatalf("passive probe with gate off = %v, want allowed", err)
	}
	if off.Stats().RefusedIntrusive != 1 {
		t.Errorf("RefusedIntrusive = %d, want 1", off.Stats().RefusedIntrusive)
	}

	on := mustGuard(t, GuardConfig{AllowAll: true, Intrusive: true})
	if err := on.Check(ctx, "POST", "http://t.test/", true); err != nil {
		t.Fatalf("intrusive probe with gate on = %v, want allowed", err)
	}
}

func TestCheckIsSideEffectFreeForBudget(t *testing.T) {
	g := mustGuard(t, GuardConfig{AllowAll: true, MaxRequests: 1})
	ctx := context.Background()
	// Check never consumes the budget, no matter how often it is called.
	for i := 0; i < 5; i++ {
		if err := g.Check(ctx, "GET", "http://t.test/", false); err != nil {
			t.Fatalf("Check call %d = %v, want nil (budget untouched)", i, err)
		}
	}
	if g.budget.Load() != 0 {
		t.Fatalf("Check consumed budget: %d", g.budget.Load())
	}
}

func TestDryRunCheckAllowsThenDoRefuses(t *testing.T) {
	g := mustGuard(t, GuardConfig{AllowAll: true, DryRun: true})
	ctx := context.Background()
	if err := g.Check(ctx, "GET", "http://t.test/", false); err != nil {
		t.Fatalf("DryRun Check = %v, want nil", err)
	}
	if g.Stats().DryRunChecked != 1 {
		t.Errorf("DryRunChecked = %d, want 1", g.Stats().DryRunChecked)
	}
	req, _ := http.NewRequest("GET", "http://t.test/", nil)
	if _, err := g.Do(req); !errors.Is(err, ErrDryRun) {
		t.Fatalf("DryRun Do = %v, want ErrDryRun", err)
	}
	if g.Stats().RefusedDryRun != 1 {
		t.Errorf("RefusedDryRun = %d, want 1", g.Stats().RefusedDryRun)
	}
	if g.Stats().RequestsSent != 0 {
		t.Errorf("DryRun sent %d requests, want 0", g.Stats().RequestsSent)
	}
}

func TestDoSendsSetsUAAndCapsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != ScannerUserAgent {
			t.Errorf("User-Agent = %q, want %q", r.Header.Get("User-Agent"), ScannerUserAgent)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, strings.Repeat("A", 4096))
	}))
	defer srv.Close()

	g := mustGuard(t, GuardConfig{Allow: []string{"127.0.0.1"}, MaxBodyBytes: 64})
	req, err := http.NewRequest("GET", srv.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := g.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, err := ReadBody(resp, DefaultProbeLimit)
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if len(body) != 64 {
		t.Errorf("body length = %d, want the 64-byte cap", len(body))
	}
	if got := g.Stats().BytesRead; got != 64 {
		t.Errorf("BytesRead = %d, want 64", got)
	}
	if g.Stats().RequestsSent != 1 {
		t.Errorf("RequestsSent = %d, want 1", g.Stats().RequestsSent)
	}
}

func TestDoKeepsCallerUserAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "custom-agent" {
			t.Errorf("User-Agent = %q, want custom-agent", got)
		}
	}))
	defer srv.Close()

	g := mustGuard(t, GuardConfig{Allow: []string{"127.0.0.1"}})
	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("User-Agent", "custom-agent")
	resp, err := g.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
}

func TestDoDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/from" {
			http.Redirect(w, r, "/to", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	g := mustGuard(t, GuardConfig{Allow: []string{"127.0.0.1"}})
	req, _ := http.NewRequest("GET", srv.URL+"/from", nil)
	resp, err := g.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect must not be followed)", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/to" {
		t.Errorf("Location = %q, want /to", loc)
	}
}

func TestDoReChecksScopeAndBudget(t *testing.T) {
	g := mustGuard(t, GuardConfig{Allow: []string{"127.0.0.1"}, MaxRequests: 1})
	// A caller that skipped Check still cannot escape the allowlist.
	out, _ := http.NewRequest("GET", "http://evil.example/", nil)
	if _, err := g.Do(out); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("Do out-of-scope = %v, want ErrOutOfScope", err)
	}
	if g.Stats().RefusedOutOfScope != 1 {
		t.Errorf("RefusedOutOfScope = %d, want 1", g.Stats().RefusedOutOfScope)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ok, _ := http.NewRequest("GET", srv.URL+"/", nil)
	resp, err := g.Do(ok)
	if err != nil {
		t.Fatalf("first in-scope Do: %v", err)
	}
	_ = resp.Body.Close()

	again, _ := http.NewRequest("GET", srv.URL+"/", nil)
	if _, err := g.Do(again); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("second Do = %v, want ErrBudgetExhausted", err)
	}
	if g.Stats().RefusedBudget != 1 {
		t.Errorf("RefusedBudget = %d, want 1", g.Stats().RefusedBudget)
	}
}

func TestRateLimiterBuckets(t *testing.T) {
	rl := newRateLimiter(1, 2) // 1 token/s, burst 2
	now := time.Now()
	if !rl.tryTake("h", now) || !rl.tryTake("h", now) {
		t.Fatal("burst of 2 should both succeed")
	}
	if rl.tryTake("h", now) {
		t.Fatal("third immediate take should fail (bucket empty)")
	}
	if !rl.tryTake("h", now.Add(1100*time.Millisecond)) {
		t.Fatal("a full second should refill one token")
	}
	// Distinct keys have distinct buckets.
	if !rl.tryTake("other", now) {
		t.Fatal("a different host has its own bucket")
	}
}

func TestDoReturnsRateLimitedEventually(t *testing.T) {
	// RPS of 1 with burst 1: the second immediate send must wait, and with a
	// short context deadline it must fail rather than hang.
	g := mustGuard(t, GuardConfig{AllowAll: true, RPS: 1, Burst: 1})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// AllowAll covers this host regardless of its port.

	first, _ := http.NewRequest("GET", srv.URL+"/", nil)
	resp, err := g.Do(first)
	if err != nil {
		t.Fatalf("first Do: %v", err)
	}
	_ = resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	second, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/", nil)
	if _, err := g.Do(second); err == nil {
		t.Fatal("second immediate Do should not succeed while rate limited")
	}
}

func TestCappedBodyTruncatesAndCounts(t *testing.T) {
	g := mustGuard(t, GuardConfig{})
	cb := &cappedBody{rc: io.NopCloser(strings.NewReader(strings.Repeat("x", 100))), remaining: 10, g: g}
	buf := make([]byte, 64)
	var total int
	for {
		n, err := cb.Read(buf)
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if total != 10 {
		t.Errorf("read %d bytes, want 10", total)
	}
	if g.Stats().BytesRead != 10 {
		t.Errorf("BytesRead = %d, want 10", g.Stats().BytesRead)
	}
}

func TestPatternSegmentAwarePath(t *testing.T) {
	p, err := parseScopePattern("host.test /api/v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, ok := range []string{"/api/v1", "/api/v1/", "/api/v1/users"} {
		if !p.matchPath(ok) {
			t.Errorf("matchPath(%q) = false, want true", ok)
		}
	}
	for _, no := range []string{"/api", "/api/v1x", "/api/v10", "/other"} {
		if p.matchPath(no) {
			t.Errorf("matchPath(%q) = true, want false", no)
		}
	}
}

func TestEffectivePort(t *testing.T) {
	cases := map[string]int{
		"http://h/":       80,
		"https://h/":      443,
		"http://h:8080/":  8080,
		"https://h:8080/": 8080,
	}
	for raw, want := range cases {
		u := guardMustURL(t, raw)
		if got := effectivePort(u); got != want {
			t.Errorf("effectivePort(%s) = %d, want %d", raw, got, want)
		}
	}
}

func TestGuardStatsSnapshot(t *testing.T) {
	g := mustGuard(t, GuardConfig{AllowAll: true})
	_ = g.Check(context.Background(), "GET", "http://t.test/", true) // refused: intrusive
	s := g.Stats()
	if s.RequestsRefused != 1 || s.RefusedIntrusive != 1 {
		t.Errorf("stats = %+v, want 1 refusal, 1 intrusive", s)
	}
}
