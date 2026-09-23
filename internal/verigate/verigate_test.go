package verigate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

//--------------------------------------------------------------
// helpers
//--------------------------------------------------------------

func newTestGate(t *testing.T, mutate func(*Options)) *VeriGate {
	t.Helper()
	opts := Options{
		Enabled:       true,
		RateLimit:     5, // 5 tokens/sec
		Burst:         5, // burst of 5
		Difficulty:    2, // easy PoW for tests
		BlockAfter:    3,
		BlockDuration: time.Minute,
	}
	if mutate != nil {
		mutate(&opts)
	}
	g, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func newServer(g *VeriGate) *httptest.Server {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	return httptest.NewServer(g.Handler(inner))
}

func doReq(t *testing.T, url, accept string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

// solveProof computes a valid nonce for a challenge prefix (mirrors the
// browser solver in vg_challenge.html).
func solveProof(prefix string, difficulty int) string {
	target := strings.Repeat("0", difficulty)
	for nonce := 0; nonce < 1<<24; nonce++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s%d", prefix, nonce)))
		if strings.HasPrefix(hex.EncodeToString(sum[:]), target) {
			return fmt.Sprintf("%d", nonce)
		}
	}
	return ""
}

//--------------------------------------------------------------
// 1. Disabled gate passes everything
//--------------------------------------------------------------

func TestDisabledGatePasses(t *testing.T) {
	g := newTestGate(t, func(o *Options) { o.Enabled = false })
	srv := newServer(g)
	defer srv.Close()

	// Hammer over the limit — but protection is off, so everything passes.
	for i := 0; i < 50; i++ {
		code, body, _ := doReq(t, srv.URL, "application/json")
		if code != http.StatusOK {
			t.Fatalf("req %d: code=%d want 200 (disabled gate must pass all)", i, code)
		}
		if body != "ok\n" {
			t.Fatalf("req %d: body=%q want %q", i, body, "ok\n")
		}
	}
	if g.Enabled() {
		t.Fatal("Enabled() should be false")
	}
}

//--------------------------------------------------------------
// 2. Rate limiting: API clients get 429
//--------------------------------------------------------------

func TestRateLimitAPI429(t *testing.T) {
	g := newTestGate(t, nil)
	srv := newServer(g)
	defer srv.Close()

	limited := 0
	var gen int
	const hits = 40
	for i := 0; i < hits; i++ {
		code, _, hdr := doReq(t, srv.URL, "application/json")
		switch code {
		case http.StatusOK:
			gen++
		case http.StatusTooManyRequests:
			limited++
			if hdr.Get("Retry-After") == "" {
				t.Fatalf("429 without Retry-After header")
			}
		default:
			t.Fatalf("unexpected status %d", code)
		}
	}
	if limited == 0 {
		t.Fatalf("expected some 429s over the burst limit, got none (200s=%d)", gen)
	}
	st := g.Stats()
	if st.RateLimited != uint64(limited) {
		t.Fatalf("RateLimited=%d want %d", st.RateLimited, limited)
	}
}

//--------------------------------------------------------------
// 3. Rate limiting: browsers get a challenge page (403) with PoW
//--------------------------------------------------------------

func TestRateLimitChallengePage(t *testing.T) {
	g := newTestGate(t, nil)
	srv := newServer(g)
	defer srv.Close()

	var sawChallenge bool
	for i := 0; i < 40; i++ {
		code, body, _ := doReq(t, srv.URL, "text/html")
		if code == http.StatusForbidden && strings.Contains(body, "proof-of-work") {
			sawChallenge = true
			break
		}
	}
	if !sawChallenge {
		t.Fatal("expected a 403 challenge page for browser traffic over the limit")
	}
}

//--------------------------------------------------------------
// 4. Full challenge flow: solve PoW -> cookie -> pass without 429
//--------------------------------------------------------------

func TestChallengeSolveAllowsPass(t *testing.T) {
	g := newTestGate(t, nil)
	srv := newServer(g)
	defer srv.Close()

	// 1. Trip the rate limit to obtain a challenge.
	var prefix string
	var code int
	for i := 0; i < 40; i++ {
		var body string
		code, body, _ = doReq(t, srv.URL, "text/html")
		if code == http.StatusForbidden && strings.Contains(body, "Security Check") {
			// The prefix is rendered as `var prefix = "..."` (Go-quoted by
			// printf %q and JS-escaped by html/template); extract the string
			// between the quotes.
			start := strings.Index(body, `var prefix = "`)
			if start < 0 {
				t.Fatal("challenge page missing prefix")
			}
			rest := body[start+len(`var prefix = "`):]
			end := strings.Index(rest, `";`)
			if end < 0 {
				t.Fatal("challenge page malformed prefix")
			}
			prefix = rest[:end]
			break
		}
	}
	if code != http.StatusForbidden || prefix == "" {
		t.Fatalf("did not receive a challenge (last code=%d)", code)
	}

	// 2. Solve it (like the browser would).
	nonce := solveProof(prefix, g.opts.Difficulty)
	if nonce == "" {
		t.Fatal("could not solve PoW")
	}

	payload, _ := json.Marshal(map[string]string{"prefix": prefix, "nonce": nonce})
	req, _ := http.NewRequest("POST", srv.URL+solvePath, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("solve POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("solve returned %d", resp.StatusCode)
	}
	if len(resp.Cookies()) == 0 {
		t.Fatal("solve did not set the pass cookie")
	}
	cookie := resp.Cookies()[0]

	// 3. Over the rate limit WITH the cookie: requests must pass.
	passed := 0
	total := 20
	for i := 0; i < total; i++ {
		req, _ := http.NewRequest("GET", srv.URL, nil)
		req.AddCookie(cookie)
		req.Header.Set("Accept", "application/json")
		r2, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		r2.Body.Close()
		if r2.StatusCode == http.StatusOK {
			passed++
		}
	}
	if passed != total {
		t.Fatalf("with cookie expected all %d to pass, got %d", total, passed)
	}
	st := g.Stats()
	if st.ChallengeSolved != 1 {
		t.Fatalf("ChallengeSolved=%d want 1", st.ChallengeSolved)
	}
}

//--------------------------------------------------------------
// 5. Invalid proofs do not solve, failures accumulate
//--------------------------------------------------------------

func TestInvalidProofFails(t *testing.T) {
	g := newTestGate(t, nil)
	srv := newServer(g)
	defer srv.Close()

	payload := `{"prefix":"deadbeef","nonce":"0"}`
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("POST", srv.URL+solvePath, strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("solve %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("invalid solve %d: code=%d want 403", i, resp.StatusCode)
		}
	}
	st := g.Stats()
	if st.ChallengeFailed != 3 {
		t.Fatalf("ChallengeFailed=%d want 3", st.ChallengeFailed)
	}
}

//--------------------------------------------------------------
// 6. IP blocking after repeated failures
//--------------------------------------------------------------

func TestIPBlockedAfterFailures(t *testing.T) {
	g := newTestGate(t, nil)
	srv := newServer(g)
	defer srv.Close()

	// Hammer with browser Accept; each over-limit request serves a challenge
	// and counts as a failure. After BlockAfter (3) the IP must be blocked.
	var sawBlocked bool
	for i := 0; i < 30 && !sawBlocked; i++ {
		code, body, _ := doReq(t, srv.URL, "text/html")
		if code == http.StatusForbidden && strings.Contains(body, "Access Temporarily Blocked") {
			sawBlocked = true
		}
	}
	if !sawBlocked {
		t.Fatal("expected the IP to be blocked after repeated challenge failures")
	}
	if len(g.BlockedIPs()) == 0 {
		t.Fatal("BlockedIPs() empty after blocking")
	}
	st := g.Stats()
	if st.RequestsBlocked == 0 {
		t.Fatal("RequestsBlocked=0 after blocking")
	}
}

//--------------------------------------------------------------
// 7. Exempt paths bypass protection
//--------------------------------------------------------------

func TestExemptPathsBypass(t *testing.T) {
	exempt := "/health"
	g := newTestGate(t, func(o *Options) {
		o.Exempt = func(r *http.Request) bool { return r.URL.Path == exempt }
	})
	srv := newServer(g)
	defer srv.Close()

	// Over the limit: /health keeps passing, / keeps being throttled.
	for i := 0; i < 40; i++ {
		code, _, _ := doReq(t, srv.URL+"/health", "application/json")
		if code != http.StatusOK {
			t.Fatalf("exempt /health req %d: code=%d", i, code)
		}
	}
	limited := 0
	for i := 0; i < 40; i++ {
		code, _, _ := doReq(t, srv.URL, "application/json")
		if code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("non-exempt path should have been rate limited")
	}
}

//--------------------------------------------------------------
// 8. Live toggle: enable/disable at runtime
//--------------------------------------------------------------

func TestLiveToggle(t *testing.T) {
	g := newTestGate(t, nil)
	srv := newServer(g)
	defer srv.Close()

	// Protect on: limit reached quickly.
	g.SetEnabled(true)
	limited := 0
	for i := 0; i < 20; i++ {
		if code, _, _ := doReq(t, srv.URL, "application/json"); code == http.StatusTooManyRequests {
			limited++
		}
	}

	// Toggle off mid-flight: everything now passes.
	g.SetEnabled(false)
	passed := 0
	for i := 0; i < 50; i++ {
		if code, _, _ := doReq(t, srv.URL, "application/json"); code == http.StatusOK {
			passed++
		}
	}
	if limited == 0 {
		t.Fatal("expected rate limiting while enabled")
	}
	if passed != 50 {
		t.Fatalf("after disable expected all 50 to pass, got %d", passed)
	}

	// And back on.
	g.SetEnabled(true)
	limited = 0
	for i := 0; i < 20; i++ {
		if code, _, _ := doReq(t, srv.URL, "application/json"); code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("expected rate limiting after re-enable")
	}
}

//--------------------------------------------------------------
// 9. Concurrency safety (run with -race)
//--------------------------------------------------------------

func TestConcurrentToggleAndTraffic(t *testing.T) {
	g := newTestGate(t, nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	srv := httptest.NewServer(g.Handler(inner))
	defer srv.Close()

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				req, _ := http.NewRequest("GET", srv.URL, nil)
				req.Header.Set("Accept", "application/json")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			g.SetEnabled(i%2 == 0)
			_ = g.Stats()
			_ = g.BlockedIPs()
			g.Reset()
		}
	}()
	wg.Wait()
}

//--------------------------------------------------------------
// 11. Difficulty is clamped to a solvable maximum
//--------------------------------------------------------------

func TestDifficultyClamped(t *testing.T) {
	g := newTestGate(t, func(o *Options) { o.Difficulty = 12 })
	if g.opts.Difficulty != MaxDifficulty {
		t.Fatalf("Difficulty=%d want clamp to %d", g.opts.Difficulty, MaxDifficulty)
	}
	// And a sane difficulty stays untouched.
	g2 := newTestGate(t, func(o *Options) { o.Difficulty = 3 })
	if g2.opts.Difficulty != 3 {
		t.Fatalf("Difficulty=%d want 3", g2.opts.Difficulty)
	}
}

//--------------------------------------------------------------
// 12. Challenges are bound to the issuing IP + timestamp (M1):
// a solved proof cannot be replayed from another IP or later.
//--------------------------------------------------------------

func TestChallengeBoundToIPAndFreshness(t *testing.T) {
	g := newTestGate(t, nil)

	prefix, _, err := g.makeChallenge("203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if !g.verifyChallenge(prefix, "203.0.113.7") {
		t.Fatal("challenge should verify for the issuing IP")
	}
	if g.verifyChallenge(prefix, "203.0.113.8") {
		t.Fatal("challenge must NOT verify for a different IP (no replay sharing)")
	}
	if g.verifyChallenge(prefix[:len(prefix)-2]+"00", "203.0.113.7") {
		t.Fatal("tampered signature must not verify")
	}

	// Expired challenge: sign a payload with a stale timestamp.
	old := hex.EncodeToString([]byte("00000000|" + strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10) + "|203.0.113.7"))
	oldSigned := old + "|" + g.sign("00000000|"+strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)+"|203.0.113.7")
	if g.verifyChallenge(oldSigned, "203.0.113.7") {
		t.Fatal("stale challenge must not verify")
	}
}

//--------------------------------------------------------------
// 13. Trusted proxy X-Forwarded-For handling (H3): the header is
// honored only when the peer is inside TrustedProxies.
//--------------------------------------------------------------

func TestClientIPTakesXFFOnlyFromTrustedProxy(t *testing.T) {
	mk := func(remote, xff string) *http.Request {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = remote + ":12345"
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		return req
	}

	// No trusted proxies: XFF is ignored entirely (no spoofing).
	g := newTestGate(t, nil)
	if got := g.clientIP(mk("127.0.0.1", "1.2.3.4")); got != "127.0.0.1" {
		t.Fatalf("without trusted proxies clientIP=%q want 127.0.0.1", got)
	}

	// Trusted proxy: the rightmost XFF value is used.
	gp := newTestGate(t, func(o *Options) {
		o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	})
	if got := gp.clientIP(mk("10.0.0.5", "203.0.113.9")); got != "203.0.113.9" {
		t.Fatalf("trusted proxy clientIP=%q want 203.0.113.9", got)
	}
	// Attacker-supplied leading entries are ignored; only the last (proxy-added) one counts.
	if got := gp.clientIP(mk("10.0.0.5", "198.51.100.1, 203.0.113.9")); got != "203.0.113.9" {
		t.Fatalf("chain clientIP=%q want rightmost 203.0.113.9", got)
	}
	// Untrusted peer: XFF ignored.
	if got := gp.clientIP(mk("203.0.113.9", "198.51.100.1")); got != "203.0.113.9" {
		t.Fatalf("untrusted peer clientIP=%q want 203.0.113.9", got)
	}
}

//--------------------------------------------------------------
// 14. A solved cookie does NOT disable rate limiting (M5): the
// cookie holder gets a bigger bucket, not an unlimited pass.
//--------------------------------------------------------------

func TestSolvedCookieStillRateLimited(t *testing.T) {
	g := newTestGate(t, nil) // burst 5, solved scale 5 -> solved burst 25
	srv := newServer(g)
	defer srv.Close()

	// Get a real pass cookie through the full challenge flow.
	var prefix string
	for i := 0; i < 40; i++ {
		_, body, _ := doReq(t, srv.URL, "text/html")
		start := strings.Index(body, `var prefix = "`)
		if start < 0 {
			continue
		}
		rest := body[start+len(`var prefix = "`):]
		if end := strings.Index(rest, `";`); end > 0 {
			prefix = rest[:end]
			break
		}
	}
	if prefix == "" {
		t.Fatal("no challenge issued")
	}
	nonce := solveProof(prefix, g.opts.Difficulty)
	if nonce == "" {
		t.Fatal("could not solve PoW")
	}
	payload, _ := json.Marshal(map[string]string{"prefix": prefix, "nonce": nonce})
	req, _ := http.NewRequest("POST", srv.URL+solvePath, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(resp.Cookies()) == 0 {
		t.Fatalf("solve failed: status=%d cookies=%d", resp.StatusCode, len(resp.Cookies()))
	}
	cookie := resp.Cookies()[0]

	// Solved bucket holds burst*5 = 25; a 200-request burst must trip it.
	limited := 0
	passed := 0
	for i := 0; i < 200; i++ {
		req, _ := http.NewRequest("GET", srv.URL, nil)
		req.AddCookie(cookie)
		req.Header.Set("Accept", "application/json")
		r2, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r2.Body.Close()
		switch r2.StatusCode {
		case http.StatusOK:
			passed++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("unexpected status %d", r2.StatusCode)
		}
	}
	if passed == 0 {
		t.Fatal("solved cookie should pass a meaningful burst")
	}
	if limited == 0 {
		t.Fatal("solved cookie holder must still be rate limited at scale")
	}
}

//--------------------------------------------------------------
// 10. Block expiry releases the IP
//--------------------------------------------------------------

func TestBlockExpiry(t *testing.T) {
	g := newTestGate(t, func(o *Options) {
		// Make the block expire after 20ms so we can observe the release.
		o.BlockDuration = 20 * time.Millisecond
	})
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	srv := httptest.NewServer(g.Handler(inner))
	defer srv.Close()

	var sawBlocked bool
	for i := 0; i < 30; i++ {
		code, body, _ := doReq(t, srv.URL, "text/html")
		if code == http.StatusForbidden && strings.Contains(body, "Access Temporarily Blocked") {
			sawBlocked = true
		}
	}
	if !sawBlocked {
		t.Fatal("expected block to trigger")
	}

	time.Sleep(40 * time.Millisecond) // past the block window
	// Protection is still on; the IP should be out of the blocklist.
	if len(g.BlockedIPs()) != 0 {
		t.Fatalf("BlockedIPs=%d want 0 after expiry", len(g.BlockedIPs()))
	}
}
