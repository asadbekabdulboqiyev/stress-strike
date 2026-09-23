// Package verigate is a lightweight, toggleable WAF-style protection
// middleware for Go HTTP servers, designed for the stress-strike demo store
// (and usable by any net/http server).
//
// It chains three defenses, in order:
//
//  1. Rate limiting — a per-IP token bucket. Requests over the configured
//     burst get a 429 (JSON/API clients) or a 403 challenge page (browsers).
//  2. Verification gate (challenge) — the 403 challenge page embeds a small
//     proof-of-work solver (SHA-256, leading-zero hex). A real browser solves
//     it, the page POSTs the solution, and a short-lived HMAC-signed cookie
//     (bound to the client IP) is issued. Naive load generators / bots that
//     cannot run the solver stay blocked.
//  3. IP blocking — after a configurable number of challenges served or
//     failed solve attempts, the offending IP is temporarily blocked (403).
//
// Everything can be toggled at runtime via SetEnabled (the demo store exposes
// this through its /admin/protect endpoint), and counters are available for
// SLAs / dashboards through Stats().
//
// The challenge is stateless: the server only stores an HMAC secret, so there
// is no per-challenge memory and no cleanup goroutine. Buckets and block
// entries expire lazily on access.
package verigate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//------------------------------------------------------------------------------
// Options
//------------------------------------------------------------------------------

// Options configures the protection middleware. Zero values fall back to the
// defaults below.
type Options struct {
	// Enabled turns protection on at startup. It can be changed at runtime
	// with VeriGate.SetEnabled.
	Enabled bool

	// RateLimit is the number of tokens (requests) added to a bucket per
	// second per IP. Default 100.
	RateLimit int

	// Burst is the bucket capacity: the maximum burst of requests an IP may
	// send before being throttled. Default 300.
	Burst int

	// Difficulty is the number of leading hex-zero digits required in the
	// proof-of-work hash. Default 4 (≈ 1/65536 of candidates qualify).
	Difficulty int

	// ChallengeTTL is how long a solved challenge cookie stays valid.
	// Default 5 minutes.
	ChallengeTTL time.Duration

	// BlockAfter is the number of challenges served (or solve failures)
	// after which an IP is blocked. Default 10.
	BlockAfter int

	// BlockDuration is how long an IP stays blocked. Default 60s.
	BlockDuration time.Duration

	// Exempt, if non-nil, marks requests that bypass protection entirely
	// (health probes, static assets, admin endpoints...).
	Exempt func(*http.Request) bool

	// TrustedProxies lists CIDR prefixes (e.g. "10.0.0.0/8") whose
	// X-Forwarded-For header is trusted. When the peer address falls inside
	// one of these prefixes, the rightmost X-Forwarded-For value is used as
	// the client IP; otherwise (including behind an untrusted proxy) the
	// peer address itself is used. This prevents both blind spoofing of
	// X-Forwarded-For and the "everyone is the proxy IP" DoS when deployed
	// behind a load balancer. Nil disables X-Forwarded-For support.
	TrustedProxies []netip.Prefix

	// Secret is the HMAC key for challenge cookies. Must be stable across
	// restarts if you want cookies to survive restarts; defaults to a fresh
	// random key when nil.
	Secret []byte
}

const (
	// DefaultRateLimit / DefaultBurst / DefaultDifficulty as above.
	DefaultRateLimit  = 100
	DefaultBurst      = 300
	DefaultDifficulty = 4

	// MaxDifficulty caps proof-of-work difficulty. The in-browser solver
	// iterates nonces up to maxNonce; above 6 the expected work exceeds the
	// cap and legitimate browsers could never solve the challenge, locking
	// every visitor out. New clamps Difficulty to this value.
	MaxDifficulty = 6

	challengePath = "/__verigate/challenge"
	solvePath     = "/__verigate/solve"

	cookieName = "vg_pass"

	// maxNonce caps the proof-of-work nonce the client may submit.
	maxNonce = 1 << 24

	// challengeWindow is how long a server-issued challenge stays valid.
	// The challenge prefix is HMAC-signed and bound to an IP + timestamp, so
	// a solved proof cannot be replayed from another IP or reused later.
	challengeWindow = 120 * time.Second

	// solvedScale multiplies bucket size/refill for clients that solved a
	// challenge. They still get rate limited (a solved cookie is not a free
	// pass) but the limit is raised so humans are never disturbed.
	solvedScale = 5

	// idleTTL: a stale bucket is re-created after this much inactivity.
	idleTTL = 10 * time.Minute
)

//------------------------------------------------------------------------------
// VeriGate
//------------------------------------------------------------------------------

// Stats is a point-in-time snapshot of the protection counters.
type Stats struct {
	Enabled         bool   `json:"enabled"`
	Requests        uint64 `json:"requests"`
	Passed          uint64 `json:"passed"`
	RateLimited     uint64 `json:"rate_limited"`
	Challenges      uint64 `json:"challenges_served"`
	ChallengeSolved uint64 `json:"challenges_solved"`
	ChallengeFailed uint64 `json:"challenges_failed"`
	RequestsBlocked uint64 `json:"requests_blocked"`
	BlockedIPs      int    `json:"blocked_ips"`
}

type bucket struct {
	tokens float64
	last   time.Time
}

// VeriGate is the protection middleware. Create it with New, wrap your
// handler with Handler, and toggle it with SetEnabled.
type VeriGate struct {
	mu      sync.Mutex
	opts    Options
	secret  []byte
	buckets map[string]*bucket   // ip -> token bucket
	blocks  map[string]time.Time // ip -> block expiry
	fails   map[string]int       // ip -> consecutive challenge failures

	requests, passed, rateLimited, challenges, solved, failed, blocked atomic.Uint64
}

// New builds a VeriGate with the given options (defaults applied).
func New(opts Options) (*VeriGate, error) {
	if opts.RateLimit <= 0 {
		opts.RateLimit = DefaultRateLimit
	}
	if opts.Burst <= 0 {
		opts.Burst = DefaultBurst
	}
	if opts.Difficulty <= 0 {
		opts.Difficulty = DefaultDifficulty
	}
	if opts.Difficulty > MaxDifficulty {
		opts.Difficulty = MaxDifficulty
	}
	if opts.ChallengeTTL <= 0 {
		opts.ChallengeTTL = 5 * time.Minute
	}
	if opts.BlockAfter <= 0 {
		opts.BlockAfter = 10
	}
	if opts.BlockDuration <= 0 {
		opts.BlockDuration = time.Minute
	}
	secret := opts.Secret
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("verigate: generate secret: %w", err)
		}
	}
	return &VeriGate{
		opts:    opts,
		secret:  secret,
		buckets: make(map[string]*bucket),
		blocks:  make(map[string]time.Time),
		fails:   make(map[string]int),
	}, nil
}

// SetEnabled turns protection on (true) or off (false) at runtime.
func (g *VeriGate) SetEnabled(on bool) {
	g.mu.Lock()
	g.opts.Enabled = on
	g.mu.Unlock()
}

// Enabled reports whether protection is currently active.
func (g *VeriGate) Enabled() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.opts.Enabled
}

// Reset clears buckets, blocks, failure counters and all statistics.
func (g *VeriGate) Reset() {
	g.mu.Lock()
	g.buckets = make(map[string]*bucket)
	g.blocks = make(map[string]time.Time)
	g.fails = make(map[string]int)
	g.mu.Unlock()
	g.requests.Store(0)
	g.passed.Store(0)
	g.rateLimited.Store(0)
	g.challenges.Store(0)
	g.solved.Store(0)
	g.failed.Store(0)
	g.blocked.Store(0)
}

// Stats returns a snapshot of the protection counters.
func (g *VeriGate) Stats() Stats {
	g.mu.Lock()
	enabled := g.opts.Enabled
	blockedIPs := 0
	for _, until := range g.blocks {
		if time.Now().Before(until) {
			blockedIPs++
		}
	}
	g.mu.Unlock()
	return Stats{
		Enabled:         enabled,
		Requests:        g.requests.Load(),
		Passed:          g.passed.Load(),
		RateLimited:     g.rateLimited.Load(),
		Challenges:      g.challenges.Load(),
		ChallengeSolved: g.solved.Load(),
		ChallengeFailed: g.failed.Load(),
		RequestsBlocked: g.blocked.Load(),
		BlockedIPs:      blockedIPs,
	}
}

// BlockedIPs returns the currently blocked client IPs.
func (g *VeriGate) BlockedIPs() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	var out []string
	for ip, until := range g.blocks {
		if now.Before(until) {
			out = append(out, ip)
		}
	}
	return out
}

//------------------------------------------------------------------------------
// Middleware
//------------------------------------------------------------------------------

// Handler wraps next with the protection middleware. When protection is
// disabled every request is passed straight through.
func (g *VeriGate) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.requests.Add(1)

		// Internal endpoints are always served by the middleware itself.
		switch r.URL.Path {
		case solvePath:
			g.handleSolve(w, r)
			return
		case challengePath:
			g.serveChallenge(w, r, "manual")
			return
		}

		if !g.Enabled() {
			next.ServeHTTP(w, r)
			return
		}
		if g.opts.Exempt != nil && g.opts.Exempt(r) {
			next.ServeHTTP(w, r)
			return
		}

		ip := g.clientIP(r)
		if until, ok := g.blockedUntil(ip); ok {
			g.blocked.Add(1)
			g.serveBlockedPage(w, until)
			return
		}

		// Clients that solved a challenge cookie are trusted to have done
		// real work, but they are still rate limited — just with a bigger
		// bucket (5x). A solved cookie is not a free run at the origin.
		solved := g.hasValidCookie(r, ip)
		if g.allow(ip, solved) {
			g.passed.Add(1)
			next.ServeHTTP(w, r)
			return
		}

		// Rate limited: browsers get a challenge, API clients get a 429.
		g.rateLimited.Add(1)
		if wantsJSON(r) {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited","retry_after":1}`))
			return
		}
		g.challenges.Add(1)
		g.noteFailure(ip)
		g.serveChallenge(w, r, "rate")
	})
}

// noteFailure records a challenge-related failure for an IP and blocks it
// once the cumulative count reaches BlockAfter.
func (g *VeriGate) noteFailure(ip string) {
	if g.opts.BlockAfter <= 0 {
		return
	}
	g.mu.Lock()
	g.fails[ip]++
	if g.fails[ip] >= g.opts.BlockAfter {
		g.blocks[ip] = time.Now().Add(g.opts.BlockDuration)
		delete(g.fails, ip)
	}
	g.mu.Unlock()
}

// allow consumes one token from the IP's bucket. Returns false when the IP
// has exhausted its burst. Clients that solved a challenge use a separate,
// larger bucket (solvedScale x) so they stay throttled without being
// disturbed.
func (g *VeriGate) allow(ip string, solved bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := ip
	cap, refill := g.opts.Burst, g.opts.RateLimit
	if solved {
		key = "solved:" + ip
		cap *= solvedScale
		refill *= solvedScale
	}
	now := time.Now()
	b := g.buckets[key]
	if b == nil || now.Sub(b.last) > idleTTL {
		b = &bucket{tokens: float64(cap)}
		g.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += float64(refill) * elapsed
		if b.tokens > float64(cap) {
			b.tokens = float64(cap)
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (g *VeriGate) blockedUntil(ip string) (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.blocks[ip]
	if !ok {
		return time.Time{}, false
	}
	if time.Now().After(until) {
		delete(g.blocks, ip)
		return time.Time{}, false
	}
	return until, true
}

//------------------------------------------------------------------------------
// Proof of work
//------------------------------------------------------------------------------

// makeChallenge issues a proof-of-work prefix for the given client IP. The
// prefix is HMAC-signed and bound to the IP and the current time, so a
// solved proof can only be produced shortly after issue and only by that IP
// — solving for one bot cannot be shared with a botnet.
func (g *VeriGate) makeChallenge(ip string) (string, int, error) {
	rand16 := make([]byte, 8)
	if _, err := rand.Read(rand16); err != nil {
		return "", 0, fmt.Errorf("verigate: generate challenge: %w", err)
	}
	raw := hex.EncodeToString(rand16) + "|" + strconv.FormatInt(time.Now().Unix(), 10) + "|" + ip
	return raw + "|" + g.sign(raw), g.opts.Difficulty, nil
}

// verifyChallenge checks a client-submitted challenge prefix: it must be
// correctly signed, fresh (not older than challengeWindow), and bound to the
// client's IP.
func (g *VeriGate) verifyChallenge(prefix, ip string) bool {
	parts := strings.Split(prefix, "|")
	if len(parts) != 4 {
		return false
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	if delta := time.Now().Unix() - ts; delta < 0 || delta > int64(challengeWindow.Seconds()) {
		return false
	}
	if parts[2] != ip {
		return false
	}
	payload := parts[0] + "|" + parts[1] + "|" + parts[2]
	expected, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got, err := hex.DecodeString(g.sign(payload))
	if err != nil {
		return false
	}
	return hmac.Equal(expected, got)
}

// validProof recomputes the PoW: sha256(prefix+nonce) must start with
// `difficulty` hex-zero characters.
func validProof(prefix, nonce string, difficulty int) bool {
	if prefix == "" || len(nonce) == 0 || len(nonce) > 10 {
		return false
	}
	n, err := strconv.ParseUint(nonce, 10, 64)
	if err != nil || n > maxNonce {
		return false
	}
	sum := sha256.Sum256([]byte(prefix + nonce))
	hexHash := hex.EncodeToString(sum[:])
	return strings.HasPrefix(hexHash, strings.Repeat("0", difficulty))
}

//------------------------------------------------------------------------------
// Cookie
//------------------------------------------------------------------------------

func (g *VeriGate) sign(payload string) string {
	mac := hmac.New(sha256.New, g.secret)
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func (g *VeriGate) makePassCookie(ip string, secure bool) *http.Cookie {
	exp := time.Now().Add(g.opts.ChallengeTTL).Unix()
	payload := fmt.Sprintf("%d|%s", exp, ip)
	val := hex.EncodeToString([]byte(payload + "|" + g.sign(payload)))
	return &http.Cookie{
		Name:     cookieName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(g.opts.ChallengeTTL.Seconds()),
	}
}

// hasValidCookie verifies the challenge cookie: it must be HMAC-signed, not
// expired, and bound to the request's client IP.
func (g *VeriGate) hasValidCookie(r *http.Request, ip string) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	raw, err := hex.DecodeString(c.Value)
	if err != nil || len(raw) == 0 {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	if parts[1] != ip {
		return false
	}
	payload := parts[0] + "|" + parts[1]
	expected, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sig := g.sign(payload)
	got, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, got)
}

//------------------------------------------------------------------------------
// Handlers: solve + pages
//------------------------------------------------------------------------------

type solveRequest struct {
	Prefix string `json:"prefix"`
	Nonce  string `json:"nonce"`
}

func (g *VeriGate) handleSolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req solveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		g.solveFail(w, r, "bad_request")
		return
	}
	ip := g.clientIP(r)
	// Only accept a challenge we issued: signed, fresh, bound to this IP.
	// This stops proof sharing across a botnet and replay of old solves.
	if !g.verifyChallenge(req.Prefix, ip) {
		g.solveFail(w, r, "stale_or_foreign_challenge")
		return
	}
	if !validProof(req.Prefix, req.Nonce, g.opts.Difficulty) {
		g.solveFail(w, r, "invalid_proof")
		return
	}
	g.solved.Add(1)
	http.SetCookie(w, g.makePassCookie(ip, r.TLS != nil))
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (g *VeriGate) solveFail(w http.ResponseWriter, r *http.Request, reason string) {
	g.failed.Add(1)
	g.noteFailure(g.clientIP(r))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprintf(w, `{"ok":false,"error":%q}`, reason)
}

func (g *VeriGate) serveBlockedPage(w http.ResponseWriter, until time.Time) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = blockedTmpl.Execute(w, map[string]any{
		"RetryAfterSec": int(time.Until(until).Seconds()) + 1,
	})
}

func (g *VeriGate) serveChallenge(w http.ResponseWriter, r *http.Request, reason string) {
	prefix, difficulty, err := g.makeChallenge(g.clientIP(r))
	if err != nil {
		http.Error(w, "challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	// Only ever redirect back to this same origin: reject absolute URLs and
	// protocol-relative paths (//evil.com) to avoid an open redirect.
	redirect := r.URL.Path
	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		redirect = "/"
	}
	if r.URL.RawQuery != "" {
		redirect += "?" + r.URL.RawQuery
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = challengeTmpl.Execute(w, map[string]any{
		"Prefix":     prefix,
		"Difficulty": difficulty,
		"Redirect":   redirect,
		"Reason":     reason,
	})
}

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

// clientIP resolves the client's IP. By default it uses the peer address
// (RemoteAddr). When the peer is in Options.TrustedProxies, the rightmost
// X-Forwarded-For value is used instead — the only safe way to honor that
// header. Blindly trusting X-Forwarded-For from the internet would let an
// attacker mint unlimited buckets.
func (g *VeriGate) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if len(g.opts.TrustedProxies) == 0 {
		return host
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	trusted := false
	for _, p := range g.opts.TrustedProxies {
		if p.Contains(addr) {
			trusted = true
			break
		}
	}
	if !trusted {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	parts := strings.Split(xff, ",")
	last := strings.TrimSpace(parts[len(parts)-1])
	// Keep untrusted chains honest: only the last entry (added by the
	// trusted proxy) is used; anything before it is attacker-controlled.
	// netip.ParseAddr accepts both IPv4 and IPv6 here.
	if last != "" {
		if _, err := netip.ParseAddr(last); err == nil {
			return last
		}
	}
	return host
}

func wantsJSON(r *http.Request) bool {
	acc := r.Header.Get("Accept")
	if strings.Contains(acc, "application/json") {
		return true
	}
	ct := r.Header.Get("Content-Type")
	return strings.Contains(ct, "application/json")
}

//go:embed vg_challenge.html vg_blocked.html
var pagesFS embed.FS

var (
	challengeTmpl = template.Must(template.ParseFS(pagesFS, "vg_challenge.html"))
	blockedTmpl   = template.Must(template.ParseFS(pagesFS, "vg_blocked.html"))
)
