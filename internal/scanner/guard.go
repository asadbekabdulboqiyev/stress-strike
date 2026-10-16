// guard.go is the production Requester: the single place where a probe's
// network access is decided.
//
// A vulnerability scanner is an offensive tool. The difference between a
// sanctioned assessment and an attack is entirely policy: who said you may
// touch this host, how hard you may push, and whether you actually stop. Guard
// is that policy, and probe.go makes it unskippable — every check family is
// written against the Requester interface, and Guard is the only real
// implementation.
//
// Guard enforces, in order:
//
//  1. structural validity  — http(s) only, no userinfo, a real host, a real
//     port. Enforced even under AllowAll.
//  2. an explicit scope allowlist — fail-closed: no allowlist and no AllowAll
//     means no probe, ever.
//  3. an intrusive opt-in — intrusive probes are off unless Intrusive is set.
//  4. a total request budget — reserved by CAS, so concurrent probes cannot
//     overshoot it.
//  5. a per-host rate limit — a token bucket keyed on the lowercased host.
//  6. a per-request timeout and a response size cap.
//  7. an identifiable User-Agent, so the scanned system's operator can see who
//     is probing.
//
// Check() answers the policy question without sending a byte; Do() re-checks
// scope (defense in depth), then actually sends. DryRun makes Do() refuse
// everything while still evaluating policy, so an operator can preview exactly
// what a scan would touch.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// GuardConfig configures a Guard. The zero value is usable and safe: it
// refuses every request (fail-closed, no allowlist) until Allow or AllowAll is
// set.
type GuardConfig struct {
	// Allow is the scope allowlist. Fail-closed: an empty Allow with
	// AllowAll=false refuses every request.
	//
	// Each entry is one pattern. A pattern is "<netloc>" or
	// "<netloc> <pathPrefix>" (the two fields separated by whitespace, so a
	// CIDR mask and a path prefix can never be confused):
	//
	//	example.com                 exact host, any port, any path
	//	example.com:8443            exact host and effective port
	//	*.example.com               subdomains only (the apex does NOT match)
	//	10.0.0.0/8                  CIDR range
	//	[::1]:8080                  IPv6 literal, with port
	//	example.com /api            exact host, path under /api
	//	10.0.0.0/8 /internal        CIDR range, path under /internal
	//
	// Port matching uses the *effective* port: the URL's explicit port, or the
	// scheme default (80 for http, 443 for https). IPv6 literals must be
	// bracketed when a port is present.
	Allow []string

	// AllowAll authorises every structurally valid http(s) target. It does not
	// relax the intrusive gate.
	AllowAll bool

	// Intrusive enables intrusive probes (injection, traversal, SSRF, ...).
	// Off by default: they can mutate server state, and are only appropriate
	// with explicit written authorisation.
	Intrusive bool

	// RPS is the per-host sustained request rate. 0 means 10. Must be finite
	// and non-negative.
	RPS float64

	// Burst is the per-host token-bucket depth. 0 means ceil(RPS), minimum 1.
	Burst int

	// MaxRequests is the total request budget for the whole Guard. 0 means
	// 2000. Every request (successful or not) counts against it.
	MaxRequests int64

	// Timeout is the per-request timeout. 0 means 10s.
	Timeout time.Duration

	// MaxBodyBytes caps how many response bytes Guard will ever hand back.
	// 0 means DefaultProbeLimit.
	MaxBodyBytes int64

	// DryRun evaluates policy but never sends. Do() returns ErrDryRun.
	DryRun bool
}

// Defaults. Exported so a caller can build a matching budget report.
const (
	DefaultRPS         = 10
	DefaultMaxRequests = 2000
	DefaultTimeout     = 10 * time.Second

	// defaultMaxRPS bounds the token-bucket refill interval away from zero.
	defaultMaxRPS = 100000

	// maxRateWait bounds how long Do() will wait for a rate token before
	// refusing, so a rate limit can never hang a scan forever.
	maxRateWait = 5 * time.Second
)

// GuardStats is a snapshot of Guard's counters.
type GuardStats struct {
	RequestsSent      int64 `json:"requests_sent"`
	RequestsRefused   int64 `json:"requests_refused"`
	RefusedOutOfScope int64 `json:"refused_out_of_scope"`
	RefusedIntrusive  int64 `json:"refused_intrusive"`
	RefusedBudget     int64 `json:"refused_budget"`
	RefusedRate       int64 `json:"refused_rate"`
	RefusedDryRun     int64 `json:"refused_dry_run"`
	DryRunChecked     int64 `json:"dry_run_checked"`
	BytesRead         int64 `json:"bytes_read"`
}

type guardStatsInternal struct {
	requestsSent      atomic.Int64
	requestsRefused   atomic.Int64
	refusedOutOfScope atomic.Int64
	refusedIntrusive  atomic.Int64
	refusedBudget     atomic.Int64
	refusedRate       atomic.Int64
	refusedDryRun     atomic.Int64
	dryRunChecked     atomic.Int64
	bytesRead         atomic.Int64
}

// Guard is the Requester every probe uses.
type Guard struct {
	cfg      GuardConfig
	patterns []scopePattern
	limiter  *rateLimiter
	client   *http.Client
	budget   atomic.Int64 // requests reserved so far
	stats    guardStatsInternal
}

// NewGuard validates cfg and builds a Guard. It fails on a non-finite or
// negative RPS, a negative budget/timeout/body-cap/burst, and any malformed
// allowlist pattern — a bad pattern is a configuration error, not something to
// discover mid-scan.
func NewGuard(cfg GuardConfig) (*Guard, error) {
	if math.IsNaN(cfg.RPS) || math.IsInf(cfg.RPS, 0) {
		return nil, fmt.Errorf("scanner: RPS must be a finite number, got %v", cfg.RPS)
	}
	if cfg.RPS < 0 {
		return nil, fmt.Errorf("scanner: RPS must not be negative, got %v", cfg.RPS)
	}
	if cfg.RPS > defaultMaxRPS {
		return nil, fmt.Errorf("scanner: RPS %v is unreasonably high (max %d)", cfg.RPS, defaultMaxRPS)
	}
	if cfg.Burst < 0 {
		return nil, fmt.Errorf("scanner: Burst must not be negative, got %d", cfg.Burst)
	}
	if cfg.MaxRequests < 0 {
		return nil, fmt.Errorf("scanner: MaxRequests must not be negative, got %d", cfg.MaxRequests)
	}
	if cfg.Timeout < 0 {
		return nil, fmt.Errorf("scanner: Timeout must not be negative, got %v", cfg.Timeout)
	}
	if cfg.MaxBodyBytes < 0 {
		return nil, fmt.Errorf("scanner: MaxBodyBytes must not be negative, got %d", cfg.MaxBodyBytes)
	}

	patterns, err := parseScopePatterns(cfg.Allow)
	if err != nil {
		return nil, err
	}

	rps := cfg.RPS
	if rps == 0 {
		rps = DefaultRPS
	}
	burst := cfg.Burst
	if burst == 0 {
		burst = int(math.Ceil(rps))
		if burst < 1 {
			burst = 1
		}
	}
	if cfg.MaxRequests == 0 {
		cfg.MaxRequests = DefaultMaxRequests
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = DefaultProbeLimit
	}
	cfg.RPS = rps
	cfg.Burst = burst

	g := &Guard{
		cfg:      cfg,
		patterns: patterns,
		limiter:  newRateLimiter(rps, burst),
	}
	g.client = &http.Client{
		Timeout: cfg.Timeout,
		// Several checks need the raw 3xx and its Location header, so a
		// redirect must never be followed implicitly.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return g, nil
}

// Config returns the effective configuration (after defaults).
func (g *Guard) Config() GuardConfig { return g.cfg }

// Stats returns a snapshot of the counters.
func (g *Guard) Stats() GuardStats {
	return GuardStats{
		RequestsSent:      g.stats.requestsSent.Load(),
		RequestsRefused:   g.stats.requestsRefused.Load(),
		RefusedOutOfScope: g.stats.refusedOutOfScope.Load(),
		RefusedIntrusive:  g.stats.refusedIntrusive.Load(),
		RefusedBudget:     g.stats.refusedBudget.Load(),
		RefusedRate:       g.stats.refusedRate.Load(),
		RefusedDryRun:     g.stats.refusedDryRun.Load(),
		DryRunChecked:     g.stats.dryRunChecked.Load(),
		BytesRead:         g.stats.bytesRead.Load(),
	}
}

// Check applies policy without sending anything. It is advisory and has no
// side effects beyond refusal counters: it never consumes budget or a rate
// token, so a probe may call it freely before building a request.
//
// It returns exactly one of ErrOutOfScope, ErrIntrusiveDisabled or
// ErrBudgetExhausted when policy forbids the probe, and nil otherwise. In
// DryRun it returns nil (the request is within policy) and records the check in
// DryRunChecked; the refusal is applied by Do.
func (g *Guard) Check(ctx context.Context, method, rawURL string, intrusive bool) error {
	_ = ctx
	_ = method
	if g == nil {
		return ErrOutOfScope
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return g.refuse(fmt.Errorf("%w: unparseable url %q: %v", ErrOutOfScope, rawURL, err), nil)
	}
	if err := g.checkScope(u); err != nil {
		return g.refuse(err, nil)
	}
	if intrusive && !g.cfg.Intrusive {
		return g.refuse(ErrIntrusiveDisabled, nil)
	}
	if !g.cfg.DryRun && g.budget.Load() >= g.cfg.MaxRequests {
		return g.refuse(ErrBudgetExhausted, nil)
	}
	if g.cfg.DryRun {
		g.stats.dryRunChecked.Add(1)
	}
	return nil
}

// Do sends req through the rate limiter, budget, timeout, body cap and
// User-Agent policy. It re-checks scope first (defense in depth: a caller that
// skipped Check still cannot escape the allowlist). Redirects are never
// followed.
func (g *Guard) Do(req *http.Request) (*http.Response, error) {
	if g == nil {
		return nil, ErrOutOfScope
	}
	if req == nil || req.URL == nil {
		return nil, g.refuse(fmt.Errorf("%w: nil request", ErrOutOfScope), nil)
	}
	if g.cfg.DryRun {
		g.stats.refusedDryRun.Add(1)
		return nil, ErrDryRun
	}
	if err := g.checkScope(req.URL); err != nil {
		return nil, g.refuse(err, nil)
	}
	if !g.reserveBudget() {
		return nil, g.refuse(ErrBudgetExhausted, nil)
	}
	if err := g.acquireRate(req.Context(), strings.ToLower(req.URL.Host)); err != nil {
		return nil, g.refuse(err, nil)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", ScannerUserAgent)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	g.stats.requestsSent.Add(1)
	// Cap the body at the Guard level too, so a caller that ignores ReadBody's
	// limit still cannot be made to read an unbounded response.
	resp.Body = &cappedBody{rc: resp.Body, remaining: g.cfg.MaxBodyBytes, g: g}
	return resp, nil
}

// refuse records a refusal and returns it.
func (g *Guard) refuse(err error, _ *string) error {
	g.stats.requestsRefused.Add(1)
	switch {
	case errors.Is(err, ErrOutOfScope):
		g.stats.refusedOutOfScope.Add(1)
	case errors.Is(err, ErrIntrusiveDisabled):
		g.stats.refusedIntrusive.Add(1)
	case errors.Is(err, ErrBudgetExhausted):
		g.stats.refusedBudget.Add(1)
	case errors.Is(err, ErrRateLimited):
		g.stats.refusedRate.Add(1)
	case errors.Is(err, ErrDryRun):
		g.stats.refusedDryRun.Add(1)
	}
	return err
}

// reserveBudget increments the budget counter only if it stays within the cap.
func (g *Guard) reserveBudget() bool {
	for {
		cur := g.budget.Load()
		if cur >= g.cfg.MaxRequests {
			return false
		}
		if g.budget.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// acquireRate waits (bounded) for a token for key, or refuses.
func (g *Guard) acquireRate(ctx context.Context, key string) error {
	deadline := time.Now().Add(maxRateWait)
	for {
		if g.limiter.tryTake(key, time.Now()) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return ErrRateLimited
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(g.limiter.tick()):
		}
	}
}

// checkScope enforces structural validity plus the allowlist.
func (g *Guard) checkScope(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("%w: nil url", ErrOutOfScope)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: scheme %q is not http(s)", ErrOutOfScope, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: url carries userinfo", ErrOutOfScope)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("%w: url has no host", ErrOutOfScope)
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%w: invalid port %q", ErrOutOfScope, p)
		}
	}
	if g.cfg.AllowAll {
		return nil
	}
	if len(g.patterns) == 0 {
		return fmt.Errorf("%w: the allowlist is empty (fail-closed)", ErrOutOfScope)
	}
	effPort := effectivePort(u)
	escPath := u.EscapedPath()
	if escPath == "" {
		escPath = "/"
	}
	for _, p := range g.patterns {
		if p.matches(host, effPort, escPath) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not covered by any allowed pattern", ErrOutOfScope, host)
}

func effectivePort(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

// ── scope patterns ──────────────────────────────────────────────────────────

type patternKind int

const (
	patExact patternKind = iota
	patWildcard
	patIP
	patCIDR
)

type scopePattern struct {
	raw        string
	kind       patternKind
	host       string // exact/wildcard base, lowercased
	ip         net.IP
	ipnet      *net.IPNet
	port       int
	portSet    bool
	pathPrefix string
}

func parseScopePatterns(entries []string) ([]scopePattern, error) {
	out := make([]scopePattern, 0, len(entries))
	for _, entry := range entries {
		p, err := parseScopePattern(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func parseScopePattern(entry string) (scopePattern, error) {
	fields := strings.Fields(strings.TrimSpace(entry))
	if len(fields) == 0 {
		return scopePattern{}, fmt.Errorf("scanner: empty scope pattern")
	}
	if len(fields) > 2 {
		return scopePattern{}, fmt.Errorf("scanner: scope pattern %q has too many fields", entry)
	}
	netloc := fields[0]
	pathPrefix := ""
	if len(fields) == 2 {
		if !strings.HasPrefix(fields[1], "/") {
			return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: path prefix must start with /", entry)
		}
		pathPrefix = strings.TrimSuffix(fields[1], "/")
		if pathPrefix == "" {
			pathPrefix = "/"
		}
	}

	p := scopePattern{raw: entry, pathPrefix: pathPrefix}

	// CIDR first: it is the only case where "/" is a mask, not a path.
	if _, ipnet, err := net.ParseCIDR(netloc); err == nil {
		p.kind = patCIDR
		p.ipnet = ipnet
		return p, nil
	}

	host, port, portSet, err := splitHostPort(netloc)
	if err != nil {
		return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: %v", entry, err)
	}
	if strings.Contains(host, "/") {
		return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: put a space before a path prefix", entry)
	}
	if host == "" {
		return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: empty host", entry)
	}
	p.port, p.portSet = port, portSet
	host = strings.ToLower(host)

	if ip := net.ParseIP(host); ip != nil {
		p.kind = patIP
		p.ip = ip
		return p, nil
	}
	if strings.HasPrefix(host, "*.") {
		base := host[2:]
		if base == "" || strings.Contains(base, "*") {
			return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: malformed wildcard", entry)
		}
		p.kind = patWildcard
		p.host = base
		return p, nil
	}
	if strings.Contains(host, "*") {
		return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: '*' is only valid as a leading '*.", entry)
	}
	p.kind = patExact
	p.host = host
	return p, nil
}

// splitHostPort splits a netloc into host and optional port, understanding
// bracketed IPv6 and bare (unbracketed, portless) IPv6.
func splitHostPort(s string) (host string, port int, portSet bool, err error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, false, fmt.Errorf("unclosed '[' in %q", s)
		}
		host = s[1:end]
		rest := s[end+1:]
		if rest == "" {
			return host, 0, false, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, false, fmt.Errorf("unexpected %q after ']'", rest)
		}
		p, e := strconv.Atoi(rest[1:])
		if e != nil || p < 1 || p > 65535 {
			return "", 0, false, fmt.Errorf("invalid port %q", rest[1:])
		}
		return host, p, true, nil
	}
	if strings.Count(s, ":") > 1 {
		// Bare IPv6 literal; a port would need brackets.
		return s, 0, false, nil
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		ps := s[i+1:]
		p, e := strconv.Atoi(ps)
		if e != nil || p < 1 || p > 65535 {
			return "", 0, false, fmt.Errorf("invalid port %q", ps)
		}
		return s[:i], p, true, nil
	}
	return s, 0, false, nil
}

func (p scopePattern) matches(host string, effPort int, escPath string) bool {
	if p.portSet && p.port != effPort {
		return false
	}
	if !p.matchPath(escPath) {
		return false
	}
	switch p.kind {
	case patExact:
		return host == p.host
	case patWildcard:
		// Subdomains only: the apex (host == base) is deliberately excluded.
		return host != p.host && strings.HasSuffix(host, "."+p.host)
	case patIP:
		ip := net.ParseIP(host)
		return ip != nil && p.ip.Equal(ip)
	case patCIDR:
		ip := net.ParseIP(host)
		return ip != nil && p.ipnet.Contains(ip)
	}
	return false
}

// matchPath is segment-aware: "/api" matches "/api" and "/api/users" but never
// "/apix".
func (p scopePattern) matchPath(escPath string) bool {
	if p.pathPrefix == "" {
		return true
	}
	if p.pathPrefix == "/" {
		return true
	}
	return escPath == p.pathPrefix || strings.HasPrefix(escPath, p.pathPrefix+"/")
}

// ── rate limiter ────────────────────────────────────────────────────────────

type rateLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	return &rateLimiter{rate: rate, burst: float64(burst), buckets: map[string]*bucket{}}
}

// tick returns the interval between tokens, clamped to a sane minimum.
func (rl *rateLimiter) tick() time.Duration {
	if rl.rate <= 0 {
		return time.Millisecond
	}
	d := time.Duration(float64(time.Second) / rl.rate)
	if d < time.Millisecond {
		d = time.Millisecond
	}
	return d
}

func (rl *rateLimiter) tryTake(key string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.buckets[key]
	if b == nil {
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	} else if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(rl.burst, b.tokens+elapsed*rl.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// ── capped body ─────────────────────────────────────────────────────────────

// cappedBody enforces MaxBodyBytes regardless of how the caller reads.
type cappedBody struct {
	rc        io.ReadCloser
	remaining int64
	g         *Guard
}

func (c *cappedBody) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.rc.Read(p)
	if n > 0 {
		c.remaining -= int64(n)
		c.g.stats.bytesRead.Add(int64(n))
	}
	return n, err
}

func (c *cappedBody) Close() error { return c.rc.Close() }
