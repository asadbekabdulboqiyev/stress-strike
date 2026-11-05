package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/oidc"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/rbac"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

// --- Authentication / authorization middleware -------------------------------
//
// The dashboard control plane can start and stop real load runs against
// arbitrary targets, so exposing it beyond loopback needs a real gate. Auth
// provides a standard-library-only middleware that combines:
//
//   - bearer-token authentication (constant-time compare),
//   - hashed API-key authentication (SHA-256 hex, constant-time compare),
//   - mutual-TLS client-certificate CN allowlisting,
//   - an origin allowlist used as a CSRF defense for state-changing methods,
//   - a per-client-IP token-bucket rate limiter.
//
// The authenticated principal is attached to the request context so downstream
// handlers (and audit logging) can attribute the caller.

// Rate-limiter tuning. The janitor sweeps idle buckets so a long-running
// control plane cannot grow its bucket map without bound.
const (
	authJanitorInterval = time.Minute
	authBucketTTL       = 10 * time.Minute
)

// AuthConfig configures the middleware. An empty BearerTokens, APIKeyHashes and
// AllowedMTLSCNs list means credential authentication always fails, which keeps
// the "secure by default" story: a caller must explicitly enroll a credential.
// AllowedOrigins empty disables the CSRF origin check (non-browser clients such
// as the CLI send no Origin header).
type AuthConfig struct {
	// BearerTokens are accepted verbatim as `Authorization: Bearer <token>`.
	BearerTokens []string

	// APIKeyHashes are lowercase hex SHA-256 digests of accepted API keys (see
	// HashKey). The presented bearer token is hashed and compared in constant
	// time, so raw keys never need to live in configuration.
	APIKeyHashes []string

	// AllowedMTLSCNs lists accepted client-certificate Common Names. A request
	// that completed a TLS handshake with one of these peer certificates is
	// authenticated with subject equal to the CN.
	AllowedMTLSCNs []string

	// AllowedOrigins is the CSRF allowlist for state-changing methods. Entries
	// are full origins ("https://app.example.com"), bare hosts
	// ("app.example.com") or "*" (allow any).
	AllowedOrigins []string

	// RateLimitRPS is the token refill rate per client IP. Zero disables the
	// limiter. RateLimitBurst is the bucket capacity (defaults to 1).
	RateLimitRPS   float64
	RateLimitBurst int

	// TrustProxy makes the limiter honor X-Forwarded-For / X-Real-IP. Only
	// enable it when the dashboard sits behind a trusted reverse proxy that
	// overwrites those headers.
	TrustProxy bool

	// OIDCIssuer is the OpenID Connect issuer URL. When non-empty, bearer
	// tokens are verified as OIDC ID tokens against this provider.
	OIDCIssuer string

	// OIDCClientID is the OAuth client ID registered with the OIDC provider.
	OIDCClientID string

	// OIDCRoleClaim is the ID token claim name used to extract the user role
	// (default: "role"). Only used when OIDCIssuer is set.
	OIDCRoleClaim string

	// RBACEnabled turns on role-based access control for state-changing
	// endpoints. Requires OIDCIssuer to be set.
	RBACEnabled bool

	// RBACRoles maps authenticated subject (sub claim) to a list of roles.
	// Empty means all authenticated users get no roles (denied by default
	// when RBACEnabled is true).
	RBACRoles map[string][]string
}

// Auth is the control-plane authentication middleware.
type Auth struct {
	cfg AuthConfig

	rateEnabled bool
	rps         float64
	burst       int

	oidcClient *oidc.Client
	rbacEnabled bool
	rbacRoles   map[string][]string

	mu      sync.Mutex
	buckets map[string]*tokenBucket

	stopCh    chan struct{}
	doneCh    chan struct{}
	closeOnce sync.Once
}

// tokenBucket is a single client's token bucket. All access is serialized by
// Auth.mu.
type tokenBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

// NewAuth builds the middleware and starts the rate-limit janitor. Callers own
// the returned Auth and should Close it to release the janitor goroutine.
func NewAuth(cfg AuthConfig) *Auth {
	normalized := cfg
	normalized.BearerTokens = compactStrings(cfg.BearerTokens)
	normalized.APIKeyHashes = lowerAll(compactStrings(cfg.APIKeyHashes))
	normalized.AllowedMTLSCNs = compactStrings(cfg.AllowedMTLSCNs)
	normalized.AllowedOrigins = normalizeOrigins(cfg.AllowedOrigins)
	normalized.OIDCRoleClaim = compactRoleClaim(cfg.OIDCRoleClaim)
	normalized.RBACRoles = compactRBACRoles(cfg.RBACRoles)

	var oidcClient *oidc.Client
	if normalized.OIDCIssuer != "" && normalized.OIDCClientID != "" {
		oidcCfg := oidc.Config{
			Issuer:        normalized.OIDCIssuer,
			ClientID:      normalized.OIDCClientID,
			AllowInsecure: false,
		}
		var err error
		oidcClient, err = oidc.New(context.Background(), oidcCfg)
		if err != nil {
			// Fail closed: if OIDC cannot be initialized, no OIDC auth.
			oidcClient = nil
		}
	}

	a := &Auth{
		cfg:         normalized,
		oidcClient:  oidcClient,
		rbacEnabled: normalized.RBACEnabled,
		rbacRoles:   normalized.RBACRoles,
		buckets:     make(map[string]*tokenBucket),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
	if cfg.RateLimitRPS > 0 {
		a.rateEnabled = true
		a.rps = cfg.RateLimitRPS
		a.burst = cfg.RateLimitBurst
		if a.burst <= 0 {
			a.burst = 1
		}
	}
	go a.janitor()
	return a
}

// Close stops the rate-limit janitor. It is safe to call multiple times.
func (a *Auth) Close() {
	a.closeOnce.Do(func() {
		close(a.stopCh)
		<-a.doneCh
	})
}

// Middleware authenticates, applies the CSRF origin check to state-changing
// methods and enforces the rate limit. Order: rate limit -> authenticate ->
// RBAC -> CSRF, so an unauthenticated flood is throttled before it can touch
// the handlers and the origin check runs only for callers that already hold a
// credential.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.allowRequest(a.clientIP(r)) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		subject, roles, ok := a.authenticate(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		// RBAC: deny state-changing methods when the subject lacks the
		// required permission. Read-only GET/HEAD/OPTIONS are exempt.
		if a.rbacEnabled && !isSafeMethod(r.Method) {
			perm := permForPath(r.URL.Path, r.Method)
			if !a.rbacAllowed(subject, roles, perm) {
				http.Error(w, "rbac: permission denied", http.StatusForbidden)
				return
			}
		}

		if !isSafeMethod(r.Method) && !a.originAllowed(r) {
			http.Error(w, "cross-origin request denied", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r.WithContext(WithPrincipalAndRoles(r.Context(), subject, roles)))
	})
}

// --- Principal plumbing ------------------------------------------------------

// PrincipalAndRoles carries both the subject and the user's roles.
type PrincipalAndRoles struct {
	Subject string
	Roles   []string
}

// principalAndRolesCtxKey stores PrincipalAndRoles in the request context.
type principalAndRolesCtxKey struct{}

// WithPrincipalAndRoles stores subject + roles in the request context.
func WithPrincipalAndRoles(ctx context.Context, subject string, roles []string) context.Context {
	return context.WithValue(ctx, principalAndRolesCtxKey{}, PrincipalAndRoles{Subject: subject, Roles: roles})
}

// PrincipalAndRolesFromContext extracts the subject and roles from context.
func PrincipalAndRolesFromContext(ctx context.Context) (string, []string, bool) {
	v, ok := ctx.Value(principalAndRolesCtxKey{}).(PrincipalAndRoles)
	if !ok {
		return "", nil, false
	}
	return v.Subject, v.Roles, true
}

// WithPrincipal returns a copy of ctx carrying the authenticated subject
// (backward-compatible wrapper).
func WithPrincipal(ctx context.Context, subject string) context.Context {
	return WithPrincipalAndRoles(ctx, subject, nil)
}

// PrincipalFromContext extracts the authenticated subject from context
// (backward-compatible wrapper).
func PrincipalFromContext(ctx context.Context) (string, bool) {
	sub, _, ok := PrincipalAndRolesFromContext(ctx)
	return sub, ok && sub != ""
}


// --- Authentication ---------------------------------------------------------

// authenticate returns the principal subject and whether the request is
// authenticated. Bearer credentials take precedence over mTLS.
func (a *Auth) authenticate(r *http.Request) (string, []string, bool) {
	if token, ok := bearerToken(r); ok {
		if a.matchBearer(token) {
			return "bearer:" + shortID(HashKey(token)), nil, true
		}
		if a.matchAPIKey(token) {
			return "apikey:" + shortID(HashKey(token)), nil, true
		}
		// Try OIDC ID token verification
		if a.oidcClient != nil {
			claims, err := a.oidcClient.VerifyIDToken(token)
			if err == nil {
				sub, _ := claims["sub"].(string)
				if sub == "" {
					sub, _ = claims["email"].(string)
				}
				roleClaim := a.cfg.OIDCRoleClaim
				if roleClaim == "" {
					roleClaim = "role"
				}
				var roles []string
				if rl, ok := claims[roleClaim].(string); ok && rl != "" {
					roles = []string{rl}
				} else if rl, ok := claims[roleClaim].([]any); ok {
					for _, r := range rl {
						if rs, ok := r.(string); ok {
							roles = append(roles, rs)
						}
					}
				}
				if sub != "" {
					return sub, roles, true
				}
			}
		}
	}
	if cn, ok := a.matchMTLS(r); ok {
		return cn, nil, true
	}
	return "", nil, false
}


// matchBearer compares token against every configured bearer token in constant
// time and without short-circuiting, so the comparison cost does not reveal
// which entry matched.
func (a *Auth) matchBearer(token string) bool {
	var match int
	for _, want := range a.cfg.BearerTokens {
		match |= subtle.ConstantTimeCompare([]byte(token), []byte(want))
	}
	return match == 1
}

// matchAPIKey hashes token and compares it against every configured digest in
// constant time.
func (a *Auth) matchAPIKey(token string) bool {
	digest := HashKey(token)
	var match int
	for _, want := range a.cfg.APIKeyHashes {
		match |= subtle.ConstantTimeCompare([]byte(digest), []byte(want))
	}
	return match == 1
}

// matchMTLS reports the CN of the first peer certificate whose CN is
// allowlisted, if any. It only trusts certificates the TLS stack validated.
func (a *Auth) matchMTLS(r *http.Request) (string, bool) {
	if r.TLS == nil || len(a.cfg.AllowedMTLSCNs) == 0 {
		return "", false
	}
	for _, cert := range r.TLS.PeerCertificates {
		cn := cert.Subject.CommonName
		if cn == "" {
			continue
		}
		for _, allowed := range a.cfg.AllowedMTLSCNs {
			if subtle.ConstantTimeCompare([]byte(cn), []byte(allowed)) == 1 {
				return cn, true
			}
		}
	}
	return "", false
}

// rbacAllowed reports whether the subject with given roles may perform perm.
func (a *Auth) rbacAllowed(subject string, roles []string, perm string) bool {
	if !a.rbacEnabled {
		return true
	}
	// Build store.Role from configured roles
	rolePerms := map[string][]string{}
	for sub, rs := range a.rbacRoles {
		rolePerms[sub] = rs
	}
	userRoles := rolePerms[subject]
	// Also include roles from OIDC token
	userRoles = append(userRoles, roles...)
	for _, rName := range userRoles {
		r := store.Role{Name: rName, Permissions: rolePerms[rName]}
		if rbac.Has(r, perm) {
			return true
		}
	}
	return false
}

// permForPath maps an HTTP method + path to a coarse permission string.
func permForPath(path, method string) string {
	switch {
	case method == http.MethodGet:
		return "tests:view"
	case strings.HasPrefix(path, "/api/run") || method == http.MethodPost:
		return "tests:run"
	case strings.HasPrefix(path, "/api/admin") || method == http.MethodDelete:
		return "admin:access"
	case strings.HasPrefix(path, "/api/audit"):
		return "audit:read"
	default:
		return "tests:view"
	}
}

// compactRoleClaim normalizes the OIDC role claim name.
func compactRoleClaim(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "role"
	}
	return s
}

// compactRBACRoles drops blank entries from role assignments.
func compactRBACRoles(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for sub, roles := range in {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}
		clean := make([]string, 0, len(roles))
		for _, r := range roles {
			r = strings.TrimSpace(r)
			if r != "" {
				clean = append(clean, r)
			}
		}
		if len(clean) > 0 {
			out[sub] = clean
		}
	}
	return out
}

// bearerToken extracts the credential from `Authorization: Bearer <token>`.
// The scheme is matched case-insensitively per RFC 7235.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// --- CSRF origin check -------------------------------------------------------

// isSafeMethod reports whether a method is exempt from the CSRF origin check.
// GET/HEAD/OPTIONS are non-mutating per RFC 9110.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// originAllowed applies the AllowedOrigins CSRF policy. It returns true when no
// allowlist is configured (non-browser clients such as curl stay usable).
func (a *Auth) originAllowed(r *http.Request) bool {
	if len(a.cfg.AllowedOrigins) == 0 {
		return true
	}
	candidate := requestOrigin(r)
	if candidate == "" {
		return false
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	host := strings.ToLower(u.Host)
	for _, allowed := range a.cfg.AllowedOrigins {
		switch {
		case allowed == "*":
			return true
		case allowed == origin:
			return true
		case !strings.Contains(allowed, "://") && allowed == host:
			return true
		}
	}
	return false
}

// requestOrigin returns the Origin header, falling back to the Referer's
// origin for the rare client that omits Origin on a cross-origin request.
func requestOrigin(r *http.Request) string {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		return origin
	}
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer == "" {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// --- Rate limiting -----------------------------------------------------------

// allowRequest consumes one token for key, returning false when the bucket is
// empty.
func (a *Auth) allowRequest(key string) bool {
	if !a.rateEnabled {
		return true
	}
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	bucket, ok := a.buckets[key]
	if !ok {
		bucket = &tokenBucket{tokens: float64(a.burst), last: now}
		a.buckets[key] = bucket
	}

	if elapsed := now.Sub(bucket.last).Seconds(); elapsed > 0 {
		bucket.tokens += elapsed * a.rps
		if bucket.tokens > float64(a.burst) {
			bucket.tokens = float64(a.burst)
		}
		bucket.last = now
	}
	bucket.lastSeen = now

	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}
	return false
}

// clientIP derives the limiter key. X-Forwarded-For / X-Real-IP are honored
// only when TrustProxy is set, so a direct client cannot spoof its identity.
func (a *Auth) clientIP(r *http.Request) string {
	if a.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.IndexByte(xff, ','); idx >= 0 {
				xff = xff[:idx]
			}
			if forwarded := strings.TrimSpace(xff); forwarded != "" {
				return forwarded
			}
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// janitor periodically evicts idle buckets.
func (a *Auth) janitor() {
	defer close(a.doneCh)
	ticker := time.NewTicker(authJanitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.sweep()
		}
	}
}

// sweep drops buckets that have not been touched within authBucketTTL.
func (a *Auth) sweep() {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, bucket := range a.buckets {
		if now.Sub(bucket.lastSeen) > authBucketTTL {
			delete(a.buckets, key)
		}
	}
}

// --- Credential helpers ------------------------------------------------------

// GenerateToken returns a cryptographically random, URL-safe token derived from
// nBytes of entropy. nBytes <= 0 defaults to 32 (256 bits).
func GenerateToken(nBytes int) (string, error) {
	if nBytes <= 0 {
		nBytes = 32
	}
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashKey returns the lowercase hex SHA-256 digest of s, matching the format
// expected by AuthConfig.APIKeyHashes.
func HashKey(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// shortID truncates a hash for use as a non-secret audit identifier.
func shortID(hash string) string {
	const n = 12
	if len(hash) <= n {
		return hash
	}
	return hash[:n]
}

// --- Config normalization ----------------------------------------------------

// compactStrings trims entries and drops blanks, preserving order.
func compactStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// lowerAll lowercases each entry so hex-hash comparisons are canonical.
func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// normalizeOrigins canonicalizes the CSRF allowlist: lowercase, no trailing
// slash, blanks dropped.
func normalizeOrigins(in []string) []string {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if s == "*" {
			out = append(out, s)
			continue
		}
		out = append(out, strings.TrimRight(strings.ToLower(s), "/"))
	}
	return out
}
