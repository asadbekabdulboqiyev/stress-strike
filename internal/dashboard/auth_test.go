package dashboard

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Test helpers ------------------------------------------------------------
//
// These live in auth_test.go and must not collide with server_test.go's
// helpers, so every name is auth-prefixed.

// authCall captures the outcome of a request that passed the middleware.
type authCall struct {
	called  bool
	subject string
	hasSubj bool
}

// authHandler returns a terminal handler that records the authenticated
// principal and answers 200.
func authHandler(call *authCall) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call.called = true
		call.subject, call.hasSubj = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

// authRequest builds a request, applies optional header mutations and runs it
// through the middleware.
func authRequest(t *testing.T, a *Auth, method, target string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	var call authCall
	a.Middleware(authHandler(&call)).ServeHTTP(rec, req)
	return rec
}

// authRun is like authRequest but also reports what the terminal handler saw.
func authRun(t *testing.T, a *Auth, method, target string, mutate func(*http.Request)) (*httptest.ResponseRecorder, authCall) {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	var call authCall
	a.Middleware(authHandler(&call)).ServeHTTP(rec, req)
	return rec, call
}

// authBearer sets an Authorization header.
func authBearer(value string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", value) }
}

// authClientCert returns a request mutator that simulates a completed mTLS
// handshake presenting a certificate with the given CN.
func authClientCert(cn string) func(*http.Request) {
	return func(r *http.Request) {
		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: cn}},
			},
		}
	}
}

// --- WithPrincipal / PrincipalFromContext ------------------------------------

func TestAuthPrincipalContextRoundTrip(t *testing.T) {
	ctx := WithPrincipal(t.Context(), "alice")
	got, ok := PrincipalFromContext(ctx)
	if !ok || got != "alice" {
		t.Fatalf("PrincipalFromContext = (%q, %v), want (alice, true)", got, ok)
	}
}

func TestAuthPrincipalContextEmptyAndMissing(t *testing.T) {
	if _, ok := PrincipalFromContext(t.Context()); ok {
		t.Error("PrincipalFromContext on a bare context must report no principal")
	}
	if _, ok := PrincipalFromContext(WithPrincipal(t.Context(), "")); ok {
		t.Error("PrincipalFromContext must treat an empty subject as unset")
	}
}

// --- Bearer authentication ---------------------------------------------------

func TestAuthBearerTokenAllowed(t *testing.T) {
	a := NewAuth(AuthConfig{BearerTokens: []string{"s3cret-token", "second"}})
	defer a.Close()

	rec, call := authRun(t, a, http.MethodGet, "/api/snapshot", authBearer("Bearer s3cret-token"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !call.called || !call.hasSubj {
		t.Fatal("handler did not observe an authenticated principal")
	}
	if !strings.HasPrefix(call.subject, "bearer:") {
		t.Errorf("subject = %q, want bearer: prefix", call.subject)
	}
}

func TestAuthBearerTokenRejected(t *testing.T) {
	a := NewAuth(AuthConfig{BearerTokens: []string{"s3cret-token"}})
	defer a.Close()

	for name, header := range map[string]string{
		"wrong token":  "Bearer nope",
		"empty token":  "Bearer ",
		"no header":    "",
		"wrong scheme": "Basic s3cret-token",
		"bare token":   "s3cret-token",
	} {
		t.Run(name, func(t *testing.T) {
			rec, call := authRun(t, a, http.MethodGet, "/api/snapshot", authBearer(header))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", got)
			}
			if call.called {
				t.Error("handler must not run for an unauthenticated request")
			}
		})
	}
}

func TestAuthBearerSchemeIsCaseInsensitive(t *testing.T) {
	a := NewAuth(AuthConfig{BearerTokens: []string{"tok"}})
	defer a.Close()

	rec := authRequest(t, a, http.MethodGet, "/", authBearer("bearer tok"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (scheme is case-insensitive)", rec.Code)
	}
}

// --- API key hash authentication ---------------------------------------------

func TestAuthAPIKeyHashAllowed(t *testing.T) {
	raw := "key-abc-123"
	a := NewAuth(AuthConfig{APIKeyHashes: []string{HashKey(raw)}})
	defer a.Close()

	rec, call := authRun(t, a, http.MethodGet, "/api/run", authBearer("Bearer "+raw))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.HasPrefix(call.subject, "apikey:") {
		t.Errorf("subject = %q, want apikey: prefix", call.subject)
	}
}

func TestAuthAPIKeyHashRejectedForRawMismatch(t *testing.T) {
	a := NewAuth(AuthConfig{APIKeyHashes: []string{HashKey("right-key")}})
	defer a.Close()

	rec := authRequest(t, a, http.MethodGet, "/", authBearer("Bearer wrong-key"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestAuthAPIKeyHashNormalization: a caller may configure an uppercase digest;
// it must still match because NewAuth canonicalizes to lowercase.
func TestAuthAPIKeyHashNormalization(t *testing.T) {
	a := NewAuth(AuthConfig{APIKeyHashes: []string{strings.ToUpper(HashKey("mixed"))}})
	defer a.Close()

	rec := authRequest(t, a, http.MethodGet, "/", authBearer("Bearer mixed"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// --- mTLS --------------------------------------------------------------------

func TestAuthMTLSCNAllowlist(t *testing.T) {
	a := NewAuth(AuthConfig{AllowedMTLSCNs: []string{"dashboard-client"}})
	defer a.Close()

	rec, call := authRun(t, a, http.MethodGet, "/", authClientCert("dashboard-client"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if call.subject != "dashboard-client" {
		t.Errorf("subject = %q, want the certificate CN", call.subject)
	}
}

func TestAuthMTLSCNRejected(t *testing.T) {
	a := NewAuth(AuthConfig{AllowedMTLSCNs: []string{"dashboard-client"}})
	defer a.Close()

	rec := authRequest(t, a, http.MethodGet, "/", authClientCert("rogue"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuthMTLSNoCertFails(t *testing.T) {
	a := NewAuth(AuthConfig{AllowedMTLSCNs: []string{"dashboard-client"}})
	defer a.Close()

	// TLS present but no peer certificate.
	rec := authRequest(t, a, http.MethodGet, "/", func(r *http.Request) {
		r.TLS = &tls.ConnectionState{}
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// --- CSRF origin allowlist ---------------------------------------------------

func TestAuthCSRFOrigin(t *testing.T) {
	a := NewAuth(AuthConfig{
		BearerTokens:   []string{"tok"},
		AllowedOrigins: []string{"https://app.example.com", "127.0.0.1:8888"},
	})
	defer a.Close()

	tests := []struct {
		name   string
		method string
		mutate func(*http.Request)
		want   int
	}{
		{
			name:   "allowed origin on POST",
			method: http.MethodPost,
			mutate: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok")
				r.Header.Set("Origin", "https://app.example.com")
			},
			want: http.StatusOK,
		},
		{
			name:   "allowed bare-host entry on POST",
			method: http.MethodPost,
			mutate: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok")
				r.Header.Set("Origin", "http://127.0.0.1:8888")
			},
			want: http.StatusOK,
		},
		{
			name:   "evil origin on POST",
			method: http.MethodPost,
			mutate: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok")
				r.Header.Set("Origin", "https://evil.example")
			},
			want: http.StatusForbidden,
		},
		{
			name:   "missing origin and referer on POST",
			method: http.MethodPost,
			mutate: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok")
			},
			want: http.StatusForbidden,
		},
		{
			name:   "referer fallback allowed on POST",
			method: http.MethodPost,
			mutate: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok")
				r.Header.Set("Referer", "https://app.example.com/settings?x=1")
			},
			want: http.StatusOK,
		},
		{
			name:   "referer fallback denied on POST",
			method: http.MethodPost,
			mutate: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok")
				r.Header.Set("Referer", "https://evil.example/steal")
			},
			want: http.StatusForbidden,
		},
		{
			name:   "malformed origin on POST",
			method: http.MethodPost,
			mutate: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok")
				r.Header.Set("Origin", "::not-a-url")
			},
			want: http.StatusForbidden,
		},
		{
			name:   "non-http origin scheme on POST",
			method: http.MethodPost,
			mutate: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok")
				r.Header.Set("Origin", "file:///etc/passwd")
			},
			want: http.StatusForbidden,
		},
		{
			name:   "safe method bypasses CSRF (evil origin on GET)",
			method: http.MethodGet,
			mutate: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok")
				r.Header.Set("Origin", "https://evil.example")
			},
			want: http.StatusOK,
		},
		{
			name:   "safe method bypasses CSRF (evil origin on OPTIONS)",
			method: http.MethodOptions,
			mutate: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok")
				r.Header.Set("Origin", "https://evil.example")
			},
			want: http.StatusOK,
		},
		{
			name:   "unauthenticated cross-origin POST is 401, not 403",
			method: http.MethodPost,
			mutate: func(r *http.Request) {
				r.Header.Set("Origin", "https://evil.example")
			},
			want: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := authRequest(t, a, tc.method, "/api/run/start", tc.mutate)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// TestAuthCSRFWildcardAllowsAnyOrigin covers the explicit "*" escape hatch.
func TestAuthCSRFWildcardAllowsAnyOrigin(t *testing.T) {
	a := NewAuth(AuthConfig{BearerTokens: []string{"tok"}, AllowedOrigins: []string{"*"}})
	defer a.Close()

	rec := authRequest(t, a, http.MethodPost, "/", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer tok")
		r.Header.Set("Origin", "https://anywhere.example")
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestAuthCSRFDisabledWhenNoAllowlist: with no allowlist, non-browser clients
// (which send no Origin) must keep working.
func TestAuthCSRFDisabledWhenNoAllowlist(t *testing.T) {
	a := NewAuth(AuthConfig{BearerTokens: []string{"tok"}})
	defer a.Close()

	rec := authRequest(t, a, http.MethodPost, "/", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer tok")
		r.Header.Set("Origin", "https://evil.example")
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (CSRF check disabled without an allowlist)", rec.Code)
	}
}

// --- Rate limiting -----------------------------------------------------------

func TestAuthRateLimitBurst(t *testing.T) {
	a := NewAuth(AuthConfig{
		BearerTokens: []string{"tok"},
		// Tiny refill rate so the burst is exhausted deterministically: the
		// test's sub-millisecond runtime refills far less than one token.
		RateLimitRPS:   0.0001,
		RateLimitBurst: 2,
	})
	defer a.Close()

	for i := 0; i < 2; i++ {
		rec := authRequest(t, a, http.MethodGet, "/", authBearer("Bearer tok"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 (within burst)", i+1, rec.Code)
		}
	}
	rec := authRequest(t, a, http.MethodGet, "/", authBearer("Bearer tok"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request 3 status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("429 response is missing Retry-After")
	}
}

// TestAuthRateLimitPerClient: distinct source IPs have independent buckets.
func TestAuthRateLimitPerClient(t *testing.T) {
	a := NewAuth(AuthConfig{
		BearerTokens:   []string{"tok"},
		RateLimitRPS:   0.0001,
		RateLimitBurst: 1,
	})
	defer a.Close()

	rec := authRequest(t, a, http.MethodGet, "/", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer tok")
		r.RemoteAddr = "10.0.0.1:1111"
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("first client status = %d, want 200", rec.Code)
	}

	rec = authRequest(t, a, http.MethodGet, "/", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer tok")
		r.RemoteAddr = "10.0.0.2:2222"
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("second client status = %d, want 200 (own bucket)", rec.Code)
	}

	rec = authRequest(t, a, http.MethodGet, "/", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer tok")
		r.RemoteAddr = "10.0.0.1:3333"
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("first client second request status = %d, want 429", rec.Code)
	}
}

func TestAuthRateLimitTrustProxy(t *testing.T) {
	t.Run("trusted proxy honours X-Forwarded-For", func(t *testing.T) {
		a := NewAuth(AuthConfig{
			BearerTokens:   []string{"tok"},
			RateLimitRPS:   0.0001,
			RateLimitBurst: 1,
			TrustProxy:     true,
		})
		defer a.Close()

		first := authRequest(t, a, http.MethodGet, "/", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer tok")
			r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
		})
		if first.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", first.Code)
		}
		second := authRequest(t, a, http.MethodGet, "/", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer tok")
			r.Header.Set("X-Forwarded-For", "203.0.113.8")
		})
		if second.Code != http.StatusOK {
			t.Fatalf("different forwarded IP status = %d, want 200", second.Code)
		}
		repeat := authRequest(t, a, http.MethodGet, "/", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer tok")
			r.Header.Set("X-Forwarded-For", "203.0.113.7")
		})
		if repeat.Code != http.StatusTooManyRequests {
			t.Fatalf("repeat forwarded IP status = %d, want 429", repeat.Code)
		}
	})

	t.Run("untrusted proxy ignores X-Forwarded-For", func(t *testing.T) {
		a := NewAuth(AuthConfig{
			BearerTokens:   []string{"tok"},
			RateLimitRPS:   0.0001,
			RateLimitBurst: 1,
			TrustProxy:     false,
		})
		defer a.Close()

		first := authRequest(t, a, http.MethodGet, "/", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer tok")
			r.Header.Set("X-Forwarded-For", "203.0.113.7")
		})
		if first.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", first.Code)
		}
		// Same RemoteAddr, different spoofed XFF: must still be one bucket.
		second := authRequest(t, a, http.MethodGet, "/", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer tok")
			r.Header.Set("X-Forwarded-For", "203.0.113.8")
		})
		if second.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429 (spoofed XFF must be ignored)", second.Code)
		}
	})
}

// TestAuthRateLimitDisabled: RPS <= 0 leaves the limiter off.
func TestAuthRateLimitDisabled(t *testing.T) {
	a := NewAuth(AuthConfig{BearerTokens: []string{"tok"}})
	defer a.Close()

	for i := 0; i < 50; i++ {
		rec := authRequest(t, a, http.MethodGet, "/", authBearer("Bearer tok"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 with the limiter disabled", i+1, rec.Code)
		}
	}
}

func TestAuthSweepEvictsIdleBuckets(t *testing.T) {
	a := NewAuth(AuthConfig{})
	defer a.Close()

	a.mu.Lock()
	a.buckets["stale"] = &tokenBucket{lastSeen: time.Now().Add(-2 * authBucketTTL)}
	a.buckets["fresh"] = &tokenBucket{lastSeen: time.Now()}
	a.mu.Unlock()

	a.sweep()

	a.mu.Lock()
	_, stale := a.buckets["stale"]
	_, fresh := a.buckets["fresh"]
	a.mu.Unlock()

	if stale {
		t.Error("idle bucket was not evicted by sweep")
	}
	if !fresh {
		t.Error("fresh bucket was incorrectly evicted by sweep")
	}
}

// TestAuthCloseIdempotent: Close must not panic or hang when called twice.
func TestAuthCloseIdempotent(t *testing.T) {
	a := NewAuth(AuthConfig{BearerTokens: []string{"tok"}})

	done := make(chan struct{})
	go func() {
		a.Close()
		a.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return within 5s")
	}
}

// --- Credential helpers ------------------------------------------------------

func TestGenerateToken(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 64; i++ {
		tok, err := GenerateToken(32)
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		// 32 bytes base64url (unpadded) => 43 chars.
		if len(tok) != 43 {
			t.Fatalf("token length = %d, want 43", len(tok))
		}
		for _, c := range tok {
			if !strings.ContainsRune("-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", c) {
				t.Fatalf("token %q contains non-URL-safe character %q", tok, c)
			}
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("GenerateToken produced a duplicate token %q", tok)
		}
		seen[tok] = struct{}{}
	}
}

func TestGenerateTokenDefaultsAndValidates(t *testing.T) {
	short, err := GenerateToken(8)
	if err != nil {
		t.Fatalf("GenerateToken(8): %v", err)
	}
	if len(short) != 11 {
		t.Fatalf("GenerateToken(8) length = %d, want 11", len(short))
	}

	def, err := GenerateToken(0)
	if err != nil {
		t.Fatalf("GenerateToken(0): %v", err)
	}
	if len(def) != 43 {
		t.Fatalf("GenerateToken(0) length = %d, want 43 (32-byte default)", len(def))
	}
}

func TestHashKey(t *testing.T) {
	// Known SHA-256 of "password".
	const want = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
	if got := HashKey("password"); got != want {
		t.Fatalf("HashKey(password) = %q, want %q", got, want)
	}
	if HashKey("a") == HashKey("b") {
		t.Fatal("HashKey collided for distinct inputs")
	}
	if len(HashKey("")) != 64 {
		t.Fatalf("HashKey(\"\") length = %d, want 64 hex chars", len(HashKey("")))
	}
}

// TestAuthEmptyConfigDenies: with no credentials configured, nothing passes.
func TestAuthEmptyConfigDenies(t *testing.T) {
	a := NewAuth(AuthConfig{})
	defer a.Close()

	rec := authRequest(t, a, http.MethodGet, "/", authBearer("Bearer anything"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuthOptionsHasCredentials(t *testing.T) {
	cases := []struct {
		name string
		opt  AuthOptions
		want bool
	}{
		{"empty denies", AuthOptions{}, false},
		{"bearer token", AuthOptions{Tokens: []string{"t"}}, true},
		{"api key hash", AuthOptions{APIKeyHashes: []string{"abc"}}, true},
		{"both", AuthOptions{Tokens: []string{"t"}, APIKeyHashes: []string{"abc"}}, true},
		{"origin allowlist alone is not a credential", AuthOptions{AllowedOrigins: []string{"https://x"}}, false},
		{"rate limit alone is not a credential", AuthOptions{RateLimitRPS: 10}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.opt.HasCredentials(); got != tc.want {
				t.Fatalf("HasCredentials() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestServerApplyAuth(t *testing.T) {
	srv := NewServer()
	opt := AuthOptions{
		Tokens:         []string{"sekret-token"},
		APIKeyHashes:   []string{hashHex("key-123")},
		AllowedOrigins: []string{"https://dash.example.com"},
		RateLimitRPS:   100,
		RateLimitBurst: 1,
	}
	a := srv.ApplyAuth(opt)
	if a == nil {
		t.Fatal("ApplyAuth returned nil")
	}
	defer a.Close()

	// An unauthenticated request must be rejected; the credentials route
	// through the same middleware used by the real dashboard.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rec.Code)
	}

	// The bearer-token credential must pass (dashboard serves HTML at /).
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer sekret-token")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatal("bearer-token request was rejected")
	}
}

// hashHex is a tiny test helper producing the SHA-256 hex used by APIKeyHashes.
func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestServerApplyAuthWithoutCredentialsLeavesOpen(t *testing.T) {
	srv := NewServer()
	// Origins alone do not authenticate anyone, so ApplyAuth must not install a
	// middleware that would 401 every request ("secure by default" belongs to
	// NewAuth, which the launcher only reaches with real credentials).
	if a := srv.ApplyAuth(AuthOptions{AllowedOrigins: []string{"https://x"}}); a != nil {
		a.Close()
		t.Fatal("ApplyAuth returned non-nil for a credential-less config")
	}
	if a := srv.ApplyAuth(AuthOptions{AllowAnonymous: true}); a != nil {
		a.Close()
		t.Fatal("ApplyAuth returned non-nil for AllowAnonymous without credentials")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatal("credential-less server rejected an unauthenticated request; expected it left open")
	}
}
