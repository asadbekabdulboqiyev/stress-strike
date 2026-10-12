package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- In-test provider --------------------------------------------------------

// fakeProvider is an httptest OIDC provider that serves discovery, JWKS and a
// configurable token endpoint. The RSA and EC keys are generated per test so
// real signatures are verified end to end.
type fakeProvider struct {
	server *httptest.Server
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	rsaKid string
	ecKid  string

	// lastForm captures the last token-endpoint form for assertions.
	lastForm url.Values
}

type fakeProviderConfig struct {
	// issuerOverride, when set, is returned as the discovery issuer (used to
	// exercise issuer-mismatch detection).
	issuerOverride string
	// discoveryStatus, when non-zero, makes the discovery endpoint fail.
	discoveryStatus int
	// tokenFn builds the token-endpoint response. A nil function returns 500.
	tokenFn func(p *fakeProvider, form url.Values) (int, string)
}

func newFakeProvider(t *testing.T, cfg fakeProviderConfig) *fakeProvider {
	t.Helper()

	p := &fakeProvider{
		rsaKey: genRSAKey(t),
		ecKey:  genECKey(t),
		rsaKid: "rsa-key-1",
		ecKid:  "ec-key-1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if cfg.discoveryStatus != 0 {
			w.WriteHeader(cfg.discoveryStatus)
			return
		}
		issuer := p.server.URL
		if cfg.issuerOverride != "" {
			issuer = cfg.issuerOverride
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": p.server.URL + "/authorize",
			"token_endpoint":         p.server.URL + "/token",
			"jwks_uri":               p.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(p.jwksJSON(t)))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		p.lastForm = r.PostForm
		if cfg.tokenFn == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		status, body := cfg.tokenFn(p, r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

// config returns a Config pointed at this provider.
func (p *fakeProvider) config() Config {
	return Config{
		Issuer:        p.server.URL,
		ClientID:      "client-1",
		ClientSecret:  "shhh",
		RedirectURI:   "https://app.example/callback",
		AllowInsecure: true,
		ClockSkew:     5 * time.Second,
	}
}

// newClient discovers and returns a Client, failing the test on error.
func (p *fakeProvider) newClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(t.Context(), p.config())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func (p *fakeProvider) jwksJSON(t *testing.T) string {
	t.Helper()
	doc := map[string]any{
		"keys": []any{
			rsaJWK(p.rsaKid, &p.rsaKey.PublicKey),
			ecJWK(p.ecKid, &p.ecKey.PublicKey),
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return string(raw)
}

// --- Key generation and signing ---------------------------------------------

func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func genECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key
}

func b64URL(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func paddedInt(i *big.Int, size int) []byte {
	b := i.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func rsaJWK(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   b64URL(pub.N.Bytes()),
		"e":   b64URL(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWK(kid string, pub *ecdsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "EC",
		"use": "sig",
		"alg": "ES256",
		"kid": kid,
		"crv": "P-256",
		"x":   b64URL(paddedInt(pub.X, 32)),
		"y":   b64URL(paddedInt(pub.Y, 32)),
	}
}

func signJWT(t *testing.T, header, claims map[string]any, sign func(string) []byte) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	input := b64URL(hb) + "." + b64URL(cb)
	return input + "." + b64URL(sign(input))
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	return signJWT(t,
		map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid},
		claims,
		func(input string) []byte {
			digest := sha256.Sum256([]byte(input))
			sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatalf("sign RS256: %v", err)
			}
			return sig
		})
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	return signJWT(t,
		map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid},
		claims,
		func(input string) []byte {
			digest := sha256.Sum256([]byte(input))
			r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
			if err != nil {
				t.Fatalf("sign ES256: %v", err)
			}
			sig := make([]byte, 64)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
			return sig
		})
}

// baseClaims builds a valid claim set for the given issuer/client.
func baseClaims(issuer, clientID string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   issuer,
		"aud":   clientID,
		"sub":   "user-123",
		"email": "user@example.com",
		"iat":   now.Add(-time.Minute).Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
}

func tokenBody(idToken string, expiresIn int64) string {
	raw, _ := json.Marshal(map[string]any{
		"access_token":  "access-token-xyz",
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"refresh_token": "refresh-xyz",
		"id_token":      idToken,
	})
	return string(raw)
}

// --- Config / New ------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ClockSkew != 30*time.Second {
		t.Errorf("ClockSkew = %v, want 30s", cfg.ClockSkew)
	}
	want := map[string]bool{"openid": true, "profile": true, "email": true}
	if len(cfg.Scopes) != len(want) {
		t.Fatalf("Scopes = %v, want %v", cfg.Scopes, want)
	}
	for _, s := range cfg.Scopes {
		if !want[s] {
			t.Errorf("unexpected scope %q", s)
		}
	}
}

func TestNewInvalidConfig(t *testing.T) {
	tests := map[string]Config{
		"empty":                {},
		"missing client_id":    {Issuer: "https://issuer.example"},
		"missing issuer":       {ClientID: "client-1"},
		"malformed issuer":     {Issuer: "not a url", ClientID: "client-1"},
		"plain http (no flag)": {Issuer: "http://issuer.example", ClientID: "client-1"},
		"issuer without host":  {Issuer: "https://", ClientID: "client-1"},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(t.Context(), cfg); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNewDiscoveryFailure(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{discoveryStatus: http.StatusNotFound})
	if _, err := New(t.Context(), p.config()); err == nil {
		t.Fatal("New with a 404 discovery endpoint must fail")
	}
}

func TestNewIssuerMismatch(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{issuerOverride: "https://other-issuer.example"})
	_, err := New(t.Context(), p.config())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New error = %v, want ErrInvalidConfig for an issuer mismatch", err)
	}
}

func TestNewMissingEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + "http://placeholder" + `","authorization_endpoint":"x"}`))
	}))
	defer srv.Close()

	_, err := New(t.Context(), Config{Issuer: srv.URL, ClientID: "c", AllowInsecure: true})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New error = %v, want ErrInvalidConfig for missing token_endpoint", err)
	}
}

func TestClientSatisfiesProvider(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	// Compile-time assertion that *Client implements Provider, plus a runtime
	// check that the concrete type survives the interface round-trip (SA4023:
	// a non-nil concrete value in an interface is never == nil).
	var provider Provider = p.newClient(t)
	if _, ok := provider.(*Client); !ok {
		t.Fatalf("newClient returned %T, want *Client", provider)
	}
}

// --- AuthURL -----------------------------------------------------------------

func TestAuthURLIncludesPKCEAndCoreParams(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	raw := c.AuthURL("state-123", "challenge-abc")
	if raw == "" {
		t.Fatal("AuthURL returned empty string")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("AuthURL is not a URL: %v", err)
	}
	if u.Path != "/authorize" {
		t.Errorf("AuthURL path = %q, want /authorize", u.Path)
	}
	q := u.Query()
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "client-1",
		"redirect_uri":          "https://app.example/callback",
		"state":                 "state-123",
		"code_challenge":        "challenge-abc",
		"code_challenge_method": "S256",
		"scope":                 "openid profile email",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("AuthURL %s = %q, want %q", key, got, want)
		}
	}
}

func TestAuthURLOmitsPKCEWhenNoChallenge(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	u, err := url.Parse(c.AuthURL("st", ""))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Query().Has("code_challenge") || u.Query().Has("code_challenge_method") {
		t.Error("AuthURL must omit PKCE params when no challenge is supplied")
	}
	if u.Query().Get("state") != "st" {
		t.Errorf("state = %q, want st", u.Query().Get("state"))
	}
}

// --- PKCE --------------------------------------------------------------------

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	// 32 bytes -> 43 base64url chars, within RFC 7636's 43..128 range.
	if len(verifier) != 43 {
		t.Errorf("verifier length = %d, want 43", len(verifier))
	}
	for _, c := range verifier {
		if !strings.ContainsRune("-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", c) {
			t.Fatalf("verifier contains non-unreserved character %q", c)
		}
	}

	digest := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if challenge != wantChallenge {
		t.Errorf("challenge = %q, want S256(verifier) = %q", challenge, wantChallenge)
	}

	// Two generations must not collide.
	otherVerifier, _, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	if verifier == otherVerifier {
		t.Error("GeneratePKCE returned the same verifier twice")
	}
}

// --- Exchange: success paths -------------------------------------------------

func TestExchangeRS256Success(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["nonce"] = "nonce-123"
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	tok, err := c.Exchange(t.Context(), "auth-code", "verifier-xyz", "nonce-123")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.Subject != "user-123" {
		t.Errorf("Subject = %q, want user-123", tok.Subject)
	}
	if tok.Email != "user@example.com" {
		t.Errorf("Email = %q, want user@example.com", tok.Email)
	}
	if tok.AccessToken != "access-token-xyz" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "refresh-xyz" {
		t.Errorf("RefreshToken = %q", tok.RefreshToken)
	}
	if time.Until(tok.ExpiresAt) < 55*time.Minute {
		t.Errorf("ExpiresAt = %v, want ~1h from now", tok.ExpiresAt)
	}

	// The token request must be a well-formed authorization_code + PKCE form.
	form := p.lastForm
	for key, want := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "auth-code",
		"code_verifier": "verifier-xyz",
		"client_id":     "client-1",
		"client_secret": "shhh",
		"redirect_uri":  "https://app.example/callback",
	} {
		if got := form.Get(key); got != want {
			t.Errorf("token form %s = %q, want %q", key, got, want)
		}
	}
}

func TestExchangeES256Success(t *testing.T) {
	newFakeProviderForEC := func() *fakeProvider {
		p := newFakeProvider(t, fakeProviderConfig{
			tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
				claims := baseClaims(p.server.URL, "client-1")
				return http.StatusOK, tokenBody(signES256(t, p.ecKey, p.ecKid, claims), 600)
			},
		})
		return p
	}
	p := newFakeProviderForEC()
	c := p.newClient(t)

	tok, err := c.Exchange(t.Context(), "code", "", "")
	if err != nil {
		t.Fatalf("Exchange (ES256): %v", err)
	}
	if tok.Subject != "user-123" {
		t.Errorf("Subject = %q, want user-123", tok.Subject)
	}
	if tok.IDToken == "" {
		t.Error("IDToken must be preserved on the Token")
	}
}

// TestExchangeAudienceArray covers the multi-audience claim form.
func TestExchangeAudienceArray(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["aud"] = []string{"client-1", "another-client"}
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 300)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err != nil {
		t.Fatalf("Exchange with array aud: %v", err)
	}
}

// --- Exchange: failure paths -------------------------------------------------

func TestExchangeNoIDToken(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			return http.StatusOK, `{"access_token":"at","token_type":"Bearer"}`
		},
	})
	c := p.newClient(t)

	_, err := c.Exchange(t.Context(), "code", "", "")
	if !errors.Is(err, ErrNoToken) {
		t.Fatalf("Exchange error = %v, want ErrNoToken", err)
	}
}

func TestExchangeTokenEndpointError(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			return http.StatusInternalServerError, `{"error":"server_error"}`
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must fail when the token endpoint errors")
	}
}

func TestExchangeEmptyCode(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "  ", "", ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Exchange error = %v, want ErrInvalidConfig", err)
	}
}

func TestExchangeExpiredToken(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["exp"] = time.Now().Add(-time.Hour).Unix()
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject an expired id_token")
	}
}

// TestExchangeExpiryWithinSkew: an exp just inside ClockSkew is still valid.
func TestExchangeExpiryWithinSkew(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["exp"] = time.Now().Add(-2 * time.Second).Unix()
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err != nil {
		t.Fatalf("Exchange within ClockSkew should succeed: %v", err)
	}
}

func TestExchangeNotYetValid(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["nbf"] = time.Now().Add(time.Hour).Unix()
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject a not-yet-valid id_token")
	}
}

func TestExchangeNonceMismatch(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["nonce"] = "expected-nonce"
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", "different-nonce"); err == nil {
		t.Fatal("Exchange must reject a nonce mismatch")
	}
}

// TestExchangeNonceMissing: a nonce was requested but the token omits it.
func TestExchangeNonceMissing(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", "expected-nonce"); err == nil {
		t.Fatal("Exchange must reject a token without the requested nonce")
	}
}

func TestExchangeWrongIssuer(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["iss"] = "https://attacker.example"
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject an id_token with the wrong issuer")
	}
}

func TestExchangeWrongAudience(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "some-other-client")
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject an id_token for another client")
	}
}

func TestExchangeMissingExp(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			delete(claims, "exp")
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject an id_token without exp")
	}
}

// TestExchangeBadSignature: the token claims are valid but signed by a key the
// provider does not publish.
func TestExchangeBadSignature(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			attacker := genRSAKey(t)
			claims := baseClaims(p.server.URL, "client-1")
			return http.StatusOK, tokenBody(signRS256(t, attacker, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject a token with an invalid signature")
	}
}

func TestExchangeUnsupportedAlg(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			// alg=none with an empty signature segment.
			unsigned := signJWT(t, map[string]any{"alg": "none", "typ": "JWT"}, claims, func(string) []byte { return nil })
			return http.StatusOK, tokenBody(unsigned, 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject alg=none")
	}
}

// TestExchangeUnknownKid: the id_token's kid is not in the published JWKS.
func TestExchangeUnknownKid(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, "ghost-kid", claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject a kid that is not published in the JWKS")
	}
}

// TestExchangeMalformedJWT: a non-JWT id_token must be rejected.
func TestExchangeMalformedJWT(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			return http.StatusOK, tokenBody("not-a-jwt", 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject a malformed id_token")
	}
}

// --- Helpers ------------------------------------------------------------------

func TestRequireHTTPS(t *testing.T) {
	if err := requireHTTPS("https://issuer.example/token"); err != nil {
		t.Errorf("requireHTTPS(https) = %v, want nil", err)
	}
	for _, raw := range []string{"http://issuer.example/token", "ftp://issuer.example", "::bad::"} {
		if err := requireHTTPS(raw); err == nil {
			t.Errorf("requireHTTPS(%q) = nil, want error", raw)
		}
	}
}

func TestAudienceContains(t *testing.T) {
	if !audienceContains("client-1", "client-1") {
		t.Error("string aud should match")
	}
	if audienceContains("client-2", "client-1") {
		t.Error("string aud mismatch should not match")
	}
	if !audienceContains([]any{"a", "client-1"}, "client-1") {
		t.Error("[]any aud should match")
	}
	if audienceContains([]any{"a", "b"}, "client-1") {
		t.Error("[]any aud mismatch should not match")
	}
	if audienceContains(nil, "client-1") {
		t.Error("nil aud should not match")
	}
}

func TestDecodeBigIntRejectsEmpty(t *testing.T) {
	if _, err := decodeBigInt(""); err == nil {
		t.Error("decodeBigInt(\"\") must fail")
	}
	if _, err := decodeBigInt("!!!not-base64!!!"); err == nil {
		t.Error("decodeBigInt of invalid base64 must fail")
	}
}

func TestContextCancellationOnDiscovery(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := New(ctx, p.config()); err == nil {
		t.Fatal("New must fail when the context is already cancelled")
	}
}
