// Package oidc implements a small, dependency-free OpenID Connect relying
// party: discovery, JWKS parsing, PKCE, and id_token verification for RS256 and
// ES256. It intentionally covers the "generic OIDC first" slice of enterprise
// SSO without pulling in a third-party library.
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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// --- Configuration -----------------------------------------------------------

// Config describes a generic OIDC provider. It is backward compatible with the
// original scaffold; HTTPClient is an optional addition for tests and custom
// transports.
type Config struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	Scopes        []string
	ClockSkew     time.Duration
	AllowInsecure bool

	// HTTPClient overrides the client used for discovery, JWKS and token
	// requests. When nil a client with a 10s timeout is used.
	HTTPClient *http.Client
}

var (
	ErrInvalidConfig = errors.New("oidc: invalid config")
	ErrNoToken       = errors.New("oidc: no token returned")
)

// Provider is the OIDC provider surface implemented by *Client.
type Provider interface {
	AuthURL(state, codeChallenge string) string
	Exchange(ctx context.Context, code, verifier, nonce string) (*Token, error)
}

// Token represents a minimal ID token response.
type Token struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresAt    time.Time
	Subject      string
	Email        string
	Claims       map[string]any
}

// DefaultConfig returns a safe default configuration template.
func DefaultConfig() Config {
	return Config{
		Scopes:    []string{"openid", "profile", "email"},
		ClockSkew: 30 * time.Second,
	}
}

// --- Client ------------------------------------------------------------------

// Client is a discovered OIDC provider.
type Client struct {
	cfg Config

	issuer   string
	authEnd  string
	tokenEnd string
	jwksURI  string

	http *http.Client

	mu   sync.RWMutex
	keys map[string]crypto.PublicKey
}

// Compile-time assertion that *Client satisfies Provider.
var _ Provider = (*Client)(nil)

// discoveryDoc mirrors the subset of the OIDC discovery document we consume.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// jwksDoc mirrors an RFC 7517 JWK Set.
type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

// jwkKey mirrors the RSA and EC JWK members we support.
type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// tokenResponse mirrors the OAuth 2.0 token endpoint response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

const maxJSONBody = 1 << 20 // 1 MiB cap on any provider response

// New performs discovery against cfg.Issuer and returns a ready client. It
// requires an issuer and client_id; a non-https issuer is rejected unless
// AllowInsecure is set (intended for tests and local providers).
func New(ctx context.Context, cfg Config) (*Client, error) {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if issuer == "" || strings.TrimSpace(cfg.ClientID) == "" {
		return nil, fmt.Errorf("%w: issuer and client_id are required", ErrInvalidConfig)
	}

	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%w: malformed issuer %q", ErrInvalidConfig, cfg.Issuer)
	}
	if u.Scheme != "https" && !cfg.AllowInsecure {
		return nil, fmt.Errorf("%w: issuer must use https (set AllowInsecure for tests)", ErrInvalidConfig)
	}

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 30 * time.Second
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	cfg.Issuer = issuer

	c := &Client{cfg: cfg, issuer: issuer, http: cfg.HTTPClient}
	if err := c.discover(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// discover fetches and validates the provider metadata document.
func (c *Client) discover(ctx context.Context) error {
	endpoint := c.issuer + "/.well-known/openid-configuration"
	doc, err := getJSON[discoveryDoc](ctx, c.http, endpoint)
	if err != nil {
		return fmt.Errorf("oidc: discovery: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return fmt.Errorf("%w: discovery document is missing required endpoints", ErrInvalidConfig)
	}
	if doc.Issuer != "" && strings.TrimRight(doc.Issuer, "/") != c.issuer {
		return fmt.Errorf("%w: discovery issuer %q does not match configured issuer %q", ErrInvalidConfig, doc.Issuer, c.issuer)
	}
	if !c.cfg.AllowInsecure {
		for _, raw := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI} {
			if raw == "" {
				continue
			}
			if err := requireHTTPS(raw); err != nil {
				return fmt.Errorf("%w: %s", ErrInvalidConfig, err)
			}
		}
	}

	c.authEnd = doc.AuthorizationEndpoint
	c.tokenEnd = doc.TokenEndpoint
	c.jwksURI = doc.JWKSURI
	return nil
}

// AuthURL builds the authorization-code redirect URL, including a PKCE S256
// challenge when codeChallenge is non-empty.
func (c *Client) AuthURL(state, codeChallenge string) string {
	if c.authEnd == "" {
		return ""
	}
	u, err := url.Parse(c.authEnd)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	if c.cfg.RedirectURI != "" {
		q.Set("redirect_uri", c.cfg.RedirectURI)
	}
	if state != "" {
		q.Set("state", state)
	}
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Issuer returns the discovered issuer identifier.
func (c *Client) Issuer() string { return c.issuer }

// Exchange redeems an authorization code (with its PKCE verifier) at the token
// endpoint, then verifies the returned id_token. When nonce is non-empty it must
// match the id_token nonce claim.
func (c *Client) Exchange(ctx context.Context, code, verifier, nonce string) (*Token, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("%w: authorization code is required", ErrInvalidConfig)
	}
	if c.tokenEnd == "" {
		return nil, fmt.Errorf("%w: client was not discovered", ErrInvalidConfig)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", c.cfg.ClientID)
	if c.cfg.RedirectURI != "" {
		form.Set("redirect_uri", c.cfg.RedirectURI)
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEnd, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONBody))
	if err != nil {
		return nil, fmt.Errorf("oidc: token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("oidc: token response decode: %w", err)
	}
	if strings.TrimSpace(tr.IDToken) == "" {
		return nil, ErrNoToken
	}

	claims, err := c.verifyIDToken(ctx, tr.IDToken, nonce)
	if err != nil {
		return nil, err
	}

	tok := &Token{
		AccessToken:  tr.AccessToken,
		IDToken:      tr.IDToken,
		RefreshToken: tr.RefreshToken,
		Claims:       claims,
	}
	if tr.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	if sub, ok := claims["sub"].(string); ok {
		tok.Subject = sub
	}
	if email, ok := claims["email"].(string); ok {
		tok.Email = email
	}
	return tok, nil
}

// --- ID token verification ---------------------------------------------------

// verifyIDToken verifies the JWT signature and the standard claims, returning
// the decoded claims on success.
func (c *Client) verifyIDToken(ctx context.Context, raw, nonce string) (map[string]any, error) {
	header, claims, signingInput, signature, err := parseJWT(raw)
	if err != nil {
		return nil, err
	}

	alg, _ := header["alg"].(string)
	switch alg {
	case "RS256", "ES256":
	default:
		return nil, fmt.Errorf("oidc: unsupported id_token signing algorithm %q", alg)
	}

	kid, _ := header["kid"].(string)
	pub, err := c.keyFor(ctx, kid)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256([]byte(signingInput))
	switch alg {
	case "RS256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("oidc: id_token is RS256 but the signing key is not RSA")
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature); err != nil {
			return nil, fmt.Errorf("oidc: id_token signature is invalid: %w", err)
		}
	case "ES256":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("oidc: id_token is ES256 but the signing key is not EC")
		}
		if len(signature) != 64 {
			return nil, errors.New("oidc: ES256 signature must be 64 bytes")
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(ecPub, digest[:], r, s) {
			return nil, errors.New("oidc: id_token signature is invalid")
		}
	}

	if err := c.validateClaims(claims, nonce); err != nil {
		return nil, err
	}
	return claims, nil
}

// validateClaims enforces iss, aud, exp/nbf (with ClockSkew) and the optional
// nonce.
func (c *Client) validateClaims(claims map[string]any, nonce string) error {
	iss, _ := claims["iss"].(string)
	if iss == "" {
		return errors.New("oidc: id_token is missing the iss claim")
	}
	if strings.TrimRight(iss, "/") != c.issuer {
		return fmt.Errorf("oidc: id_token issuer %q does not match %q", iss, c.issuer)
	}
	if !audienceContains(claims["aud"], c.cfg.ClientID) {
		return fmt.Errorf("oidc: id_token audience does not include client_id %q", c.cfg.ClientID)
	}

	now := time.Now()
	skew := c.cfg.ClockSkew

	exp, ok := numericClaim(claims["exp"])
	if !ok {
		return errors.New("oidc: id_token is missing the exp claim")
	}
	if now.After(time.Unix(exp, 0).Add(skew)) {
		return errors.New("oidc: id_token has expired")
	}

	if nbf, ok := numericClaim(claims["nbf"]); ok {
		if now.Before(time.Unix(nbf, 0).Add(-skew)) {
			return errors.New("oidc: id_token is not yet valid")
		}
	}

	if nonce != "" {
		got, _ := claims["nonce"].(string)
		if got != nonce {
			return errors.New("oidc: id_token nonce mismatch")
		}
	}
	return nil
}

// keyFor resolves the verification key by kid, loading and caching the JWKS on
// first use. A kid miss triggers a single refresh to tolerate key rotation.
func (c *Client) keyFor(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	keys := c.keys
	c.mu.RUnlock()

	if len(keys) == 0 {
		loaded, err := c.loadKeys(ctx)
		if err != nil {
			return nil, err
		}
		keys = loaded
	}

	if kid != "" {
		if pub, ok := keys[kid]; ok {
			return pub, nil
		}
		if refreshed, err := c.loadKeys(ctx); err == nil {
			if pub, ok := refreshed[kid]; ok {
				return pub, nil
			}
		}
		return nil, fmt.Errorf("oidc: no verification key found for kid %q", kid)
	}

	if len(keys) == 1 {
		for _, pub := range keys {
			return pub, nil
		}
	}
	return nil, errors.New("oidc: id_token has no kid and the provider publishes multiple keys")
}

// loadKeys fetches and parses the JWKS, caching the result.
func (c *Client) loadKeys(ctx context.Context) (map[string]crypto.PublicKey, error) {
	if c.jwksURI == "" {
		return nil, fmt.Errorf("%w: provider did not advertise a jwks_uri", ErrInvalidConfig)
	}
	doc, err := getJSON[jwksDoc](ctx, c.http, c.jwksURI)
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks: %w", err)
	}

	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := k.publicKey()
		if err != nil {
			continue // ignore unusable keys (e.g. unsupported curves)
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("oidc: jwks contained no usable keys")
	}

	c.mu.Lock()
	c.keys = keys
	c.mu.Unlock()
	return keys, nil
}

// publicKey converts a JWK into an rsa or ecdsa public key.
func (k jwkKey) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := decodeBigInt(k.N)
		if err != nil {
			return nil, fmt.Errorf("oidc: jwk RSA modulus: %w", err)
		}
		e, err := decodeBigInt(k.E)
		if err != nil {
			return nil, fmt.Errorf("oidc: jwk RSA exponent: %w", err)
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > int64(^uint32(0)) {
			return nil, errors.New("oidc: jwk RSA exponent is out of range")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("oidc: unsupported EC curve %q", k.Crv)
		}
		x, err := decodeBigInt(k.X)
		if err != nil {
			return nil, fmt.Errorf("oidc: jwk EC x: %w", err)
		}
		y, err := decodeBigInt(k.Y)
		if err != nil {
			return nil, fmt.Errorf("oidc: jwk EC y: %w", err)
		}
		if !elliptic.P256().IsOnCurve(x, y) {
			return nil, errors.New("oidc: jwk EC point is not on P-256")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("oidc: unsupported jwk key type %q", k.Kty)
	}
}

// --- PKCE --------------------------------------------------------------------

// GeneratePKCE returns an RFC 7636 code verifier and its S256 challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("oidc: generate PKCE verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	digest := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(digest[:])
	return verifier, challenge, nil
}

// --- JWT helpers -------------------------------------------------------------

// parseJWT splits and decodes a compact JWS without verifying it.
func parseJWT(raw string) (header, claims map[string]any, signingInput string, signature []byte, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, "", nil, errors.New("oidc: id_token is not a well-formed JWT")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("oidc: decode id_token header: %w", err)
	}
	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("oidc: decode id_token claims: %w", err)
	}
	signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("oidc: decode id_token signature: %w", err)
	}

	header = map[string]any{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, "", nil, fmt.Errorf("oidc: parse id_token header: %w", err)
	}
	claims = map[string]any{}
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		return nil, nil, "", nil, fmt.Errorf("oidc: parse id_token claims: %w", err)
	}
	return header, claims, parts[0] + "." + parts[1], signature, nil
}

// audienceContains reports whether the aud claim (string or []string) includes
// want.
func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, entry := range v {
			if s, ok := entry.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	}
	return false
}

// numericClaim reads a JSON number claim. encoding/json decodes numbers as
// float64; json.Number is handled too for callers that opt into UseNumber.
func numericClaim(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

// decodeBigInt decodes a base64url-encoded, big-endian integer (JWK n/e/x/y).
func decodeBigInt(s string) (*big.Int, error) {
	if s == "" {
		return nil, errors.New("empty value")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

// getJSON performs a bounded GET and decodes the JSON response, requiring 200.
func getJSON[T any](ctx context.Context, client *http.Client, endpoint string) (T, error) {
	var out T
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBody)).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

// requireHTTPS rejects non-https endpoints when AllowInsecure is unset.
func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("malformed endpoint %q", raw)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("endpoint %q must use https", raw)
	}
	return nil
}
