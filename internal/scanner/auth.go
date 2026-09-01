package scanner

// Authentication support for authenticated scanning. It lets the scanner
// operate behind a login wall (form sessions, raw cookies, or static headers)
// where most real-world vulnerabilities live.
//
// Security notes:
//   - credentials are never logged;
//   - error messages never contain passwords, cookies, or header values.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// AuthType selects how a scan session authenticates against a target.
type AuthType int

const (
	AuthNone   AuthType = iota // no authentication
	AuthForm                   // POST credentials to a login URL, keep session cookies
	AuthCookie                 // inject a raw Cookie header on every request (static override)
	AuthHeader                 // inject a static header (e.g. Authorization: Bearer x)
)

// String returns a stable, human-readable name for the auth type.
func (t AuthType) String() string {
	switch t {
	case AuthForm:
		return "form"
	case AuthCookie:
		return "cookie"
	case AuthHeader:
		return "header"
	default:
		return "none"
	}
}

// AuthConfig describes how to authenticate against a target application.
type AuthConfig struct {
	Type          AuthType          `json:"type"`
	LoginURL      string            `json:"login_url,omitempty"`      // form POST target
	UsernameField string            `json:"username_field,omitempty"` // default "username"
	PasswordField string            `json:"password_field,omitempty"` // default "password"
	Username      string            `json:"username,omitempty"`
	Password      string            `json:"password,omitempty"`
	SuccessMatch  string            `json:"success_match,omitempty"` // substring in body after login (optional)
	FailureMatch  string            `json:"failure_match,omitempty"` // substring meaning login failed (optional)
	ExtraFields   map[string]string `json:"extra_fields,omitempty"`  // hidden fields (csrf token name->value)
	Cookie        string            `json:"cookie,omitempty"`        // AuthCookie: "k1=v1; k2=v2"
	HeaderName    string            `json:"header_name,omitempty"`   // AuthHeader
	HeaderValue   string            `json:"header_value,omitempty"`
}

// authRetryKey marks requests that have already been retried after a
// re-login, so a persistent 401/403 can never trigger an infinite loop.
type authRetryKey struct{}

const (
	defaultAuthTimeout = 15 * time.Second

	// maxAuthResponseRead caps how much of a login response body is inspected.
	maxAuthResponseRead = 4 << 20 // 4 MiB

	// browserUserAgent mimics a common desktop browser for login POSTs; some
	// applications reject non-browser user agents outright.
	browserUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

	maxLoginRedirects = 10
)

// AuthSession holds an authenticated HTTP client used by the scanner to send
// requests on behalf of a logged-in principal.
//
// A session is safe for concurrent use by multiple goroutines.
type AuthSession struct {
	cfg        AuthConfig
	client     *http.Client // public client: redirects, timeout, injection layers
	authClient *http.Client // private client used only for login/refresh calls
	jar        http.CookieJar

	mu sync.Mutex // serializes login/refresh and guards ok
	ok bool
}

// NewAuthSession validates cfg, performs the initial login when required and
// returns a ready-to-use session.
//
// For form authentication a failed login yields both a non-nil session (with
// OK() == false, usable for diagnostics) and a non-nil error describing why
// the login failed. For configuration problems only the error is meaningful
// and nil is returned as the session.
func NewAuthSession(cfg AuthConfig, timeout time.Duration) (*AuthSession, error) {
	if timeout <= 0 {
		timeout = defaultAuthTimeout
	}
	s := &AuthSession{cfg: cfg}

	switch cfg.Type {
	case AuthNone:
		s.ok = true

	case AuthForm:
		loginURL, err := url.Parse(strings.TrimSpace(cfg.LoginURL))
		if err != nil || loginURL.Scheme == "" || loginURL.Host == "" {
			return nil, errors.New("auth: login_url must be an absolute http(s) URL")
		}
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("auth: create cookie jar: %w", err)
		}
		s.jar = jar

	case AuthCookie:
		if strings.TrimSpace(cfg.Cookie) == "" {
			return nil, errors.New("auth: cookie must not be empty for cookie authentication")
		}
		s.ok = true

	case AuthHeader:
		if strings.TrimSpace(cfg.HeaderName) == "" || strings.TrimSpace(cfg.HeaderValue) == "" {
			return nil, errors.New("auth: header_name and header_value are required for header authentication")
		}
		s.ok = true

	default:
		return nil, fmt.Errorf("auth: unsupported auth type %d", int(cfg.Type))
	}

	// Transport chain for the public client: static credential injection is
	// applied first, then the transparent re-authentication layer.
	var rt http.RoundTripper = http.DefaultTransport
	switch cfg.Type {
	case AuthHeader:
		rt = &headerInjector{
			base:  rt,
			name:  http.CanonicalHeaderKey(strings.TrimSpace(cfg.HeaderName)),
			value: cfg.HeaderValue,
		}
	case AuthCookie:
		rt = &cookieInjector{base: rt, cookie: cfg.Cookie}
	case AuthForm:
		rt = &reauthTransport{session: s, base: rt}
	}

	s.client = &http.Client{
		Transport: rt,
		Jar:       s.jar, // nil unless form authentication
		Timeout:   timeout,
	}
	// The login client bypasses the re-auth transport on purpose: a failing
	// refresh must never recurse into another refresh. Redirects are capped
	// so hostile targets cannot spin us in circles.
	s.authClient = &http.Client{
		Jar:     s.jar,
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxLoginRedirects {
				return errors.New("auth: stopped after 10 redirects during login")
			}
			return nil
		},
	}

	if cfg.Type == AuthForm {
		s.mu.Lock()
		err := s.loginLocked()
		s.mu.Unlock()
		if err != nil {
			// Hand back the half-initialized session alongside the error so
			// callers can inspect Type()/OK(); ok stays false.
			return s, err
		}
	}
	return s, nil
}

// Client returns the HTTP client that carries the authenticated session:
// cookies via the jar (form mode) or injected headers (cookie/header modes).
// The client follows redirects and applies the configured timeout.
func (s *AuthSession) Client() *http.Client { return s.client }

// OK reports whether the session is verified: after a successful form login
// it is true; for other modes it reflects config validity.
func (s *AuthSession) OK() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ok
}

// Type returns the configured authentication type.
func (s *AuthSession) Type() AuthType { return s.cfg.Type }

// Refresh re-establishes the session. For form authentication it re-runs the
// login flow; for all other modes it is a no-op returning nil.
func (s *AuthSession) Refresh() error {
	if s.cfg.Type != AuthForm {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loginLocked()
}

// loginLocked performs the credential POST and verifies the outcome.
// Callers must hold s.mu. The error never contains credentials.
func (s *AuthSession) loginLocked() error {
	form := url.Values{}
	form.Set(orDefault(s.cfg.UsernameField, "username"), s.cfg.Username)
	form.Set(orDefault(s.cfg.PasswordField, "password"), s.cfg.Password)
	for _, k := range sortedKeys(s.cfg.ExtraFields) { // sorted: deterministic bodies
		form.Set(k, s.cfg.ExtraFields[k])
	}

	req, err := http.NewRequest(http.MethodPost, s.cfg.LoginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("auth: build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", browserUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := s.authClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth: login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthResponseRead))
	if err != nil {
		return fmt.Errorf("auth: read login response: %w", err)
	}
	bodyText := string(body)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		s.ok = false
		return fmt.Errorf("auth: login rejected with HTTP %d", resp.StatusCode)
	}

	failed := false
	switch {
	case s.cfg.SuccessMatch != "":
		failed = !strings.Contains(bodyText, s.cfg.SuccessMatch)
	case s.cfg.FailureMatch != "":
		failed = strings.Contains(bodyText, s.cfg.FailureMatch)
	default:
		failed = resp.StatusCode < 200 || resp.StatusCode >= 400
	}

	s.ok = !failed
	if failed {
		return fmt.Errorf("auth: login verification failed with HTTP %d", resp.StatusCode)
	}
	return nil
}

// --- transport helpers ------------------------------------------------------

// headerInjector adds one fixed header to every outgoing request.
type headerInjector struct {
	base  http.RoundTripper
	name  string
	value string
}

func (h *headerInjector) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set(h.name, h.value)
	return h.base.RoundTrip(r)
}

// cookieInjector replaces the entire Cookie header on every request; any
// cookies a jar might have attached are dropped (static override semantics).
type cookieInjector struct {
	base   http.RoundTripper
	cookie string
}

func (c *cookieInjector) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Del("Cookie")
	r.Header.Set("Cookie", c.cookie)
	return c.base.RoundTrip(r)
}

// reauthTransport retries a request exactly once through a fresh login when
// the origin answers 401/403 (typically an expired session cookie). The
// retry is marked in the request context so it can never cascade.
type reauthTransport struct {
	session *AuthSession
	base    http.RoundTripper
}

func (r *reauthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return resp, nil
	}
	// Only form sessions can transparently re-login; others get the status
	// they were given.
	if r.session.cfg.Type != AuthForm || req.Context().Value(authRetryKey{}) != nil {
		return resp, nil
	}
	if r.session.Refresh() != nil {
		// Re-login failed: surface the original 401/403 to the caller
		// (its body is returned unconsumed; net/http will close it).
		return resp, nil
	}

	retry := req.Clone(context.WithValue(req.Context(), authRetryKey{}, true))
	// Re-read cookies from the jar: Refresh replaced the server-side session.
	retry.Header.Del("Cookie")
	for _, ck := range r.session.jar.Cookies(retry.URL) {
		retry.AddCookie(ck)
	}
	if retry.Body != nil {
		resp.Body.Close()
		if retry.GetBody == nil {
			return nil, errors.New("auth: cannot replay request body for re-authenticated retry")
		}
		fresh, berr := retry.GetBody()
		if berr != nil {
			return nil, fmt.Errorf("auth: replay request body: %w", berr)
		}
		retry.Body = fresh
	}
	return r.base.RoundTrip(retry)
}

// --- small helpers ----------------------------------------------------------

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
