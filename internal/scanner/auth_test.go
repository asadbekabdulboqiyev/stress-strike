package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// authTestState is shared server-side state for the auth test servers.
type authTestState struct {
	mu         sync.Mutex
	validToken string // session token currently accepted by /protected
	logins     int    // number of times /login was hit
	csrfOK     bool   // whether the server expects the csrf_token field
}

func (st *authTestState) setValid(tok string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.validToken = tok
}

func (st *authTestState) currentValid() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.validToken
}

// newAuthTestServer starts a test origin with /login and /protected.
//
// /login accepts user=admin, pw=s3cret and csrf_token=csrf-42 (when enabled),
// issues a fresh session cookie per successful login and answers wrong
// credentials with HTTP 200 + "invalid credentials" (like many real apps).
// /protected serves content only for a cookie matching the latest token.
// With rejectAll, /protected always answers 401 (for retry-guard tests).
func newAuthTestServer(t *testing.T, st *authTestState, rejectAll bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		st.logins++
		n := st.logins
		st.mu.Unlock()

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.PostFormValue("user") != "admin" ||
			r.PostFormValue("pw") != "s3cret" ||
			(st.csrfOK && r.PostFormValue("csrf_token") != "csrf-42") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>invalid credentials, please retry</html>"))
			return
		}
		tok := fmt.Sprintf("sess-%d-%d", n, time.Now().UnixNano())
		st.setValid(tok)
		http.SetCookie(w, &http.Cookie{Name: "session", Value: tok, Path: "/"})
		_, _ = w.Write([]byte("<html>dashboard home</html>"))
	})
	mux.HandleFunc("/bounce", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/protected", http.StatusFound)
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if rejectAll || err != nil || c.Value == "" || c.Value != st.currentValid() {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		_, _ = w.Write([]byte("top secret area"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// formCfg builds a form-auth config pointing at srv with CSRF required.
func formCfg(srvURL string) AuthConfig {
	return AuthConfig{
		Type:          AuthForm,
		LoginURL:      srvURL + "/login",
		UsernameField: "user",
		PasswordField: "pw",
		Username:      "admin",
		Password:      "s3cret",
		SuccessMatch:  "dashboard",
		ExtraFields:   map[string]string{"csrf_token": "csrf-42"},
	}
}

func TestAuthFormLoginSuccessAndFetch(t *testing.T) {
	st := &authTestState{csrfOK: true}
	srv := newAuthTestServer(t, st, false)

	sess, err := NewAuthSession(formCfg(srv.URL), 5*time.Second)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}
	if !sess.OK() {
		t.Fatal("expected OK() == true after successful login")
	}
	if sess.Type() != AuthForm {
		t.Fatalf("Type() = %v, want form", sess.Type())
	}
	if sess.Client() == nil || sess.Client().Timeout <= 0 {
		t.Fatal("Client() must be non-nil with timeout applied")
	}

	resp, err := sess.Client().Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("GET /protected: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/protected status = %d, want 200", resp.StatusCode)
	}
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "top secret area") {
		t.Fatalf("unexpected /protected body %q", string(buf[:n]))
	}

	// The client must follow redirects while carrying the session.
	resp2, err := sess.Client().Get(srv.URL + "/bounce")
	if err != nil {
		t.Fatalf("GET /bounce: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("/bounce -> /protected status = %d, want 200 after redirect", resp2.StatusCode)
	}
}

func TestAuthFormWrongPassword(t *testing.T) {
	st := &authTestState{csrfOK: true}
	srv := newAuthTestServer(t, st, false)

	cfg := formCfg(srv.URL)
	cfg.Password = "definitely-not-the-password"

	sess, err := NewAuthSession(cfg, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if sess == nil {
		t.Fatal("expected a session object even when login fails")
	}
	if sess.OK() {
		t.Fatal("OK() must be false after failed login")
	}
	for _, secret := range []string{cfg.Password, "s3cret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaks credential %q: %s", secret, err.Error())
		}
	}
}

func TestAuthFormFailureMatch(t *testing.T) {
	st := &authTestState{csrfOK: true}
	srv := newAuthTestServer(t, st, false)

	cfg := formCfg(srv.URL)
	cfg.Password = "definitely-not-the-password"
	cfg.SuccessMatch = "" // rely on FailureMatch instead
	cfg.FailureMatch = "invalid credentials"

	sess, err := NewAuthSession(cfg, 5*time.Second)
	if err == nil {
		t.Fatal("expected error when FailureMatch appears in response")
	}
	if sess != nil && sess.OK() {
		t.Fatal("OK() must be false when FailureMatch matched")
	}
}

func TestAuthFormRejectedWith401(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("nope"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := formCfg(srv.URL)
	cfg.ExtraFields = nil // server ignores everything anyway

	sess, err := NewAuthSession(cfg, 5*time.Second)
	if err == nil {
		t.Fatal("expected error on HTTP 401 login")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error should mention HTTP 401, got: %s", err.Error())
	}
	if sess != nil && sess.OK() {
		t.Fatal("OK() must be false on rejected login")
	}
}

func TestAuthFormRequiresExtraFields(t *testing.T) {
	st := &authTestState{csrfOK: true} // server enforces csrf_token=csrf-42
	srv := newAuthTestServer(t, st, false)

	cfg := formCfg(srv.URL)
	cfg.ExtraFields = nil // missing CSRF -> server rejects

	if _, err := NewAuthSession(cfg, 5*time.Second); err == nil {
		t.Fatal("expected login failure without required csrf extra field")
	}

	cfg.ExtraFields = map[string]string{"csrf_token": "csrf-42"}
	sess, err := NewAuthSession(cfg, 5*time.Second)
	if err != nil {
		t.Fatalf("login with csrf should succeed: %v", err)
	}
	if !sess.OK() {
		t.Fatal("expected OK() with csrf submitted")
	}
}

func TestAuthCookieMode(t *testing.T) {
	var got atomicString
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.set(r.Header.Get("Cookie"))
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	sess, err := NewAuthSession(AuthConfig{Type: AuthCookie, Cookie: "k1=v1; k2=v2"}, 5*time.Second)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}
	if !sess.OK() || sess.Type() != AuthCookie {
		t.Fatalf("cookie mode misconfigured: OK=%v type=%v", sess.OK(), sess.Type())
	}
	resp, err := sess.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if got.get() != "k1=v1; k2=v2" {
		t.Fatalf("Cookie header = %q, want exact static override", got.get())
	}
}

func TestAuthHeaderMode(t *testing.T) {
	var got atomicString
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.set(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := AuthConfig{Type: AuthHeader, HeaderName: "Authorization", HeaderValue: "Bearer tok-abc"}
	sess, err := NewAuthSession(cfg, 5*time.Second)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}
	if sess.Type() != AuthHeader {
		t.Fatalf("Type() = %v, want header", sess.Type())
	}
	resp, err := sess.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if got.get() != "Bearer tok-abc" {
		t.Fatalf("Authorization = %q, want %q", got.get(), "Bearer tok-abc")
	}
}

func TestAuthValidationAndNone(t *testing.T) {
	if _, err := NewAuthSession(AuthConfig{Type: AuthType(99)}, time.Second); err == nil {
		t.Fatal("expected error for unknown auth type")
	}
	if _, err := NewAuthSession(AuthConfig{Type: AuthCookie, Cookie: "   "}, time.Second); err == nil {
		t.Fatal("expected error for empty cookie")
	}
	if _, err := NewAuthSession(AuthConfig{Type: AuthHeader, HeaderName: "X", HeaderValue: ""}, time.Second); err == nil {
		t.Fatal("expected error for empty header value")
	}
	if _, err := NewAuthSession(AuthConfig{Type: AuthForm}, time.Second); err == nil {
		t.Fatal("expected error for form auth without login_url")
	}

	sess, err := NewAuthSession(AuthConfig{Type: AuthNone}, time.Second)
	if err != nil {
		t.Fatalf("AuthNone: %v", err)
	}
	if !sess.OK() || sess.Refresh() != nil || sess.Client() == nil {
		t.Fatal("AuthNone must yield valid no-op session")
	}
}

func TestAuthRefreshReissuesSession(t *testing.T) {
	st := &authTestState{csrfOK: true}
	srv := newAuthTestServer(t, st, false)

	sess, err := NewAuthSession(formCfg(srv.URL), 5*time.Second)
	if err != nil {
		t.Fatalf("initial login: %v", err)
	}
	st.mu.Lock()
	initialLogins := st.logins
	st.mu.Unlock()
	if initialLogins != 1 {
		t.Fatalf("logins = %d, want 1 after construction", initialLogins)
	}

	// Simulate server-side invalidation of the current session.
	st.setValid("")
	if err := sess.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	st.mu.Lock()
	afterRefresh := st.logins
	st.mu.Unlock()
	if afterRefresh != 2 {
		t.Fatalf("logins after Refresh = %d, want 2", afterRefresh)
	}

	resp, err := sess.Client().Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("GET /protected after Refresh: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/protected status = %d, want 200 after refresh", resp.StatusCode)
	}
}

func TestAuthAutoReauthOnExpiry(t *testing.T) {
	st := &authTestState{csrfOK: true}
	srv := newAuthTestServer(t, st, false)

	sess, err := NewAuthSession(formCfg(srv.URL), 5*time.Second)
	if err != nil {
		t.Fatalf("initial login: %v", err)
	}

	// Expire the session server-side AFTER the client obtained its cookie:
	// the next request gets a 401, triggers one transparent re-login and
	// succeeds on the automatic retry.
	st.setValid("")

	resp, err := sess.Client().Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("GET /protected: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/protected status = %d, want auto-reauthenticated 200", resp.StatusCode)
	}
	st.mu.Lock()
	logins := st.logins
	st.mu.Unlock()
	if logins != 2 {
		t.Fatalf("logins = %d, want exactly one transparent re-login (2 total)", logins)
	}
}

func TestAuthAutoReauthRetriesOnce(t *testing.T) {
	st := &authTestState{csrfOK: true}
	srv := newAuthTestServer(t, st, true) // /protected rejects everything

	sess, err := NewAuthSession(formCfg(srv.URL), 5*time.Second)
	if err != nil {
		t.Fatalf("initial login: %v", err)
	}

	resp, err := sess.Client().Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("GET /protected: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("persistent 401 expected to reach caller, got %d", resp.StatusCode)
	}
	st.mu.Lock()
	logins := st.logins
	st.mu.Unlock()
	if logins != 2 {
		t.Fatalf("logins = %d, want 2 (initial + single guarded retry)", logins)
	}
}

// atomicString is a tiny thread-safe string cell for handler assertions.
type atomicString struct {
	mu sync.Mutex
	v  string
}

func (a *atomicString) set(v string) {
	a.mu.Lock()
	a.v = v
	a.mu.Unlock()
}

func (a *atomicString) get() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.v
}
