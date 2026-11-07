package main

// handlers_test.go — HTTP-level coverage for the VoltStore demo target.
//
// demo_store_test.go exercises the store model; these tests drive the actual
// routes through httptest so the page, cart, checkout and VeriGate admin
// handlers execute with their real request/response plumbing.

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doJSON sends a JSON request with optional cookies and Origin header.
func doJSON(t *testing.T, method, url string, body any, cookies []*http.Cookie, origin string) (*http.Response, string) {
	t.Helper()
	var rdr io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rdr = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(data)
}

func sessionCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == "ss_session" && c.Value != "" {
			return c
		}
	}
	t.Fatalf("response carried no session cookie: %v", resp.Cookies())
	return nil
}

func TestHandlersPages(t *testing.T) {
	_, _, ts := newTestSrv(t, false)

	cases := []struct {
		path string
		want int
		body string
	}{
		{"/", http.StatusOK, "VoltStore"},
		{"/nonexistent", http.StatusNotFound, "404"},
		{"/products", http.StatusOK, "Catalog"},
		{"/products?category=laptops&q=mac&sort=price-asc", http.StatusOK, "MacBook"},
		{"/product/1", http.StatusOK, "product"},
		{"/product/99999", http.StatusNotFound, ""},
		{"/product/not-a-number", http.StatusNotFound, ""},
		{"/cart", http.StatusOK, "Cart"},
		{"/login", http.StatusOK, "Sign in"},
		{"/register", http.StatusOK, "Create account"},
		{"/admin", http.StatusOK, "VeriGate"},
		{"/health", http.StatusOK, "ok"},
	}
	for _, tc := range cases {
		resp, body := get(t, ts.URL+tc.path)
		if resp.StatusCode != tc.want {
			t.Errorf("GET %s = %d, want %d", tc.path, resp.StatusCode, tc.want)
		}
		if tc.body != "" && !strings.Contains(body, tc.body) {
			t.Errorf("GET %s body missing %q", tc.path, tc.body)
		}
	}
}

func TestHandlersAuthFlow(t *testing.T) {
	_, _, ts := newTestSrv(t, false)

	// Malformed body.
	resp, _ := doJSON(t, http.MethodPost, ts.URL+"/api/auth/register", "{", nil, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("register malformed = %d, want 400", resp.StatusCode)
	}
	// Missing fields / short password.
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/auth/register", authRequest{Email: "a@b.c", Password: "x"}, nil, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("register short password = %d, want 400", resp.StatusCode)
	}
	// Cross-origin rejected.
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/auth/register",
		authRequest{Name: "A", Email: "a@b.c", Password: "secret1"}, nil, "http://evil.example")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("register cross-origin = %d, want 403", resp.StatusCode)
	}

	// Successful registration, with a guest cookie to merge.
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/auth/register",
		authRequest{Name: "Ada", Email: "ada@volt.store", Password: "secret1"},
		[]*http.Cookie{{Name: guestCookie, Value: "guest-cart-1"}}, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d, want 201", resp.StatusCode)
	}
	sess := sessionCookie(t, resp)

	// Duplicate registration conflicts.
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/auth/register",
		authRequest{Name: "Ada", Email: "ada@volt.store", Password: "secret1"}, nil, "")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate register = %d, want 409", resp.StatusCode)
	}

	// Login: malformed, wrong password, success.
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/auth/login", "{", nil, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("login malformed = %d, want 400", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/auth/login",
		authRequest{Email: "ada@volt.store", Password: "wrong"}, nil, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("login wrong password = %d, want 401", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/auth/login",
		authRequest{Email: "ada@volt.store", Password: "secret1"}, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("login = %d, want 200", resp.StatusCode)
	}

	// Account with and without a session.
	resp, _ = doJSON(t, http.MethodGet, ts.URL+"/api/account", nil, nil, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("account anonymous = %d, want 401", resp.StatusCode)
	}
	resp, body := doJSON(t, http.MethodGet, ts.URL+"/api/account", nil, []*http.Cookie{sess}, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "ada@volt.store") {
		t.Errorf("account = %d %q, want 200 with the user", resp.StatusCode, body)
	}

	// Logout clears the cookie and destroys the session.
	resp, body = doJSON(t, http.MethodPost, ts.URL+"/api/auth/logout", nil, []*http.Cookie{sess}, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Errorf("logout = %d %q", resp.StatusCode, body)
	}
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == "ss_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/auth/logout", nil, nil, "http://evil.example")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("logout cross-origin = %d, want 403", resp.StatusCode)
	}
}

func TestHandlersCartAndCheckout(t *testing.T) {
	_, _, ts := newTestSrv(t, false)

	// Register a user to get a session.
	resp, _ := doJSON(t, http.MethodPost, ts.URL+"/api/auth/register",
		authRequest{Name: "Bob", Email: "handler-bob@test.local", Password: "secret1"}, nil, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d", resp.StatusCode)
	}
	sess := sessionCookie(t, resp)
	cookies := []*http.Cookie{sess}

	// Cart: anonymous GET creates a guest cookie.
	resp, body := doJSON(t, http.MethodGet, ts.URL+"/api/cart", nil, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("cart = %d", resp.StatusCode)
	}
	var hasGuest bool
	for _, c := range resp.Cookies() {
		if c.Name == guestCookie {
			hasGuest = true
		}
	}
	if !hasGuest {
		t.Error("anonymous cart did not set the guest cookie")
	}
	if !strings.Contains(body, `"Count"`) {
		t.Errorf("cart body = %q", body)
	}

	// Add: malformed, negative, missing product, success.
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/cart/items", "{", cookies, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("cart add malformed = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/cart/items",
		cartItemRequest{ProductID: 1, Quantity: -1}, cookies, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("cart add negative = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/cart/items",
		cartItemRequest{ProductID: 99999, Quantity: 1}, cookies, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("cart add missing product = %d", resp.StatusCode)
	}
	resp, body = doJSON(t, http.MethodPost, ts.URL+"/api/cart/items",
		cartItemRequest{ProductID: 1}, cookies, "") // quantity defaults to 1
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"count":1`) {
		t.Errorf("cart add = %d %q", resp.StatusCode, body)
	}

	// Checkout page: empty cart redirects to /cart; account redirects when
	// anonymous; with a filled cart the page renders.
	resp, _ = doJSON(t, http.MethodGet, ts.URL+"/checkout", nil, nil, "")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("checkout anonymous = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = doJSON(t, http.MethodGet, ts.URL+"/account", nil, nil, "")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("account page anonymous = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = doJSON(t, http.MethodGet, ts.URL+"/account", nil, cookies, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("account page = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodGet, ts.URL+"/checkout", nil, cookies, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("checkout page = %d", resp.StatusCode)
	}

	// Checkout API: anonymous, malformed, missing fields, success, empty cart.
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/checkout", checkoutRequest{}, nil, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("checkout anonymous = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/checkout", "{", cookies, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("checkout malformed = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/checkout",
		checkoutRequest{FullName: "Bob"}, cookies, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("checkout missing fields = %d", resp.StatusCode)
	}
	resp, body = doJSON(t, http.MethodPost, ts.URL+"/api/checkout",
		checkoutRequest{FullName: "Bob", Address: "1 Main St", CardLast: "4242"}, cookies, "")
	if resp.StatusCode != http.StatusCreated || !strings.Contains(body, `"order_id"`) {
		t.Errorf("checkout = %d %q", resp.StatusCode, body)
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/checkout",
		checkoutRequest{FullName: "Bob", Address: "1 Main St", CardLast: "4242"}, cookies, "")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("checkout empty cart = %d, want 409", resp.StatusCode)
	}

	// Remove: invalid id, missing item, success.
	resp, _ = doJSON(t, http.MethodDelete, ts.URL+"/api/cart/items/nope", nil, cookies, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("cart remove invalid id = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodDelete, ts.URL+"/api/cart/items/1", nil, cookies, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("cart remove empty = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/api/cart/items",
		cartItemRequest{ProductID: 3, Quantity: 1}, cookies, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cart add for remove = %d", resp.StatusCode)
	}
	resp, body = doJSON(t, http.MethodDelete, ts.URL+"/api/cart/items/3", nil, cookies, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Errorf("cart remove = %d %q", resp.StatusCode, body)
	}

	// Catalog API honours the query string.
	resp, body = doJSON(t, http.MethodGet, ts.URL+"/api/products?category=laptops&q=mac&sort=price-asc", nil, nil, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "MacBook") {
		t.Errorf("products api = %d %q", resp.StatusCode, body)
	}
}

func TestHandlersAdminPlane(t *testing.T) {
	_, gate, ts := newTestSrv(t, false)

	resp, body := doJSON(t, http.MethodGet, ts.URL+"/admin/protect", nil, nil, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"enabled":false`) {
		t.Errorf("protect get = %d %q", resp.StatusCode, body)
	}

	resp, body = doJSON(t, http.MethodPost, ts.URL+"/admin/protect", map[string]bool{"enabled": true}, nil, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"enabled":true`) || !gate.Enabled() {
		t.Errorf("protect set = %d %q enabled=%v", resp.StatusCode, body, gate.Enabled())
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/admin/protect", "{", nil, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("protect set malformed = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/admin/protect", map[string]bool{"enabled": false}, nil, "http://evil.example")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("protect set cross-origin = %d", resp.StatusCode)
	}

	resp, body = doJSON(t, http.MethodPost, ts.URL+"/admin/reset", nil, nil, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Errorf("reset = %d %q", resp.StatusCode, body)
	}
	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/admin/reset", nil, nil, "http://evil.example")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("reset cross-origin = %d", resp.StatusCode)
	}

	resp, body = doJSON(t, http.MethodGet, ts.URL+"/admin/stats", nil, nil, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"difficulty"`) {
		t.Errorf("stats = %d %q", resp.StatusCode, body)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	plain := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(plain, req)
	for _, name := range []string{
		"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
		"Permissions-Policy", "Content-Security-Policy",
	} {
		if plain.Header().Get(name) == "" {
			t.Errorf("missing header %s", name)
		}
	}
	if hsts := plain.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS on a plaintext request = %q, want empty", hsts)
	}

	secure := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	h.ServeHTTP(secure, req)
	if secure.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS missing on a TLS request")
	}
}

func TestAdaptiveOptions(t *testing.T) {
	if got := adaptiveOptions(false, 1, 2); got != nil {
		t.Errorf("adaptiveOptions(false) = %+v, want nil", got)
	}
	got := adaptiveOptions(true, 300, 40)
	if got == nil {
		t.Fatal("adaptiveOptions(true) = nil")
	}
	if got.HighWaterRPS != 300 || got.LowWaterRPS != 40 {
		t.Errorf("adaptiveOptions(true) = %+v, want the configured watermarks", got)
	}
}

func TestFormatPriceHandler(t *testing.T) {
	cases := map[int]string{
		0:        "$0.00",
		99:       "$0.99",
		123456:   "$1,234.56",
		10000000: "$100,000.00",
	}
	for cents, want := range cases {
		if got := formatPrice(cents); got != want {
			t.Errorf("formatPrice(%d) = %q, want %q", cents, got, want)
		}
	}
}
