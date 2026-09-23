package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/verigate"
)

// newTestSrv builds a demo server with protection disabled unless protect=true.
func newTestSrv(t *testing.T, protect bool) (*demoServer, *verigate.VeriGate, *httptest.Server) {
	t.Helper()
	store := NewStore()
	gate, err := verigate.New(verigate.Options{
		Enabled:       protect,
		RateLimit:     5,
		Burst:         5,
		Difficulty:    2,
		BlockAfter:    3,
		BlockDuration: 60e9,
		Exempt: func(r *http.Request) bool {
			p := r.URL.Path
			return p == "/health" || strings.HasPrefix(p, "/static/") || strings.HasPrefix(p, "/admin")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewDemoServer(store, gate)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv.Routes(mux)
	ts := httptest.NewServer(gate.Handler(mux))
	t.Cleanup(ts.Close)
	return srv, gate, ts
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

//--------------------------------------------------------------
// Store logic
//--------------------------------------------------------------

func TestStoreCatalogAndSearch(t *testing.T) {
	s := NewStore()
	if len(s.Products()) != 12 {
		t.Fatalf("products = %d, want 12", len(s.Products()))
	}
	laptops := s.SearchProducts("laptops", "", "default")
	if len(laptops) != 2 {
		t.Fatalf("laptops = %d, want 2", len(laptops))
	}
	byName := s.SearchProducts("", "macbook", "default")
	if len(byName) != 1 || byName[0].Name != `MacBook Pro 14" M3 Max` {
		t.Fatalf("search macbook = %+v", byName)
	}
	sorted := s.SearchProducts("", "", "price-asc")
	if len(sorted) < 2 || sorted[0].PriceCents > sorted[1].PriceCents {
		t.Fatal("price-asc sort broken")
	}
	if p := s.ProductByID(99999); p != nil {
		t.Fatal("ProductByID(99999) should be nil")
	}
}

func TestAuthAndCartAndCheckout(t *testing.T) {
	s := NewStore()

	// Register
	u, err := s.Register("Test User", "test@volt.store", "secret1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("Test User", "test@volt.store", "other"); err == nil {
		t.Fatal("duplicate email should fail")
	}

	// Authenticate
	token, got, err := s.Authenticate("test@volt.store", "secret1")
	if err != nil || got.ID != u.ID {
		t.Fatalf("authenticate: user=%v err=%v", got, err)
	}
	if s.UserBySession("bogus-token") != nil {
		t.Fatal("bogus session resolved")
	}

	// Cart lifecycle
	if _, err := s.AddToCart(token, 99999, 1); err == nil {
		t.Fatal("adding missing product should fail")
	}
	if _, err := s.AddToCart(token, 1, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddToCart(token, 3, 1); err != nil {
		t.Fatal(err)
	}
	if n := s.CartCount(token); n != 3 {
		t.Fatalf("cart count = %d, want 3", n)
	}
	if err := s.RemoveFromCart(token, 1); err != nil {
		t.Fatal(err)
	}
	if n := s.CartCount(token); n != 1 {
		t.Fatalf("cart count after remove = %d, want 1", n)
	}

	// Checkout
	order, err := s.Checkout(token, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if order.TotalCents != s.ProductByID(3).PriceCents {
		t.Fatalf("order total = %d, want product 3 price", order.TotalCents)
	}
	if s.CartCount(token) != 0 {
		t.Fatal("cart should be empty after checkout")
	}
	if len(s.OrdersByUser(u.ID)) != 1 {
		t.Fatal("order history should have 1 order")
	}
	if _, err := s.Checkout(token, u.ID); err == nil {
		t.Fatal("checkout of empty cart should fail")
	}
}

//--------------------------------------------------------------
// HTTP smoke: pages + API
//--------------------------------------------------------------

func TestPagesServe(t *testing.T) {
	_, _, ts := newTestSrv(t, false)
	for _, path := range []string{"/", "/products", "/product/1", "/cart", "/login", "/register", "/account", "/admin", "/health"} {
		resp, body := get(t, ts.URL+path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status=%d", path, resp.StatusCode)
		}
		if !strings.Contains(body, "VoltStore") && path != "/health" {
			t.Fatalf("%s: page missing VoltStore brand", path)
		}
	}
	// 404s
	resp, _ := get(t, ts.URL+"/product/999")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/product/999 status=%d want 404", resp.StatusCode)
	}
}

func TestLoginAndCartAPI(t *testing.T) {
	_, _, ts := newTestSrv(t, false)

	// Bad login -> 401
	resp, err := http.Post(ts.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"email":"alice@volt.store","password":"wrong"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login status=%d want 401", resp.StatusCode)
	}

	// Good login -> session cookie
	resp, err = http.Post(ts.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"email":"alice@volt.store","password":"demo1234"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d want 200", resp.StatusCode)
	}
	var cookies []*http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "ss_session" {
			cookies = append(cookies, c)
		}
	}
	if len(cookies) != 1 {
		t.Fatal("login did not set ss_session cookie")
	}

	// Add to cart with cookie
	req, _ := http.NewRequest("POST", ts.URL+"/api/cart/items",
		strings.NewReader(`{"product_id":2,"quantity":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookies[0])
	cresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer cresp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(cresp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["count"].(float64) != 1 {
		t.Fatalf("cart count = %v, want 1", out["count"])
	}

	// Checkout without login -> API rejects
	req, _ = http.NewRequest("POST", ts.URL+"/api/checkout",
		strings.NewReader(`{"full_name":"X","address":"Y","card_last4":"4242"}`))
	req.Header.Set("Content-Type", "application/json")
	oresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	oresp.Body.Close()
	if oresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("guest checkout status=%d want 401", oresp.StatusCode)
	}
}

//--------------------------------------------------------------
// VeriGate integration
//--------------------------------------------------------------

func TestProtectedStoreRateLimitsAttacks(t *testing.T) {
	_, _, ts := newTestSrv(t, true)
	// API-style requests over the burst are throttled with 429s.
	limited := 0
	passthrough := 0
	for i := 0; i < 40; i++ {
		req, _ := http.NewRequest("GET", ts.URL+"/api/products", nil)
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			passthrough++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("unexpected status %d", resp.StatusCode)
		}
	}
	if limited == 0 {
		t.Fatal("protected store should rate-limit an API attack")
	}
	if passthrough == 0 {
		t.Fatal("protected store should still serve the burst")
	}
}

func TestProtectedStoreToggleViaAdmin(t *testing.T) {
	_, gate, ts := newTestSrv(t, true)

	// Toggle OFF via the control plane endpoint.
	resp, err := http.Post(ts.URL+"/admin/protect", "application/json",
		strings.NewReader(`{"enabled":false}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("toggle status=%d", resp.StatusCode)
	}
	if gate.Enabled() {
		t.Fatal("gate should be disabled after toggle")
	}

	// Hammer while off: everything passes.
	for i := 0; i < 60; i++ {
		req, _ := http.NewRequest("GET", ts.URL+"/api/products", nil)
		req.Header.Set("Accept", "application/json")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("req %d: status=%d want 200 (protection off)", i, r.StatusCode)
		}
	}

	// Toggle back ON.
	resp, err = http.Post(ts.URL+"/admin/protect", "application/json",
		strings.NewReader(`{"enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !gate.Enabled() {
		t.Fatal("gate should be enabled again")
	}
}

func TestAdminStatsShape(t *testing.T) {
	_, _, ts := newTestSrv(t, true)
	resp, body := get(t, ts.URL+"/admin/stats")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats status=%d", resp.StatusCode)
	}
	var st struct {
		Enabled  bool `json:"enabled"`
		Requests int  `json:"requests"`
	}
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("stats not valid json: %v", err)
	}
	if st.Requests == 0 {
		t.Fatal("stats.requests should be > 0 after requests")
	}
}
