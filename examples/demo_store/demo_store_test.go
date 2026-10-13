package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	// Unknown paths must not fall through to the homepage with a 200
	// ("GET /" is the ServeMux catch-all).
	resp, _ = get(t, ts.URL+"/nonexistent")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/nonexistent status=%d want 404", resp.StatusCode)
	}
}

func TestPriceFormattingAndHeroStats(t *testing.T) {
	_, _, ts := newTestSrv(t, false)
	_, body := get(t, ts.URL+"/")
	// formatPrice-style output: thousands separators on 4+ digit prices.
	if !strings.Contains(body, "$3,499.00") {
		t.Fatalf("home page price missing thousands separator, got: %q", substringAround(body, "$3,4"))
	}
	// Hero stats must reflect the real catalog (12 products, 6 categories).
	if !strings.Contains(body, `>12</div><div class="lbl">Products</div>`) {
		t.Fatalf("hero product count not 12, got: %q", substringAround(body, "Products"))
	}
	if !strings.Contains(body, `>6</div><div class="lbl">Categories</div>`) {
		t.Fatalf("hero category count not 6, got: %q", substringAround(body, "Categories"))
	}
}

func TestEmailCaseNormalization(t *testing.T) {
	s := NewStore()
	// Registering with mixed-case email must be treated as the same account
	// as the lowercase form (and must not hijack an existing lookup key).
	if _, err := s.Register("Mixed Case", "MiXeD@Volt.Store", "secret1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("Dup", "mixed@volt.store", "secret1"); err == nil {
		t.Fatal("register with same email in different case should fail")
	}
	if _, _, err := s.Authenticate("MIXED@VOLT.STORE", "secret1"); err != nil {
		t.Fatalf("authenticate with different case should work: %v", err)
	}
	// Demo accounts (seeded via createUser) resolve case-insensitively too.
	if _, _, err := s.Authenticate("ALICE@VOLT.STORE", "demo1234"); err != nil {
		t.Fatalf("alice login with uppercase email failed: %v", err)
	}
}

func TestCatalogSortSelectNotInline(t *testing.T) {
	_, _, ts := newTestSrv(t, false)
	_, body := get(t, ts.URL+"/products?q=pro&x")
	// The sort control must not build its URL from raw template values inline.
	if strings.Contains(body, "onchange=") {
		t.Fatal("sort select should use app.js handler, not an inline onchange")
	}
	if !strings.Contains(body, `id="sort-select"`) {
		t.Fatal("sort select missing id=sort-select for JS handler")
	}
}

// substringAround returns a short window around needle for readable failures.
func substringAround(s, needle string) string {
	i := strings.Index(s, needle)
	if i < 0 {
		i = 0
		if len(s) > 80 {
			s = s[:80]
		}
		return s
	}
	lo, hi := i-40, i+40
	if lo < 0 {
		lo = 0
	}
	if hi > len(s) {
		hi = len(s)
	}
	return s[lo:hi]
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

// The stats endpoint must report the difficulty the gate is charging and
// whether an adaptive controller is driving it.
func TestAdminStatsReportsDifficulty(t *testing.T) {
	_, _, ts := newTestSrv(t, true)
	resp, body := get(t, ts.URL+"/admin/stats")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats status=%d", resp.StatusCode)
	}
	var st struct {
		Difficulty int     `json:"difficulty"`
		Adaptive   bool    `json:"adaptive"`
		RateRPS    float64 `json:"rate_rps"`
		StepsUp    uint64  `json:"steps_up"`
		StepsDown  uint64  `json:"steps_down"`
	}
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("stats not valid json: %v", err)
	}
	if st.Difficulty != 2 {
		t.Errorf("difficulty = %d, want the configured 2", st.Difficulty)
	}
	if st.Adaptive {
		t.Error("adaptive = true for a gate with no adaptive options")
	}
	if st.StepsUp != 0 || st.StepsDown != 0 {
		t.Errorf("steps = (%d,%d), want (0,0) for a static gate", st.StepsUp, st.StepsDown)
	}
}

// The demo's Pillar 3 claim must be observable: traffic raises the charged
// difficulty, and the stats endpoint shows it moving.
func TestAdaptiveGateRaisesDifficultyUnderLoad(t *testing.T) {
	store := NewStore()
	adaptive := verigate.DefaultAdaptiveOptions()
	adaptive.HighWaterRPS = 20
	adaptive.LowWaterRPS = 2
	adaptive.StepInterval = time.Millisecond
	adaptive.HalfLife = 5 * time.Millisecond

	gate, err := verigate.New(verigate.Options{
		Enabled:    true,
		RateLimit:  1,
		Burst:      1,
		Difficulty: 2,
		Secret:     []byte("adaptive-demo"),
		Exempt: func(r *http.Request) bool {
			p := r.URL.Path
			return p == "/health" || strings.HasPrefix(p, "/admin")
		},
		Adaptive: &adaptive,
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
	defer ts.Close()

	// The stats path is exempt from throttling, so it is a clean way to apply
	// load: the gate still counts and observes every request.
	for i := 0; i < 500; i++ {
		resp, _ := get(t, ts.URL+"/admin/stats")
		resp.Body.Close()
	}

	_, body := get(t, ts.URL+"/admin/stats")
	var st struct {
		Difficulty int                        `json:"difficulty"`
		Adaptive   bool                       `json:"adaptive"`
		StepsUp    uint64                     `json:"steps_up"`
		Schedule   []verigate.DifficultyEntry `json:"schedule_tail"`
	}
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("stats not valid json: %v", err)
	}
	if !st.Adaptive {
		t.Fatal("adaptive = false, want true")
	}
	if st.StepsUp == 0 {
		t.Fatalf("difficulty never rose: difficulty=%d, steps_up=%d", st.Difficulty, st.StepsUp)
	}
	if st.Difficulty <= 2 {
		t.Fatalf("difficulty = %d under load, want above the baseline 2", st.Difficulty)
	}
	if len(st.Schedule) == 0 {
		t.Fatal("schedule_tail is empty after difficulty changes")
	}
	if last := st.Schedule[len(st.Schedule)-1]; last.Difficulty != st.Difficulty {
		t.Errorf("schedule ends at %d but difficulty is %d", last.Difficulty, st.Difficulty)
	}
}
