package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/verigate"
)

//------------------------------------------------------------------------------
// Server wiring
//------------------------------------------------------------------------------

// demoServer bundles the store and all HTTP routes.
type demoServer struct {
	store *Store
	gate  *verigate.VeriGate
	pages *template.Template
}

// NewDemoServer builds the server, wiring the VeriGate protection middleware
// around the site with /health, /static and /admin always exempt (so the
// protection itself can be toggled and health probes always work).
func NewDemoServer(store *Store, gate *verigate.VeriGate) (*demoServer, error) {
	funcs := template.FuncMap{
		"div":   func(a, b int) int { return a / b },
		"mod":   func(a, b int) int { return a % b },
		"mult":  func(a, b int) int { return a * b },
		"price": formatPrice,
	}
	pages, err := template.New("store").Funcs(funcs).ParseFS(viewsFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &demoServer{store: store, gate: gate, pages: pages}, nil
}

// Routes registers every endpoint on mux.
func (s *demoServer) Routes(mux *http.ServeMux) {
	// Pages
	mux.HandleFunc("GET /", s.handleHome)
	mux.HandleFunc("GET /products", s.handleProducts)
	mux.HandleFunc("GET /product/{id}", s.handleProduct)
	mux.HandleFunc("GET /cart", s.handleCart)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("GET /register", s.handleRegisterPage)
	mux.HandleFunc("GET /checkout", s.handleCheckoutPage)
	mux.HandleFunc("GET /account", s.handleAccount)
	mux.HandleFunc("GET /admin", s.handleAdminPage)
	mux.HandleFunc("GET /health", s.handleHealth)

	// API: auth
	mux.HandleFunc("POST /api/auth/login", s.apiLogin)
	mux.HandleFunc("POST /api/auth/register", s.apiRegister)
	mux.HandleFunc("POST /api/auth/logout", s.apiLogout)

	// API: cart
	mux.HandleFunc("GET /api/cart", s.apiCart)
	mux.HandleFunc("POST /api/cart/items", s.apiCartAdd)
	mux.HandleFunc("DELETE /api/cart/items/{id}", s.apiCartRemove)

	// API: checkout + account
	mux.HandleFunc("POST /api/checkout", s.apiCheckout)
	mux.HandleFunc("GET /api/account", s.apiAccount)

	// API: catalog
	mux.HandleFunc("GET /api/products", s.apiProducts)

	// Admin (VeriGate control plane)
	mux.HandleFunc("GET /admin/protect", s.adminProtectGet)
	mux.HandleFunc("POST /admin/protect", s.adminProtectSet)
	mux.HandleFunc("POST /admin/reset", s.adminReset)
	mux.HandleFunc("GET /admin/stats", s.adminStats)
}

//------------------------------------------------------------------------------
// View model
//------------------------------------------------------------------------------

type view struct {
	Title      string
	User       *User
	CartCount  int
	Products   []Product
	Product    *Product
	Cart       CartView
	Orders     []Order
	Categories []string
	Category   string
	Query      string
	SortBy     string
	Error      string
	Message    string
	Gate       verigate.Stats
}

func (s *demoServer) baseView(w http.ResponseWriter, r *http.Request) view {
	v := view{
		User:       s.store.UserBySession(sessionToken(r)),
		Categories: s.store.Categories(),
		Gate:       s.gate.Stats(),
	}
	v.CartCount = s.store.CartCount(s.cartKey(w, r))
	return v
}

func sessionToken(r *http.Request) string {
	c, err := r.Cookie("ss_session")
	if err != nil {
		return ""
	}
	return c.Value
}

// guestCookie is the anonymous-visitor cart cookie. It exists so that a cart
// is per-browser even before login: without it every guest would share one
// global cart (a real cross-user data leak).
const guestCookie = "ss_guest"

// cartKey returns the storage key for the caller's cart: the session token
// when logged in, otherwise a per-browser guest cookie (created on first
// anonymous use).
func (s *demoServer) cartKey(w http.ResponseWriter, r *http.Request) string {
	if tok := sessionToken(r); tok != "" {
		return tok
	}
	if c, err := r.Cookie(guestCookie); err == nil && c.Value != "" {
		return c.Value
	}
	id := randomHex(12)
	http.SetCookie(w, &http.Cookie{
		Name: guestCookie, Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int((30 * 24 * time.Hour).Seconds()),
	})
	return id
}

// mergeGuestCart folds an anonymous cart into the just-created session cart
// on login/register, so items added before signing in survive the login.
func (s *demoServer) mergeGuestCart(r *http.Request, token string) {
	if gc, err := r.Cookie(guestCookie); err == nil && gc.Value != "" && gc.Value != token {
		s.store.MergeCarts(gc.Value, token)
	}
}

func setSessionCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: "ss_session", Value: token, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
		MaxAge: int((24 * time.Hour).Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: "ss_session", Value: "", Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// sameOrigin is a cheap CSRF defense-in-depth: browsers always attach an
// Origin header to cross-origin POSTs (even simple form posts), while
// non-browser clients (curl, stress-strike) send none. Requests from another
// origin are rejected, which closes the classic text/plain form CSRF on
// /admin/protect.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" || o == "null" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// render executes a page template with the base view as data.
func (s *demoServer) render(w http.ResponseWriter, name string, v view, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.pages.ExecuteTemplate(w, name, v); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

//------------------------------------------------------------------------------
// Pages
//------------------------------------------------------------------------------

func (s *demoServer) handleHome(w http.ResponseWriter, r *http.Request) {
	v := s.baseView(w, r)
	v.Title = "VoltStore — Premium Tech Store"
	v.Products = s.store.FeaturedProducts()
	s.render(w, "home.html", v, http.StatusOK)
}

func (s *demoServer) handleProducts(w http.ResponseWriter, r *http.Request) {
	v := s.baseView(w, r)
	v.Title = "Catalog — VoltStore"
	q := r.URL.Query()
	v.Category = q.Get("category")
	v.Query = q.Get("q")
	v.SortBy = q.Get("sort")
	if v.SortBy == "" {
		v.SortBy = "default"
	}
	v.Products = s.store.SearchProducts(v.Category, v.Query, v.SortBy)
	s.render(w, "products.html", v, http.StatusOK)
}

func (s *demoServer) handleProduct(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p := s.store.ProductByID(id)
	if p == nil {
		http.NotFound(w, r)
		return
	}
	v := s.baseView(w, r)
	v.Title = p.Name + " — VoltStore"
	v.Product = p
	s.render(w, "product.html", v, http.StatusOK)
}

func (s *demoServer) handleCart(w http.ResponseWriter, r *http.Request) {
	v := s.baseView(w, r)
	v.Title = "Your Cart — VoltStore"
	v.Cart = s.store.Cart(s.cartKey(w, r))
	s.render(w, "cart.html", v, http.StatusOK)
}

func (s *demoServer) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	v := s.baseView(w, r)
	v.Title = "Sign in — VoltStore"
	s.render(w, "login.html", v, http.StatusOK)
}

func (s *demoServer) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	v := s.baseView(w, r)
	v.Title = "Create account — VoltStore"
	s.render(w, "register.html", v, http.StatusOK)
}

func (s *demoServer) handleCheckoutPage(w http.ResponseWriter, r *http.Request) {
	if s.store.UserBySession(sessionToken(r)) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	v := s.baseView(w, r)
	v.Title = "Checkout — VoltStore"
	v.Cart = s.store.Cart(s.cartKey(w, r))
	if v.Cart.Count == 0 {
		http.Redirect(w, r, "/cart", http.StatusSeeOther)
		return
	}
	s.render(w, "checkout.html", v, http.StatusOK)
}

func (s *demoServer) handleAccount(w http.ResponseWriter, r *http.Request) {
	u := s.store.UserBySession(sessionToken(r))
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	v := s.baseView(w, r)
	v.Title = "My account — VoltStore"
	v.Orders = s.store.OrdersByUser(u.ID)
	s.render(w, "account.html", v, http.StatusOK)
}

func (s *demoServer) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	v := s.baseView(w, r)
	v.Title = "VeriGate Control — VoltStore Admin"
	s.render(w, "admin.html", v, http.StatusOK)
}

func (s *demoServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok","time":"`+time.Now().UTC().Format(time.RFC3339)+`"}`+"\n")
}

//------------------------------------------------------------------------------
// API helpers
//------------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

//------------------------------------------------------------------------------
// Auth API
//------------------------------------------------------------------------------

type authRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *demoServer) apiLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		apiError(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	var req authRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	token, user, err := s.store.Authenticate(req.Email, req.Password)
	if err != nil {
		apiError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	s.mergeGuestCart(r, token)
	setSessionCookie(w, token, r.TLS != nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user})
}

func (s *demoServer) apiRegister(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		apiError(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	var req authRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || req.Email == "" || len(req.Password) < 6 {
		apiError(w, http.StatusBadRequest, "name, email and password (6+ chars) required")
		return
	}
	u, err := s.store.Register(req.Name, req.Email, req.Password)
	if err != nil {
		apiError(w, http.StatusConflict, err.Error())
		return
	}
	token, _, err := s.store.Authenticate(req.Email, req.Password)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "session error")
		return
	}
	s.mergeGuestCart(r, token)
	setSessionCookie(w, token, r.TLS != nil)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "user": u})
}

func (s *demoServer) apiLogout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		apiError(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	s.store.DestroySession(sessionToken(r))
	clearSessionCookie(w, r.TLS != nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

//------------------------------------------------------------------------------
// Cart API
//------------------------------------------------------------------------------

func (s *demoServer) apiCart(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Cart(s.cartKey(w, r)))
}

type cartItemRequest struct {
	ProductID int `json:"product_id"`
	Quantity  int `json:"quantity"`
}

func (s *demoServer) apiCartAdd(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		apiError(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	var req cartItemRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Quantity == 0 {
		req.Quantity = 1
	}
	if req.Quantity < 0 {
		apiError(w, http.StatusBadRequest, "quantity must be positive")
		return
	}
	count, err := s.store.AddToCart(s.cartKey(w, r), req.ProductID, req.Quantity)
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": count})
}

func (s *demoServer) apiCartRemove(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		apiError(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid product id")
		return
	}
	if err := s.store.RemoveFromCart(s.cartKey(w, r), id); err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": s.store.CartCount(s.cartKey(w, r))})
}

//------------------------------------------------------------------------------
// Checkout + account API
//------------------------------------------------------------------------------

type checkoutRequest struct {
	FullName string `json:"full_name"`
	Address  string `json:"address"`
	CardLast string `json:"card_last4"`
}

func (s *demoServer) apiCheckout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		apiError(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	u := s.store.UserBySession(sessionToken(r))
	if u == nil {
		apiError(w, http.StatusUnauthorized, "login required to checkout")
		return
	}
	var req checkoutRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.FullName == "" || req.Address == "" || len(req.CardLast) < 4 {
		apiError(w, http.StatusBadRequest, "full_name, address and card_last4 required")
		return
	}
	order, err := s.store.Checkout(sessionToken(r), u.ID)
	if err != nil {
		apiError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok": true, "order_id": order.ID, "total_cents": order.TotalCents,
	})
}

func (s *demoServer) apiAccount(w http.ResponseWriter, r *http.Request) {
	u := s.store.UserBySession(sessionToken(r))
	if u == nil {
		apiError(w, http.StatusUnauthorized, "login required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":   u,
		"orders": s.store.OrdersByUser(u.ID),
	})
}

//------------------------------------------------------------------------------
// Catalog API
//------------------------------------------------------------------------------

func (s *demoServer) apiProducts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	writeJSON(w, http.StatusOK, map[string]any{
		"products": s.store.SearchProducts(q.Get("category"), q.Get("q"), q.Get("sort")),
	})
}

//------------------------------------------------------------------------------
// VeriGate admin (control plane — exempt from protection)
//------------------------------------------------------------------------------

func (s *demoServer) adminProtectGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"enabled": s.gate.Enabled()})
}

func (s *demoServer) adminProtectSet(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		apiError(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s.gate.SetEnabled(req.Enabled)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": s.gate.Enabled()})
	log.Printf("verigate: protection %s", map[bool]string{true: "ENABLED", false: "DISABLED"}[s.gate.Enabled()])
}

func (s *demoServer) adminReset(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		apiError(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	s.gate.Reset()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *demoServer) adminStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.gate.Stats())
}

// formatPrice renders cents as "$1,234.56".
func formatPrice(cents int) string {
	whole := cents / 100
	frac := cents % 100
	withCommas := strconv.Itoa(whole)
	// Insert thousands separators.
	var sb strings.Builder
	for i, c := range withCommas {
		if i > 0 && (len(withCommas)-i)%3 == 0 {
			sb.WriteByte(',')
		}
		sb.WriteRune(c)
	}
	return fmt.Sprintf("$%s.%02d", sb.String(), frac)
}
