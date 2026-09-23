// Package main — VoltStore: a realistic e-commerce demo target built to
// real-world standards (product catalog, auth, cart, checkout, orders) so it
// can be load-tested with stress-strike and protected with VeriGate.
//
// Everything runs in-memory: no database, no external dependencies — a single
// binary that behaves like a production shop on loopback.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

//------------------------------------------------------------------------------
// Domain model
//------------------------------------------------------------------------------

// Product is a catalog item. PriceCents avoids float money math.
type Product struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Category    string  `json:"category"`
	PriceCents  int     `json:"price_cents"`
	Stock       int     `json:"stock"`
	Rating      float64 `json:"rating"`
	Reviews     int     `json:"reviews"`
	Description string  `json:"description"`
	Accent      string  `json:"accent"` // hex color for the card art
	Featured    bool    `json:"featured"`
	Badge       string  `json:"badge,omitempty"` // "New", "Hot", "Sale"
}

// User is a registered customer.
type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	PassHash  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// Order is a completed checkout.
type Order struct {
	ID         string      `json:"id"`
	UserID     string      `json:"user_id"`
	Items      []OrderLine `json:"items"`
	TotalCents int         `json:"total_cents"`
	PlacedAt   time.Time   `json:"placed_at"`
}

// OrderLine is one product line inside an order.
type OrderLine struct {
	ProductID int    `json:"product_id"`
	Name      string `json:"name"`
	Qty       int    `json:"qty"`
	UnitCents int    `json:"unit_cents"`
}

// Session is a logged-in browser session.
type Session struct {
	Token   string
	UserID  string
	Expires time.Time
}

// CartView is what the UI renders.
type CartView struct {
	Lines      []CartLineView
	TotalCents int
	Count      int
}

// CartLineView is one cart row for the UI.
type CartLineView struct {
	Product   Product
	Qty       int
	LineCents int
}

//------------------------------------------------------------------------------
// Store
//------------------------------------------------------------------------------

// Store is the in-memory "database": products, users, sessions, carts, orders.
// Thread-safe; fine for a demo target.
type Store struct {
	mu       sync.RWMutex
	products []Product
	users    map[string]*User       // id -> user
	byEmail  map[string]*User       // email -> user
	sessions map[string]*Session    // token -> session
	carts    map[string]map[int]int // session_token -> productID -> qty
	orders   []Order
	nextID   int
}

// NewStore seeds the catalog and demo accounts.
func NewStore() *Store {
	s := &Store{
		users:    make(map[string]*User),
		byEmail:  make(map[string]*User),
		sessions: make(map[string]*Session),
		carts:    make(map[string]map[int]int),
	}
	s.products = seedProducts()
	s.nextID = 1000
	s.seedOrders()
	// Demo accounts (argon2id hashed — production-grade credentials even in
	// the demo).
	s.createUser("Alice Demo", "alice@volt.store", "demo1234")
	s.createUser("Bob Demo", "bob@volt.store", "demo1234")
	return s
}

//------------------------------------------------------------------------------
// Products
//------------------------------------------------------------------------------

// Products returns the full catalog.
func (s *Store) Products() []Product {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Product, len(s.products))
	copy(out, s.products)
	return out
}

// ProductByID returns a product or nil.
func (s *Store) ProductByID(id int) *Product {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.products {
		if s.products[i].ID == id {
			p := s.products[i]
			return &p
		}
	}
	return nil
}

// SearchProducts filters by category / free-text and sorts.
func (s *Store) SearchProducts(category, q, sortBy string) []Product {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Product, 0, len(s.products))
	for _, p := range s.products {
		if category != "" && p.Category != category {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(p.Name), strings.ToLower(q)) {
			continue
		}
		out = append(out, p)
	}
	switch sortBy {
	case "price-asc":
		sort.Slice(out, func(i, j int) bool { return out[i].PriceCents < out[j].PriceCents })
	case "price-desc":
		sort.Slice(out, func(i, j int) bool { return out[i].PriceCents > out[j].PriceCents })
	case "rating":
		sort.Slice(out, func(i, j int) bool {
			if out[i].Rating == out[j].Rating {
				return out[i].Reviews > out[j].Reviews
			}
			return out[i].Rating > out[j].Rating
		})
	default:
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	}
	return out
}

// FeaturedProducts returns the homepage highlights.
func (s *Store) FeaturedProducts() []Product {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Product
	for _, p := range s.products {
		if p.Featured {
			out = append(out, p)
		}
	}
	return out
}

// Categories returns the distinct categories in display order.
func (s *Store) Categories() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for _, p := range s.products {
		if !seen[p.Category] {
			seen[p.Category] = true
			out = append(out, p.Category)
		}
	}
	return out
}

//------------------------------------------------------------------------------
// Users & sessions
//------------------------------------------------------------------------------

// argon2id parameters (OWASP-recommended for interactive logins). The demo
// stays fast because stores are in-memory; real deployments would persist
// these encoded hashes in a database.
const (
	argonMemory      = 64 * 1024 // 64 MiB
	argonIterations  = 3
	argonParallelism = 2
	argonSaltLen     = 16
	argonKeyLen      = 32
)

// hashPassword derives an argon2id hash with a fresh per-user salt, encoded
// as $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash> (PHC string format).
func hashPassword(pw string) string {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(err) // crypto/rand.Read never fails on supported platforms
	}
	key := argon2.IDKey([]byte(pw), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// verifyPassword checks pw against a PHC-encoded argon2id hash in constant
// time (per-hash comparison uses subtle.ConstantTimeCompare).
func verifyPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var memory, iterations, parallelism uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, iterations, memory, uint8(parallelism), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// createUser registers a user (used to seed demo accounts). The argon2id hash
// is computed before taking the lock: hashing takes ~100ms + 64 MiB, and
// doing it under the store-wide lock would serialize every request.
func (s *Store) createUser(name, email, pw string) *User {
	hash := hashPassword(pw)
	s.mu.Lock()
	defer s.mu.Unlock()
	u := &User{
		ID:        fmt.Sprintf("u_%d", s.nextID),
		Name:      name,
		Email:     email,
		PassHash:  hash,
		CreatedAt: time.Now(),
	}
	s.nextID++
	s.users[u.ID] = u
	s.byEmail[email] = u
	return u
}

// Register creates a new account. Returns error if the email is taken.
func (s *Store) Register(name, email, pw string) (*User, error) {
	// Hash first (expensive) — only touch the lock for the map operations.
	hash := hashPassword(pw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byEmail[strings.ToLower(email)]; ok {
		return nil, fmt.Errorf("email already registered")
	}
	u := &User{
		ID:        fmt.Sprintf("u_%d", s.nextID),
		Name:      name,
		Email:     email,
		PassHash:  hash,
		CreatedAt: time.Now(),
	}
	s.nextID++
	s.users[u.ID] = u
	s.byEmail[strings.ToLower(email)] = u
	return u, nil
}

// Authenticate checks credentials and, on success, starts a session. The
// argon2id verification runs outside the lock so parallel logins never
// serialize the whole store.
func (s *Store) Authenticate(email, pw string) (string, *User, error) {
	s.mu.RLock()
	u, ok := s.byEmail[strings.ToLower(email)]
	s.mu.RUnlock()
	if !ok || !verifyPassword(u.PassHash, pw) {
		return "", nil, fmt.Errorf("invalid credentials")
	}
	token := randomHex(24)
	s.mu.Lock()
	s.sessions[token] = &Session{Token: token, UserID: u.ID, Expires: time.Now().Add(24 * time.Hour)}
	s.mu.Unlock()
	return token, u, nil
}

// UserBySession resolves a session token to a user.
func (s *Store) UserBySession(token string) *User {
	if token == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[token]
	if !ok || time.Now().After(sess.Expires) {
		return nil
	}
	return s.users[sess.UserID]
}

// DestroySession logs out.
func (s *Store) DestroySession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// OrdersByUser returns a user's orders, newest first.
func (s *Store) OrdersByUser(userID string) []Order {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Order
	for _, o := range s.orders {
		if o.UserID == userID {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PlacedAt.After(out[j].PlacedAt) })
	return out
}

//------------------------------------------------------------------------------
// Cart
//------------------------------------------------------------------------------

// Cart returns the session's cart (nil-safe).
func (s *Store) Cart(token string) CartView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := s.carts[token]
	cv := CartView{}
	for pid, qty := range items {
		p := s.productByIDLocked(pid)
		if p == nil {
			continue
		}
		cv.Lines = append(cv.Lines, CartLineView{
			Product:   *p,
			Qty:       qty,
			LineCents: p.PriceCents * qty,
		})
		cv.Count += qty
		cv.TotalCents += p.PriceCents * qty
	}
	sort.Slice(cv.Lines, func(i, j int) bool { return cv.Lines[i].Product.ID < cv.Lines[j].Product.ID })
	return cv
}

// AddToCart adds a product to the session cart; returns new total count.
func (s *Store) AddToCart(token string, productID, qty int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if qty <= 0 {
		return 0, fmt.Errorf("quantity must be positive")
	}
	p := s.productByIDLocked(productID)
	if p == nil {
		return 0, fmt.Errorf("product not found")
	}
	if s.carts[token] == nil {
		s.carts[token] = make(map[int]int)
	}
	s.carts[token][productID] += qty
	count := 0
	for _, n := range s.carts[token] {
		count += n
	}
	return count, nil
}

// RemoveFromCart removes a line from the cart.
func (s *Store) RemoveFromCart(token string, productID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.carts[token][productID]; !ok {
		return fmt.Errorf("product not in cart")
	}
	delete(s.carts[token], productID)
	return nil
}

// Checkout converts the cart into an order and clears the cart.
func (s *Store) Checkout(token, userID string) (*Order, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := s.carts[token]
	if len(items) == 0 {
		return nil, fmt.Errorf("cart is empty")
	}
	// Validate the whole cart before mutating anything: a later line that
	// cannot be fulfilled must not leave earlier lines half-committed.
	lines := make([]OrderLine, 0, len(items))
	total := 0
	for pid, qty := range items {
		p := s.productByIDLocked(pid)
		if p == nil {
			return nil, fmt.Errorf("product %d is no longer available", pid)
		}
		if p.Stock < qty {
			return nil, fmt.Errorf("insufficient stock for %s (only %d left)", p.Name, p.Stock)
		}
		lines = append(lines, OrderLine{ProductID: p.ID, Name: p.Name, Qty: qty, UnitCents: p.PriceCents})
		total += p.PriceCents * qty
	}
	// Commit: decrement stock, record the order, clear the cart.
	for pid, qty := range items {
		if p := s.productByIDLocked(pid); p != nil {
			p.Stock -= qty
		}
	}
	o := &Order{
		ID:         fmt.Sprintf("ord_%s", randomHex(8)),
		UserID:     userID,
		Items:      lines,
		TotalCents: total,
		PlacedAt:   time.Now(),
	}
	s.orders = append(s.orders, *o)
	delete(s.carts, token)
	return o, nil
}

// CartCount returns the number of items in the session cart.
func (s *Store) CartCount(token string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, n := range s.carts[token] {
		count += n
	}
	return count
}

// MergeCarts folds one cart into another (used when a guest logs in so
// pre-login items survive). Quantities add; the destination wins on keys.
func (s *Store) MergeCarts(from, to string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if from == to || from == "" || to == "" || s.carts[from] == nil {
		return
	}
	if s.carts[to] == nil {
		s.carts[to] = make(map[int]int)
	}
	for pid, qty := range s.carts[from] {
		s.carts[to][pid] += qty
	}
	delete(s.carts, from)
}

func (s *Store) productByIDLocked(id int) *Product {
	for i := range s.products {
		if s.products[i].ID == id {
			return &s.products[i]
		}
	}
	return nil
}

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand.Read never fails on supported platforms
	}
	return hex.EncodeToString(b)
}

func (s *Store) seedOrders() {
	// Empty: orders appear after real checkouts. Kept as a hook.
}
