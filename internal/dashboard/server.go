package dashboard

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/demostore"
	"github.com/gorilla/websocket"
)

//go:embed index.html
var dashboardHTML []byte

//go:embed style.css
var dashboardCSS []byte

//go:embed app.js
var dashboardJS []byte

// --- Limits -----------------------------------------------------------------
//
// Defense-in-depth caps for the local dashboard control plane. The dashboard
// can start/stop real load runs, so the HTTP + WebSocket surface is hardened:
// bounded request bodies, bounded WebSocket frames, a connection cap, and
// read deadlines so a stalled peer cannot pin a goroutine forever.

const (
	// maxAPIRequestBody caps POST bodies (run config JSON) at 1 MiB.
	maxAPIRequestBody = 1 << 20

	// maxWSConnections caps simultaneous WebSocket peers (browser tabs).
	maxWSConnections = 32

	// wsReadLimit caps a single WebSocket control message at 4 KiB.
	wsReadLimit = 4096

	// wsIdleTimeout is the read deadline per message. It is refreshed on
	// every received message and kept alive by the ping/pong watchdog, so
	// idle dashboards stay connected while slow/stalled peers are dropped.
	wsIdleTimeout = 90 * time.Second

	// wsPingInterval keeps quiet connections alive (browsers answer pings
	// with pongs at the WebSocket protocol level).
	wsPingInterval = 30 * time.Second
)

// --- Types ------------------------------------------------------------------

type LiveSnapshot struct {
	Timestamp   time.Time      `json:"timestamp"`
	RPS         float64        `json:"rps"`
	TotalReq    uint64         `json:"total_requests"`
	TotalErrors uint64         `json:"total_errors"`
	ErrorRate   float64        `json:"error_rate"`
	P50Latency  float64        `json:"p50_latency_ms"`
	P95Latency  float64        `json:"p95_latency_ms"`
	P99Latency  float64        `json:"p99_latency_ms"`
	AvgLatency  float64        `json:"avg_latency_ms"`
	MaxLatency  float64        `json:"max_latency_ms"`
	ActiveUsers int            `json:"active_users"`
	StatusCodes map[int]uint64 `json:"status_codes"`
	Workers     []WorkerStatus `json:"workers,omitempty"`
}

type WorkerStatus struct {
	ID      string  `json:"id"`
	Address string  `json:"address"`
	Status  string  `json:"status"`
	RPS     float64 `json:"rps"`
	Latency float64 `json:"latency_ms"`
	Errors  uint64  `json:"errors"`
}

type RunConfig struct {
	TargetURL       string            `json:"target_url"`
	Users           int               `json:"users"`
	DurationSeconds int               `json:"duration_seconds"`
	RateLimit       int               `json:"rate_limit"`
	Method          string            `json:"method"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	Profile         string            `json:"profile,omitempty"`
	TLSFingerprint  string            `json:"tls_fingerprint,omitempty"`
}

type RunState struct {
	Status    string        `json:"status"`
	Config    *RunConfig    `json:"config,omitempty"`
	StartTime time.Time     `json:"start_time,omitempty"`
	EndTime   time.Time     `json:"end_time,omitempty"`
	Elapsed   time.Duration `json:"elapsed"`
	Duration  time.Duration `json:"duration"`
	Progress  float64       `json:"progress"`
	Error     string        `json:"error,omitempty"`
}

type HistoryEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Config    RunConfig `json:"config"`
	Result    RunResult `json:"result"`
	Duration  string    `json:"duration"`
}

type RunResult struct {
	TotalRequests uint64         `json:"total_requests"`
	TotalErrors   uint64         `json:"total_errors"`
	RPS           float64        `json:"rps"`
	P50Latency    float64        `json:"p50_latency"`
	P95Latency    float64        `json:"p95_latency"`
	P99Latency    float64        `json:"p99_latency"`
	AvgLatency    float64        `json:"avg_latency"`
	MaxLatency    float64        `json:"max_latency"`
	StatusCodes   map[int]uint64 `json:"status_codes"`
}

// AttestationInfo holds the latest attestation state produced by a completed run.
type AttestationInfo struct {
	Exists      bool   `json:"exists"`
	RunID       string `json:"runID,omitempty"`
	PubKeyHex   string `json:"pubKeyHex,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`

	// COCorrected reports whether the bundle's percentiles carry the
	// coordinated-omission correction. Dashboard runs never set
	// profile.coordinated_omission, so this is false and the UI must say the
	// percentiles are raw — claiming the correction would be the exact
	// dishonesty this tool exists to expose.
	COCorrected bool `json:"coCorrected"`

	// BundlePath and SamplesPath are absolute, server-local filesystem paths.
	// They are deliberately NOT serialised. The browser fetches the artifacts
	// through /api/attestation/download?type=..., so it never needs to learn
	// where they live on disk — and because the dashboard can be bound beyond
	// loopback, a remote client must not be handed the host's directory layout.
	BundlePath  string `json:"-"`
	SamplesPath string `json:"-"`
}

// AttestationVerifyRequest is the body of POST /api/attestation/verify. It is
// deliberately empty: the endpoint verifies the attestation the dashboard
// itself produced for the latest run.
//
// It must never grow a caller-supplied path field. verify loads and parses a
// file from disk, so honouring a caller-supplied path would turn the local
// control plane into an arbitrary-file-read oracle. Decoding uses
// DisallowUnknownFields, so a body that names a path is rejected (400) rather
// than silently ignored.
type AttestationVerifyRequest struct{}

// --- Dashboard Server -------------------------------------------------------

type Server struct {
	upgrader  websocket.Upgrader
	clients   map[*websocket.Conn]bool
	wsSem     chan struct{} // caps simultaneous WebSocket connections
	mu        sync.RWMutex
	snapshot  *LiveSnapshot
	runState  *RunState
	history   []HistoryEntry
	onCommand func(cmd string, args map[string]interface{})
	store     *demostore.DemoStore // bundled VoltStore demo launcher/supervisor

	// Optional operations endpoints and auth, injected by the host binary.
	// They are plain http.Handler / middleware values so this package does not
	// depend on the metrics, health or auth packages (no import cycle) and the
	// CLI can wire exactly what it needs.
	metricsHandler   http.Handler
	livenessHandler  http.Handler
	readinessHandler http.Handler
	authMiddleware   func(http.Handler) http.Handler

	attestMu   sync.RWMutex
	attestInfo AttestationInfo
}

func NewServer() *Server {
	return &Server{
		upgrader: websocket.Upgrader{
			// Only same-origin (or non-browser) clients may upgrade. See
			// sameOrigin below.
			CheckOrigin:     sameOrigin,
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		clients:  make(map[*websocket.Conn]bool),
		wsSem:    make(chan struct{}, maxWSConnections),
		snapshot: &LiveSnapshot{StatusCodes: make(map[int]uint64)},
		runState: &RunState{Status: "idle"},
		history:  make([]HistoryEntry, 0),
		// The dashboard always launches the store with VeriGate protection
		// ON: the whole point is to demo the WAF. Visitors can still flip it
		// OFF from the store's own /admin control plane.
		store: demostore.New(demostore.Options{ExtraArgs: []string{"-protect"}}),
	}
}

func (s *Server) SetCommandHandler(handler func(cmd string, args map[string]interface{})) {
	s.onCommand = handler
}

// SetMetricsHandler wires the Prometheus exposition endpoint (/metrics).
func (s *Server) SetMetricsHandler(h http.Handler) { s.metricsHandler = h }

// SetHealthHandlers wires the liveness (/healthz) and readiness (/readyz)
// endpoints. Either handler may be nil; the built-in default reports "ok".
func (s *Server) SetHealthHandlers(live, ready http.Handler) {
	s.livenessHandler = live
	s.readinessHandler = ready
}

// SetAuthMiddleware installs a middleware wrapped around every UI/API/WebSocket
// route. The operations endpoints (/healthz, /readyz, /metrics) are always
// exempt so orchestrators can probe a locked-down dashboard. A nil middleware
// leaves the server open, which is only appropriate on a loopback bind.
func (s *Server) SetAuthMiddleware(mw func(http.Handler) http.Handler) {
	s.authMiddleware = mw
}

func (s *Server) GetAttestationInfo() AttestationInfo {
	s.attestMu.RLock()
	defer s.attestMu.RUnlock()
	return s.attestInfo
}

func (s *Server) SetAttestationInfo(info AttestationInfo) {
	s.attestMu.Lock()
	defer s.attestMu.Unlock()
	s.attestInfo = info
}

// AuthOptions configures the dashboard control-plane gate from CLI flags or
// environment configuration.
type AuthOptions struct {
	// Tokens are accepted verbatim as `Authorization: Bearer <token>`.
	Tokens []string
	// APIKeyHashes are lowercase hex SHA-256 digests of accepted API keys.
	APIKeyHashes []string
	// AllowedOrigins is the CSRF allowlist for state-changing methods.
	AllowedOrigins []string
	// RateLimitRPS refills each client IP's token bucket; 0 disables.
	RateLimitRPS float64
	// RateLimitBurst is the limiter capacity; defaults to 1.
	RateLimitBurst int
	// TrustProxy makes the limiter honor X-Forwarded-For / X-Real-IP.
	TrustProxy bool
	// AllowAnonymous explicitly acknowledges that the control API is reachable
	// without credentials when bound to a non-loopback address. It is an
	// opt-in escape hatch (CLI: -insecure / --dashboard-insecure) for demos
	// whose host port is published on loopback only; it never enables anything
	// by accident and is ignored when credentials are enrolled.
	AllowAnonymous bool
}

// HasCredentials reports whether at least one credential is enrolled. Only
// bearer tokens and API keys authenticate callers; an origin allowlist alone
// still rejects every caller (secure by default).
func (o AuthOptions) HasCredentials() bool {
	return len(o.Tokens) > 0 || len(o.APIKeyHashes) > 0
}

// ApplyAuth builds the authentication middleware from opt, installs it on the
// server and returns the backing *Auth so the caller can Close it (releasing
// the rate-limit janitor). The operations endpoints stay open for probes and
// scrapes. When no credential is enrolled it installs nothing and returns nil —
// callers must decide whether an open dashboard is acceptable for their bind
// address (loopback, or an explicit -insecure acknowledgement).
func (s *Server) ApplyAuth(opt AuthOptions) *Auth {
	if !opt.HasCredentials() {
		return nil
	}
	a := NewAuth(AuthConfig{
		BearerTokens:   opt.Tokens,
		APIKeyHashes:   opt.APIKeyHashes,
		AllowedOrigins: opt.AllowedOrigins,
		RateLimitRPS:   opt.RateLimitRPS,
		RateLimitBurst: opt.RateLimitBurst,
		TrustProxy:     opt.TrustProxy,
	})
	s.SetAuthMiddleware(a.Middleware)
	return a
}

func (s *Server) UpdateSnapshot(snap *LiveSnapshot) {
	s.mu.Lock()
	s.snapshot = snap
	s.mu.Unlock()
	s.broadcast()
}

func (s *Server) SetRunState(state *RunState) {
	s.mu.Lock()
	s.runState = state
	s.mu.Unlock()
	s.broadcastRunState()
}

func (s *Server) AddHistoryEntry(entry HistoryEntry) {
	s.mu.Lock()
	s.history = append(s.history, entry)
	s.mu.Unlock()
}

// --- HTTP Handlers ----------------------------------------------------------

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w, r)

	// Operations endpoints are never behind auth: a locked-down dashboard must
	// still be probeable and scrapeable by the platform.
	switch r.URL.Path {
	case "/healthz":
		s.serveOps(w, r, s.livenessHandler, true)
		return
	case "/readyz":
		s.serveOps(w, r, s.readinessHandler, true)
		return
	case "/metrics":
		s.serveOps(w, r, s.metricsHandler, false)
		return
	}

	if s.authMiddleware != nil {
		s.authMiddleware(http.HandlerFunc(s.serveApp)).ServeHTTP(w, r)
		return
	}
	s.serveApp(w, r)
}

// serveOps dispatches an operations request to its handler. When no handler
// was injected, health endpoints answer a minimal 200 and /metrics answers 404,
// so the server is still useful without the optional packages wired in.
func (s *Server) serveOps(w http.ResponseWriter, r *http.Request, h http.Handler, defaultOK bool) {
	if h != nil {
		h.ServeHTTP(w, r)
		return
	}
	if defaultOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}
	http.NotFound(w, r)
}

// serveApp routes the UI, JSON API and WebSocket traffic.
func (s *Server) serveApp(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/ws":
		s.handleWebSocket(w, r)
	case path == "/api/snapshot":
		s.handleSnapshot(w, r)
	case path == "/api/run":
		s.handleRunAPI(w, r)
	case path == "/api/history":
		s.handleHistory(w, r)
	case path == "/api/run/start":
		s.handleStartRun(w, r)
	case path == "/api/run/stop":
		s.handleStopRun(w, r)
	case path == "/api/attestation":
		s.handleAttestationGet(w, r)
	case path == "/api/attestation/download":
		s.handleAttestationDownload(w, r)
	case path == "/api/attestation/verify":
		s.handleAttestationVerify(w, r)
	case path == "/api/demo-store/start":
		s.handleDemoStoreStart(w, r)
	case path == "/api/demo-store/stop":
		s.handleDemoStoreStop(w, r)
	case path == "/api/demo-store/status":
		s.handleDemoStoreStatus(w, r)
	case path == "/style.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write(dashboardCSS)
	case path == "/app.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write(dashboardJS)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Cap concurrent sockets so a flood of tabs cannot exhaust descriptors,
	// memory or goroutines on the host running the dashboard.
	select {
	case s.wsSem <- struct{}{}:
	default:
		http.Error(w, "too many websocket connections", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-s.wsSem }()

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	s.mu.Lock()
	s.clients[conn] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	// Bound the frame size so a malicious peer cannot stream an unbounded
	// message into memory.
	conn.SetReadLimit(wsReadLimit)

	// Ping watchdog: WriteControl is safe to call concurrently with the
	// read loop and the broadcast writer. Browser pongs keep the read
	// deadline rolling for idle-but-alive dashboards.
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(wsPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					return
				}
			}
		}
	}()

	// Send initial state
	s.mu.RLock()
	initMsg, _ := json.Marshal(map[string]interface{}{
		"type":    "init",
		"state":   s.runState,
		"history": s.history,
	})
	s.mu.RUnlock()
	conn.WriteMessage(websocket.TextMessage, initMsg)

	// Listen for commands
	for {
		// A stalled peer (partial frame, no pongs) is dropped after the
		// idle timeout; a live peer refreshes the deadline on every read.
		conn.SetReadDeadline(time.Now().Add(wsIdleTimeout))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var cmd struct {
			Type string                 `json:"type"`
			Args map[string]interface{} `json:"args,omitempty"`
		}
		if err := json.Unmarshal(msg, &cmd); err != nil {
			continue
		}
		if s.onCommand != nil {
			s.onCommand(cmd.Type, cmd.Args)
		}
	}
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.snapshot)
}

func (s *Server) handleRunAPI(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.runState)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.history)
}

func (s *Server) handleStartRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	// Simple-request CSRF defense: a browser cross-origin POST carries an
	// Origin header that will not match r.Host; non-browser clients (curl,
	// CLI tooling) send no Origin and stay allowed.
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIRequestBody)
	var config RunConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Server-side validation (not just frontend): an empty/invalid target
	// must never silently start a run against a default URL.
	if strings.TrimSpace(config.TargetURL) == "" {
		http.Error(w, "target_url is required", http.StatusBadRequest)
		return
	}
	if u, err := url.Parse(config.TargetURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "target_url must be an http(s) URL", http.StatusBadRequest)
		return
	}
	if s.onCommand != nil {
		// The bridge decodes the config as a JSON object (map), not as a typed
		// struct. Round-trip through JSON so browser overrides (target url,
		// users, duration, method) survive the hand-off to the engine bridge.
		raw, _ := json.Marshal(config)
		asMap := map[string]interface{}{}
		_ = json.Unmarshal(raw, &asMap)
		s.onCommand("start", map[string]interface{}{"config": asMap})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) handleStopRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	// Same CSRF defense as start: cross-origin browser POSTs are rejected.
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIRequestBody)
	if s.onCommand != nil {
		s.onCommand("stop", nil)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

// --- Demo store control plane ------------------------------------------------

// handleDemoStoreStatus reports whether the bundled VoltStore demo is up
// (and whether this dashboard spawned it).
func (s *Server) handleDemoStoreStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.store.Status())
}

// handleDemoStoreStart launches the VoltStore demo (VeriGate protection ON)
// if nothing is listening yet, then reports the URL. Non-browser clients
// (curl) and same-origin browser POSTs are allowed; cross-origin POSTs are
// rejected like every other mutating endpoint.
func (s *Server) handleDemoStoreStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	url, alreadyRunning, err := s.store.Start()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":              true,
		"url":             url,
		"already_running": alreadyRunning,
		"protection":      true,
	})
}

// handleDemoStoreStop shuts down the demo store only when this dashboard
// spawned it (a user-managed store is left running).
func (s *Server) handleDemoStoreStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	if err := s.store.Stop(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// --- Security helpers -------------------------------------------------------

// sameOrigin reports whether the request's Origin header (when present)
// matches the host the request was sent to.
//
//   - No Origin header (curl, CLI clients, non-browser consumers): allowed.
//   - Origin present and its host equals r.Host: allowed — this covers the
//     localhost dev case because a browser connecting to
//     http://127.0.0.1:8888 sends Origin "http://127.0.0.1:8888", which
//     matches the Host header of the request it makes.
//   - Origin present with a different host, or a non-http(s) scheme (as a
//     cross-site WebSocket or fetch would carry): rejected.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser client
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// securityHeaders applies defense-in-depth response headers on every
// dashboard response. connect-src explicitly re-allows the same-origin
// WebSocket endpoint (ws/wss on r.Host) because 'self' matching for
// WebSockets is inconsistent across browsers.
func securityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy",
		fmt.Sprintf("default-src 'self'; connect-src 'self' ws://%s wss://%s", r.Host, r.Host))
}

// IsLoopbackAddr reports whether a listen address binds only to the
// loopback interface. ":port" or "0.0.0.0:port" bind every interface and
// report false; 127.0.0.1, ::1 and "localhost" report true. Used to warn
// when the dashboard control plane is exposed to the network.
func IsLoopbackAddr(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if host == "" {
		return false // ":port" wildcard — all interfaces
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(strings.Trim(host, "[]"), "localhost")
}

// --- Broadcast --------------------------------------------------------------

func (s *Server) broadcast() {
	s.mu.RLock()
	snap := s.snapshot
	clients := make([]*websocket.Conn, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.RUnlock()

	msg, err := json.Marshal(map[string]interface{}{
		"type": "snapshot",
		"data": snap,
	})
	if err != nil {
		return
	}

	var dead []*websocket.Conn
	for _, c := range clients {
		if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
			dead = append(dead, c)
		}
	}

	if len(dead) > 0 {
		s.mu.Lock()
		for _, c := range dead {
			c.Close()
			delete(s.clients, c)
		}
		s.mu.Unlock()
	}
}

func (s *Server) broadcastRunState() {
	s.mu.RLock()
	state := s.runState
	clients := make([]*websocket.Conn, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.RUnlock()

	msg, err := json.Marshal(map[string]interface{}{
		"type": "run_state",
		"data": state,
	})
	if err != nil {
		return
	}

	var dead []*websocket.Conn
	for _, c := range clients {
		if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
			dead = append(dead, c)
		}
	}

	if len(dead) > 0 {
		s.mu.Lock()
		for _, c := range dead {
			c.Close()
			delete(s.clients, c)
		}
		s.mu.Unlock()
	}
}

func verifyAttestation(bundlePath, samplesPath string) map[string]interface{} {
	bundle, err := attest.LoadBundle(bundlePath)
	if err != nil {
		return map[string]interface{}{
			"valid":      false,
			"reason":     fmt.Sprintf("load bundle failed: %v", err),
			"bundlePath": bundlePath,
		}
	}

	var samples map[string][]attest.Record
	var loadStats attest.SampleLoadStats
	if samplesPath != "" {
		samples, loadStats, err = attest.LoadSamples(samplesPath, attest.DefaultSampleLoadOptions())
		if err != nil {
			return map[string]interface{}{
				"valid":        false,
				"reason":       fmt.Sprintf("load samples failed: %v", err),
				"bundlePath":   bundlePath,
				"samplesPath":  samplesPath,
				"samplesStats": map[string]interface{}{"lines": loadStats.Lines},
			}
		}
	}

	res := attest.VerifyWith(bundle, samples, attest.VerifyOptions{})
	out := map[string]interface{}{
		"valid":         res.Valid,
		"format":        res.Format,
		"samplesAbsent": res.SamplesAbsent,
		"bundleDigest":  res.BundleDigest,
		"workers":       len(res.Workers),
		"summary": map[string]interface{}{
			"workers":        res.Summary.Workers,
			"workersOK":      res.Summary.WorkersOK,
			"workersFailed":  res.Summary.WorkersFailed,
			"samplesTotal":   res.Summary.SamplesTotal,
			"checksRun":      res.Summary.ChecksRun,
			"checksFailed":   res.Summary.ChecksFailed,
			"proofsVerified": res.Summary.ProofsVerified,
		},
	}
	if !res.Valid {
		reasons := make([]string, 0, len(res.Checks)+len(res.Workers))
		for _, c := range res.Checks {
			if !c.OK {
				reasons = append(reasons, "bundle/"+c.Name+": "+c.Detail)
			}
		}
		for _, w := range res.Workers {
			for _, e := range w.Errors {
				reasons = append(reasons, e.Error())
			}
		}
		if len(reasons) > 0 {
			out["reason"] = strings.Join(reasons, "; ")
		} else {
			out["reason"] = "verification failed"
		}
	}
	if loadStats.Lines > 0 {
		out["samplesStats"] = map[string]interface{}{
			"lines":        loadStats.Lines,
			"records":      loadStats.Records,
			"blankLines":   loadStats.BlankLines,
			"nonCanonical": loadStats.NonCanonicalLines,
			"unsorted":     loadStats.UnsortedLines,
			"bytes":        loadStats.Bytes,
			"workers":      loadStats.Workers,
		}
	}
	return out
}

func (s *Server) handleAttestationGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	s.attestMu.RLock()
	info := s.attestInfo
	s.attestMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func (s *Server) handleAttestationDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	typ := r.URL.Query().Get("type")
	s.attestMu.RLock()
	info := s.attestInfo
	s.attestMu.RUnlock()
	if !info.Exists {
		http.NotFound(w, r)
		return
	}
	var path string
	if typ == "bundle" {
		path = info.BundlePath
	} else if typ == "samples" {
		path = info.SamplesPath
	} else {
		http.Error(w, "type must be bundle|samples", http.StatusBadRequest)
		return
	}
	if path == "" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, path)
}

func (s *Server) handleAttestationVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIRequestBody)
	// DisallowUnknownFields makes this contract fail-closed: a body that tries
	// to name a path ({"bundlePath": "..."}) is rejected with 400 instead of
	// being silently ignored. See AttestationVerifyRequest.
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req AttestationVerifyRequest
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.attestMu.RLock()
	info := s.attestInfo
	s.attestMu.RUnlock()
	if !info.Exists || info.BundlePath == "" {
		http.Error(w, "no attestation available to verify", http.StatusBadRequest)
		return
	}
	res := verifyAttestation(info.BundlePath, info.SamplesPath)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func getDashboardDataDir() (string, error) {
	if d, err := os.UserConfigDir(); err == nil && d != "" {
		dir := filepath.Join(d, "stress-strike", "dashboard")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", err
		}
		return dir, nil
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		dir := filepath.Join(h, ".stress-strike", "dashboard")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", err
		}
		return dir, nil
	}
	return "", fmt.Errorf("cannot determine user config/home dir")
}
