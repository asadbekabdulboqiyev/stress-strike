package dashboard

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

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
	}
}

func (s *Server) SetCommandHandler(handler func(cmd string, args map[string]interface{})) {
	s.onCommand = handler
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
