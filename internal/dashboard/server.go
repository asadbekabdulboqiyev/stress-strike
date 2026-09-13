package dashboard

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed index.html
var dashboardHTML []byte

// --- Types ------------------------------------------------------------------

type LiveSnapshot struct {
	Timestamp   time.Time         `json:"timestamp"`
	RPS         float64           `json:"rps"`
	TotalReq    uint64            `json:"total_requests"`
	TotalErrors uint64            `json:"total_errors"`
	ErrorRate   float64           `json:"error_rate"`
	P50Latency  float64           `json:"p50_latency_ms"`
	P95Latency  float64           `json:"p95_latency_ms"`
	P99Latency  float64           `json:"p99_latency_ms"`
	AvgLatency  float64           `json:"avg_latency_ms"`
	MaxLatency  float64           `json:"max_latency_ms"`
	ActiveUsers int               `json:"active_users"`
	PeakUsers   int64             `json:"peak_users"`
	StatusCodes map[int]uint64    `json:"status_codes"`
	Errors      map[string]uint64 `json:"errors,omitempty"`
	Steps       []StepSnapshot    `json:"steps,omitempty"`
	Workers     []WorkerStatus    `json:"workers,omitempty"`
}

type StepSnapshot struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Requests uint64  `json:"requests"`
	RPS      float64 `json:"rps"`
	P95Ms    float64 `json:"p95_ms"`
	Errors   uint64  `json:"errors"`
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

	Profile     string `json:"profile"`
	Warmup      int    `json:"warmup"`
	RampUp      int    `json:"ramp_up"`
	SpikeUsers  int    `json:"spike_users"`
	SpikeWarmup int    `json:"spike_warmup"`
	SpikeHold   int    `json:"spike_hold"`
	WavePeriod  int    `json:"wave_period"`
	Timeout     int    `json:"timeout"`
}

type RunState struct {
	Status    string        `json:"status"`
	Config    *RunConfig    `json:"config,omitempty"`
	StartTime time.Time     `json:"start_time,omitempty"`
	EndTime   time.Time     `json:"end_time,omitempty"`
	Elapsed   time.Duration `json:"elapsed"`
	Duration  time.Duration `json:"duration"`
	Progress  float64       `json:"progress"`
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
	StatusCodes   map[int]uint64 `json:"status_codes"`
}

// --- Dashboard Server -------------------------------------------------------

type Server struct {
	upgrader  websocket.Upgrader
	clients   map[*websocket.Conn]bool
	mu        sync.RWMutex
	snapshot  *LiveSnapshot
	runState  *RunState
	history   []HistoryEntry
	onCommand func(cmd string, args map[string]interface{})
}

func NewServer() *Server {
	return &Server{
		upgrader: websocket.Upgrader{
			CheckOrigin:     func(r *http.Request) bool { return true },
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		clients:  make(map[*websocket.Conn]bool),
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
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
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
	var config RunConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.onCommand != nil {
		s.onCommand("start", map[string]interface{}{"config": config})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) handleStopRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if s.onCommand != nil {
		s.onCommand("stop", nil)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
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
