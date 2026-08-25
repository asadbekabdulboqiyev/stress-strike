package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- NewServer Tests --------------------------------------------------------

func TestNewServer(t *testing.T) {
	s := NewServer()

	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.clients == nil {
		t.Error("clients map not initialized")
	}
	if s.snapshot == nil {
		t.Error("snapshot not initialized")
	}
	if s.runState == nil {
		t.Error("runState not initialized")
	}
	if s.history == nil {
		t.Error("history not initialized")
	}
	if s.runState.Status != "idle" {
		t.Errorf("initial runState.Status = %q, want idle", s.runState.Status)
	}
	if s.snapshot.StatusCodes == nil {
		t.Error("snapshot.StatusCodes not initialized")
	}
}

// --- UpdateSnapshot Tests ---------------------------------------------------

func TestUpdateSnapshot(t *testing.T) {
	s := NewServer()

	snap := &LiveSnapshot{
		RPS:         1234.5,
		TotalReq:    10000,
		TotalErrors: 50,
		ErrorRate:   0.5,
		P50Latency:  25.0,
		P95Latency:  100.0,
		P99Latency:  200.0,
		AvgLatency:  30.0,
		MaxLatency:  500.0,
		ActiveUsers: 100,
		StatusCodes: map[int]uint64{200: 9900, 500: 50, 404: 50},
	}

	s.UpdateSnapshot(snap)

	s.mu.RLock()
	got := s.snapshot
	s.mu.RUnlock()

	if got.RPS != 1234.5 {
		t.Errorf("RPS = %f, want 1234.5", got.RPS)
	}
	if got.TotalReq != 10000 {
		t.Errorf("TotalReq = %d, want 10000", got.TotalReq)
	}
	if got.ActiveUsers != 100 {
		t.Errorf("ActiveUsers = %d, want 100", got.ActiveUsers)
	}
	if got.StatusCodes[200] != 9900 {
		t.Errorf("StatusCodes[200] = %d, want 9900", got.StatusCodes[200])
	}
}

func TestUpdateSnapshot_Overwrite(t *testing.T) {
	s := NewServer()

	s1 := &LiveSnapshot{RPS: 100, TotalReq: 100}
	s.UpdateSnapshot(s1)

	s2 := &LiveSnapshot{RPS: 200, TotalReq: 200}
	s.UpdateSnapshot(s2)

	s.mu.RLock()
	if s.snapshot.RPS != 200 {
		t.Errorf("snapshot not overwritten: RPS = %f", s.snapshot.RPS)
	}
	s.mu.RUnlock()
}

// --- SetRunState Tests ------------------------------------------------------

func TestSetRunState(t *testing.T) {
	s := NewServer()

	state := &RunState{
		Status: "running",
		Config: &RunConfig{
			TargetURL: "https://example.com",
			Users:     50,
		},
		StartTime: time.Now(),
		Duration:  30 * time.Second,
	}

	s.SetRunState(state)

	s.mu.RLock()
	got := s.runState
	s.mu.RUnlock()

	if got.Status != "running" {
		t.Errorf("Status = %q, want running", got.Status)
	}
	if got.Config == nil {
		t.Fatal("Config is nil")
	}
	if got.Config.TargetURL != "https://example.com" {
		t.Errorf("Config.TargetURL = %q", got.Config.TargetURL)
	}
	if got.Config.Users != 50 {
		t.Errorf("Config.Users = %d, want 50", got.Config.Users)
	}
}

func TestSetRunState_Transitions(t *testing.T) {
	s := NewServer()

	s.SetRunState(&RunState{Status: "running"})
	s.mu.RLock()
	if s.runState.Status != "running" {
		t.Errorf("after running: Status = %q", s.runState.Status)
	}
	s.mu.RUnlock()

	s.SetRunState(&RunState{Status: "completed"})
	s.mu.RLock()
	if s.runState.Status != "completed" {
		t.Errorf("after completed: Status = %q", s.runState.Status)
	}
	s.mu.RUnlock()

	s.SetRunState(&RunState{Status: "failed"})
	s.mu.RLock()
	if s.runState.Status != "failed" {
		t.Errorf("after failed: Status = %q", s.runState.Status)
	}
	s.mu.RUnlock()
}

// --- AddHistoryEntry Tests --------------------------------------------------

func TestAddHistoryEntry(t *testing.T) {
	s := NewServer()

	entry := HistoryEntry{
		ID:        "run-001",
		Timestamp: time.Now(),
		Config: RunConfig{
			TargetURL: "https://example.com",
			Users:     10,
		},
		Result: RunResult{
			TotalRequests: 500,
			TotalErrors:   5,
			RPS:           50.0,
			StatusCodes:   map[int]uint64{200: 490, 500: 5, 404: 5},
		},
		Duration: "30s",
	}

	s.AddHistoryEntry(entry)

	s.mu.RLock()
	if len(s.history) != 1 {
		t.Fatalf("history length = %d, want 1", len(s.history))
	}
	if s.history[0].ID != "run-001" {
		t.Errorf("history[0].ID = %q", s.history[0].ID)
	}
	if s.history[0].Result.TotalRequests != 500 {
		t.Errorf("history[0].Result.TotalRequests = %d", s.history[0].Result.TotalRequests)
	}
	s.mu.RUnlock()
}

func TestAddHistoryEntry_Multiple(t *testing.T) {
	s := NewServer()

	for i := 0; i < 5; i++ {
		s.AddHistoryEntry(HistoryEntry{
			ID:        "run-" + string(rune('0'+i)),
			Timestamp: time.Now(),
		})
	}

	s.mu.RLock()
	if len(s.history) != 5 {
		t.Errorf("history length = %d, want 5", len(s.history))
	}
	s.mu.RUnlock()
}

// --- HTTP API Tests ---------------------------------------------------------

func TestServeHTTP_DefaultServesHTML(t *testing.T) {
	s := NewServer()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET / status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestServeHTTP_SnapshotAPI(t *testing.T) {
	s := NewServer()
	s.UpdateSnapshot(&LiveSnapshot{RPS: 42.0, TotalReq: 100})

	req := httptest.NewRequest("GET", "/api/snapshot", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /api/snapshot status = %d", w.Code)
	}

	var snap LiveSnapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if snap.RPS != 42.0 {
		t.Errorf("snapshot RPS = %f, want 42", snap.RPS)
	}
}

func TestServeHTTP_RunAPI(t *testing.T) {
	s := NewServer()
	s.SetRunState(&RunState{Status: "running"})

	req := httptest.NewRequest("GET", "/api/run", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /api/run status = %d", w.Code)
	}

	var state RunState
	if err := json.NewDecoder(w.Body).Decode(&state); err != nil {
		t.Fatalf("decode run state: %v", err)
	}
	if state.Status != "running" {
		t.Errorf("run state Status = %q, want running", state.Status)
	}
}

func TestServeHTTP_HistoryAPI(t *testing.T) {
	s := NewServer()
	s.AddHistoryEntry(HistoryEntry{
		ID:     "run-1",
		Config: RunConfig{TargetURL: "https://example.com"},
	})

	req := httptest.NewRequest("GET", "/api/history", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /api/history status = %d", w.Code)
	}

	var history []HistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&history); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if len(history) != 1 {
		t.Errorf("history length = %d, want 1", len(history))
	}
	if history[0].Config.TargetURL != "https://example.com" {
		t.Errorf("history[0] URL = %q", history[0].Config.TargetURL)
	}
}

func TestServeHTTP_StartRunPOST(t *testing.T) {
	s := NewServer()
	var receivedCmd string
	var receivedConfig interface{}
	s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		receivedCmd = cmd
		if cfg, ok := args["config"]; ok {
			receivedConfig = cfg
		}
	})

	body := `{"target_url":"https://example.com","users":25,"duration_seconds":60}`
	req := httptest.NewRequest("POST", "/api/run/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("POST /api/run/start status = %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "started" {
		t.Errorf("response status = %q, want started", resp["status"])
	}
	if receivedCmd != "start" {
		t.Errorf("command = %q, want start", receivedCmd)
	}
	if receivedConfig == nil {
		t.Error("config not received")
	}
}

func TestServeHTTP_StartRunMethodNotAllowed(t *testing.T) {
	s := NewServer()

	req := httptest.NewRequest("GET", "/api/run/start", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/run/start status = %d, want 405", w.Code)
	}
}

func TestServeHTTP_StopRunPOST(t *testing.T) {
	s := NewServer()
	var receivedCmd string
	s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		receivedCmd = cmd
	})

	req := httptest.NewRequest("POST", "/api/run/stop", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("POST /api/run/stop status = %d", w.Code)
	}
	if receivedCmd != "stop" {
		t.Errorf("command = %q, want stop", receivedCmd)
	}
}

func TestServeHTTP_StopRunMethodNotAllowed(t *testing.T) {
	s := NewServer()

	req := httptest.NewRequest("GET", "/api/run/stop", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/run/stop status = %d, want 405", w.Code)
	}
}

func TestServeHTTP_StartRunInvalidJSON(t *testing.T) {
	s := NewServer()

	req := httptest.NewRequest("POST", "/api/run/start", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON status = %d, want 400", w.Code)
	}
}

// --- Command Handler Tests --------------------------------------------------

func TestSetCommandHandler(t *testing.T) {
	s := NewServer()
	called := false
	s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		called = true
	})
	if s.onCommand == nil {
		t.Error("onCommand handler not set")
	}
	// Simulate calling it
	s.onCommand("test", nil)
	if !called {
		t.Error("handler was not called")
	}
}

// --- Data Integrity Tests ---------------------------------------------------

func TestRunConfig_JSON(t *testing.T) {
	cfg := RunConfig{
		TargetURL:       "https://example.com",
		Users:           100,
		DurationSeconds: 60,
		RateLimit:       1000,
		Method:          "POST",
		Headers:         map[string]string{"Authorization": "Bearer token"},
		Body:            `{"data": "test"}`,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var decoded RunConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.TargetURL != cfg.TargetURL {
		t.Errorf("TargetURL = %q", decoded.TargetURL)
	}
	if decoded.Users != cfg.Users {
		t.Errorf("Users = %d", decoded.Users)
	}
	if decoded.DurationSeconds != cfg.DurationSeconds {
		t.Errorf("DurationSeconds = %d", decoded.DurationSeconds)
	}
}

func TestRunState_JSON(t *testing.T) {
	state := RunState{
		Status:   "completed",
		Config:   &RunConfig{TargetURL: "https://example.com"},
		Progress: 100,
	}

	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}

	var decoded RunState
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Status != "completed" {
		t.Errorf("Status = %q", decoded.Status)
	}
	if decoded.Progress != 100 {
		t.Errorf("Progress = %f", decoded.Progress)
	}
}

func TestLiveSnapshot_JSON(t *testing.T) {
	snap := LiveSnapshot{
		RPS:         500.0,
		TotalReq:    10000,
		TotalErrors: 100,
		ErrorRate:   1.0,
		StatusCodes: map[int]uint64{200: 9900, 500: 100},
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}

	var decoded LiveSnapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.RPS != 500.0 {
		t.Errorf("RPS = %f", decoded.RPS)
	}
	if decoded.TotalReq != 10000 {
		t.Errorf("TotalReq = %d", decoded.TotalReq)
	}
}

func TestHistoryEntry_JSON(t *testing.T) {
	entry := HistoryEntry{
		ID:        "run-123",
		Timestamp: time.Now(),
		Config:    RunConfig{TargetURL: "https://example.com", Users: 10},
		Result:    RunResult{TotalRequests: 500, RPS: 50},
		Duration:  "30s",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}

	var decoded HistoryEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.ID != "run-123" {
		t.Errorf("ID = %q", decoded.ID)
	}
	if decoded.Duration != "30s" {
		t.Errorf("Duration = %q", decoded.Duration)
	}
}

func TestWorkerStatus_JSON(t *testing.T) {
	ws := WorkerStatus{
		ID:      "worker-1",
		Address: "10.0.0.1:8080",
		Status:  "active",
		RPS:     150.0,
		Latency: 25.5,
		Errors:  3,
	}

	data, err := json.Marshal(ws)
	if err != nil {
		t.Fatal(err)
	}

	var decoded WorkerStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.ID != "worker-1" {
		t.Errorf("ID = %q", decoded.ID)
	}
	if decoded.RPS != 150.0 {
		t.Errorf("RPS = %f", decoded.RPS)
	}
}
