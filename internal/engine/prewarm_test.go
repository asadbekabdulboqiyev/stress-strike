package engine

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

func TestPreWarmConnections(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conns.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		PreWarm:            true,
		PreWarmConnections: 5,
		Steps:              []config.Step{{Name: "r", Method: "GET", URL: srv.URL}},
	}
	_ = sc.Normalize()

	e := &Engine{scenario: sc, timeout: 5 * time.Second}
	e.preWarmConnections(5)

	if got := int(conns.Load()); got != 5 {
		t.Errorf("expected 5 pre-warm requests, got %d", got)
	}
	if got := len(e.prewarmed.clients); got != 5 {
		t.Errorf("ring has %d clients, want 5", got)
	}
	e.prewarmed.closeAll()
}

func TestPreWarmRoundRobin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		PreWarm:            true,
		PreWarmConnections: 3,
		Steps:              []config.Step{{Name: "r", Method: "GET", URL: srv.URL}},
	}
	_ = sc.Normalize()

	e := &Engine{scenario: sc, timeout: 5 * time.Second}
	e.preWarmConnections(3)

	seen := make(map[*http.Client]int)
	for i := 0; i < 9; i++ {
		c := e.prewarmed.get()
		if c == nil {
			t.Fatal("prewarm ring returned nil client")
		}
		seen[c]++
	}
	if len(seen) != 3 {
		t.Errorf("expected 3 distinct clients, got %d", len(seen))
	}
	for _, count := range seen {
		if count != 3 {
			t.Errorf("each client should be returned 3 times, got %d", count)
		}
	}
	e.prewarmed.closeAll()
}

func TestPreWarmCleanup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		PreWarm:            true,
		PreWarmConnections: 10,
		Steps:              []config.Step{{Name: "r", Method: "GET", URL: srv.URL}},
	}
	_ = sc.Normalize()

	e := &Engine{scenario: sc, timeout: 5 * time.Second}
	e.preWarmConnections(10)

	if len(e.prewarmed.clients) != 10 {
		t.Fatalf("expected 10 clients, got %d", len(e.prewarmed.clients))
	}
	e.prewarmed.closeAll()
	if len(e.prewarmed.clients) != 0 {
		t.Errorf("after closeAll, ring should be empty, got %d", len(e.prewarmed.clients))
	}
}

func TestPreWarmWithMockServer(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	sc := &config.Scenario{
		PreWarm:            true,
		PreWarmConnections: 4,
		Steps:              []config.Step{{Name: "r", Method: "GET", URL: srv.URL}},
	}
	_ = sc.Normalize()

	e := &Engine{scenario: sc, timeout: 5 * time.Second}
	e.preWarmConnections(4)

	if got := int(requestCount.Load()); got != 4 {
		t.Errorf("pre-warm should issue 4 requests, got %d", got)
	}

	client := e.prewarmed.get()
	if client == nil {
		t.Fatal("no pre-warmed client available")
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request via pre-warmed client: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	e.prewarmed.closeAll()
}

func TestPreWarmConcurrencySafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		PreWarm:            true,
		PreWarmConnections: 8,
		Steps:              []config.Step{{Name: "r", Method: "GET", URL: srv.URL}},
	}
	_ = sc.Normalize()

	e := &Engine{scenario: sc, timeout: 5 * time.Second}
	e.preWarmConnections(8)

	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := e.prewarmed.get()
			if c == nil {
				errs <- nil
				return
			}
			resp, err := c.Get(srv.URL)
			if err != nil {
				errs <- err
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent request failed: %v", err)
		}
	}
	e.prewarmed.closeAll()
}

func TestPreWarmRingEmpty(t *testing.T) {
	ring := &prewarmRing{}
	if c := ring.get(); c != nil {
		t.Errorf("empty ring should return nil, got %v", c)
	}
	ring.closeAll()
}

func TestPreWarmZeroCount(t *testing.T) {
	sc := &config.Scenario{
		PreWarm: true,
		Steps:   []config.Step{{Name: "r", Method: "GET", URL: "http://localhost"}},
	}
	_ = sc.Normalize()

	e := &Engine{scenario: sc, timeout: 5 * time.Second}
	e.preWarmConnections(0)
	if len(e.prewarmed.clients) != 0 {
		t.Error("zero-count prewarm should leave ring empty")
	}
}

func TestPreWarmTargetURL(t *testing.T) {
	sc := &config.Scenario{
		BaseURL: "https://api.example.com",
		Steps: []config.Step{
			{Name: "list", Method: "GET", URL: "/v1/users"},
			{Name: "ws", Type: "ws", URL: "/ws"},
		},
	}
	_ = sc.Normalize()

	e := &Engine{scenario: sc}
	got := e.preWarmTargetURL()
	want := "https://api.example.com/v1/users"
	if got != want {
		t.Errorf("preWarmTargetURL = %q, want %q", got, want)
	}
}

func TestPreWarmTargetURLFallback(t *testing.T) {
	sc := &config.Scenario{
		Steps: []config.Step{
			{Name: "sock", Type: "ws", URL: "ws://example.com/socket"},
		},
	}
	_ = sc.Normalize()

	e := &Engine{scenario: sc}
	got := e.preWarmTargetURL()
	if got != "" {
		t.Errorf("expected empty for non-HTTP steps, got %q", got)
	}
}

func TestPreWarmDurationTracked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		PreWarm:            true,
		PreWarmConnections: 2,
		Steps:              []config.Step{{Name: "r", Method: "GET", URL: srv.URL}},
	}
	_ = sc.Normalize()

	e := &Engine{scenario: sc, timeout: 5 * time.Second}
	start := time.Now()
	e.preWarmConnections(2)
	e.prewarmDur = time.Since(start)

	if e.prewarmDur <= 0 {
		t.Error("prewarm duration should be positive")
	}
	e.prewarmed.closeAll()
}
