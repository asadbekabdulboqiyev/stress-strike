package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"stress-strike/internal/config"
	"stress-strike/internal/metrics"
)

type testAPI struct {
	loginHits atomic.Int64
	tokenOK   atomic.Int64
	failHits  atomic.Int64
}

func newTestServer() (*httptest.Server, *testAPI) {
	api := &testAPI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		api.loginHits.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.Username == "" || req.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"token":"tok-%s"}}`, req.Username)
	})
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer tok-user") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		api.tokenOK.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/fail", func(w http.ResponseWriter, _ *http.Request) {
		api.failHits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	return srv, api
}

func runScenario(t *testing.T, sc *config.Scenario, dur time.Duration) *metrics.Telemetry {
	t.Helper()
	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tel, err := eng.Run(ctx, RunOptions{Out: io.Discard, Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	return tel
}

func TestEngineScenarioFlow(t *testing.T) {
	srv, api := newTestServer()
	defer srv.Close()

	sc := &config.Scenario{
		Name:    "flow",
		BaseURL: srv.URL,
		Profile: config.Profile{Type: config.ProfileSteady, Users: 5, Duration: 2, Timeout: 5},
		Steps: []config.Step{
			{Name: "login", Method: "POST", URL: "/login", Body: `{"username":"{{user}}","password":"{{pass}}"}`,
				Extract: []config.Extract{{Name: "token", From: "json", Path: "data.token"}}},
			{Name: "profile", Method: "GET", URL: "/profile", Headers: map[string]string{"Authorization": "Bearer {{token}}"}},
		},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}

	tel := runScenario(t, sc, 2*time.Second)

	if tel.TotalRequests() == 0 {
		t.Fatal("no requests were recorded")
	}
	if tel.TotalErrors() != 0 {
		t.Errorf("errors = %d, want 0: %v", tel.TotalErrors(), tel.Errors())
	}
	if api.loginHits.Load() == 0 {
		t.Error("server received no /login requests")
	}
	if api.tokenOK.Load() == 0 {
		t.Error("token extraction failed: no /profile reached with valid token")
	}
	if len(tel.Steps) != 2 {
		t.Errorf("steps = %d, want 2", len(tel.Steps))
	}
	if code, ok := tel.Steps[1].StatusCodes()[200]; !ok || code == 0 {
		t.Error("profile step has no 200 responses")
	}
	if tel.RPS() <= 0 {
		t.Error("RPS should be positive")
	}
}

func TestEngineCountsServerErrors(t *testing.T) {
	srv, api := newTestServer()
	defer srv.Close()

	sc := &config.Scenario{
		Name:    "errors",
		BaseURL: srv.URL,
		Profile: config.Profile{Type: config.ProfileSteady, Users: 3, Duration: 1, Timeout: 5},
		Steps:   []config.Step{{Name: "fail", Method: "GET", URL: "/fail"}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	tel := runScenario(t, sc, time.Second)

	if api.failHits.Load() == 0 {
		t.Error("server received no /fail requests")
	}
	errs := tel.Errors()
	if errs["status_5xx"] == 0 {
		t.Errorf("expected status_5xx errors, got %v", errs)
	}
	if code, ok := tel.Steps[0].StatusCodes()[500]; !ok || code == 0 {
		t.Error("expected 500 status code recorded")
	}
}

func TestEngineLinearRampReachesPeak(t *testing.T) {
	srv, _ := newTestServer()
	defer srv.Close()

	sc := &config.Scenario{
		Name:    "ramp",
		BaseURL: srv.URL,
		Profile: config.Profile{Type: config.ProfileLinearRamp, Users: 20, Duration: 3, RampUp: 2, Timeout: 5},
		Steps:   []config.Step{{Name: "health", Method: "GET", URL: "/health"}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	tel := runScenario(t, sc, 3*time.Second)

	if tel.PeakUsers.Load() != 20 {
		t.Errorf("peak users = %d, want 20", tel.PeakUsers.Load())
	}
	if tel.TotalRequests() == 0 {
		t.Error("no requests recorded")
	}
}

func TestEngineRPSCap(t *testing.T) {
	srv, _ := newTestServer()
	defer srv.Close()

	sc := &config.Scenario{
		Name:    "capped",
		BaseURL: srv.URL,
		Profile: config.Profile{Type: config.ProfileSteady, Users: 50, Duration: 2, Timeout: 5, RPS: 100},
		Steps:   []config.Step{{Name: "health", Method: "GET", URL: "/health"}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	tel := runScenario(t, sc, 2*time.Second)

	elapsed := tel.Elapsed().Seconds()
	measured := tel.TotalRequests()
	if measured < 100 || measured > 400 {
		t.Errorf("requests %d over %.1fs, expected ~200 (100 rps cap)", measured, elapsed)
	}
}

func TestEngineWebSocketStep(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.TextMessage, []byte("echo:"+string(msg)))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	sc := &config.Scenario{
		Name:    "ws",
		Profile: config.Profile{Type: config.ProfileSteady, Users: 3, Duration: 1, Timeout: 5},
		Steps: []config.Step{
			{Name: "ws-echo", Type: "ws", URL: wsURL, Body: "hello {{user}}",
				Assertions: []config.Assertion{{Type: "regex", Value: "echo:hello"}}},
		},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	tel := runScenario(t, sc, time.Second)
	if tel.TotalRequests() == 0 {
		t.Error("no ws requests recorded")
	}
	if tel.TotalErrors() != 0 {
		t.Errorf("errors = %d, want 0: %v", tel.TotalErrors(), tel.Errors())
	}
}

func TestEngineAssertionFailure(t *testing.T) {
	srv, _ := newTestServer()
	defer srv.Close()
	sc := &config.Scenario{
		Name:    "assert",
		BaseURL: srv.URL,
		Profile: config.Profile{Type: config.ProfileSteady, Users: 2, Duration: 1, Timeout: 5},
		Steps: []config.Step{
			{Name: "health", URL: "/health", Assertions: []config.Assertion{{Type: "status", Value: "204"}}},
		},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	tel := runScenario(t, sc, time.Second)
	errs := tel.Errors()
	if errs["assert_failed"] == 0 {
		t.Errorf("expected assert_failed errors, got %v", errs)
	}
}
