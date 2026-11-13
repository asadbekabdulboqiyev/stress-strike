package main

// main_runs_test.go — coverage for the dashboard's run plumbing:
// scenarioFromConfig, startRun/stopRun (including the duplicate-start guard and
// invalid-config rejection) and streamTelemetry.
//
// Runs target a loopback httptest server with a 1-second profile so the suite
// stays fast and needs no external network.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/dashboard"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
	prom "github.com/asadbekabdulboqiyev/sift/internal/metrics/exporter"
)

func TestScenarioFromConfigDefaults(t *testing.T) {
	sc, err := scenarioFromConfig(&dashboard.RunConfig{TargetURL: "http://127.0.0.1:1/health"})
	if err != nil {
		t.Fatalf("scenarioFromConfig: %v", err)
	}
	if sc.Profile.Type != config.ProfileSteady {
		t.Errorf("profile = %q, want %q", sc.Profile.Type, config.ProfileSteady)
	}
	if sc.Profile.Users != 10 || sc.Profile.Duration != 30 {
		t.Errorf("users/duration = %d/%d, want 10/30", sc.Profile.Users, sc.Profile.Duration)
	}
	if len(sc.Steps) != 1 || sc.Steps[0].Method != "GET" {
		t.Errorf("steps = %+v, want one GET step", sc.Steps)
	}
}

func TestScenarioFromConfigConstantRPS(t *testing.T) {
	sc, err := scenarioFromConfig(&dashboard.RunConfig{
		TargetURL: "http://127.0.0.1:1/health",
		Profile:   config.ProfileConstantRPS,
		RateLimit: 50,
		Method:    "post",
	})
	if err != nil {
		t.Fatalf("scenarioFromConfig(constant-rps): %v", err)
	}
	if sc.Profile.TargetRPS != 50 || sc.Profile.RPS != 50 {
		t.Errorf("target_rps/rps = %d/%d, want 50/50", sc.Profile.TargetRPS, sc.Profile.RPS)
	}
	if sc.Steps[0].Method != "POST" {
		t.Errorf("method = %q, want POST", sc.Steps[0].Method)
	}
}

func TestScenarioFromConfigRequiresTarget(t *testing.T) {
	if _, err := scenarioFromConfig(&dashboard.RunConfig{}); err == nil {
		t.Fatal("scenarioFromConfig(no target) = nil error, want an error")
	}
}

func TestScenarioFromConfigRejectsUnknownProfile(t *testing.T) {
	_, err := scenarioFromConfig(&dashboard.RunConfig{
		TargetURL: "http://127.0.0.1:1/health",
		Profile:   "warp-speed",
	})
	if err == nil {
		t.Fatal("scenarioFromConfig(unknown profile) = nil error, want an error")
	}
}

func TestStartRunDuplicateIsIgnored(t *testing.T) {
	srv := dashboard.NewServer()
	bridge := dashboard.NewEngineBridge(srv)
	var mu sync.Mutex
	var cancel context.CancelFunc
	active := true // pretend a run is already in flight

	startRun(bridge, srv, prom.NewMetrics(), &mu, &active, &cancel, map[string]interface{}{})
	if !active {
		t.Error("startRun duplicate start cleared runActive, want it untouched")
	}
}

func TestStartRunInvalidConfigMarksInactive(t *testing.T) {
	srv := dashboard.NewServer()
	bridge := dashboard.NewEngineBridge(srv)
	var mu sync.Mutex
	var cancel context.CancelFunc
	active := false

	startRun(bridge, srv, prom.NewMetrics(), &mu, &active, &cancel, map[string]interface{}{
		"config": dashboard.RunConfig{Users: 2, DurationSeconds: 1},
	})
	mu.Lock()
	got := active
	mu.Unlock()
	if got {
		t.Error("startRun with an invalid config left runActive set")
	}
	if cancel != nil {
		t.Error("startRun with an invalid config installed a cancel func")
	}
}

func TestStartRunCompletesAndStreams(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	srv := dashboard.NewServer()
	bridge := dashboard.NewEngineBridge(srv)
	var mu sync.Mutex
	var cancel context.CancelFunc
	active := false

	startRun(bridge, srv, prom.NewMetrics(), &mu, &active, &cancel, map[string]interface{}{
		"config": dashboard.RunConfig{
			TargetURL:       target.URL,
			Users:           2,
			DurationSeconds: 1,
			Method:          "GET",
		},
	})

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := !active && cancel == nil
		mu.Unlock()
		if done {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("startRun did not finish its 1s run within 20s")
}

func TestStartRunRawMapConfig(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	srv := dashboard.NewServer()
	bridge := dashboard.NewEngineBridge(srv)
	var mu sync.Mutex
	var cancel context.CancelFunc
	active := false

	startRun(bridge, srv, prom.NewMetrics(), &mu, &active, &cancel, map[string]interface{}{
		"config": map[string]interface{}{
			"target_url":       target.URL,
			"users":            float64(1),
			"duration_seconds": float64(1),
			"method":           "GET",
			"headers":          map[string]interface{}{"X-Test": "1"},
		},
	})
	// The raw-map branch should parse the target and start a real run.
	mu.Lock()
	started := active || cancel != nil
	mu.Unlock()
	if !started {
		t.Error("startRun(raw map config) did not start a run")
	}

	stopRun(bridge, &mu, &cancel)
	if !bridge.IsStopped() {
		t.Error("stopRun did not mark the bridge stopped")
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := !active
		mu.Unlock()
		if done {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("stopped run did not finish within 20s")
}

func TestStopRunWithoutCancel(t *testing.T) {
	srv := dashboard.NewServer()
	bridge := dashboard.NewEngineBridge(srv)
	var mu sync.Mutex
	var cancel context.CancelFunc
	// No active run: stopRun must tolerate a nil cancel func.
	stopRun(bridge, &mu, &cancel)
}

func TestStreamTelemetryStops(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	eng, err := engineForURL(t, target.URL)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	srv := dashboard.NewServer()
	bridge := dashboard.NewEngineBridge(srv)
	stop := make(chan struct{})
	done := make(chan struct{})

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_, _ = eng.Run(runCtx, engine.RunOptions{Quiet: true, Out: io.Discard})
	}()
	go streamTelemetry(bridge, eng, prom.NewMetrics(), stop, done)

	// Let at least two 500ms ticks land so the snapshot branch runs.
	time.Sleep(1200 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("streamTelemetry did not return after stop closed")
	}
	cancelRun()
	<-runDone
}

func TestStreamTelemetryNilMetrics(t *testing.T) {
	eng, err := engineForURL(t, "http://127.0.0.1:1/health")
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	srv := dashboard.NewServer()
	bridge := dashboard.NewEngineBridge(srv)
	stop := make(chan struct{})
	done := make(chan struct{})
	go streamTelemetry(bridge, eng, nil, stop, done)
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("streamTelemetry(nil metrics) did not return")
	}
}

// engineForURL builds a 1-user/1-second engine aimed at url.
func engineForURL(t *testing.T, url string) (*engine.Engine, error) {
	t.Helper()
	sc, err := scenarioFromConfig(&dashboard.RunConfig{
		TargetURL:       url,
		Users:           1,
		DurationSeconds: 1,
	})
	if err != nil {
		return nil, err
	}
	return engine.New(sc)
}
