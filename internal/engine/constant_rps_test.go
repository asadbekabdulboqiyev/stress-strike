package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
)

func TestConstantRPSProfile(t *testing.T) {
	p := newConstantRPSProfile(500, 10, 30*time.Second)

	if p.targetRPS != 500 {
		t.Errorf("targetRPS = %d, want 500", p.targetRPS)
	}
	if p.Duration() != 30*time.Second {
		t.Errorf("duration = %s, want 30s", p.Duration())
	}
	if p.MaxConcurrency() != 500 {
		t.Errorf("MaxConcurrency = %d, want 500", p.MaxConcurrency())
	}
	if p.ConcurrencyAt(0) != 500 {
		t.Errorf("ConcurrencyAt(0) = %d, want 500 (fixed workers)", p.ConcurrencyAt(0))
	}
	if !p.IsConstantRPS() {
		t.Error("IsConstantRPS should be true")
	}
}

func TestConstantRPSRampUp(t *testing.T) {
	p := newConstantRPSProfile(1000, 10, 30*time.Second)

	if got := p.TargetRPSAt(0); got != 1 {
		t.Errorf("TargetRPSAt(0) = %d, want 1", got)
	}
	if got := p.TargetRPSAt(5 * time.Second); got < 490 || got > 510 {
		t.Errorf("TargetRPSAt(5s) = %d, want ~500", got)
	}
	if got := p.TargetRPSAt(10 * time.Second); got != 1000 {
		t.Errorf("TargetRPSAt(10s) = %d, want 1000", got)
	}
	if got := p.TargetRPSAt(20 * time.Second); got != 1000 {
		t.Errorf("TargetRPSAt(20s) = %d, want 1000 (post-ramp)", got)
	}
}

func TestConstantRPSZeroRampUp(t *testing.T) {
	p := newConstantRPSProfile(200, 0, 30*time.Second)

	// rampUp=0 defaults to dur/2 = 15s, so at t=0 RPS is 1.
	if got := p.TargetRPSAt(0); got != 1 {
		t.Errorf("TargetRPSAt(0) = %d, want 1 (ramp starts at 0)", got)
	}
	if p.RampDuration() != 15*time.Second {
		t.Errorf("RampDuration = %s, want 15s (default = dur/2)", p.RampDuration())
	}
	// At t=15s, should reach full target.
	if got := p.TargetRPSAt(15 * time.Second); got != 200 {
		t.Errorf("TargetRPSAt(15s) = %d, want 200", got)
	}
}

func TestBuildProfileConstantRPS(t *testing.T) {
	p, err := buildProfile(config.Profile{
		Type:      config.ProfileConstantRPS,
		TargetRPS: 500,
		Duration:  30,
		RampUp:    5,
	})
	if err != nil {
		t.Fatal(err)
	}
	crps, ok := p.(*constantRPSProfile)
	if !ok {
		t.Fatalf("expected *constantRPSProfile, got %T", p)
	}
	if crps.targetRPS != 500 {
		t.Errorf("targetRPS = %d, want 500", crps.targetRPS)
	}
}

func TestConstantRPSEndToEnd(t *testing.T) {
	var reqCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "rps-test",
		Profile: config.Profile{
			Type:      config.ProfileConstantRPS,
			TargetRPS: 200,
			Duration:  3,
			RampUp:    1,
			Timeout:   5,
		},
		Steps: []config.Step{
			{Name: "hit", Method: "GET", URL: srv.URL + "/"},
		},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	telemetry, err := eng.Run(context.Background(), RunOptions{Quiet: true})
	if err != nil {
		t.Fatal(err)
	}

	actual := telemetry.RPS()
	if actual < 50 {
		t.Errorf("actual RPS = %.1f, want >= 50", actual)
	}
	if actual > 400 {
		t.Errorf("actual RPS = %.1f, want <= 400 (cap ~200 rps + ramp overhead)", actual)
	}
	t.Logf("target=200 rps, actual=%.1f rps, total_requests=%d", actual, telemetry.TotalRequests())
}

func TestConstantRPSCapEnforcement(t *testing.T) {
	var reqCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "cap-test",
		Profile: config.Profile{
			Type:      config.ProfileConstantRPS,
			TargetRPS: 50,
			Duration:  3,
			RampUp:    0,
			Timeout:   5,
		},
		Steps: []config.Step{
			{Name: "hit", Method: "GET", URL: srv.URL + "/"},
		},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	telemetry, err := eng.Run(context.Background(), RunOptions{Quiet: true})
	if err != nil {
		t.Fatal(err)
	}

	actual := telemetry.RPS()
	// With 50 rps target and 3s duration, expect 120-200 total (accounting for
	// burst at start and ramp-up overhead).
	if actual < 30 {
		t.Errorf("actual RPS = %.1f, want >= 30 (ramp-up consumed some time)", actual)
	}
	if actual > 100 {
		t.Errorf("actual RPS = %.1f, want <= 100 (cap should hold at 50)", actual)
	}
	t.Logf("target=50 rps, actual=%.1f rps, total_requests=%d", actual, telemetry.TotalRequests())
}

func TestConstantRPSConfigNormalize(t *testing.T) {
	// Missing target_rps should fail.
	sc := &config.Scenario{
		Profile: config.Profile{Type: config.ProfileConstantRPS},
		Steps:   []config.Step{{URL: "/x"}},
	}
	if err := sc.Normalize(); err == nil {
		t.Error("expected error for constant-rps without target_rps")
	}

	// Valid constant-rps.
	sc = &config.Scenario{
		Profile: config.Profile{Type: config.ProfileConstantRPS, TargetRPS: 100, Duration: 30},
		Steps:   []config.Step{{URL: "/x"}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc.Profile.RampUp != 15 {
		t.Errorf("default ramp_up = %d, want 15 (duration/2)", sc.Profile.RampUp)
	}
}

func TestConstantRPSReportShowsTargetRPS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "rps-report",
		Profile: config.Profile{
			Type:      config.ProfileConstantRPS,
			TargetRPS: 100,
			Duration:  2,
			RampUp:    1,
			Timeout:   5,
		},
		Steps: []config.Step{
			{Name: "hit", Method: "GET", URL: srv.URL + "/"},
		},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	telemetry, err := eng.Run(context.Background(), RunOptions{Quiet: true})
	if err != nil {
		t.Fatal(err)
	}

	r := report.Build(telemetry, sc)
	if r.TargetRPS != 100 {
		t.Errorf("report TargetRPS = %d, want 100", r.TargetRPS)
	}
	if r.LoadProfile != "constant-rps" {
		t.Errorf("report LoadProfile = %q, want constant-rps", r.LoadProfile)
	}
}
