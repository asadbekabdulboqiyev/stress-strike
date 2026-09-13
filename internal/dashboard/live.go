package dashboard

import (
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
)

// ScenarioFromRunConfig builds a single-step load scenario from the browser
// RunConfig so both dashboard entry points drive the real engine. Profile and
// advanced ramp/spike/wave fields flow straight into config.Profile.
func ScenarioFromRunConfig(scenarioName string, cfg *RunConfig) (*config.Scenario, error) {
	profile := cfg.Profile
	if profile == "" {
		profile = config.ProfileSteady
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5
	}
	rateLimit := cfg.RateLimit
	if rateLimit <= 0 {
		rateLimit = cfg.Users
	}
	keepAlive := true
	sc := &config.Scenario{
		Name: scenarioName,
		Profile: config.Profile{
			Type:        profile,
			Users:       cfg.Users,
			Duration:    cfg.DurationSeconds,
			Warmup:      cfg.Warmup,
			RampUp:      cfg.RampUp,
			SpikeUsers:  cfg.SpikeUsers,
			SpikeWarmup: cfg.SpikeWarmup,
			SpikeHold:   cfg.SpikeHold,
			WavePeriod:  cfg.WavePeriod,
			RPS:         rateLimit,
			TargetRPS:   rateLimit,
			Timeout:     timeout,
			KeepAlive:   &keepAlive,
		},
		Steps: []config.Step{
			{
				Name:    "request",
				Method:  cfg.Method,
				URL:     cfg.TargetURL,
				Headers: cfg.Headers,
				Body:    cfg.Body,
			},
		},
	}
	if err := sc.Normalize(); err != nil {
		return nil, err
	}
	return sc, nil
}

// SnapshotFromTelemetry converts the engine's live Telemetry into a
// LiveSnapshot for WebSocket broadcast. It is the single source of truth for
// what the dashboard renders, including per-step and error breakdowns.
func SnapshotFromTelemetry(e *engine.Engine, sc *config.Scenario) *LiveSnapshot {
	t, ok := engineTelemetry(e)
	if !ok {
		return &LiveSnapshot{
			Timestamp:   time.Now(),
			ActiveUsers: sc.Profile.Users,
			StatusCodes: map[int]uint64{},
			Errors:      map[string]uint64{},
		}
	}

	elapsed := t.Elapsed()
	elapsedSec := elapsed.Seconds()
	if elapsedSec <= 0 {
		elapsedSec = 0.001
	}

	reqs := t.TotalRequests()
	errs := t.TotalErrors()
	var errRate float64
	if reqs > 0 {
		errRate = float64(errs) / float64(reqs) * 100
	}

	snap := t.Overall.Latency.Snapshot()
	p50 := snap.Percentile(0.50)
	p95 := snap.Percentile(0.95)
	p99 := snap.Percentile(0.99)

	totalDur := sc.Profile.TotalDuration()
	progress := 0.0
	if totalDur > 0 {
		progress = elapsedSec / float64(totalDur) * 100
		if progress > 100 {
			progress = 100
		}
	}

	return &LiveSnapshot{
		Timestamp:   time.Now(),
		RPS:         float64(reqs) / elapsedSec,
		TotalReq:    reqs,
		TotalErrors: errs,
		ErrorRate:   errRate,
		P50Latency:  p50.Seconds() * 1000,
		P95Latency:  p95.Seconds() * 1000,
		P99Latency:  p99.Seconds() * 1000,
		AvgLatency:  snap.Average.Seconds() * 1000,
		MaxLatency:  snap.Max.Seconds() * 1000,
		ActiveUsers: int(t.ActiveUsers.Load()),
		PeakUsers:   t.PeakUsers.Load(),
		StatusCodes: t.StatusCodes(),
		Errors:      t.Errors(),
		Steps:       snapshotSteps(t, sc),
	}
}

// StreamTelemetry samples the engine's live Telemetry and pushes snapshots to
// the WebSocket server at a fixed interval until stop is closed. It also keeps
// the run-state progress bar honest by recomputing % complete from the
// scenario's total duration. Safe to fork as a goroutine.
func StreamTelemetry(srv *Server, e *engine.Engine, sc *config.Scenario, stop <-chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			srv.UpdateSnapshot(SnapshotFromTelemetry(e, sc))
			srv.UpdateRunProgress(sc, e)
		}
	}
}

// UpdateRunProgress refreshes the run-state elapsed/percent from the engine so
// the progress bar tracks reality even mid-run.
func (s *Server) UpdateRunProgress(sc *config.Scenario, e *engine.Engine) {
	t, ok := engineTelemetry(e)
	if !ok {
		return
	}
	elapsed := t.Elapsed()
	progress := 0.0
	totalDur := sc.Profile.TotalDuration()
	if totalDur > 0 {
		progress = elapsed.Seconds() / float64(totalDur) * 100
		if progress > 100 {
			progress = 100
		}
	}
	s.mu.RLock()
	state := s.runState
	s.mu.RUnlock()
	if state == nil || state.Status != "running" {
		return
	}
	s.SetRunState(&RunState{
		Status:    "running",
		Config:    state.Config,
		StartTime: time.Now().Add(-elapsed),
		Elapsed:   elapsed,
		Duration:  time.Duration(sc.Profile.TotalDuration()) * time.Second,
		Progress:  progress,
	})
}

// snapshotSteps builds per-step telemetry rows, tagging each with its protocol
// (http, ws, grpc, tcp, udp, tep) so the UI can badge steps.
func snapshotSteps(t *metrics.Telemetry, sc *config.Scenario) []StepSnapshot {
	if len(t.Steps) == 0 {
		return nil
	}
	out := make([]StepSnapshot, 0, len(t.Steps))
	for i, st := range t.Steps {
		reqs := st.Requests()
		elapsed := t.Elapsed().Seconds()
		if elapsed <= 0 {
			elapsed = 0.001
		}
		typ := ""
		if sc != nil && i < len(sc.Steps) {
			typ = sc.Steps[i].Type
		}
		if typ == "" {
			typ = "http"
		}
		s := st.Latency.Snapshot()
		out = append(out, StepSnapshot{
			Name:     st.Name,
			Type:     typ,
			Requests: reqs,
			RPS:      float64(reqs) / elapsed,
			P95Ms:    s.Percentile(0.95).Seconds() * 1000,
			Errors:   st.ErrorCount(),
		})
	}
	return out
}

// engineTelemetry safely returns the engine's live telemetry if available.
func engineTelemetry(e *engine.Engine) (*metrics.Telemetry, bool) {
	t := e.Telemetry()
	if t == nil {
		return nil, false
	}
	return t, true
}
