// Package api exposes a small, stable Go library API on top of the
// stress-strike engine. It is intended for embedding load tests into other
// programs, test suites or custom tooling.
package api

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
)

// Config describes a single load test to run against one HTTP endpoint.
type Config struct {
	URL       string
	Method    string
	Users     int
	Duration  time.Duration
	RPS       int
	Timeout   time.Duration
	KeepAlive bool
	Profile   string
	// SLA optionally defines pass/fail thresholds; Result.SLAPassed reports
	// the verdict so callers can fail builds or deployment gates.
	SLA *config.SLA
}

// Result summarizes a completed load test.
type Result struct {
	TotalRequests uint64
	RPS           float64
	ErrorRatePct  float64
	P50, P95, P99 time.Duration
	StatusCodes   map[int]uint64
	Errors        map[string]uint64
	// SLAResults holds per-threshold outcomes (nil when no SLA configured).
	SLAResults []report.SLAResult
	// SLAPassed is true when every SLA check passed.
	SLAPassed bool
}

// Run executes a load test described by cfg and blocks until it completes or
// ctx is canceled. Profile defaults to "steady"; zero values fall back to 10
// users, a 30 second duration and a 5 second per-request timeout.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	duration := int(cfg.Duration.Seconds())
	if duration <= 0 {
		duration = 30
	}
	timeout := int(cfg.Timeout.Seconds())
	if timeout <= 0 {
		timeout = 5
	}
	users := cfg.Users
	if users <= 0 {
		users = 10
	}
	profile := cfg.Profile
	if profile == "" {
		profile = config.ProfileSteady
	}
	method := cfg.Method
	if method == "" {
		method = "GET"
	}
	keepAlive := cfg.KeepAlive

	sc := &config.Scenario{
		Name: "api-run",
		Profile: config.Profile{
			Type:      profile,
			Users:     users,
			Duration:  duration,
			RPS:       cfg.RPS,
			Timeout:   timeout,
			KeepAlive: &keepAlive,
		},
		Steps: []config.Step{
			{Name: "request", Method: method, URL: cfg.URL},
		},
	}
	if err := sc.Normalize(); err != nil {
		return nil, fmt.Errorf("api: invalid config: %w", err)
	}

	eng, err := engine.New(sc)
	if err != nil {
		return nil, fmt.Errorf("api: engine: %w", err)
	}
	tel, err := eng.Run(ctx, engine.RunOptions{Quiet: true, Out: io.Discard})
	if err != nil {
		return nil, fmt.Errorf("api: run: %w", err)
	}
	rep := report.Build(tel, sc)
	res := resultFrom(tel)
	res.SLAResults = rep.SLA
	res.SLAPassed = report.SLAPassed(rep.SLA)
	return res, nil
}

// resultFrom converts engine telemetry into a public Result.
func resultFrom(tel *metrics.Telemetry) *Result {
	reqs := tel.TotalRequests()
	errs := tel.TotalErrors()
	errPct := 0.0
	if reqs > 0 {
		errPct = float64(errs) / float64(reqs) * 100
	}
	snap := tel.Overall.Latency.Snapshot()
	return &Result{
		TotalRequests: reqs,
		RPS:           tel.RPS(),
		ErrorRatePct:  errPct,
		P50:           snap.Percentile(0.50),
		P95:           snap.Percentile(0.95),
		P99:           snap.Percentile(0.99),
		StatusCodes:   tel.StatusCodes(),
		Errors:        tel.Errors(),
	}
}
