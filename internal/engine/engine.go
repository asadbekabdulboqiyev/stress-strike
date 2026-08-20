package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stress-strike/internal/config"
	"stress-strike/internal/metrics"
	"stress-strike/internal/report"
)

const (
	errTimeout       = "timeout"
	errConnection    = "connection_error"
	errCanceled      = "canceled"
	errOther         = "error"
	errRedirectLimit = "redirect_limit"
	errStatus4xx     = "status_4xx"
	errStatus5xx     = "status_5xx"
	errExtract       = "extract_error"
	errAssert        = "assert_failed"
	bodyReadLimit    = 8 << 20
	defaultUserAgent = "stress-strike/0.1"
	adjustInterval   = 100 * time.Millisecond
)

type RunOptions struct {
	Out   io.Writer
	Quiet bool
}

type stepResult struct {
	latency time.Duration
	status  int
	errName string
}

// Worker is the per-virtual-user execution loop used by the engine. The
// engine implements it through loadWorker so a distributed coordinator can
// dispatch users to workers uniformly.
type Worker interface {
	// Run starts the load loop and returns when runCtx is done.
	Run(runCtx, reqBase context.Context, index int)
}

// loadWorker drives a single virtual user through the scenario loop.
type loadWorker struct {
	e *Engine
}

// Run implements the Worker load loop for a single virtual user.
func (w *loadWorker) Run(runCtx, reqBase context.Context, index int) {
	for {
		if runCtx.Err() != nil {
			return
		}
		if int64(index) >= w.e.target.Load() {
			if err := w.e.signal.wait(runCtx); err != nil {
				return
			}
			continue
		}
		if w.e.limiter != nil {
			if err := w.e.limiter.wait(runCtx); err != nil {
				return
			}
		}
		w.e.runIteration(reqBase, index)
	}
}

type Engine struct {
	scenario  *config.Scenario
	profile   LoadProfile
	client    *http.Client
	timeout   time.Duration
	keepAlive bool
	limiter   *tokenBucket
	target    atomic.Int64
	signal    *broadcast
	stepStats []*metrics.StepStats
	telemetry *metrics.Telemetry
}

func New(scenario *config.Scenario) (*Engine, error) {
	if err := scenario.Normalize(); err != nil {
		return nil, err
	}
	profile, err := buildProfile(scenario.Profile)
	if err != nil {
		return nil, err
	}
	keepAlive := true
	if scenario.Profile.KeepAlive != nil {
		keepAlive = *scenario.Profile.KeepAlive
	}
	maxConns := profile.MaxConcurrency() * 2
	e := &Engine{
		scenario:  scenario,
		profile:   profile,
		client:    newClient(time.Duration(scenario.Profile.Timeout)*time.Second, keepAlive, maxConns),
		timeout:   time.Duration(scenario.Profile.Timeout) * time.Second,
		keepAlive: keepAlive,
		limiter:   newTokenBucket(scenario.Profile.RPS),
		signal:    newBroadcast(),
	}
	e.stepStats = make([]*metrics.StepStats, len(scenario.Steps))
	for i, step := range scenario.Steps {
		e.stepStats[i] = metrics.NewStepStats(step.Name)
	}
	return e, nil
}

func (e *Engine) Run(ctx context.Context, opts RunOptions) (*metrics.Telemetry, error) {
	out := opts.Out
	if out == nil {
		out = io.Discard
	}

	reqBase, reqCancel := context.WithCancel(ctx)
	defer reqCancel()

	runCtx, runCancel := context.WithTimeout(ctx, e.profile.Duration())
	defer runCancel()

	e.telemetry = metrics.NewTelemetry()
	for _, st := range e.stepStats {
		e.telemetry.AddStep(st)
	}

	initialTarget := e.profile.ConcurrencyAt(0)
	e.target.Store(int64(initialTarget))
	e.telemetry.ActiveUsers.Store(int64(initialTarget))

	var stopLive func()
	if !opts.Quiet {
		stopLive = report.StartLive(e.telemetry, e.profile.Duration(), out)
	}

	var wg sync.WaitGroup
	maxUsers := e.profile.MaxConcurrency()
	w := &loadWorker{e: e}
	for i := 0; i < maxUsers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			w.Run(runCtx, reqBase, idx)
		}(i)
	}

	go e.controller(runCtx)

	<-runCtx.Done()
	runCancel()

	drained := make(chan struct{})
	go func() {
		wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(e.timeout):
		reqCancel()
		<-drained
	}

	if stopLive != nil {
		stopLive()
	}
	e.telemetry.Finish()
	return e.telemetry, nil
}

func (e *Engine) controller(ctx context.Context) {
	ticker := time.NewTicker(adjustInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			elapsed := time.Since(e.telemetry.Start)
			target := e.profile.ConcurrencyAt(elapsed)
			if int64(target) != e.target.Load() {
				e.target.Store(int64(target))
				e.signal.notify()
			}
			e.telemetry.ActiveUsers.Store(int64(target))
			if int64(target) > e.telemetry.PeakUsers.Load() {
				e.telemetry.PeakUsers.Store(int64(target))
			}
		}
	}
}

func (e *Engine) runIteration(reqBase context.Context, userIndex int) {
	vars := newVars(e.scenario, userIndex)
	iterStart := time.Now()
	var lastStatus int
	var firstErr string
	for i, step := range e.scenario.Steps {
		res := e.runStep(reqBase, step, vars)
		e.stepStats[i].Record(res.latency, res.status, res.errName)
		if res.errName != "" {
			if firstErr == "" {
				firstErr = res.errName
			}
			break
		}
		lastStatus = res.status
	}
	e.telemetry.Overall.Record(time.Since(iterStart), lastStatus, firstErr)
}

func (e *Engine) runStep(ctx context.Context, step config.Step, vars map[string]string) stepResult {
	fullURL := step.URL
	if step.Type == "http" && e.scenario.BaseURL != "" {
		fullURL = strings.TrimRight(e.scenario.BaseURL, "/") + "/" + strings.TrimLeft(step.URL, "/")
	}
	fullURL = render(fullURL, vars)

	timeout := e.timeout
	if step.Timeout > 0 {
		timeout = time.Duration(step.Timeout) * time.Second
	}

	var res stepResult
	var body []byte
	switch step.Type {
	case "ws":
		res, body = e.wsClient(ctx, fullURL, step, vars, timeout)
	case "grpc":
		res, body = e.grpcClient(ctx, fullURL, timeout)
	case "tcp", "udp":
		res, body = e.rawClient(ctx, step.Type, fullURL, step, vars, timeout)
	default:
		res, body = e.httpClient(ctx, fullURL, step, vars, timeout)
	}
	if res.errName == "" && len(step.Assertions) > 0 {
		if err := checkAssertions(step.Assertions, res.status, body); err != nil {
			res.errName = errAssert
		}
	}
	return res
}

func (e *Engine) httpClient(ctx context.Context, fullURL string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	stepCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var body io.Reader
	if step.Body != "" {
		body = strings.NewReader(renderBody(step.Body, vars))
	}

	req, err := http.NewRequestWithContext(stepCtx, step.Method, fullURL, body)
	if err != nil {
		return stepResult{errName: errOther}, nil
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	for k, v := range step.Headers {
		req.Header.Set(k, render(v, vars))
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	if err != nil {
		res := classifyError(err, time.Since(start))
		return res, nil
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, bodyReadLimit))
	if readErr != nil {
		res := classifyError(readErr, time.Since(start))
		return res, nil
	}
	latency := time.Since(start)
	status := resp.StatusCode

	var errName string
	switch {
	case status >= 500:
		errName = errStatus5xx
	case status >= 400:
		errName = errStatus4xx
	}
	if errName != "" {
		return stepResult{latency: latency, status: status, errName: errName}, respBody
	}

	for _, ex := range step.Extract {
		value, exErr := extractValue(ex.From, ex.Path, respBody, resp.Header.Get(ex.Path))
		if exErr != nil {
			return stepResult{latency: latency, status: status, errName: errExtract}, respBody
		}
		vars[ex.Name] = value
	}
	return stepResult{latency: latency, status: status}, respBody
}

func classifyError(err error, elapsed time.Duration) stepResult {
	switch {
	case errors.Is(err, context.Canceled):
		return stepResult{errName: errCanceled}
	case errors.Is(err, context.DeadlineExceeded):
		return stepResult{latency: elapsed, errName: errTimeout}
	}
	if errors.Is(err, errRedirectLimitReached) {
		return stepResult{latency: elapsed, errName: errRedirectLimit}
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return stepResult{latency: elapsed, errName: errConnection}
	}
	return stepResult{latency: elapsed, errName: errOther}
}
