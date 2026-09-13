package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
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
	Out      io.Writer
	Quiet    bool
	Capture  ResponseCapture
	Pool     []string
	Progress *ProgressTracker
}

type stepResult struct {
	latency time.Duration
	status  int
	errName string
}

// prewarmClient is a single pre-warmed HTTP client bound to its own transport.
// Each instance holds an established TCP+TLS connection ready for immediate use.
type prewarmClient struct {
	client    *http.Client
	transport *http.Transport
}

// prewarmRing is a lock-free ring buffer for round-robin distribution of
// pre-warmed clients across virtual users.
type prewarmRing struct {
	clients []*prewarmClient
	next    atomic.Uint64
}

func (r *prewarmRing) get() *http.Client {
	if len(r.clients) == 0 {
		return nil
	}
	idx := r.next.Add(1) - 1
	return r.clients[idx%uint64(len(r.clients))].client
}

func (r *prewarmRing) closeAll() {
	for _, pc := range r.clients {
		pc.transport.CloseIdleConnections()
	}
	r.clients = nil
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
	if w.e.gate {
		w.runGatedOnce(runCtx, reqBase, index)
		return
	}
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

// Telemetry returns the live telemetry for the current run, or nil if no run
// is in progress. Safe for concurrent reads from the dashboard.
func (e *Engine) Telemetry() *metrics.Telemetry {
	e.teleMu.RLock()
	defer e.teleMu.RUnlock()
	return e.telemetry
}

// runGatedOnce parks the virtual user on the start gate and fires exactly
// one iteration the instant the gate opens — the race-condition primitive:
// N requests hit the target as close to simultaneously as the scheduler
// allows, maximizing the chance of exploiting check-then-act windows.
func (w *loadWorker) runGatedOnce(runCtx, reqBase context.Context, index int) {
	select {
	case <-runCtx.Done():
		return
	case <-w.e.startGate:
	}
	w.e.runIteration(reqBase, index)
}

type Engine struct {
	scenario  *config.Scenario
	profile   LoadProfile
	client    *http.Client
	transport *http.Transport
	timeout   time.Duration
	keepAlive bool
	limiter   *tokenBucket
	target    atomic.Int64
	signal    *broadcast
	startGate chan struct{}
	gate      bool
	stepStats []*metrics.StepStats
	telemetry *metrics.Telemetry
	teleMu    sync.RWMutex
	targetRPS atomic.Int64
	progress  *ProgressTracker

	// Pre-warmed connections: round-robin ring of HTTP clients with
	// established TCP+TLS connections, populated before the test starts.
	prewarmed  prewarmRing
	prewarmDur time.Duration

	// Per-virtual-user persistent protocol sessions (guarded by sessMu).
	// Each worker goroutine exclusively touches its own index during the run;
	// the mutex protects the teardown path in closeSessions.
	sessMu     sync.Mutex
	wsConns    map[int]*websocket.Conn
	wsURLs     map[int]string
	tcpConns   map[int]net.Conn
	cookieJars map[int]http.CookieJar
	// grpcConns holds shared ClientConns keyed by target (all workers).
	grpcConns map[string]*grpc.ClientConn

	capture ResponseCapture

	pool    []string
	poolIdx atomic.Int64
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
	transport := newTransport(keepAlive, maxConns)

	// For constant-rps mode, the token bucket starts at rate 0 and is
	// dynamically updated by the controller during ramp-up.
	// For other profiles a non-positive RPS means unlimited throughput:
	// no limiter is installed so workers never block on the bucket.
	var limiter *tokenBucket
	if _, ok := profile.(*constantRPSProfile); ok {
		limiter = newTokenBucket(0)
	} else if scenario.Profile.RPS > 0 {
		limiter = newTokenBucket(scenario.Profile.RPS)
	}

	e := &Engine{
		scenario: scenario,
		profile:  profile,
		client: &http.Client{
			Transport:     transport,
			Timeout:       time.Duration(scenario.Profile.Timeout) * time.Second,
			CheckRedirect: checkRedirect,
		},
		transport: transport,
		timeout:   time.Duration(scenario.Profile.Timeout) * time.Second,
		keepAlive: keepAlive,
		limiter:   limiter,
		signal:    newBroadcast(),
		startGate: make(chan struct{}),
		gate:      scenario.Profile.Gate,
	}
	e.stepStats = make([]*metrics.StepStats, len(scenario.Steps))
	for i, step := range scenario.Steps {
		e.stepStats[i] = metrics.NewStepStats(step.Name)
	}
	return e, nil
}

// preWarmTargetURL returns the resolved URL to use for connection pre-warming.
// It picks the first HTTP step's full URL.
func (e *Engine) preWarmTargetURL() string {
	for _, step := range e.scenario.Steps {
		if step.Type == "" || step.Type == "http" {
			u := step.URL
			if e.scenario.BaseURL != "" {
				u = strings.TrimRight(e.scenario.BaseURL, "/") + "/" + strings.TrimLeft(u, "/")
			}
			return u
		}
	}
	if e.scenario.BaseURL != "" {
		return e.scenario.BaseURL
	}
	return ""
}

// preWarmConnections opens count TCP+TLS connections to the target before the
// test starts, eliminating handshake latency from the first request each virtual
// user sends. Each connection gets its own http.Transport and http.Client stored
// in a lock-free ring buffer for round-robin distribution.
func (e *Engine) preWarmConnections(count int) {
	target := e.preWarmTargetURL()
	if target == "" || count <= 0 {
		return
	}

	// Quick TCP reachability check before spawning goroutines.
	parsed, err := url.Parse(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Pre-warm: bad URL %s: %v\n", target, err)
		return
	}
	host := parsed.Host
	conn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Pre-warm: cannot reach %s: %v\n", host, err)
		return
	}
	conn.Close()

	ring := &prewarmRing{clients: make([]*prewarmClient, count)}
	done := make(chan struct{}, count)
	sem := make(chan struct{}, 64) // limit concurrency

	for i := 0; i < count; i++ {
		sem <- struct{}{}
		go func(idx int) {
			defer func() { <-sem; done <- struct{}{} }()

			transport := &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          1,
				MaxIdleConnsPerHost:   1,
				MaxConnsPerHost:       1,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: time.Second,
				TLSClientConfig: &tls.Config{
					MinVersion:         tls.VersionTLS12,
					ClientSessionCache: tls.NewLRUClientSessionCache(0),
				},
			}
			client := &http.Client{
				Transport:     transport,
				Timeout:       e.timeout,
				CheckRedirect: checkRedirect,
			}
			// Trigger the actual TCP+TLS handshake by issuing a HEAD
			// request. The response is discarded; the connection is what
			// matters — it will be reused by Go's transport pool.
			resp, err := client.Head(target)
			if err != nil {
				transport.CloseIdleConnections()
				ring.clients[idx] = nil
				return
			}
			resp.Body.Close()
			ring.clients[idx] = &prewarmClient{client: client, transport: transport}
		}(i)
	}
	for i := 0; i < count; i++ {
		<-done
	}

	// Remove any failed slots.
	var active []*prewarmClient
	for _, pc := range ring.clients {
		if pc != nil {
			active = append(active, pc)
		}
	}
	ring.clients = active
	// Install only the client slice: assigning the whole struct would copy
	// the atomic counter inside prewarmRing (a lock value).
	e.prewarmed.clients = ring.clients
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

	e.capture = opts.Capture
	e.pool = opts.Pool

	e.teleMu.Lock()
	e.telemetry = metrics.NewTelemetry()
	e.teleMu.Unlock()
	if e.scenario.Profile.Warmup > 0 {
		e.telemetry.SetWarmup(time.Duration(e.scenario.Profile.Warmup) * time.Second)
	}
	for _, st := range e.stepStats {
		e.telemetry.AddStep(st)
	}

	initialTarget := e.profile.ConcurrencyAt(0)
	e.target.Store(int64(initialTarget))
	e.telemetry.ActiveUsers.Store(int64(initialTarget))

	// Pre-warm TCP+TLS connections before starting workers so the first
	// request from each virtual user skips the handshake penalty.
	if e.scenario.PreWarm {
		connCount := e.scenario.PreWarmConnections
		if connCount <= 0 {
			connCount = e.profile.MaxConcurrency()
		}
		fmt.Fprintf(out, "Pre-warming %d connections... ", connCount)
		pwStart := time.Now()
		e.preWarmConnections(connCount)
		e.prewarmDur = time.Since(pwStart)
		fmt.Fprintf(out, "done (%s)\n", e.prewarmDur.Round(time.Millisecond))
	}

	if !opts.Quiet {
		e.progress = opts.Progress
		if e.progress == nil {
			e.progress = newProgressTracker(e.profile.Duration(), e.profile.MaxConcurrency(), out)
		}
	}

	// Per-second timeline sampling (used for CSV export and trend analysis).
	samplerDone := make(chan struct{})
	metrics.StartSampling(e.telemetry, &e.telemetry.Timeline, samplerDone)

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

	if e.gate {
		go func() {
			time.Sleep(150 * time.Millisecond)
			close(e.startGate)
		}()
	} else {
		go e.controller(runCtx)
	}

	drained := make(chan struct{})
	go func() {
		wg.Wait()
		close(drained)
	}()

	if e.gate {
		<-drained
		runCancel()
	} else {
		<-runCtx.Done()
		runCancel()
		select {
		case <-drained:
		case <-time.After(e.timeout):
			reqCancel()
			<-drained
		}
	}

	if e.progress != nil {
		e.progress.Finish()
	}
	close(samplerDone)
	// Capture the final partial second so short runs are not empty.
	e.telemetry.Timeline.Record(metrics.TimelineSample{
		Second:      int(e.telemetry.Elapsed().Seconds()) + 1,
		Requests:    e.telemetry.TotalRequests(),
		Errors:      e.telemetry.TotalErrors(),
		ActiveUsers: e.telemetry.ActiveUsers.Load(),
	})
	e.closeSessions()
	e.prewarmed.closeAll()
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

			// For constant-rps, dynamically adjust the token bucket rate.
			if crps, ok := e.profile.(*constantRPSProfile); ok {
				newRPS := crps.TargetRPSAt(elapsed)
				e.targetRPS.Store(int64(newRPS))
				if e.limiter != nil {
					e.limiter.setRate(newRPS)
				}
			}
		}
	}
}

func (e *Engine) runIteration(reqBase context.Context, userIndex int) {
	vars := newVars(e.scenario, userIndex)
	if len(e.pool) > 0 {
		idx := e.poolIdx.Add(1) - 1
		vars["pool"] = e.pool[int(idx%int64(len(e.pool)))]
	}
	iterStart := time.Now()
	record := e.telemetry.Recording()
	var lastStatus int
	var firstErr string
	for i, step := range e.scenario.Steps {
		res := e.runStepForUser(reqBase, step, vars, userIndex)
		if record {
			e.stepStats[i].Record(res.latency, res.status, res.errName)
		}
		if res.errName != "" {
			if firstErr == "" {
				firstErr = res.errName
			}
			break
		}
		lastStatus = res.status
	}
	if record {
		e.telemetry.Overall.Record(time.Since(iterStart), lastStatus, firstErr)
	}
	if e.progress != nil {
		e.progress.Update(
			e.telemetry.TotalRequests(),
			e.telemetry.TotalErrors(),
			time.Since(iterStart),
		)
	}
}

// runStep dispatches one step to the matching protocol client. It is kept for
// library compatibility and runs without per-user session pooling.
func (e *Engine) runStep(ctx context.Context, step config.Step, vars map[string]string) stepResult {
	return e.runStepForUser(ctx, step, vars, -1)
}

func (e *Engine) runStepForUser(ctx context.Context, step config.Step, vars map[string]string, userIndex int) stepResult {
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
		res, body = e.wsClientForUser(userIndex, ctx, fullURL, step, vars, timeout)
	case "grpc":
		if step.GrpcMethod != "" {
			res, body = e.grpcMethodClient(ctx, fullURL, step, vars, timeout)
		} else {
			res, body = e.grpcClient(ctx, fullURL, timeout)
		}
	case "tcp", "udp":
		res, body = e.rawClientForUser(userIndex, ctx, step.Type, fullURL, step, vars, timeout)
	case "tep":
		res, body = e.tepClient(ctx, step, timeout)
	default:
		res, body = e.httpClientForUser(userIndex, ctx, fullURL, step, vars, timeout)
	}
	if res.errName == "" && len(step.Assertions) > 0 {
		if err := checkAssertions(step.Assertions, res.status, body); err != nil {
			res.errName = errAssert
		}
	}
	if e.capture != nil && res.errName != errCanceled {
		e.capture.Record(CapturedResponse{
			Step:   step.Name,
			Method: step.Method,
			URL:    fullURL,
			Status: res.status,
			Err:    res.errName,
			Body:   body,
		})
	}
	return res
}

func (e *Engine) httpClient(ctx context.Context, fullURL string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	return e.httpClientForUser(-1, ctx, fullURL, step, vars, timeout)
}

// cookieJarFor returns (lazily creating) the per-virtual-user cookie jar used
// to carry login sessions across scenario steps. Jars only exist when
// keep-alive is enabled; without it every request is a fresh session.
func (e *Engine) cookieJarFor(userIndex int) http.CookieJar {
	if userIndex < 0 || !e.keepAlive {
		return nil
	}
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	if e.cookieJars == nil {
		e.cookieJars = make(map[int]http.CookieJar)
	}
	if jar, ok := e.cookieJars[userIndex]; ok {
		return jar
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil
	}
	e.cookieJars[userIndex] = jar
	return jar
}

// dropCookieJar discards the session cookies of one virtual user.
func (e *Engine) dropCookieJar(userIndex int) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	delete(e.cookieJars, userIndex)
}

// httpClientForUser performs one HTTP exchange. When a per-user cookie jar is
// active, Set-Cookie responses are stored and replayed on later requests,
// enabling realistic multi-step authenticated flows.
func (e *Engine) httpClientForUser(userIndex int, ctx context.Context, fullURL string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
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
	client := e.clientForJar(e.cookieJarFor(userIndex), timeout)
	// Prefer a pre-warmed client (established TCP+TLS) when no per-user
	// cookie jar is required; the round-robin ring distributes them evenly.
	if client == e.client {
		if pw := e.prewarmed.get(); pw != nil {
			client = pw
		}
	}
	resp, err := client.Do(req)
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

	var uerr *url.Error
	if errors.As(err, &uerr) {
		err = uerr.Unwrap()
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return stepResult{latency: elapsed, errName: errTimeout}
		}
		return stepResult{latency: elapsed, errName: errConnection}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return stepResult{latency: elapsed, errName: errConnection}
	}
	return stepResult{latency: elapsed, errName: errOther}
}
