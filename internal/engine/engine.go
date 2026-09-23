package engine

import (
	"context"
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
	"github.com/asadbekabdulboqiyev/stress-strike/internal/fingerprint"
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
	sessMu   sync.Mutex
	wsConns  map[int]*websocket.Conn
	wsURLs   map[int]string
	tcpConns map[int]net.Conn
	// cookieJars and jarClients are parallel, lock-free slices indexed by
	// virtual user (0..MaxConcurrency-1). They are pre-allocated and fully
	// populated in Run() before any worker starts, so the hot request path is
	// a single slice read with no mutex — the previous global sessMu lock on
	// every request was the throughput bottleneck at 100k+ RPS. The slices
	// are structurally frozen during a run; the lazy fallback (direct library
	// use, or a jar dropped via dropCookieJar) takes sessMu and is never on
	// the hot path. Per-index writes are owned by exactly one worker.
	cookieJars []http.CookieJar
	jarClients []*http.Client
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
	transport := newTransport(keepAlive, maxConns, fingerprint.Profile(scenario.Profile.TLSFingerprint))
	// Explicit http2: false (or --no-http2) pins the transport to HTTP/1.1.
	applyHTTP2Preference(transport, scenario.Profile.HTTP2Enabled())

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

			transport := baseTransport(true, fingerprint.Profile(e.scenario.Profile.TLSFingerprint))
			transport.MaxIdleConns = 1
			transport.MaxIdleConnsPerHost = 1
			transport.MaxConnsPerHost = 1
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
	// Fresh run: clear stop_on_status state from any previous run on this
	// Engine instance (library reuse), and release the package-level flag
	// registry entry when this run completes.
	e.stopFlag().reset()
	defer stopFlags.Delete(e)

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
	// Pre-create per-user cookie jars (and their bound clients) before any
	// worker starts so the hot request path is a lock-free slice read. The
	// extra slot (+1) guards any index that reaches exactly MaxConcurrency.
	e.precreateJars(maxUsers + 1)
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

	// Early termination: when stop_on_status fires, close the run window
	// immediately instead of spinning no-op workers for the remaining
	// duration (saves CPU and gives CI an accurate elapsed time).
	go func() {
		select {
		case <-e.stopFlag().notifyChan():
			runCancel()
		case <-runCtx.Done():
		}
	}()

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
	// stop_on_status fired in an earlier iteration → the whole run is halted;
	// every subsequent iteration is a no-op until the run window ends.
	if e.stopFlag().armed() {
		return
	}
	vars := newVars(e.scenario, userIndex)
	if len(e.pool) > 0 {
		idx := e.poolIdx.Add(1) - 1
		vars["pool"] = e.pool[int(idx%int64(len(e.pool)))]
	}
	iterStart := time.Now()
	record := e.telemetry.Recording()
	state := &flowState{}
	e.runStepSequence(reqBase, e.scenario.Steps, vars, userIndex, -1, 0, state)
	if state.stopRun {
		e.stopFlag().mark("stop_on_status fired")
	}
	if record {
		e.telemetry.Overall.Record(time.Since(iterStart), state.lastStatus, state.firstErr)
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

// newCookieJar builds a fresh per-user cookie jar. cookiejar.New is cheap
// (no I/O, no allocations beyond one empty map), so pre-creating one per
// virtual user in Run is negligible.
func newCookieJar() http.CookieJar {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil
	}
	return jar
}

// precreateJars pre-allocates and fully populates the per-user cookie jars
// (and their bound clients) for indexes 0..n-1. It runs in Run() before any
// worker goroutine starts, so the slices become structurally frozen and the
// hot request path never grows or mutates them — no lock required during a
// run. If a previous library call already created some sessions (e.g. direct
// cookieJarFor use), those are preserved and the remaining slots filled.
func (e *Engine) precreateJars(n int) {
	if n <= 0 {
		return
	}
	if len(e.cookieJars) < n || len(e.jarClients) < n {
		jars := make([]http.CookieJar, n)
		clients := make([]*http.Client, n)
		copy(jars, e.cookieJars)
		copy(clients, e.jarClients)
		e.cookieJars = jars
		e.jarClients = clients
	}
	for i := 0; i < n; i++ {
		if e.cookieJars[i] != nil {
			continue
		}
		jar := newCookieJar()
		e.cookieJars[i] = jar
		if jar != nil {
			e.jarClients[i] = &http.Client{
				Transport:     e.transport,
				Jar:           jar,
				Timeout:       e.timeout,
				CheckRedirect: checkRedirect,
			}
		}
	}
}

// ensureUserSession lazily builds the cookie jar (+bound client) for one
// virtual user. Callers must have missed the lock-free fast path; this is the
// cold path only (direct library use before Run, or a slot dropped by
// dropCookieJar). It takes sessMu because it may grow the slices; during a
// run the fast path always hits, so workers never serialize here.
func (e *Engine) ensureUserSession(userIndex int) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	need := userIndex + 1
	if len(e.cookieJars) < need || len(e.jarClients) < need {
		jars := make([]http.CookieJar, need)
		clients := make([]*http.Client, need)
		copy(jars, e.cookieJars)
		copy(clients, e.jarClients)
		e.cookieJars = jars
		e.jarClients = clients
	}
	if e.cookieJars[userIndex] != nil {
		return
	}
	jar := newCookieJar()
	if jar == nil {
		return
	}
	e.cookieJars[userIndex] = jar
	e.jarClients[userIndex] = &http.Client{
		Transport:     e.transport,
		Jar:           jar,
		Timeout:       e.timeout,
		CheckRedirect: checkRedirect,
	}
}

// cookieJarFor returns the per-virtual-user cookie jar used to carry login
// sessions across scenario steps. Jars only exist when keep-alive is enabled;
// without it every request is a fresh session. The fast path is a single
// slice read with no lock — the previous implementation took the global
// sessMu for every request, serializing all workers at high concurrency.
func (e *Engine) cookieJarFor(userIndex int) http.CookieJar {
	if userIndex < 0 || !e.keepAlive {
		return nil
	}
	jars := e.cookieJars
	if userIndex < len(jars) {
		if jar := jars[userIndex]; jar != nil {
			return jar
		}
	}
	// Miss: not pre-created yet or the slot was dropped. Cold path only.
	e.ensureUserSession(userIndex)
	if userIndex < len(e.cookieJars) {
		return e.cookieJars[userIndex]
	}
	return nil
}

// dropCookieJar discards the session cookies of one virtual user. Its slot is
// set to nil and a fresh jar (and client) is lazily recreated on the user's
// next request. Per-index writes are safe because a user index is owned by
// exactly one worker goroutine during a run — callers must follow that
// invariant (never drop another worker's index concurrently).
func (e *Engine) dropCookieJar(userIndex int) {
	if userIndex < 0 || !e.keepAlive {
		return
	}
	if userIndex < len(e.cookieJars) {
		e.cookieJars[userIndex] = nil
	}
	if userIndex < len(e.jarClients) {
		e.jarClients[userIndex] = nil
	}
}

// readBodyPooled drains r into a pooled buffer, reading at most bodyReadLimit
// bytes (same limit as before). The returned *ReusableBuffer must be released
// with ReleaseBuffer once its bytes are no longer needed; callers that need
// the body to outlive the buffer must copy it first. hint is a Content-Length
// hint so the pool picks an appropriately sized tier on the first read.
func readBodyPooled(r io.Reader, hint int) (*ReusableBuffer, error) {
	rb := GetBufferMin(hint)
	buf := rb.Bytes()[:0]
	total := 0
	for {
		avail := cap(buf) - total
		if avail <= 0 {
			// Body larger than the biggest pool tier: read the remainder into
			// a fresh slice (a rare path that the pool intentionally does not
			// absorb; ReleaseBuffer still handles it via put's default case).
			rest, err := io.ReadAll(io.LimitReader(r, int64(bodyReadLimit-total)))
			if err != nil {
				return rb, err
			}
			buf = append(buf, rest...)
			rb.buf = buf
			return rb, nil
		}
		n, err := r.Read(buf[total:cap(buf)])
		total += n
		buf = buf[:total]
		if err != nil {
			if err == io.EOF {
				break
			}
			return rb, err
		}
		if total >= bodyReadLimit {
			break
		}
	}
	rb.buf = buf
	return rb, nil
}

// httpClientForUser performs one HTTP exchange. When a per-user cookie jar is
// active, Set-Cookie responses are stored and replayed on later requests,
// enabling realistic multi-step authenticated flows. The response body is
// read through the tiered buffer pool (see buffer_pool.go) so the hot path
// performs zero heap allocations for typical small responses; assertion and
// extract logic is unchanged.
func (e *Engine) httpClientForUser(userIndex int, ctx context.Context, fullURL string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	// http.Client.Timeout already bounds every exchange with e.timeout, so a
	// per-request context (one allocation) is only created when a step
	// overrides the timeout. Skipping it on the common path removes a
	// context.WithTimeout allocation per request.
	reqCtx := ctx
	cancel := func() {}
	if step.Timeout > 0 {
		reqCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	var body io.Reader
	if step.Body != "" {
		body = strings.NewReader(renderBody(step.Body, vars))
	}

	req, err := http.NewRequestWithContext(reqCtx, step.Method, fullURL, body)
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
	client := e.clientForJar(userIndex)
	// Prefer a pre-warmed client (established TCP+TLS) when no per-user
	// cookie jar is required; the round-robin ring distributes them evenly.
	if client == e.client {
		if pw := e.prewarmed.get(); pw != nil {
			client = pw
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return classifyError(err, time.Since(start)), nil
	}
	defer resp.Body.Close()

	// The body only needs to outlive this function when the caller will run
	// assertions or capture against it. In the common benchmark path (no
	// assertions, no capture) the body is drained into a pooled buffer and
	// discarded, which keeps the keep-alive connection reusable without a
	// single heap allocation.
	needBody := e.capture != nil || len(step.Assertions) > 0

	hint := 0
	if resp.ContentLength > 0 && resp.ContentLength < int64(bodyReadLimit) {
		hint = int(resp.ContentLength)
	}
	pooled, readErr := readBodyPooled(resp.Body, hint)
	if readErr != nil {
		res := classifyError(readErr, time.Since(start))
		ReleaseBuffer(pooled)
		return res, nil
	}

	status := resp.StatusCode
	var errName string
	switch {
	case status >= 500:
		errName = errStatus5xx
	case status >= 400:
		errName = errStatus4xx
	}
	if errName == "" {
		for _, ex := range step.Extract {
			value, exErr := extractValue(ex.From, ex.Path, pooled.Bytes(), resp.Header.Get(ex.Path))
			if exErr != nil {
				errName = errExtract
				break
			}
			vars[ex.Name] = value
		}
	}
	latency := time.Since(start)

	if needBody {
		// Copy before returning the buffer to the pool: assertions/capture
		// run in the caller and must see the exact body bytes.
		bodyCopy := append([]byte(nil), pooled.Bytes()...)
		ReleaseBuffer(pooled)
		return stepResult{latency: latency, status: status, errName: errName}, bodyCopy
	}
	// No consumer — release the pooled buffer. Returning a nil body here is
	// safe: with no assertions and no capture the caller never touches it.
	ReleaseBuffer(pooled)
	return stepResult{latency: latency, status: status, errName: errName}, nil
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
