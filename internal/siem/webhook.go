// Package siem provides a durable SIEM event notifier.
//
// The notifier offers at-least-once delivery: Send enqueues events into a
// bounded in-memory queue without blocking, background workers POST them to a
// webhook with exponential-backoff retries, and any event that exhausts its
// retries (or is rejected because the buffer is full) is appended to an
// on-disk spool so an operator can replay it later with ReplaySpool. Events
// are therefore never silently dropped.
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Event is a minimal SIEM event.
type Event struct {
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Severity  string            `json:"severity"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// Sentinel errors.
var (
	// ErrBufferFull is returned by Send when the bounded in-memory queue is
	// full. The event has already been counted as Dropped and spooled (when a
	// SpoolDir is configured); the caller decides whether to retry or give up.
	ErrBufferFull = errors.New("siem: notifier buffer full")
	// ErrClosed is returned by Send after the notifier has been closed.
	ErrClosed = errors.New("siem: notifier closed")
)

// Defaults applied by New for zero-valued Config fields.
const (
	defaultTimeout      = 5 * time.Second
	defaultMaxRetries   = 3
	defaultBaseBackoff  = 100 * time.Millisecond
	defaultMaxBackoff   = 5 * time.Second
	defaultBufferSize   = 1024
	defaultWorkers      = 2
	defaultCloseTimeout = 30 * time.Second
	// maxRetryAfter bounds a server-supplied Retry-After so a hostile or
	// misconfigured endpoint cannot park a worker for an unbounded time.
	maxRetryAfter = time.Hour
)

// Config configures a Notifier.
type Config struct {
	// URL is the webhook endpoint. When empty the notifier is a no-op that
	// still records Stats.
	URL string
	// Headers are added to every request (Content-Type defaults to
	// application/json unless overridden here).
	Headers map[string]string
	// Timeout bounds a single HTTP attempt. Defaults to 5s.
	Timeout time.Duration
	// MaxRetries is the number of *retries* after the initial attempt, so a
	// single event results in at most MaxRetries+1 HTTP requests. Defaults to 3.
	MaxRetries int
	// BaseBackoff is the first backoff interval. Defaults to 100ms.
	BaseBackoff time.Duration
	// MaxBackoff caps the exponential backoff. Defaults to 5s.
	MaxBackoff time.Duration
	// BufferSize is the bounded in-memory queue capacity. Defaults to 1024.
	BufferSize int
	// SpoolDir, when set, receives JSON-lines spool files for undeliverable
	// events.
	SpoolDir string
	// Client overrides the default HTTP client.
	Client *http.Client
}

// Stats is a snapshot of the durable sink's counters. All fields are read
// atomically, so a snapshot may be very slightly inconsistent across fields but
// never torn.
//
// Field meanings for both Notifier and Sink:
//
//	Emitted   events accepted for delivery (queued in the ring or spooled)
//	Delivered events the SIEM endpoint accepted (2xx)
//	Failed    events whose delivery exhausted the retry budget
//	Dropped   events discarded without delivery and without being spooled
//	Spooled   events persisted to the disk spool
//	Retried   retry attempts performed (not events)
type Stats struct {
	Emitted   uint64
	Delivered uint64
	Failed    uint64
	Dropped   uint64
	Spooled   uint64
	Retried   uint64
}

// Notifier is a durable, retrying SIEM webhook notifier. It is safe for
// concurrent use.
type Notifier struct {
	cfg    Config
	client *http.Client

	ch      chan Event
	baseCtx context.Context
	quit    chan struct{}

	startOnce sync.Once
	closeOnce sync.Once
	wg        sync.WaitGroup

	spoolMu sync.Mutex

	closed  uint32
	pending int64

	enqueued uint64
	sent     uint64
	failed   uint64
	dropped  uint64
	spooled  uint64
	retried  uint64
}

// New builds a Notifier from cfg, filling in defaults. Call Start to begin
// delivering queued events (Send/Flush/Close will start it lazily if needed).
func New(cfg Config) *Notifier {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = defaultBaseBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if cfg.MaxBackoff < cfg.BaseBackoff {
		cfg.MaxBackoff = cfg.BaseBackoff
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = defaultBufferSize
	}

	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}

	return &Notifier{
		cfg:     cfg,
		client:  client,
		ch:      make(chan Event, cfg.BufferSize),
		baseCtx: context.Background(),
		quit:    make(chan struct{}),
	}
}

// Send enqueues ev without blocking. It returns ErrBufferFull when the bounded
// queue is full (the event is counted as Dropped and spooled, and the caller
// may decide to retry) and ErrClosed after Close. A notifier with an empty URL
// is a no-op that still updates Stats.
func (n *Notifier) Send(ctx context.Context, ev Event) error {
	if n.cfg.URL == "" {
		atomic.AddUint64(&n.enqueued, 1)
		atomic.AddUint64(&n.sent, 1)
		return nil
	}
	if atomic.LoadUint32(&n.closed) == 1 {
		return ErrClosed
	}

	select {
	case n.ch <- ev:
		atomic.AddUint64(&n.enqueued, 1)
		atomic.AddInt64(&n.pending, 1)
		return nil
	default:
		atomic.AddUint64(&n.dropped, 1)
		n.spoolEvent(ev)
		return ErrBufferFull
	}
}

// TrySend delivers ev synchronously, performing the initial attempt plus any
// retries inline, and returns the final error (nil on success). It does not use
// the buffered queue and updates Stats the same way a worker would.
func (n *Notifier) TrySend(ctx context.Context, ev Event) error {
	return n.deliver(ctx, ev, true)
}

// emit is the Sink hot path. It never blocks on network I/O and never allocates
// a goroutine:
//
//   - enqueue into the bounded ring, starting the workers lazily; or
//   - when the ring is full and a SpoolDir is configured, spill the event to
//     disk instead of dropping it; or
//   - when the ring is full and no spool is configured, count the event Dropped
//     and report ErrBufferFull.
//
// Unlike Send, a spilled event is counted as Emitted+Spooled rather than
// Dropped, because nothing was discarded.
func (n *Notifier) emit(ev Event) error {
	if atomic.LoadUint32(&n.closed) == 1 {
		return ErrClosed
	}

	select {
	case n.ch <- ev:
		atomic.AddUint64(&n.enqueued, 1)
		atomic.AddInt64(&n.pending, 1)
		n.Start() // idempotent; ensures a consumer exists
		return nil
	default:
	}

	if n.cfg.SpoolDir != "" && n.spoolEvent(ev) {
		atomic.AddUint64(&n.enqueued, 1)
		return nil
	}

	atomic.AddUint64(&n.dropped, 1)
	return ErrBufferFull
}

// Start launches the background worker goroutines. It is idempotent and a no-op
// for an empty-URL notifier.
func (n *Notifier) Start() {
	if n.cfg.URL == "" {
		return
	}
	n.startOnce.Do(func() {
		for i := 0; i < defaultWorkers; i++ {
			n.wg.Add(1)
			go n.worker()
		}
	})
}

// Flush blocks until every queued event has been processed, or until ctx is
// done (returning ctx.Err()). It starts the workers if they are not running.
func (n *Notifier) Flush(ctx context.Context) error {
	n.Start()
	for {
		if atomic.LoadInt64(&n.pending) <= 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

// Close flushes queued events, stops the workers, and sweeps anything that was
// enqueued concurrently. It is idempotent and always safe to call.
func (n *Notifier) Close() error {
	n.Start()

	flushCtx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	err := n.Flush(flushCtx)

	n.shutdown()
	return err
}

// shutdown stops the workers and spools anything still queued. It is idempotent
// and does not flush: callers that care about draining within a deadline should
// Flush first (this is what Sink.Close does).
func (n *Notifier) shutdown() {
	n.closeOnce.Do(func() {
		atomic.StoreUint32(&n.closed, 1)
		close(n.quit)
	})
	n.wg.Wait()

	// Final sweep: a Send that raced past the closed check must not be lost.
	for {
		select {
		case ev := <-n.ch:
			atomic.AddInt64(&n.pending, -1)
			atomic.AddUint64(&n.dropped, 1)
			n.spoolEvent(ev)
		default:
			return
		}
	}
}

// Stats returns a snapshot of the notifier counters.
func (n *Notifier) Stats() Stats {
	return Stats{
		Emitted:   atomic.LoadUint64(&n.enqueued),
		Delivered: atomic.LoadUint64(&n.sent),
		Failed:    atomic.LoadUint64(&n.failed),
		Dropped:   atomic.LoadUint64(&n.dropped),
		Spooled:   atomic.LoadUint64(&n.spooled),
		Retried:   atomic.LoadUint64(&n.retried),
	}
}

// worker drains the queue until Close signals shutdown.
func (n *Notifier) worker() {
	defer n.wg.Done()
	for {
		select {
		case ev := <-n.ch:
			n.process(ev)
		case <-n.quit:
			for {
				select {
				case ev := <-n.ch:
					n.process(ev)
				default:
					return
				}
			}
		}
	}
}

func (n *Notifier) process(ev Event) {
	_ = n.deliver(n.baseCtx, ev, true)
	atomic.AddInt64(&n.pending, -1)
}

// deliver performs one logical delivery of ev. spool controls whether an
// exhausted event is written to the spool file (ReplaySpool manages the file
// itself and passes false).
func (n *Notifier) deliver(ctx context.Context, ev Event, spool bool) error {
	if n.cfg.URL == "" {
		atomic.AddUint64(&n.sent, 1)
		return nil
	}

	err := n.sendWithRetries(ctx, ev)
	if err != nil {
		atomic.AddUint64(&n.failed, 1)
		if spool {
			n.spoolEvent(ev)
		}
		return err
	}
	atomic.AddUint64(&n.sent, 1)
	return nil
}

// sendWithRetries POSTs ev, retrying per the configured policy.
func (n *Notifier) sendWithRetries(ctx context.Context, ev Event) error {
	var lastErr error
	for attempt := 0; ; attempt++ {
		res, err := n.post(ctx, ev)
		if err == nil {
			return nil
		}
		lastErr = err

		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt >= n.cfg.MaxRetries || !shouldRetry(res, err) {
			return lastErr
		}

		delay := backoff(attempt+1, n.cfg.BaseBackoff, n.cfg.MaxBackoff, randFloat())
		switch res.status {
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			if d, ok := parseRetryAfter(res.retryAfterRaw); ok {
				if d > maxRetryAfter {
					d = maxRetryAfter
				}
				delay = d
			}
		}

		atomic.AddUint64(&n.retried, 1)
		if err := sleepCtx(ctx, delay); err != nil {
			return err
		}
	}
}

// attemptResult captures the parts of an HTTP response the retry policy needs.
type attemptResult struct {
	status        int
	retryAfterRaw string
}

// post performs a single HTTP POST of ev. A non-2xx response is reported as an
// error together with its status so the caller can decide whether to retry.
func (n *Notifier) post(ctx context.Context, ev Event) (attemptResult, error) {
	body, err := json.Marshal(ev)
	if err != nil {
		return attemptResult{}, fmt.Errorf("siem: marshal event: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, n.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, n.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return attemptResult{}, fmt.Errorf("siem: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range n.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return attemptResult{}, fmt.Errorf("siem: post: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	res := attemptResult{status: resp.StatusCode, retryAfterRaw: resp.Header.Get("Retry-After")}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return res, fmt.Errorf("siem: webhook returned %s", resp.Status)
	}
	return res, nil
}

// shouldRetry reports whether an attempt should be retried: network errors and
// 5xx/429 responses are retryable, other 4xx responses are not.
func shouldRetry(res attemptResult, err error) bool {
	if err == nil {
		return false
	}
	if res.status == 0 {
		// Transport/network error: no response was received.
		return true
	}
	if res.status >= 500 || res.status == http.StatusTooManyRequests {
		return true
	}
	return false
}

// backoff returns an exponentially increasing delay with full jitter: the
// result is a uniform random value in [0, min(base*2^(attempt-1), max)]. r must
// be in [0, 1] (values outside are clamped).
func backoff(attempt int, base, max time.Duration, r float64) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if base <= 0 {
		base = defaultBaseBackoff
	}
	if max <= 0 {
		max = defaultMaxBackoff
	}
	if max < base {
		max = base
	}

	d := float64(base) * float64(int64(1)<<uint(min(attempt-1, 62))) //nolint:gosec // attempt-1 is clamped to [0,62]
	if d > float64(max) {
		d = float64(max)
	}
	if r < 0 {
		r = 0
	}
	if r > 1 {
		r = 1
	}
	return time.Duration(r * d)
}

func randFloat() float64 { return rand.Float64() } //nolint:gosec // backoff jitter only; not security-sensitive

// sleepCtx sleeps for d, returning early if ctx is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
