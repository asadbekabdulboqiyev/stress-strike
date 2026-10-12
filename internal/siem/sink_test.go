package siem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// --- test doubles ---

// sinkFlakyServer is a controllable SIEM endpoint: it can fail the first N
// requests, be put into an always-fail mode, delay responses, and report how
// many requests it has seen.
type sinkFlakyServer struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests int
	failN    int
	fail     bool
	status   int
	delay    time.Duration
}

func newSinkFlakyServer(failN int) *sinkFlakyServer {
	s := &sinkFlakyServer{failN: failN, status: http.StatusOK}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *sinkFlakyServer) handle(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	_ = r.Body.Close()

	s.mu.Lock()
	delay := s.delay
	s.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}

	s.mu.Lock()
	s.requests++
	n := s.requests
	shouldFail := s.fail || n <= s.failN
	st := s.status
	s.mu.Unlock()

	if shouldFail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(st)
}

func (s *sinkFlakyServer) URL() string { return s.srv.URL }

func (s *sinkFlakyServer) Close() { s.srv.Close() }

func (s *sinkFlakyServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *sinkFlakyServer) setFail(v bool) {
	s.mu.Lock()
	s.fail = v
	s.mu.Unlock()
}

func (s *sinkFlakyServer) setDelay(d time.Duration) {
	s.mu.Lock()
	s.delay = d
	s.mu.Unlock()
}

// sinkTestLogger records everything logged through the Sink's Logger hook.
type sinkTestLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *sinkTestLogger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *sinkTestLogger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// --- construction ---

func TestSinkNewRejectsEmptyURL(t *testing.T) {
	if _, err := NewSink(SinkConfig{}); !errors.Is(err, ErrNoURL) {
		t.Fatalf("NewSink(empty URL) err = %v, want ErrNoURL", err)
	}
	if _, err := NewSink(SinkConfig{URL: "   "}); !errors.Is(err, ErrNoURL) {
		t.Fatalf("NewSink(blank URL) err = %v, want ErrNoURL", err)
	}
}

func TestSinkNewDefaultsAndSpoolDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "nested", "spool")

	s, err := NewSink(SinkConfig{URL: "http://127.0.0.1:1", SpoolDir: dir})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("spool dir not created: %v", err)
	}
	// Default MaxAttempts is 3 total attempts, i.e. 2 retries.
	if got := s.n.cfg.MaxRetries; got != defaultSinkMaxAttempts-1 {
		t.Fatalf("default MaxRetries = %d, want %d", got, defaultSinkMaxAttempts-1)
	}

	// An explicit MaxAttempts of 1 must mean "no retries", not New's default.
	s2, err := NewSink(SinkConfig{URL: "http://127.0.0.1:1", MaxAttempts: 1})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close(context.Background()) })
	if got := s2.n.cfg.MaxRetries; got != 0 {
		t.Fatalf("MaxAttempts=1 => MaxRetries = %d, want 0", got)
	}
}

// --- delivery ---

func TestSinkRetriesThenSucceeds(t *testing.T) {
	srv := newSinkFlakyServer(2) // first two requests fail
	defer srv.Close()

	s, err := NewSink(SinkConfig{
		URL:         srv.URL(),
		MaxAttempts: 5,
		BaseBackoff: time.Millisecond,
		MaxBackoff:  2 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Emit(ctx, Event{Message: "retry me"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	st := s.Stats()
	if st.Delivered != 1 || st.Failed != 0 {
		t.Fatalf("stats = %+v, want Delivered=1 Failed=0", st)
	}
	if st.Retried != 2 {
		t.Fatalf("Retried = %d, want 2", st.Retried)
	}
	if got := srv.count(); got != 3 {
		t.Fatalf("server requests = %d, want 3", got)
	}

	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// --- spool / replay ---

func TestSinkSpoolsAndReplays(t *testing.T) {
	srv := newSinkFlakyServer(0)
	srv.setFail(true)
	defer srv.Close()

	dir := t.TempDir()
	s, err := NewSink(SinkConfig{
		URL:         srv.URL(),
		SpoolDir:    dir,
		MaxAttempts: 2,
		BaseBackoff: time.Millisecond,
		MaxBackoff:  time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Emit(ctx, Event{Message: "doomed", Severity: "high"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	st := s.Stats()
	if st.Failed != 1 {
		t.Fatalf("Failed = %d, want 1", st.Failed)
	}
	if st.Spooled < 1 {
		t.Fatalf("Spooled = %d, want >= 1", st.Spooled)
	}

	path := filepath.Join(dir, spoolFileName)
	lines := readSpoolLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("spool has %d lines, want 1", len(lines))
	}
	var ev Event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("spool line is not valid JSON: %v", err)
	}
	if ev.Message != "doomed" || ev.Severity != "high" {
		t.Fatalf("spooled event = %+v", ev)
	}

	// Flip the endpoint to success and replay the spool.
	srv.setFail(false)
	if err := s.ReplaySpool(ctx); err != nil {
		t.Fatalf("ReplaySpool: %v", err)
	}
	if got := len(readSpoolLines(t, path)); got != 0 {
		t.Fatalf("spool not drained after replay: %d line(s)", got)
	}
	if got := s.Stats().Delivered; got != 1 {
		t.Fatalf("Delivered after replay = %d, want 1", got)
	}

	// A second replay with an empty spool must not contact the server.
	before := srv.count()
	if err := s.ReplaySpool(ctx); err != nil {
		t.Fatalf("second ReplaySpool: %v", err)
	}
	if got := srv.count(); got != before {
		t.Fatalf("empty replay made %d extra request(s)", got-before)
	}

	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSinkReplaySpoolLogs(t *testing.T) {
	srv := newSinkFlakyServer(0) // always succeeds
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, spoolFileName)
	writeSpool(t, path, []Event{{Message: "one"}})

	logger := &sinkTestLogger{}
	s, err := NewSink(SinkConfig{URL: srv.URL(), SpoolDir: dir, Logger: logger})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })

	if err := s.ReplaySpool(context.Background()); err != nil {
		t.Fatalf("ReplaySpool: %v", err)
	}
	if got := len(logger.snapshot()); got == 0 {
		t.Fatal("Logger was not invoked on a successful replay")
	}
	if lines := readSpoolLines(t, path); len(lines) != 0 {
		t.Fatalf("spool not truncated: %d line(s)", len(lines))
	}
}

// --- backpressure ---

func TestSinkEmitBufferFullWithoutSpool(t *testing.T) {
	srv := newSinkFlakyServer(0)
	srv.setFail(true)
	srv.setDelay(150 * time.Millisecond)
	defer srv.Close()

	// A short client timeout keeps each of the 5 attempts fast while the
	// handler is still slow enough to keep the workers busy.
	client := &http.Client{Timeout: 50 * time.Millisecond}
	s, err := NewSink(SinkConfig{
		URL:         srv.URL(),
		Capacity:    1,
		MaxAttempts: 5,
		BaseBackoff: time.Millisecond,
		MaxBackoff:  time.Millisecond,
		HTTPClient:  client,
	})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	var full int
	for i := 0; i < 200; i++ {
		switch err := s.Emit(context.Background(), Event{Message: "flood"}); {
		case errors.Is(err, ErrBufferFull):
			full++
		case err != nil:
			t.Fatalf("Emit #%d: %v", i, err)
		}
	}
	if full == 0 {
		t.Fatal("expected at least one ErrBufferFull, got none")
	}
	if st := s.Stats(); st.Dropped == 0 {
		t.Fatalf("Dropped = 0, want > 0")
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSinkSpillsInsteadOfDropping(t *testing.T) {
	srv := newSinkFlakyServer(0)
	srv.setFail(true)
	srv.setDelay(150 * time.Millisecond)
	defer srv.Close()

	dir := t.TempDir()
	client := &http.Client{Timeout: 50 * time.Millisecond}
	s, err := NewSink(SinkConfig{
		URL:         srv.URL(),
		Capacity:    1,
		SpoolDir:    dir,
		MaxAttempts: 5,
		BaseBackoff: time.Millisecond,
		MaxBackoff:  time.Millisecond,
		HTTPClient:  client,
	})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	const total = 200
	for i := 0; i < total; i++ {
		if err := s.Emit(context.Background(), Event{Message: "spill"}); err != nil {
			t.Fatalf("Emit #%d: %v", i, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	st := s.Stats()
	if st.Dropped != 0 {
		t.Fatalf("Dropped = %d, want 0 (events must spill, not drop)", st.Dropped)
	}
	if st.Spooled == 0 {
		t.Fatal("Spooled = 0, want > 0")
	}
	if st.Emitted != total {
		t.Fatalf("Emitted = %d, want %d", st.Emitted, total)
	}

	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// --- concurrency & lifecycle ---

func TestSinkConcurrentEmitIsRaceFree(t *testing.T) {
	srv := newSinkFlakyServer(0) // always succeeds
	defer srv.Close()

	s, err := NewSink(SinkConfig{URL: srv.URL(), Capacity: 1024})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	const goroutines = 16
	const perGoroutine = 50

	var wg sync.WaitGroup
	var mu sync.Mutex
	var emitErrs int
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if err := s.Emit(context.Background(), Event{Message: fmt.Sprintf("g%d-%d", g, i)}); err != nil {
					mu.Lock()
					emitErrs++
					mu.Unlock()
				}
			}
		}(g)
	}
	wg.Wait()

	if emitErrs != 0 {
		t.Fatalf("%d Emit call(s) failed with a 1024-deep ring", emitErrs)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	st := s.Stats()
	if want := uint64(goroutines * perGoroutine); st.Emitted != want {
		t.Fatalf("Emitted = %d, want %d", st.Emitted, want)
	}
	if st.Delivered+st.Failed != st.Emitted {
		t.Fatalf("Delivered(%d)+Failed(%d) != Emitted(%d)", st.Delivered, st.Failed, st.Emitted)
	}

	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSinkCloseDrainsAndRejectsAfterClose(t *testing.T) {
	srv := newSinkFlakyServer(0)
	defer srv.Close()

	s, err := NewSink(SinkConfig{URL: srv.URL(), Capacity: 16})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	ctx := context.Background()
	const n = 5
	for i := 0; i < n; i++ {
		if err := s.Emit(ctx, Event{Message: fmt.Sprintf("e%d", i)}); err != nil {
			t.Fatalf("Emit #%d: %v", i, err)
		}
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if st := s.Stats(); st.Delivered != n || st.Failed != 0 {
		t.Fatalf("stats = %+v, want Delivered=%d Failed=0", st, n)
	}

	if err := s.Emit(ctx, Event{Message: "after close"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Emit after Close err = %v, want ErrClosed", err)
	}
	// Close is idempotent.
	if err := s.Close(closeCtx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSinkEmitCancelledContext(t *testing.T) {
	s, err := NewSink(SinkConfig{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Emit(ctx, Event{Message: "drop me"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Emit with cancelled ctx = %v, want context.Canceled", err)
	}
	if st := s.Stats(); st.Emitted != 0 {
		t.Fatalf("Emitted = %d, want 0 (event must not be accepted)", st.Emitted)
	}
}
