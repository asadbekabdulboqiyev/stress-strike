package siem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

// --- backoff / jitter ---

func TestBackoffBounds(t *testing.T) {
	base := 100 * time.Millisecond
	max := 5 * time.Second

	tests := []struct {
		name    string
		attempt int
		r       float64
		want    time.Duration
	}{
		{"attempt1 r0", 1, 0, 0},
		{"attempt1 r1", 1, 1, 100 * time.Millisecond},
		{"attempt2 r1", 2, 1, 200 * time.Millisecond},
		{"attempt3 r1", 3, 1, 400 * time.Millisecond},
		{"attempt4 r1", 4, 1, 800 * time.Millisecond},
		{"attempt5 r1", 5, 1, 1600 * time.Millisecond},
		{"attempt6 r1 capped", 6, 1, 3200 * time.Millisecond},
		{"attempt7 r1 capped", 7, 1, max},
		{"attempt100 r1 capped", 100, 1, max},
		{"attempt0 treated as 1", 0, 1, 100 * time.Millisecond},
		{"r above 1 clamps", 3, 5, 400 * time.Millisecond},
		{"r below 0 clamps", 3, -1, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := backoff(tc.attempt, base, max, tc.r)
			if got != tc.want {
				t.Fatalf("backoff(%d, %s, %s, %v) = %s, want %s", tc.attempt, base, max, tc.r, got, tc.want)
			}
		})
	}

	// Full-jitter invariant: for any r in [0,1] the delay is within
	// [0, min(base*2^(attempt-1), max)].
	for attempt := 1; attempt <= 12; attempt++ {
		upper := float64(base) * float64(int64(1)<<uint(attempt-1))
		if upper > float64(max) {
			upper = float64(max)
		}
		for i := 0; i <= 100; i++ {
			r := float64(i) / 100
			if d := backoff(attempt, base, max, r); d < 0 || float64(d) > upper {
				t.Fatalf("backoff(%d, r=%v) = %s out of bounds [0, %s]", attempt, r, d, time.Duration(upper))
			}
		}
	}

	// Zero base/max fall back to defaults rather than producing a zero delay.
	if d := backoff(3, 0, 0, 1); d != defaultBaseBackoff*4 {
		t.Fatalf("backoff defaults = %s, want %s", d, defaultBaseBackoff*4)
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"", 0, false},
		{"   ", 0, false},
		{"5", 5 * time.Second, true},
		{"0", 0, true},
		{"-1", 0, false},
		{"garbage", 0, false},
	}
	for _, tc := range tests {
		got, ok := parseRetryAfter(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("parseRetryAfter(%q) = (%s, %v), want (%s, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}

	// HTTP-date in the future is honoured; in the past is an immediate retry.
	future := time.Now().Add(2 * time.Second).UTC().Format(http.TimeFormat)
	if d, ok := parseRetryAfter(future); !ok || d <= 0 {
		t.Fatalf("parseRetryAfter(future date) = (%s, %v), want positive duration", d, ok)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if d, ok := parseRetryAfter(past); !ok || d != 0 {
		t.Fatalf("parseRetryAfter(past date) = (%s, %v), want (0, true)", d, ok)
	}
}

// --- retry semantics ---

func TestTrySendRetriesThenSucceeds(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := New(Config{
		URL:         srv.URL,
		MaxRetries:  5,
		BaseBackoff: time.Millisecond,
		MaxBackoff:  2 * time.Millisecond,
	})

	if err := notifier.TrySend(context.Background(), Event{Message: "hello"}); err != nil {
		t.Fatalf("TrySend: %v", err)
	}

	stats := notifier.Stats()
	if stats.Delivered != 1 || stats.Failed != 0 || stats.Retried != 2 {
		t.Fatalf("stats = %+v, want Sent=1 Failed=0 Retried=2", stats)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("server hits = %d, want 3", got)
	}
}

func TestTrySendExhaustsRetriesAndSpools(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	notifier := New(Config{
		URL:         srv.URL,
		MaxRetries:  2,
		BaseBackoff: time.Millisecond,
		MaxBackoff:  time.Millisecond,
		SpoolDir:    dir,
	})

	err := notifier.TrySend(context.Background(), Event{Message: "doomed"})
	if err == nil {
		t.Fatal("TrySend unexpectedly succeeded against an always-500 server")
	}

	stats := notifier.Stats()
	if stats.Failed != 1 || stats.Delivered != 0 || stats.Retried != 2 {
		t.Fatalf("stats = %+v, want Failed=1 Sent=0 Retried=2", stats)
	}

	path := filepath.Join(dir, spoolFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("spool file missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("spool file mode = %o, want 600", perm)
	}
	lines := readSpoolLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("spool has %d lines, want 1", len(lines))
	}
	var ev Event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("spool line is not valid JSON: %v", err)
	}
	if ev.Message != "doomed" {
		t.Fatalf("spooled event = %+v", ev)
	}
}

func TestTrySendDoesNotRetry4xx(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	notifier := New(Config{
		URL: srv.URL, MaxRetries: 5, BaseBackoff: time.Millisecond, MaxBackoff: time.Millisecond,
	})
	if err := notifier.TrySend(context.Background(), Event{Message: "bad"}); err == nil {
		t.Fatal("TrySend unexpectedly succeeded on 400")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("server hits = %d, want 1 (4xx must not be retried)", got)
	}
	stats := notifier.Stats()
	if stats.Retried != 0 || stats.Failed != 1 {
		t.Fatalf("stats = %+v, want Retried=0 Failed=1", stats)
	}
}

func TestTrySendRetries429AndHonoursRetryAfter(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "0") // 0s: honoured but instant
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := New(Config{
		URL: srv.URL, MaxRetries: 3, BaseBackoff: time.Millisecond, MaxBackoff: time.Millisecond,
	})
	if err := notifier.TrySend(context.Background(), Event{Message: "429"}); err != nil {
		t.Fatalf("TrySend: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("server hits = %d, want 2", got)
	}
	if s := notifier.Stats(); s.Delivered != 1 || s.Retried != 1 {
		t.Fatalf("stats = %+v, want Sent=1 Retried=1", s)
	}
}

// --- buffering ---

func TestSendBufferFull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	notifier := New(Config{
		URL:        srv.URL,
		BufferSize: 2,
		SpoolDir:   dir,
		// deliberately not started: nothing drains the queue.
	})

	ctx := context.Background()
	if err := notifier.Send(ctx, Event{Message: "1"}); err != nil {
		t.Fatalf("Send #1: %v", err)
	}
	if err := notifier.Send(ctx, Event{Message: "2"}); err != nil {
		t.Fatalf("Send #2: %v", err)
	}
	err := notifier.Send(ctx, Event{Message: "3"})
	if !errors.Is(err, ErrBufferFull) {
		t.Fatalf("Send #3 err = %v, want ErrBufferFull", err)
	}

	stats := notifier.Stats()
	if stats.Emitted != 2 || stats.Dropped != 1 {
		t.Fatalf("stats = %+v, want Enqueued=2 Dropped=1", stats)
	}
	if lines := readSpoolLines(t, filepath.Join(dir, spoolFileName)); len(lines) != 1 {
		t.Fatalf("overfull event was not spooled: %v", lines)
	}

	// Clean up: let the two queued events drain.
	if err := notifier.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSendNoURLIsNoOpButCounts(t *testing.T) {
	notifier := New(Config{})
	if err := notifier.Send(context.Background(), Event{Message: "x"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := notifier.TrySend(context.Background(), Event{Message: "y"}); err != nil {
		t.Fatalf("TrySend: %v", err)
	}
	if s := notifier.Stats(); s.Emitted != 1 || s.Delivered != 2 {
		t.Fatalf("stats = %+v, want Enqueued=1 Sent=2", s)
	}
	if err := notifier.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// --- lifecycle ---

func TestStartFlushClose(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := New(Config{URL: srv.URL, BufferSize: 64})

	// Start and Close must both be idempotent.
	notifier.Start()
	notifier.Start()

	const n = 20
	for i := 0; i < n; i++ {
		if err := notifier.Send(context.Background(), Event{Message: fmt.Sprintf("e%d", i)}); err != nil {
			t.Fatalf("Send #%d: %v", i, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := notifier.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if s := notifier.Stats(); s.Delivered != n {
		t.Fatalf("after Flush Sent = %d, want %d", s.Delivered, n)
	}

	if err := notifier.Close(); err != nil {
		t.Fatalf("Close #1: %v", err)
	}
	if err := notifier.Close(); err != nil {
		t.Fatalf("Close #2 (idempotent): %v", err)
	}
	if err := notifier.Send(context.Background(), Event{Message: "after close"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Send after Close err = %v, want ErrClosed", err)
	}
	if got := atomic.LoadInt32(&hits); got != n {
		t.Fatalf("server hits = %d, want %d", got, n)
	}
}

func TestConcurrentSendIsRaceFree(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := New(Config{URL: srv.URL, BufferSize: 512})
	notifier.Start()

	const goroutines = 32
	const perGoroutine = 40

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				_ = notifier.Send(context.Background(), Event{Message: fmt.Sprintf("g%d-%d", g, i)})
			}
		}(g)
	}
	wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := notifier.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := notifier.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s := notifier.Stats()
	if s.Emitted+s.Dropped != goroutines*perGoroutine {
		t.Fatalf("Enqueued(%d)+Dropped(%d) = %d, want %d", s.Emitted, s.Dropped, s.Emitted+s.Dropped, goroutines*perGoroutine)
	}
	if s.Delivered+s.Failed != s.Emitted {
		t.Fatalf("Sent(%d)+Failed(%d) != Enqueued(%d)", s.Delivered, s.Failed, s.Emitted)
	}
}

// --- spool replay ---

func TestReplaySpoolResendsAndTruncates(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, spoolFileName)
	writeSpool(t, path, []Event{
		{Message: "one", Severity: "low"},
		{Message: "two", Severity: "high"},
	})

	notifier := New(Config{URL: srv.URL, SpoolDir: dir})
	n, err := notifier.ReplaySpool(context.Background())
	if err != nil {
		t.Fatalf("ReplaySpool: %v", err)
	}
	if n != 2 {
		t.Fatalf("ReplaySpool returned %d, want 2", n)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("server hits = %d, want 2", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat spool: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("spool not truncated: size = %d", info.Size())
	}
	if s := notifier.Stats(); s.Delivered != 2 {
		t.Fatalf("stats = %+v, want Sent=2", s)
	}
}

func TestReplaySpoolKeepsFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, spoolFileName)
	writeSpool(t, path, []Event{{Message: "still doomed"}})

	notifier := New(Config{
		URL: srv.URL, SpoolDir: dir, MaxRetries: 1,
		BaseBackoff: time.Millisecond, MaxBackoff: time.Millisecond,
	})
	n, err := notifier.ReplaySpool(context.Background())
	if err == nil {
		t.Fatal("ReplaySpool unexpectedly succeeded")
	}
	if n != 0 {
		t.Fatalf("ReplaySpool returned %d, want 0", n)
	}
	lines := readSpoolLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("failed event not preserved in spool: %v", lines)
	}
}

func TestReplaySpoolMissingFileIsNoOp(t *testing.T) {
	notifier := New(Config{URL: "http://127.0.0.1:1", SpoolDir: t.TempDir()})
	n, err := notifier.ReplaySpool(context.Background())
	if err != nil {
		t.Fatalf("ReplaySpool missing file: %v", err)
	}
	if n != 0 {
		t.Fatalf("ReplaySpool missing file returned %d, want 0", n)
	}

	// No SpoolDir configured is also a no-op.
	n, err = New(Config{}).ReplaySpool(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("ReplaySpool without SpoolDir = (%d, %v), want (0, nil)", n, err)
	}
}

// --- helpers ---

func readSpoolLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool %s: %v", path, err)
	}
	var lines []string
	for _, l := range splitLines(string(data)) {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func writeSpool(t *testing.T, path string, events []Event) {
	t.Helper()
	var buf []byte
	for _, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal spool event: %v", err)
		}
		buf = append(buf, b...)
		buf = append(buf, '\n')
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write spool: %v", err)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
