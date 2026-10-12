package siem

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrNoURL is returned by NewSink when SinkConfig.URL is empty. Unlike a bare
// Notifier — which treats an empty URL as a stats-only no-op — a Sink is a
// delivery component, so a missing endpoint is a configuration error.
var ErrNoURL = errors.New("siem: sink requires a URL")

// defaultSinkMaxAttempts is the total number of HTTP attempts (the initial
// request plus its retries) a Sink makes for one event when
// SinkConfig.MaxAttempts is unset.
const defaultSinkMaxAttempts = 3

// Logger is the minimal logging hook a Sink accepts, so operators can observe
// spool replays without the package depending on a logging framework.
// *log.Logger satisfies it directly; adapters can wrap slog.
type Logger interface {
	Printf(format string, args ...any)
}

// SinkConfig configures a Sink. The zero value is not usable; URL is required.
type SinkConfig struct {
	// URL is the SIEM webhook endpoint. Required.
	URL string
	// Capacity bounds the in-memory ring buffer. Defaults to 1024. When the
	// ring is full Emit spills to SpoolDir if one is set, otherwise it reports
	// ErrBufferFull.
	Capacity int
	// SpoolDir, when set, receives undeliverable events as JSON lines and
	// enables spill-to-disk when the ring is full. It is created if missing.
	SpoolDir string
	// MaxAttempts is the total number of HTTP attempts (initial + retries)
	// performed per event. Defaults to 3; a value below 2 disables retries.
	MaxAttempts int
	// BaseBackoff is the first retry delay. Defaults to 100ms.
	BaseBackoff time.Duration
	// MaxBackoff caps the exponential retry delay. Defaults to 5s.
	MaxBackoff time.Duration
	// HTTPClient overrides the default HTTP client. When nil, the default
	// applies a 5-second per-attempt timeout.
	HTTPClient *http.Client
	// Logger, when non-nil, receives spool-replay diagnostics.
	Logger Logger
}

// Sink is the durable, non-blocking SIEM delivery facade for production use. It
// wraps a Notifier: Emit never blocks on network I/O, and once the ring is full
// it spills events to the disk spool rather than dropping them (when SpoolDir is
// configured). It is safe for concurrent use.
type Sink struct {
	n      *Notifier
	logger Logger
}

// NewSink validates cfg and builds a Sink. It returns ErrNoURL when URL is
// empty, and creates SpoolDir when one is configured so a later spill cannot
// fail on a missing directory.
func NewSink(cfg SinkConfig) (*Sink, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, ErrNoURL
	}

	attempts := cfg.MaxAttempts
	if attempts <= 0 {
		attempts = defaultSinkMaxAttempts
	}

	if cfg.SpoolDir != "" {
		if err := os.MkdirAll(cfg.SpoolDir, 0o700); err != nil {
			return nil, fmt.Errorf("siem: create spool dir: %w", err)
		}
	}

	n := New(Config{
		URL:         cfg.URL,
		BufferSize:  cfg.Capacity,
		SpoolDir:    cfg.SpoolDir,
		BaseBackoff: cfg.BaseBackoff,
		MaxBackoff:  cfg.MaxBackoff,
		Client:      cfg.HTTPClient,
	})
	// MaxAttempts counts the initial attempt, so the retry budget is one fewer.
	// This is applied after New because New coerces a non-positive MaxRetries to
	// its own default, which would inflate a MaxAttempts of 1 (no retries) to
	// four total attempts. Workers have not started yet, so this write is not
	// racy.
	n.cfg.MaxRetries = attempts - 1

	return &Sink{n: n, logger: cfg.Logger}, nil
}

// Emit enqueues ev without blocking on network I/O. It returns ErrBufferFull
// when the ring is full and no spool is configured (the event is then counted
// Dropped), and ErrClosed after Close. With a SpoolDir set, a full ring spills
// the event to disk instead and Emit returns nil. A cancelled ctx is reported
// before the event is accepted.
func (s *Sink) Emit(ctx context.Context, ev Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.n.emit(ev)
}

// Flush blocks until every queued event has been processed or ctx is done. It
// does not replay the spool; use ReplaySpool for that.
func (s *Sink) Flush(ctx context.Context) error {
	return s.n.Flush(ctx)
}

// ReplaySpool re-sends every event in the disk spool (see
// Notifier.ReplaySpool). When a Logger is configured the outcome is logged.
func (s *Sink) ReplaySpool(ctx context.Context) error {
	sent, err := s.n.ReplaySpool(ctx)
	if s.logger != nil {
		switch {
		case err != nil:
			s.logger.Printf("siem: spool replay sent %d event(s): %v", sent, err)
		case sent > 0:
			s.logger.Printf("siem: spool replay sent %d event(s)", sent)
		}
	}
	return err
}

// Stats returns a snapshot of the sink counters.
func (s *Sink) Stats() Stats { return s.n.Stats() }

// Close drains queued events within ctx, then stops the workers, spilling
// anything that could not be delivered. It returns ctx.Err() when the drain did
// not finish in time; the sink is stopped either way. It is idempotent and safe
// to call concurrently with Emit.
func (s *Sink) Close(ctx context.Context) error {
	err := s.n.Flush(ctx)
	s.n.shutdown()
	return err
}
