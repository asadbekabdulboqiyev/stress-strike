package engine

import (
	"context"
	"math"
	"sync"
	"time"
)

type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	rate   float64
	burst  float64
	last   time.Time

	// Coordinated-omission (CO) schedule tracking (see acquire/correctedDelay).
	// Issued counts tokens granted since the current schedule anchor; the
	// anchor is re-set only when the refill rate actually changes.
	issued   uint64
	anchor   time.Time
	coAnchor bool
}

func newTokenBucket(rps int) *tokenBucket {
	if rps < 0 {
		rps = 0
	}
	rate := float64(rps)
	if rps == 0 {
		// Start with zero rate; setRate will bring it up.
		return &tokenBucket{last: time.Now()}
	}
	return &tokenBucket{
		tokens: rate,
		rate:   rate,
		burst:  rate,
		last:   time.Now(),
	}
}

// setRate atomically updates the refill rate and burst ceiling. A real change
// in the rate re-anchors the coordinated-omission schedule: the intended
// inter-arrival spacing has changed, so accumulated skew from the old rate is
// no longer meaningful. A no-op update (same rate) leaves the anchor intact,
// which is the common case once ramp-up has settled.
func (t *tokenBucket) setRate(rps int) {
	if rps < 0 {
		rps = 0
	}
	rate := float64(rps)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rate != rate {
		t.coAnchor = false
		t.issued = 0
	}
	t.rate = rate
	t.burst = rate
}

// acquire behaves like wait but additionally reports the coordinated-omission
// correction for the granted token: how much later than its nominal schedule
// slot the request was allowed to start.
//
// The intended schedule is modelled as an anchor plus one inter-arrival slot
// per granted token, where interval = 1/rate. When a token is granted later
// than its nominal slot (the whole worker pool was blocked on slow responses,
// so the generator fell behind its own arrival schedule), the difference is
// the hidden queue time Gil Tene's correction adds back to the latency. A
// request that keeps up with the schedule reports zero.
func (t *tokenBucket) acquire(ctx context.Context) (time.Duration, error) {
	if err := t.wait(ctx); err != nil {
		return 0, err
	}
	return t.correctedDelay(), nil
}

// correctedDelay returns (and advances) the schedule skew for the most recent
// grant. It reads the current rate under the bucket mutex so a concurrent
// setRate cannot tear the schedule mid-computation.
func (t *tokenBucket) correctedDelay() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rate <= 0 {
		return 0
	}
	now := time.Now()
	if !t.coAnchor {
		// First grant of a schedule: this token defines slot zero.
		t.coAnchor = true
		t.anchor = now
	}
	interval := time.Duration(float64(time.Second) / t.rate)
	nominal := t.anchor.Add(time.Duration(t.issued) * interval) //nolint:gosec // issued-token counter fits int64
	t.issued++
	if now.After(nominal) {
		return now.Sub(nominal)
	}
	return 0
}

func (t *tokenBucket) wait(ctx context.Context) error {
	for {
		t.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(t.last).Seconds()
		t.last = now
		if t.rate > 0 {
			t.tokens = math.Min(t.burst, t.tokens+elapsed*t.rate)
		}
		if t.rate <= 0 {
			// Rate is zero (ramp-up hasn't started); wait briefly and retry.
			t.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		if t.tokens >= 1 {
			t.tokens--
			t.mu.Unlock()
			return nil
		}
		deficit := 1 - t.tokens
		waitFor := time.Duration(deficit / t.rate * float64(time.Second))
		t.mu.Unlock()

		timer := time.NewTimer(waitFor)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
