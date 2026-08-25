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

// setRate atomically updates the refill rate and burst ceiling.
func (t *tokenBucket) setRate(rps int) {
	if rps < 0 {
		rps = 0
	}
	rate := float64(rps)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rate = rate
	t.burst = rate
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
