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
	if rps <= 0 {
		return nil
	}
	return &tokenBucket{
		tokens: float64(rps),
		rate:   float64(rps),
		burst:  float64(rps),
		last:   time.Now(),
	}
}

func (t *tokenBucket) wait(ctx context.Context) error {
	for {
		t.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(t.last).Seconds()
		t.last = now
		t.tokens = math.Min(t.burst, t.tokens+elapsed*t.rate)
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
