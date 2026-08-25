package engine

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestTokenBucketThroughput(t *testing.T) {
	b := newTokenBucket(100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	var grants int64
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if err := b.wait(ctx); err != nil {
					return
				}
				mu.Lock()
				grants++
				mu.Unlock()
			}
		}()
	}
	time.Sleep(2 * time.Second)
	cancel()
	wg.Wait()
	if grants < 100 || grants > 350 {
		t.Errorf("grants over 2s = %d, want ~200 (100 rps cap)", grants)
	}
}

func TestTokenBucketSetRate(t *testing.T) {
	b := newTokenBucket(0)
	if b.rate != 0 {
		t.Errorf("initial rate = %f, want 0", b.rate)
	}

	// Should block when rate is 0.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	err := b.wait(ctx)
	cancel()
	if err == nil {
		t.Error("expected timeout when rate is 0")
	}

	// Ramp up to 200 rps.
	b.setRate(200)
	if b.rate != 200 || b.burst != 200 {
		t.Errorf("after setRate: rate=%f burst=%f, want 200/200", b.rate, b.burst)
	}

	// Should now grant tokens.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	if err := b.wait(ctx2); err != nil {
		t.Errorf("expected grant after setRate(200), got %v", err)
	}
}
