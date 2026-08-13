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
