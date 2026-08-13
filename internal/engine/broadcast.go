package engine

import (
	"context"
	"sync"
)

type broadcast struct {
	mu sync.Mutex
	ch chan struct{}
}

func newBroadcast() *broadcast {
	return &broadcast{ch: make(chan struct{})}
}

func (b *broadcast) notify() {
	b.mu.Lock()
	close(b.ch)
	b.ch = make(chan struct{})
	b.mu.Unlock()
}

func (b *broadcast) wait(ctx context.Context) error {
	b.mu.Lock()
	ch := b.ch
	b.mu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
