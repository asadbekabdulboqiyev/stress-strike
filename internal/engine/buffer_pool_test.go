package engine

import (
	"sync"
	"testing"
)

func TestBufferGetReleaseCycle(t *testing.T) {
	p := NewBufferPool()
	rb := p.Get()

	if rb == nil {
		t.Fatal("Get returned nil")
	}
	if rb.buf == nil {
		t.Fatal("buffer slice is nil")
	}
	if len(rb.buf) != 0 {
		t.Fatalf("expected len 0, got %d", len(rb.buf))
	}

	rb.buf = append(rb.buf, "hello"...)
	if rb.Len() != 5 {
		t.Fatalf("expected len 5, got %d", rb.Len())
	}

	rb.Release()

	stats := p.Stats()
	if stats.Gets != 1 {
		t.Fatalf("expected 1 get, got %d", stats.Gets)
	}
	if stats.Releases != 1 {
		t.Fatalf("expected 1 release, got %d", stats.Releases)
	}
	if stats.Saved != 1 {
		t.Fatalf("expected 1 saved allocation, got %d", stats.Saved)
	}
}

func TestBufferAutoScaling(t *testing.T) {
	p := NewBufferPool()

	rb := p.GetMinSize(0)
	if cap(rb.buf) < bufSmall {
		t.Fatalf("small buffer cap %d < %d", cap(rb.buf), bufSmall)
	}
	rb.Release()

	rb = p.GetMinSize(bufSmall + 1)
	if cap(rb.buf) < bufMedium {
		t.Fatalf("expected medium buffer, got cap %d", cap(rb.buf))
	}
	rb.Release()

	rb = p.GetMinSize(bufMedium + 1)
	if cap(rb.buf) < bufLarge {
		t.Fatalf("expected large buffer, got cap %d", cap(rb.buf))
	}
	rb.Release()

	oversize := bufLarge + 1
	rb = p.GetMinSize(oversize)
	if cap(rb.buf) < oversize {
		t.Fatalf("expected oversize buffer, got cap %d", cap(rb.buf))
	}
	rb.Release()

	stats := p.Stats()
	if stats.Allocations != 1 {
		t.Fatalf("expected 1 forced allocation, got %d", stats.Allocations)
	}
	if stats.Upgrades != 1 {
		t.Fatalf("expected 1 upgrade, got %d", stats.Upgrades)
	}
}

func TestBufferResizing(t *testing.T) {
	p := NewBufferPool()

	rb := p.GetMinSize(0)
	for i := 0; i < bufSmall+1024; i++ {
		rb.buf = append(rb.buf, byte(i%256))
	}
	if cap(rb.buf) <= bufSmall {
		t.Fatalf("buffer should have grown beyond small tier")
	}
	rb.Release()

	stats := p.Stats()
	if stats.Releases != 1 {
		t.Fatalf("expected 1 release, got %d", stats.Releases)
	}
}

func TestBufferPoolConcurrent(t *testing.T) {
	p := NewBufferPool()
	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				rb := p.Get()
				rb.buf = append(rb.buf, "concurrent data"...)
				rb.Reset()
				rb.Release()
			}
		}()
	}
	wg.Wait()

	stats := p.Stats()
	if stats.Gets != goroutines*iterations {
		t.Fatalf("expected %d gets, got %d", goroutines*iterations, stats.Gets)
	}
	if stats.Releases != goroutines*iterations {
		t.Fatalf("expected %d releases, got %d", goroutines*iterations, stats.Releases)
	}
	if stats.Saved != goroutines*iterations {
		t.Fatalf("expected %d saved, got %d", goroutines*iterations, stats.Saved)
	}
}

func TestBufferPoolConcurrentTiers(t *testing.T) {
	p := NewBufferPool()
	const goroutines = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				var rb *ReusableBuffer
				switch (id + i) % 3 {
				case 0:
					rb = p.GetMinSize(0)
				case 1:
					rb = p.GetMinSize(bufSmall + 1)
				case 2:
					rb = p.GetMinSize(bufMedium + 1)
				}
				rb.buf = append(rb.buf, []byte("payload")...)
				rb.Reset()
				rb.Release()
			}
		}(g)
	}
	wg.Wait()

	stats := p.Stats()
	if stats.Gets != goroutines*iterations {
		t.Fatalf("expected %d gets, got %d", goroutines*iterations, stats.Gets)
	}
	if stats.Releases != goroutines*iterations {
		t.Fatalf("expected %d releases, got %d", goroutines*iterations, stats.Releases)
	}
}

func TestBufferStatsTracking(t *testing.T) {
	p := NewBufferPool()

	rb1 := p.Get()
	rb1.Release()
	rb2 := p.Get()
	rb2.Release()

	stats := p.Stats()
	if stats.Gets != 2 {
		t.Fatalf("expected 2 gets, got %d", stats.Gets)
	}
	if stats.Releases != 2 {
		t.Fatalf("expected 2 releases, got %d", stats.Releases)
	}
	if stats.Saved != 2 {
		t.Fatalf("expected 2 saved, got %d", stats.Saved)
	}

	p.Reset()
	stats = p.Stats()
	if stats.Gets != 0 {
		t.Fatalf("expected 0 gets after reset, got %d", stats.Gets)
	}
	if stats.Releases != 0 {
		t.Fatalf("expected 0 releases after reset, got %d", stats.Releases)
	}
}

func TestBufferReset(t *testing.T) {
	p := NewBufferPool()

	rb := p.Get()
	rb.buf = append(rb.buf, "some data"...)
	if rb.Len() != 9 {
		t.Fatalf("expected len 9, got %d", rb.Len())
	}

	rb.Reset()
	if rb.Len() != 0 {
		t.Fatalf("expected len 0 after reset, got %d", rb.Len())
	}
}

func TestDefaultPool(t *testing.T) {
	rb := GetBuffer()
	if rb == nil {
		t.Fatal("GetBuffer returned nil")
	}
	rb.buf = append(rb.buf, "default pool data"...)
	ReleaseBuffer(rb)

	rb2 := GetBufferMin(bufMedium)
	if rb2 == nil {
		t.Fatal("GetBufferMin returned nil")
	}
	ReleaseBuffer(rb2)
}

func TestBufferNoReturnToPool(t *testing.T) {
	rb := &ReusableBuffer{buf: make([]byte, 0, 100), pool: nil}
	rb.buf = append(rb.buf, "no pool"...)
	rb.Release()

	if rb.buf == nil {
		t.Fatal("buffer should still have data when no pool")
	}
	if rb.Len() != 7 {
		t.Fatalf("expected len 7, got %d", rb.Len())
	}
}
