package metrics

import (
	"sync"
	"testing"
	"time"
)

// TestHistogramAddSnapshot tests basic Add and Snapshot functionality
func TestHistogramAddSnapshot(t *testing.T) {
	h := &Histogram{}
	values := []time.Duration{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	for _, v := range values {
		h.Add(v * time.Millisecond)
	}
	snap := h.Snapshot()
	if snap.Count != 10 {
		t.Fatalf("count = %d, want 10", snap.Count)
	}
	if snap.Sum != 550 {
		t.Errorf("sum = %d, want 550", snap.Sum)
	}
	if snap.Min != 10*time.Millisecond || snap.Max != 100*time.Millisecond {
		t.Errorf("min=%s max=%s, want 10ms/100ms", snap.Min, snap.Max)
	}
	if snap.Average != 55*time.Millisecond {
		t.Errorf("avg = %s, want 55ms", snap.Average)
	}
	if snap.Clamped != 0 {
		t.Errorf("clamped = %d, want 0", snap.Clamped)
	}
}

// TestHistogramPercentiles tests percentile calculations
func TestHistogramPercentiles(t *testing.T) {
	h := &Histogram{}
	values := []time.Duration{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	for _, v := range values {
		h.Add(v * time.Millisecond)
	}
	snap := h.Snapshot()
	if got := snap.Percentile(0.50); got != 50*time.Millisecond {
		t.Errorf("p50 = %s, want 50ms", got)
	}
	if got := snap.Percentile(0.90); got != 90*time.Millisecond {
		t.Errorf("p90 = %s, want 90ms", got)
	}
	// With 10 values, p95 rank = ceil(10 * 0.95) = 10, returns 10th value = 100ms
	if got := snap.Percentile(0.95); got != 100*time.Millisecond {
		t.Errorf("p95 = %s, want 100ms (rank=10 for 10 values)", got)
	}
	if got := snap.Percentile(0.99); got != 100*time.Millisecond {
		t.Errorf("p99 = %s, want 100ms", got)
	}
}

// TestHistogramEmpty tests empty histogram behavior
func TestHistogramEmpty(t *testing.T) {
	h := &Histogram{}
	snap := h.Snapshot()
	if snap.Count != 0 || snap.Percentile(0.95) != 0 {
		t.Errorf("expected empty histogram values, got count=%d p95=%s", snap.Count, snap.Percentile(0.95))
	}
	if snap.Min != 0 || snap.Max != 0 || snap.Average != 0 {
		t.Errorf("empty histogram min/max/avg not zero: min=%s max=%s avg=%s", snap.Min, snap.Max, snap.Average)
	}
}

// TestHistogramClamped tests values exceeding histogramMax (60s)
func TestHistogramClamped(t *testing.T) {
	h := &Histogram{}
	// Add values > 60s (histogramMax = 60000ms)
	h.Add(70 * time.Second)
	h.Add(120 * time.Second)
	h.Add(300 * time.Second)

	snap := h.Snapshot()
	if snap.Count != 3 {
		t.Errorf("count = %d, want 3", snap.Count)
	}
	if snap.Clamped != 3 {
		t.Errorf("clamped = %d, want 3 (all values > 60s)", snap.Clamped)
	}
	// All clamped values should go to last bucket (index 59999)
	if snap.Buckets[histogramMax-1] != 3 {
		t.Errorf("bucket[59999] = %d, want 3", snap.Buckets[histogramMax-1])
	}
}

// TestHistogramNegativeDurations tests negative duration handling
func TestHistogramNegativeDurations(t *testing.T) {
	h := &Histogram{}
	h.Add(-10 * time.Millisecond)
	h.Add(-100 * time.Millisecond)
	h.Add(50 * time.Millisecond)

	snap := h.Snapshot()
	if snap.Count != 3 {
		t.Errorf("count = %d, want 3", snap.Count)
	}
	// Negative values should be treated as 0ms
	if snap.Buckets[0] != 2 {
		t.Errorf("bucket[0] = %d, want 2 (negative values clamped to 0)", snap.Buckets[0])
	}
	if snap.Buckets[50] != 1 {
		t.Errorf("bucket[50] = %d, want 1", snap.Buckets[50])
	}
	// Min tracks smallest positive value (0 is not tracked as min)
	if snap.Min != 50*time.Millisecond {
		t.Errorf("min = %s, want 50ms (0 not tracked as min)", snap.Min)
	}
}

// TestHistogram1msBucketAccuracy tests 1ms bucket precision
func TestHistogram1msBucketAccuracy(t *testing.T) {
	h := &Histogram{}
	// Add values at different ms boundaries
	h.Add(1 * time.Millisecond)
	h.Add(1500 * time.Microsecond) // 1.5ms -> rounds to 1ms
	h.Add(2 * time.Millisecond)
	h.Add(2500 * time.Microsecond) // 2.5ms -> rounds to 2ms

	snap := h.Snapshot()
	if snap.Buckets[1] != 2 {
		t.Errorf("bucket[1] = %d, want 2", snap.Buckets[1])
	}
	if snap.Buckets[2] != 2 {
		t.Errorf("bucket[2] = %d, want 2", snap.Buckets[2])
	}
	if snap.Count != 4 {
		t.Errorf("count = %d, want 4", snap.Count)
	}
}

// TestHistogramConcurrentAdd tests thread-safe concurrent Add calls
func TestHistogramConcurrentAdd(t *testing.T) {
	h := &Histogram{}
	var wg sync.WaitGroup
	numGoroutines := 100
	valuesPerGoroutine := 1000

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			for j := 0; j < valuesPerGoroutine; j++ {
				h.Add(time.Duration(start+j) * time.Millisecond)
			}
		}(i * valuesPerGoroutine)
	}
	wg.Wait()

	snap := h.Snapshot()
	expectedCount := uint64(numGoroutines * valuesPerGoroutine)
	if snap.Count != expectedCount {
		t.Errorf("count = %d, want %d", snap.Count, expectedCount)
	}
	// Verify no data race by checking sum is reasonable
	if snap.Sum == 0 {
		t.Error("sum should not be zero")
	}
}

// TestHistogramPercentileEdgeCases tests percentile edge cases
func TestHistogramPercentileEdgeCases(t *testing.T) {
	t.Run("p0_returns_min", func(t *testing.T) {
		h := &Histogram{}
		h.Add(100 * time.Millisecond)
		snap := h.Snapshot()
		if snap.Percentile(0) != snap.Min {
			t.Errorf("p0 = %s, want min=%s", snap.Percentile(0), snap.Min)
		}
	})

	t.Run("p1_returns_max", func(t *testing.T) {
		h := &Histogram{}
		h.Add(100 * time.Millisecond)
		snap := h.Snapshot()
		if snap.Percentile(1) != snap.Max {
			t.Errorf("p1 = %s, want max=%s", snap.Percentile(1), snap.Max)
		}
	})

	t.Run("p_greater_than_1_returns_max", func(t *testing.T) {
		h := &Histogram{}
		h.Add(100 * time.Millisecond)
		snap := h.Snapshot()
		if snap.Percentile(1.5) != snap.Max {
			t.Errorf("p1.5 = %s, want max=%s", snap.Percentile(1.5), snap.Max)
		}
	})

	t.Run("negative_p_returns_min", func(t *testing.T) {
		h := &Histogram{}
		h.Add(100 * time.Millisecond)
		snap := h.Snapshot()
		if snap.Percentile(-0.5) != snap.Min {
			t.Errorf("p-0.5 = %s, want min=%s", snap.Percentile(-0.5), snap.Min)
		}
	})
}

// TestHistogramLargeValues tests very large number of samples
func TestHistogramLargeValues(t *testing.T) {
	h := &Histogram{}
	// Add 1M samples
	for i := 0; i < 1_000_000; i++ {
		h.Add(time.Duration(i%100+1) * time.Millisecond)
	}
	snap := h.Snapshot()
	if snap.Count != 1_000_000 {
		t.Errorf("count = %d, want 1000000", snap.Count)
	}
	// p50 should be around 50ms
	p50 := snap.Percentile(0.50)
	if p50 < 40*time.Millisecond || p50 > 60*time.Millisecond {
		t.Errorf("p50 = %s, want ~50ms", p50)
	}
}

// TestHistogramSnapshotBucketsCopy tests that buckets are copied not referenced
func TestHistogramSnapshotBucketsCopy(t *testing.T) {
	h := &Histogram{}
	h.Add(10 * time.Millisecond)
	snap1 := h.Snapshot()
	snap1.Buckets[10] = 999 // modify snapshot

	h.Add(20 * time.Millisecond)
	snap2 := h.Snapshot()

	// Original histogram should be unaffected by snapshot modification
	if snap2.Buckets[10] != 1 {
		t.Errorf("bucket[10] = %d, want 1 (original unaffected by snapshot mutation)", snap2.Buckets[10])
	}
}
