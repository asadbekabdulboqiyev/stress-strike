package metrics

import (
	"math"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// TestHistogramAddSnapshot tests basic Add and Snapshot functionality.
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
	// Sum is now nanoseconds: 550 ms == 550_000_000 ns.
	if snap.Sum != uint64(550*time.Millisecond) {
		t.Errorf("sum = %d, want %d", snap.Sum, 550*time.Millisecond)
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

// TestHistogramPercentiles tests percentile calculations. Percentiles report
// the inclusive upper bound of the bucket, so exactly-on-bucket-edge values
// (like whole milliseconds, which are not bucket edges) come back within the
// documented 0.049 % tolerance.
func TestHistogramPercentiles(t *testing.T) {
	h := &Histogram{}
	values := []time.Duration{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	for _, v := range values {
		h.Add(v * time.Millisecond)
	}
	snap := h.Snapshot()
	for _, tc := range []struct {
		p    float64
		want time.Duration
	}{
		{0.50, 50 * time.Millisecond},
		{0.90, 90 * time.Millisecond},
		{0.95, 100 * time.Millisecond},
		{0.99, 100 * time.Millisecond},
	} {
		got := snap.Percentile(tc.p)
		if got < tc.want || float64(got) > float64(tc.want)*1.001 {
			t.Errorf("p%.2f = %s, want within 0.1%% of %s", tc.p, got, tc.want)
		}
	}
}

// TestHistogramSubMillisecondResolution is the regression test for the whole
// reason this histogram was rewritten: sub-millisecond latencies must not
// collapse to zero.
func TestHistogramSubMillisecondResolution(t *testing.T) {
	h := &Histogram{}
	// A realistic mix of very fast observations.
	for i := 0; i < 900; i++ {
		h.Add(40 * time.Microsecond) // 0.040 ms
	}
	for i := 0; i < 100; i++ {
		h.Add(850 * time.Microsecond) // 0.850 ms
	}
	snap := h.Snapshot()

	if snap.Min != 40*time.Microsecond {
		t.Errorf("min = %s, want 40µs (must not quantise to 0)", snap.Min)
	}
	p50 := snap.Percentile(0.50)
	if p50 < 40*time.Microsecond || p50 > 41*time.Microsecond {
		t.Errorf("p50 = %s, want ~40µs", p50)
	}
	p99 := snap.Percentile(0.99)
	if p99 < 850*time.Microsecond || p99 > 851*time.Microsecond {
		t.Errorf("p99 = %s, want ~850µs", p99)
	}
	// These two values previously landed in different millisecond buckets
	// only by luck; now they are always distinguishable.
	if p50 == p99 {
		t.Fatalf("sub-ms p50 == p99 (%s): resolution lost", p50)
	}
}

// TestHistogramEmpty tests empty histogram behavior.
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

// TestHistogramClamped tests values exceeding the top bucket.
func TestHistogramClamped(t *testing.T) {
	h := &Histogram{}
	// All beyond the ~18-minute ceiling.
	h.Add(time.Duration(maxTrackable) + time.Second)
	h.Add(time.Duration(maxTrackable) + time.Minute)
	h.Add(time.Hour)

	snap := h.Snapshot()
	if snap.Count != 3 {
		t.Errorf("count = %d, want 3", snap.Count)
	}
	if snap.Clamped != 3 {
		t.Errorf("clamped = %d, want 3 (all values beyond maxTrackable)", snap.Clamped)
	}
	if got := h.Clamped(); got != 3 {
		t.Errorf("Clamped() = %d, want 3", got)
	}
	if snap.Buckets[histogramBuckets-1] != 3 {
		t.Errorf("top bucket = %d, want 3", snap.Buckets[histogramBuckets-1])
	}
}

// TestHistogramNegativeDurations tests negative duration handling.
func TestHistogramNegativeDurations(t *testing.T) {
	h := &Histogram{}
	h.Add(-10 * time.Millisecond)
	h.Add(-100 * time.Millisecond)
	h.Add(50 * time.Millisecond)

	snap := h.Snapshot()
	if snap.Count != 3 {
		t.Errorf("count = %d, want 3", snap.Count)
	}
	if snap.Buckets[0] != 2 {
		t.Errorf("bucket[0] = %d, want 2 (negative values clamped to 0)", snap.Buckets[0])
	}
	if snap.Buckets[bucketIndexOf(uint64(50*time.Millisecond))] != 1 {
		t.Errorf("bucket[50ms] != 1")
	}
	if snap.Min != 50*time.Millisecond {
		t.Errorf("min = %s, want 50ms (0 not tracked as min)", snap.Min)
	}
}

// TestHistogramConcurrentAdd tests thread-safe concurrent Add calls.
func TestHistogramConcurrentAdd(t *testing.T) {
	h := &Histogram{}
	var wg sync.WaitGroup
	const numGoroutines = 100
	const valuesPerGoroutine = 1000

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			for j := 0; j < valuesPerGoroutine; j++ {
				h.Add(time.Duration(start+j) * time.Microsecond)
			}
		}(i * valuesPerGoroutine)
	}
	wg.Wait()

	snap := h.Snapshot()
	expectedCount := uint64(numGoroutines * valuesPerGoroutine)
	if snap.Count != expectedCount {
		t.Errorf("count = %d, want %d", snap.Count, expectedCount)
	}
	if snap.Sum == 0 {
		t.Error("sum should not be zero")
	}
}

// TestHistogramPercentileEdgeCases tests percentile edge cases.
func TestHistogramPercentileEdgeCases(t *testing.T) {
	newH := func() *Histogram {
		h := &Histogram{}
		h.Add(100 * time.Millisecond)
		return h
	}
	t.Run("p0_returns_min", func(t *testing.T) {
		snap := newH().Snapshot()
		if snap.Percentile(0) != snap.Min {
			t.Errorf("p0 = %s, want min=%s", snap.Percentile(0), snap.Min)
		}
	})
	t.Run("p1_returns_max", func(t *testing.T) {
		snap := newH().Snapshot()
		if snap.Percentile(1) != snap.Max {
			t.Errorf("p1 = %s, want max=%s", snap.Percentile(1), snap.Max)
		}
	})
	t.Run("p_greater_than_1_returns_max", func(t *testing.T) {
		snap := newH().Snapshot()
		if snap.Percentile(1.5) != snap.Max {
			t.Errorf("p1.5 = %s, want max=%s", snap.Percentile(1.5), snap.Max)
		}
	})
	t.Run("negative_p_returns_min", func(t *testing.T) {
		snap := newH().Snapshot()
		if snap.Percentile(-0.5) != snap.Min {
			t.Errorf("p-0.5 = %s, want min=%s", snap.Percentile(-0.5), snap.Min)
		}
	})
}

// TestHistogramLivePercentileMatchesSnapshot checks the lock-free in-place
// Percentile agrees with the snapshot-based one.
func TestHistogramLivePercentileMatchesSnapshot(t *testing.T) {
	h := &Histogram{}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		h.Add(time.Duration(rng.Intn(5_000_000)))
	}
	snap := h.Snapshot()
	for _, p := range []float64{0.5, 0.9, 0.95, 0.99, 0.999} {
		if got, want := h.Percentile(p), snap.Percentile(p); got != want {
			t.Errorf("live p%.3f = %s, snapshot p%.3f = %s; want equal", p, got, p, want)
		}
	}
}

// TestHistogramLargeValues tests a very large number of samples.
func TestHistogramLargeValues(t *testing.T) {
	h := &Histogram{}
	for i := 0; i < 1_000_000; i++ {
		h.Add(time.Duration(i%100+1) * time.Millisecond)
	}
	snap := h.Snapshot()
	if snap.Count != 1_000_000 {
		t.Errorf("count = %d, want 1000000", snap.Count)
	}
	p50 := snap.Percentile(0.50)
	if p50 < 40*time.Millisecond || p50 > 60*time.Millisecond {
		t.Errorf("p50 = %s, want ~50ms", p50)
	}
}

// TestHistogramSnapshotBucketsCopy tests that buckets are copied not referenced.
func TestHistogramSnapshotBucketsCopy(t *testing.T) {
	h := &Histogram{}
	h.Add(10 * time.Millisecond)
	idx := bucketIndexOf(uint64(10 * time.Millisecond))
	snap1 := h.Snapshot()
	orig := snap1.Buckets[idx]
	snap1.Buckets[idx] = 999

	snap2 := h.Snapshot()
	if got := snap2.Buckets[idx]; got != orig {
		t.Errorf("bucket mutation leaked: %d, want %d", got, orig)
	}
}

// --- index arithmetic properties -------------------------------------------

// TestBucketIndexMapping is the exhaustive correctness proof for the log-linear
// bucketing: every value must land in a bucket whose [lower, upper] range
// contains it, and ranges must tile the number line without gaps or overlap.
func TestBucketIndexMapping(t *testing.T) {
	values := []uint64{
		0, 1, 2, 3, 1023, 1024, 2047, 2048, 2049, 4094, 4095, 4096, 4097,
		1_000_000, // 1 ms
		1_500_000, // 1.5 ms
		999_999, 1_000_001,
		uint64(time.Second),
		uint64(10 * time.Second),
		uint64(time.Minute),
		uint64(600 * time.Second),
		maxTrackable,
	}
	for _, v := range values {
		idx := bucketIndexOf(v)
		if idx < 0 || idx >= histogramBuckets {
			t.Fatalf("bucketIndexOf(%d) = %d, out of range", v, idx)
		}
		lo := bucketLowerBound(idx)
		hi := uint64(bucketUpperBound(idx))
		if v < lo || v > hi {
			t.Errorf("value %d outside its bucket [%d, %d] (idx %d)", v, lo, hi, idx)
		}
		// The relative error is bounded by 1/subBucketCount.
		if v >= subBucketCount {
			width := hi - lo + 1
			if float64(width)/float64(lo+1) > 1.0/float64(subBucketHalf)+0.0001 {
				t.Errorf("bucket width %d at %d exceeds precision bound", width, v)
			}
		}
	}
}

// TestBucketRangesAreContiguous walks consecutive buckets and asserts their
// ranges abut exactly, so no latency value can fall between two buckets.
func TestBucketRangesAreContiguous(t *testing.T) {
	prevUpper := uint64(0)
	for idx := 0; idx < histogramBuckets; idx++ {
		lo := bucketLowerBound(idx)
		hi := uint64(bucketUpperBound(idx))
		if lo != prevUpper {
			t.Fatalf("bucket %d lower %d != previous upper+1 %d", idx, lo, prevUpper)
		}
		if hi < lo {
			t.Fatalf("bucket %d has inverted range [%d,%d]", idx, lo, hi)
		}
		prevUpper = hi + 1
	}
	if prevUpper-1 != maxTrackable {
		t.Errorf("top bucket upper = %d, want maxTrackable = %d", prevUpper-1, maxTrackable)
	}
}

// TestBucketIndexMonotonic asserts the mapping and its inverse are monotone,
// which is what makes percentile scanning correct.
func TestBucketIndexMonotonic(t *testing.T) {
	prev := -1
	for _, v := range []uint64{0, 1, 2047, 2048, 4095, 4096, 1 << 20, 1 << 30, maxTrackable} {
		idx := bucketIndexOf(v)
		if idx < prev {
			t.Fatalf("bucketIndexOf not monotone: %d -> %d after %d", v, idx, prev)
		}
		prev = idx
	}
}

// TestBucketUpperBoundIsInclusive guards the off-by-one that would make the
// reported percentile slightly optimistic.
func TestBucketUpperBoundIsInclusive(t *testing.T) {
	for _, v := range []uint64{2048, 4095, 4096, 1 << 20, maxTrackable} {
		idx := bucketIndexOf(v)
		if got := uint64(bucketUpperBound(idx)); got < v {
			t.Errorf("upper bound %d of bucket %d is below its own value %d", got, idx, v)
		}
		// The next bucket must not also contain v.
		if idx+1 < histogramBuckets {
			if lo := bucketLowerBound(idx + 1); lo <= v {
				t.Errorf("value %d also lies in next bucket (lower %d)", v, lo)
			}
		}
	}
}

// TestCumulativeBuckets verifies the Prometheus-facing cumulative view.
func TestCumulativeBuckets(t *testing.T) {
	h := &Histogram{}
	h.Add(500 * time.Microsecond)
	h.Add(500 * time.Microsecond)
	h.Add(2 * time.Millisecond)

	snap := h.Snapshot()
	cum := snap.CumulativeBuckets()
	if len(cum) != histogramBuckets {
		t.Fatalf("len = %d, want %d", len(cum), histogramBuckets)
	}
	// Cumulative counts must be non-decreasing and end at Count.
	var last uint64
	for i, b := range cum {
		if b.Count < last {
			t.Fatalf("cumulative count decreased at %d: %d < %d", i, b.Count, last)
		}
		last = b.Count
	}
	if last != 3 {
		t.Errorf("final cumulative = %d, want 3", last)
	}
	// The 2 ms bucket must be the first with count 3 (all three are <= 2 ms).
	for _, b := range cum {
		if b.Count == 3 && b.UpperBound < 2*time.Millisecond {
			t.Errorf("cumulative reached 3 at upper bound %s, before 2ms", b.UpperBound)
		}
	}
}

// TestHistogramAverageExact checks Average uses nanosecond sums (no ms
// truncation).
func TestHistogramAverageExact(t *testing.T) {
	h := &Histogram{}
	h.Add(1 * time.Microsecond)
	h.Add(2 * time.Microsecond)
	// mean = 1.5 µs; the old ms-based Average would report 0.
	if got := h.Avg(); got != 1500*time.Nanosecond {
		t.Errorf("avg = %s, want 1.5µs", got)
	}
	if snap := h.Snapshot(); math.Abs(float64(snap.Average)-1500) > 1 {
		t.Errorf("snapshot avg = %s, want ~1.5µs", snap.Average)
	}
}
