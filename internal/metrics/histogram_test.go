package metrics

import (
	"testing"
	"time"
)

func TestHistogramPercentiles(t *testing.T) {
	h := &Histogram{}
	values := []time.Duration{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	for _, v := range values {
		h.Add(v * time.Millisecond)
	}
	snap := h.Snapshot()
	if snap.Count != 10 {
		t.Fatalf("count = %d, want 10", snap.Count)
	}
	if got := snap.Percentile(0.50); got != 50*time.Millisecond {
		t.Errorf("p50 = %s, want 50ms", got)
	}
	if got := snap.Percentile(0.90); got != 90*time.Millisecond {
		t.Errorf("p90 = %s, want 90ms", got)
	}
	if got := snap.Percentile(0.99); got != 100*time.Millisecond {
		t.Errorf("p99 = %s, want 100ms", got)
	}
	if snap.Min != 10*time.Millisecond || snap.Max != 100*time.Millisecond {
		t.Errorf("min=%s max=%s, want 10ms/100ms", snap.Min, snap.Max)
	}
	if snap.Average != 55*time.Millisecond {
		t.Errorf("avg = %s, want 55ms", snap.Average)
	}
}

func TestHistogramEmpty(t *testing.T) {
	h := &Histogram{}
	snap := h.Snapshot()
	if snap.Count != 0 || snap.Percentile(0.95) != 0 {
		t.Errorf("expected empty histogram values, got count=%d p95=%s", snap.Count, snap.Percentile(0.95))
	}
}
