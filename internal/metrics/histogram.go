package metrics

import (
	"math"
	"sync/atomic"
	"time"
)

const histogramMax = 60000

type Histogram struct {
	buckets [histogramMax]atomic.Uint64
	count   atomic.Uint64
	sum     atomic.Uint64
	min     atomic.Uint64
	max     atomic.Uint64
	clamped atomic.Uint64
}

type HistogramSnapshot struct {
	Count   uint64
	Sum     uint64
	Min     time.Duration
	Max     time.Duration
	Average time.Duration
	Clamped uint64
	Buckets [histogramMax]uint64
}

func (h *Histogram) Add(d time.Duration) {
	if d < 0 {
		d = 0
	}
	ms := uint64(d.Milliseconds())
	trueMs := ms
	if ms >= histogramMax {
		ms = histogramMax - 1
		h.clamped.Add(1)
	}
	h.buckets[ms].Add(1)
	h.count.Add(1)
	h.sum.Add(trueMs)
	for {
		cur := h.min.Load()
		if cur != 0 && cur <= trueMs {
			break
		}
		if h.min.CompareAndSwap(cur, trueMs) {
			break
		}
	}
	for {
		cur := h.max.Load()
		if trueMs <= cur {
			break
		}
		if h.max.CompareAndSwap(cur, trueMs) {
			break
		}
	}
}

func (h *Histogram) Count() uint64 {
	return h.count.Load()
}

func (h *Histogram) Snapshot() HistogramSnapshot {
	s := HistogramSnapshot{}
	s.Count = h.count.Load()
	s.Sum = h.sum.Load()
	s.Min = time.Duration(h.min.Load()) * time.Millisecond
	s.Max = time.Duration(h.max.Load()) * time.Millisecond
	s.Clamped = h.clamped.Load()
	if s.Count > 0 {
		s.Average = time.Duration(s.Sum/s.Count) * time.Millisecond
	}
	for i := range h.buckets {
		s.Buckets[i] = h.buckets[i].Load()
	}
	return s
}

func (s *HistogramSnapshot) Percentile(p float64) time.Duration {
	if s.Count == 0 {
		return 0
	}
	if p <= 0 {
		return s.Min
	}
	if p >= 1 {
		return s.Max
	}
	rank := uint64(math.Ceil(float64(s.Count) * p))
	if rank == 0 {
		rank = 1
	}
	var cum uint64
	for i, n := range s.Buckets {
		cum += n
		if cum >= rank {
			return time.Duration(i) * time.Millisecond
		}
	}
	return s.Max
}

// Percentile computes p-th percentile directly from the live buckets without
// materializing a Snapshot.
//
// Snapshot copies all histogramMax buckets (480KB) so that a percentile read
// is a pure function of an immutable value. That is the right trade for a
// one-shot report, but the live progress display and the dashboard call it
// several times a second, where 480KB per read dominates the cost of the read
// itself. Scanning the atomic buckets in place and stopping at the first
// bucket that reaches the target rank yields the same answer for a fraction of
// the work, and does not allocate at all.
//
// The result is a weakly consistent view: a concurrent Add may be missed by
// the scan, so Count here can differ from h.Count() by an in-flight sample.
// Percentiles are already approximations at millisecond resolution, and every
// caller of this method renders the value for a human or pushes it to a live
// dashboard, where a one-sample skew is not observable. Use Snapshot for
// anything that is archived or compared.
func (h *Histogram) Percentile(p float64) time.Duration {
	count := h.count.Load()
	if count == 0 {
		return 0
	}
	minMs, maxMs := h.min.Load(), h.max.Load()
	if p <= 0 {
		return time.Duration(minMs) * time.Millisecond
	}
	if p >= 1 {
		return time.Duration(maxMs) * time.Millisecond
	}
	rank := uint64(math.Ceil(float64(count) * p))
	if rank == 0 {
		rank = 1
	}
	// Only buckets up to the observed max can hold samples, so the scan can
	// stop there instead of walking the full 60000-bucket range.
	limit := int(maxMs) + 1
	if limit > histogramMax {
		limit = histogramMax
	}
	var cum uint64
	for i := 0; i < limit; i++ {
		cum += h.buckets[i].Load()
		if cum >= rank {
			return time.Duration(i) * time.Millisecond
		}
	}
	return time.Duration(maxMs) * time.Millisecond
}

// Avg returns the mean sample value without copying any buckets.
func (h *Histogram) Avg() time.Duration {
	count := h.count.Load()
	if count == 0 {
		return 0
	}
	return time.Duration(h.sum.Load()/count) * time.Millisecond
}

// MinLatency and MaxLatency expose the observed extremes directly, so callers
// that need the range alongside live percentiles do not have to copy buckets.
func (h *Histogram) MinLatency() time.Duration {
	if h.count.Load() == 0 {
		return 0
	}
	return time.Duration(h.min.Load()) * time.Millisecond
}

func (h *Histogram) MaxLatency() time.Duration {
	if h.count.Load() == 0 {
		return 0
	}
	return time.Duration(h.max.Load()) * time.Millisecond
}
