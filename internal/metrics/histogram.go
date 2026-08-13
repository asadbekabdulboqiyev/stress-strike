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
