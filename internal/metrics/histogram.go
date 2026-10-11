package metrics

import (
	"math/bits"
	"sync/atomic"
	"time"
)

// Histogram is a lock-free, allocation-free latency histogram with
// log-linear ("HDR-style") bucketing.
//
// # Why not millisecond buckets
//
// The previous implementation bucketed whole milliseconds. A load generator
// that reports 1 ms resolution cannot distinguish a 40 µs cache hit from a
// 900 µs one: both land in the same bucket, and every sub-millisecond target
// (which is most Go/Java/Rust services on a LAN) reports min = p50 = 0 ms.
// Enterprise load tools (k6, wrk2, Vegeta, Gatling) all resolve at the
// microsecond/nanosecond level, so stress-strike now does too.
//
// # Layout
//
// Values are nanoseconds. Bucket 0..subBucketCount-1 hold values 0..2047
// exactly (1 ns resolution). Every octave above that is split into
// subBucketHalf = 1024 buckets, giving a worst-case relative error of
//
//	1 / subBucketHalf == 0.098 %
//
// up to 2^40 ns (~18 minutes) of latency, in 31744 buckets (254 KB) — less
// memory than the 480 KB the old 60000 × 1 ms layout needed, with ~2000×
// finer resolution near zero. All counters are atomics, so Add never takes a
// lock and never allocates; the engine's hot path is unaffected.
type Histogram struct {
	buckets [histogramBuckets]atomic.Uint64
	count   atomic.Uint64
	// sum is the running total in nanoseconds (uint64 wraps after ~584 years).
	sum     atomic.Uint64
	min     atomic.Uint64
	max     atomic.Uint64
	clamped atomic.Uint64
}

const (
	// subBucketBits selects subBucketCount = 2048, the number of buckets per
	// power-of-two magnitude. Precision is 1/2048 ≈ 0.049 %.
	subBucketBits  = 11
	subBucketCount = 1 << subBucketBits
	subBucketHalf  = subBucketCount >> 1
	// maxExp is the highest bit handled; the top bucket ends at 2^40-1 ns
	// (~18 minutes), after which observations are clamped.
	maxExp           = 39
	histogramBuckets = subBucketCount + (maxExp-subBucketBits+1)*subBucketHalf
	// maxTrackable is the inclusive upper bound of the last bucket.
	maxTrackable = (uint64(subBucketCount) << (maxExp - subBucketBits + 1)) - 1
)

// Bucket is one histogram cell with its inclusive upper bound. It is used by
// the Prometheus exporter and by tests; the engine never allocates these on
// the hot path.
type Bucket struct {
	// UpperBound is the largest value (inclusive) that maps into this bucket.
	UpperBound time.Duration
	// Count is the cumulative number of observations with value <= UpperBound.
	Count uint64
}

// HistogramSnapshot is an immutable copy of a Histogram. Percentile and the
// bucket helpers are pure functions of a snapshot, so a report can be
// computed from a consistent point-in-time view while a run continues.
type HistogramSnapshot struct {
	Count   uint64
	Sum     uint64 // nanoseconds
	Min     time.Duration
	Max     time.Duration
	Average time.Duration
	Clamped uint64
	// Buckets holds non-cumulative per-bucket counts, low index first.
	Buckets []uint64
}

// Add records one observation. It is safe to call concurrently with itself
// and with every reader.
func (h *Histogram) Add(d time.Duration) {
	var ns uint64
	if d <= 0 {
		ns = 0
	} else {
		ns = uint64(d.Nanoseconds())
	}
	trueNs := ns
	if ns > maxTrackable {
		// Values beyond the top bucket (~18 min) are clamped so the histogram
		// stays bounded; Clamped tells the caller how many were affected.
		ns = maxTrackable
		h.clamped.Add(1)
	}
	h.buckets[bucketIndexOf(ns)].Add(1)
	h.count.Add(1)
	h.sum.Add(trueNs)

	for {
		cur := h.min.Load()
		if cur != 0 && cur <= trueNs {
			break
		}
		if h.min.CompareAndSwap(cur, trueNs) {
			break
		}
	}
	for {
		cur := h.max.Load()
		if trueNs <= cur {
			break
		}
		if h.max.CompareAndSwap(cur, trueNs) {
			break
		}
	}
}

func (h *Histogram) Count() uint64 { return h.count.Load() }

// Clamped reports how many observations exceeded the top bucket and were
// counted there verbatim. Callers that archive a report should surface it.
func (h *Histogram) Clamped() uint64 { return h.clamped.Load() }

// Snapshot copies the histogram into an immutable value. It allocates one
// 254 KB slice, so use it for reports and exports, not for live dashboards —
// Percentile/Count/Avg/MinLatency/MaxLatency read the atomics in place.
func (h *Histogram) Snapshot() HistogramSnapshot {
	s := HistogramSnapshot{
		Count:   h.count.Load(),
		Sum:     h.sum.Load(),
		Min:     time.Duration(h.min.Load()),
		Max:     time.Duration(h.max.Load()),
		Clamped: h.clamped.Load(),
		Buckets: make([]uint64, histogramBuckets),
	}
	if s.Count > 0 {
		s.Average = time.Duration(s.Sum / s.Count)
	}
	for i := range h.buckets {
		s.Buckets[i] = h.buckets[i].Load()
	}
	return s
}

// Percentile returns the p-th percentile latency from a snapshot, using the
// bucket's inclusive upper bound. Reporting the upper bound makes the value
// conservative: p95 is never advertised as better than it really was. The
// error versus the true percentile is bounded by 1/1024 of the value.
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
	rank := uint64(float64(s.Count)*p + 0.999999)
	if rank == 0 {
		rank = 1
	}
	var cum uint64
	for i, n := range s.Buckets {
		cum += n
		if cum >= rank {
			return bucketUpperBound(i)
		}
	}
	return s.Max
}

// Percentile computes the p-th percentile directly from the live atomic
// buckets without materialising a Snapshot.
//
// The result is a weakly consistent view: a concurrent Add may be missed by
// the scan, so Count here can differ from h.Count() by an in-flight sample.
// That is the right trade for the live progress bar and the dashboard, which
// call this several times a second and must not copy 254 KB each time. Use
// Snapshot for anything archived or compared.
func (h *Histogram) Percentile(p float64) time.Duration {
	count := h.count.Load()
	if count == 0 {
		return 0
	}
	if p <= 0 {
		return time.Duration(h.min.Load())
	}
	if p >= 1 {
		return time.Duration(h.max.Load())
	}
	rank := uint64(float64(count)*p + 0.999999)
	if rank == 0 {
		rank = 1
	}
	var cum uint64
	for i := 0; i < histogramBuckets; i++ {
		cum += h.buckets[i].Load()
		if cum >= rank {
			return bucketUpperBound(i)
		}
	}
	return time.Duration(h.max.Load())
}

// Avg returns the exact mean without copying any buckets.
func (h *Histogram) Avg() time.Duration {
	count := h.count.Load()
	if count == 0 {
		return 0
	}
	return time.Duration(h.sum.Load() / count)
}

// MinLatency and MaxLatency expose the observed extremes directly.
func (h *Histogram) MinLatency() time.Duration {
	if h.count.Load() == 0 {
		return 0
	}
	return time.Duration(h.min.Load())
}

func (h *Histogram) MaxLatency() time.Duration {
	if h.count.Load() == 0 {
		return 0
	}
	return time.Duration(h.max.Load())
}

// CumulativeBuckets returns the non-cumulative snapshot folded into
// cumulative buckets with inclusive upper bounds, ready for Prometheus
// histogram exposition (the `le` series). Callers append the +Inf bucket from
// Count themselves.
func (s *HistogramSnapshot) CumulativeBuckets() []Bucket {
	out := make([]Bucket, len(s.Buckets))
	var cum uint64
	for i, n := range s.Buckets {
		cum += n
		out[i] = Bucket{UpperBound: bucketUpperBound(i), Count: cum}
	}
	return out
}

// --- index arithmetic -------------------------------------------------------

// bucketIndexOf maps a nanosecond value to its bucket. Values below
// subBucketCount are exact; above that each octave is split into subBucketHalf
// buckets. It is a pure function (unit-tested exhaustively in
// histogram_bounds_test.go).
func bucketIndexOf(v uint64) int {
	if v < subBucketCount {
		return int(v)
	}
	e := bits.Len64(v) - 1           // highest set bit
	shift := e - (subBucketBits - 1) // >= 1
	mantissa := v >> uint(shift)     // in [subBucketHalf, subBucketCount)
	idx := subBucketCount + (shift-1)*subBucketHalf + int(mantissa-subBucketHalf)
	if idx >= histogramBuckets {
		idx = histogramBuckets - 1
	}
	return idx
}

// bucketLowerBound returns the smallest value that maps into bucket idx.
func bucketLowerBound(idx int) uint64 {
	if idx < subBucketCount {
		return uint64(idx)
	}
	t := idx - subBucketCount
	shift := t/subBucketHalf + 1
	mantissa := t%subBucketHalf + subBucketHalf
	return uint64(mantissa) << uint(shift)
}

// bucketUpperBound returns the largest value that maps into bucket idx.
func bucketUpperBound(idx int) time.Duration {
	if idx < subBucketCount {
		return time.Duration(idx)
	}
	t := idx - subBucketCount
	shift := t/subBucketHalf + 1
	mantissa := t%subBucketHalf + subBucketHalf
	upper := (uint64(mantissa) + 1) << uint(shift)
	return time.Duration(upper) - 1
}
