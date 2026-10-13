package honesty

// ci.go — a 95% confidence interval for a latency quantile, computed twice.
//
// Pillar 2 of VeriBench is not only "correct the latency" (see the corrected
// values assembled in verify.go) but also "say how sure you are". A single
// number like p99 = 41 ms hides the fact that the 99th percentile of a finite
// sample is itself uncertain. VeriBench therefore reports an interval.
//
// Two independent, integer-only methods are provided:
//
//   - CI95Bootstrap resamples the raw values with replacement and reports the
//     2.5th/97.5th percentile of the resampled quantiles. It is deterministic:
//     the pseudo-random stream is fixed (splitmix64 seeded by a constant), so a
//     producer and a verifier using this package derive byte-identical bounds.
//     This is the value committed in a bundle's aggregate.co_ci95_ns.
//
//   - CI95OrderStatistic is a distribution-free interval for a quantile derived
//     from the binomial distribution of the rank. It is the *cross-check*: it
//     does not depend on the resampling stream at all, so it catches a producer
//     that fudged the bootstrap. It uses a normal approximation of the binomial
//     (documented, integer fixed-point) — good enough to flag a mismatch, not
//     to serve as the headline number.
//
// Neither function can panic and neither reads a clock: given the same sorted
// input they always return the same answer.

import "sort"

// Bootstrap parameters. They are exported so a bundle reader can tell exactly
// how the interval in front of them was produced.
const (
	// DefaultBootstrapIterations is the number of resamples used when a caller
	// does not specify one.
	DefaultBootstrapIterations = 400
	// MaxBootstrapSamples caps the number of raw values fed into a single
	// resample. Larger inputs are reduced by a deterministic, evenly spaced
	// subsample first; this keeps an interval computation bounded in time and
	// memory while remaining reproducible.
	MaxBootstrapSamples = 10_000
	// DefaultBootstrapSeed is the fixed seed of the resampling stream. It is a
	// protocol constant: changing it changes every committed interval.
	DefaultBootstrapSeed = 0x9E3779B97F4A7C15
)

// SortValues returns a new ascending copy of v. Callers use it before building
// histograms and percentiles so the source slice is never mutated.
func SortValues(v []int64) []int64 {
	out := make([]int64, len(v))
	copy(out, v)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// rng is a splitmix64 generator. It is not cryptographic and does not need to
// be: it exists only so that a resampling procedure is reproducible across
// machines and languages.
type rng struct{ state uint64 }

func (r *rng) next() uint64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// intn returns a uniform-ish index in [0, n). The modulo bias is irrelevant to
// a reproducibility aid and is far cheaper than rejection sampling.
func (r *rng) intn(n int) int { return int(r.next() % uint64(n)) }

// CI95Bootstrap returns a 95% confidence interval for the ppm quantile of the
// ascending sorted slice, by percentile bootstrap.
//
// iterations <= 0 selects DefaultBootstrapIterations. When the input is longer
// than MaxBootstrapSamples it is first reduced to exactly MaxBootstrapSamples
// evenly spaced values, which is deterministic and preserves the shape of the
// distribution. An empty slice yields (0, 0); a single value yields (v, v).
func CI95Bootstrap(sorted []int64, ppm, iterations int, seed uint64) (int64, int64) {
	if len(sorted) == 0 {
		return 0, 0
	}
	work := sorted
	if len(work) > MaxBootstrapSamples {
		work = subsample(sorted, MaxBootstrapSamples)
	}
	m := len(work)
	if m == 1 {
		return work[0], work[0]
	}
	if iterations <= 0 {
		iterations = DefaultBootstrapIterations
	}

	r := &rng{state: seed}
	buf := make([]int64, m)
	quants := make([]int64, iterations)
	for it := range quants {
		for i := range buf {
			buf[i] = work[r.intn(m)]
		}
		sort.Slice(buf, func(a, b int) bool { return buf[a] < buf[b] })
		quants[it] = Percentile(buf, ppm)
	}
	sort.Slice(quants, func(a, b int) bool { return quants[a] < quants[b] })

	lo := Percentile(quants, 25_000)  // 2.5th percentile
	hi := Percentile(quants, 975_000) // 97.5th percentile
	if lo > hi {
		lo, hi = hi, lo
	}
	return lo, hi
}

// subsample picks m evenly spaced values from an ascending slice. It is not a
// random sample and does not pretend to be: it is a deterministic reduction
// whose only job is to keep the bootstrap bounded while keeping the same
// distribution shape.
func subsample(sorted []int64, m int) []int64 {
	n := len(sorted)
	if m >= n {
		out := make([]int64, n)
		copy(out, sorted)
		return out
	}
	out := make([]int64, m)
	for i := 0; i < m; i++ {
		idx := i * n / m
		if idx >= n {
			idx = n - 1
		}
		out[i] = sorted[idx]
	}
	return out
}

// z95 is the 97.5% point of the standard normal distribution, scaled by 1e6
// (1.959964). It is used as a rational so no float enters the computation.
const z95 = 1_959_964

// CI95OrderStatistic returns a distribution-free 95% interval for the ppm
// quantile of the ascending sorted slice, using the normal approximation of the
// binomial rank distribution.
//
// It is intentionally independent of CI95Bootstrap so that the two can disagree
// only when something is wrong. An empty slice yields (0, 0).
func CI95OrderStatistic(sorted []int64, ppm int) (int64, int64) {
	n := len(sorted)
	if n == 0 {
		return 0, 0
	}
	if n == 1 {
		return sorted[0], sorted[0]
	}
	if ppm <= 0 {
		return sorted[0], sorted[0]
	}
	if ppm >= ppmScale {
		return sorted[n-1], sorted[n-1]
	}

	nn := int64(n)
	fp := int64(ppm)
	// Mean rank, scaled by 1e6: n * ppm.
	meanS := nn * fp
	// (sd scaled by 1e6)^2 = n * ppm * (1e6 - ppm).
	varSq := uint64(nn) * uint64(fp) * uint64(ppmScale-ppm)
	sdS := int64(isqrt(varSq))
	delta := int64(mulDivRoundU(uint64(z95), uint64(sdS), ppmScale))

	loRank := ceilScale(meanS-delta, ppmScale)
	hiRank := ceilScale(meanS+delta, ppmScale)
	loRank = clamp(loRank, 1, nn)
	hiRank = clamp(hiRank, 1, nn)

	return sorted[loRank-1], sorted[hiRank-1]
}

// ceilScale returns ceil(s / scale) for a signed numerator. It is used to turn
// a rank expressed in millionths into a 1-based rank.
func ceilScale(s, scale int64) int64 {
	if s >= 0 {
		return (s + scale - 1) / scale
	}
	return -((-s) / scale) // negative ranks cannot occur; keep it total
}

func clamp(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
