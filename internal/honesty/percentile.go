package honesty

// percentile.go — exact, integer-only quantiles.
//
// # Why not interpolate
//
// Commercial tools usually report a percentile by interpolating between two
// neighbouring samples, which is a modelling choice: "the 95th percentile" then
// depends on which interpolation formula the tool picked. VeriBench does not
// want a modelling choice inside the evidence, because a producer and a
// verifier must agree *bit for bit*.
//
// So VeriBench uses the nearest-rank definition and nothing else: for a sorted
// sample of length n and a fraction p (given in parts per million), the answer
// is
//
//	rank  = ceil(p * n / 1_000_000)          (clamped to 1..n)
//	value = sorted[rank - 1]
//
// The result is exactly one of the measured values. No interpolation, no
// floating point, no platform dependence. ppm is expressed in parts per million
// (ppm) rather than a percentage so that p99 is 990_000 and p99.9 is 999_000
// without ever writing a decimal point.

import "math/bits"

// Quantile fractions in parts per million.
const (
	// PPM50 is the median.
	PPM50 = 500_000
	// PPM95 is the 95th percentile.
	PPM95 = 950_000
	// PPM99 is the 99th percentile.
	PPM99 = 990_000
	// PPM999 is the 99.9th percentile.
	PPM999 = 999_000
	// ppmScale is 100% expressed in parts per million.
	ppmScale = 1_000_000
)

// Percentile returns the nearest-rank quantile of an ascending sorted slice.
// ppm is the fraction in parts per million: Percentile(v, PPM99) is p99.
//
// The slice must be sorted ascending; callers own that contract (see
// SortValues). An empty slice returns 0. ppm <= 0 returns the minimum and
// ppm >= 1_000_000 returns the maximum, so the function is total.
func Percentile(sorted []int64, ppm int) int64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if ppm <= 0 {
		return sorted[0]
	}
	if ppm >= ppmScale {
		return sorted[n-1]
	}
	// rank = ceil(ppm*n / 1e6), computed exactly. ppm*n is at most
	// 1e6 * 2^31 for any realistic n and fits comfortably in int64.
	rank := (int64(ppm)*int64(n) + ppmScale - 1) / ppmScale
	if rank < 1 {
		rank = 1
	}
	if rank > int64(n) {
		rank = int64(n)
	}
	return sorted[rank-1]
}

// PercentileUint is Percentile for latency values held as uint64. Negative
// inputs are impossible by construction; the values are converted to int64
// after a range check so a hostile bundle cannot wrap a large uint64 into a
// negative latency.
func PercentileUint(sorted []uint64, ppm int) (int64, bool) {
	for _, v := range sorted {
		if v > 1<<62 {
			return 0, false
		}
	}
	asInt := make([]int64, len(sorted))
	for i, v := range sorted {
		asInt[i] = int64(v)
	}
	return Percentile(asInt, ppm), true
}

// isqrt returns floor(sqrt(x)) for a non-negative integer, exactly, using
// Newton's method in integer arithmetic.
func isqrt(x uint64) uint64 {
	if x == 0 {
		return 0
	}
	// Initial guess: 2^(ceil(bits/2)) is an upper bound on sqrt(x).
	guess := uint64(1) << ((bits.Len64(x) + 1) / 2)
	for {
		next := (guess + x/guess) / 2
		if next >= guess {
			return guess
		}
		guess = next
	}
}
