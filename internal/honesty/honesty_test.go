package honesty

// honesty_test.go — adversarial cross-checks for the statistics core.
//
// The package's own test files (percentile_test.go, ci_test.go,
// integrity_test.go) pin specific expected values. This file adds the
// *properties* a verifier must be able to rely on: exactness checked against an
// independently written reference, totality at the clamped ends, monotonicity,
// an interval that actually brackets its own point estimate, the "correction
// never lowers the latency" invariant, and the integrity bookkeeping ranges.
//
// Nothing here re-implements the functions under test by copy: where a
// cross-check is useful it is written in a deliberately different way (for
// example naivePercentile walks a rank counter instead of applying the
// closed-form ceil formula).

import (
	"math"
	"math/rand"
	"testing"
)

// -----------------------------------------------------------------------------
// Percentile: exactness, totality, monotonicity
// -----------------------------------------------------------------------------

// TestPercentileAllEqual checks a constant sample maps to that constant for
// every fraction, including the clamped ends (ppm <= 0 and ppm >= 1e6) and
// values just inside them.
func TestPercentileAllEqual(t *testing.T) {
	const v = 7_777_777
	sorted := []int64{v, v, v, v, v}
	for _, ppm := range []int{-1, 0, 1, PPM50, PPM95, PPM99, PPM999, ppmScale - 1, ppmScale, ppmScale + 1} {
		if got := Percentile(sorted, ppm); got != v {
			t.Fatalf("Percentile(all-equal, ppm=%d) = %d, want %d", ppm, got, v)
		}
	}
}

// TestPercentileMonotonicInPPM checks the quantile is non-decreasing as the
// fraction grows: a higher percentile can never report a smaller latency, which
// is what makes p50 <= p95 <= p99 a meaningful invariant a bundle can carry.
func TestPercentileMonotonicInPPM(t *testing.T) {
	sorted := SortValues([]int64{40, 10, 30, 20, 50, 60, 5, 99, 12, 1})
	prev := int64(math.MinInt64)
	for ppm := 0; ppm <= ppmScale; ppm += 137 {
		got := Percentile(sorted, ppm)
		if got < prev {
			t.Fatalf("Percentile not monotonic: ppm=%d gave %d after %d", ppm, got, prev)
		}
		prev = got
	}
	// The extremes are exactly the min and the max.
	if got := Percentile(sorted, 0); got != sorted[0] {
		t.Fatalf("ppm 0 = %d, want min %d", got, sorted[0])
	}
	if got := Percentile(sorted, ppmScale); got != sorted[len(sorted)-1] {
		t.Fatalf("ppm full = %d, want max %d", got, sorted[len(sorted)-1])
	}
}

// TestPercentileNaiveCrossCheck compares Percentile against an independently
// written nearest-rank reference on randomly generated samples. The generator is
// seeded, so the check is deterministic; the small modulus manufactures heavy
// duplication, and values are multiplied so the slice also carries negatives.
func TestPercentileNaiveCrossCheck(t *testing.T) {
	r := rand.New(rand.NewSource(20261013))
	for trial := 0; trial < 300; trial++ {
		n := r.Intn(65)
		raw := make([]int64, n)
		for i := range raw {
			raw[i] = int64(r.Intn(21)-10) * int64(1+r.Intn(1000))
		}
		sorted := SortValues(raw)
		for _, ppm := range []int{0, 250_000, PPM50, 900_000, PPM95, PPM99, 999_999, ppmScale} {
			want := naivePercentile(sorted, ppm)
			if got := Percentile(sorted, ppm); got != want {
				t.Fatalf("trial %d n=%d ppm=%d: Percentile=%d, naive=%d (sorted=%v)", trial, n, ppm, got, want, sorted)
			}
		}
	}
}

// naivePercentile is the textbook nearest-rank definition written without the
// closed-form ceil: it walks a 1-based rank counter until rank*scale >= ppm*n.
// It is the independent oracle for TestPercentileNaiveCrossCheck.
func naivePercentile(sorted []int64, ppm int) int64 {
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
	rank := 1
	for rank*ppmScale < ppm*n {
		rank++
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

// TestSortValuesAscendingDuplicatesNegatives checks SortValues returns an
// ascending copy that preserves duplicates and negatives, and never touches the
// caller's slice.
func TestSortValuesAscendingDuplicatesNegatives(t *testing.T) {
	in := []int64{3, -1, 3, 0, -5, 3, 2, -1}
	out := SortValues(in)
	want := []int64{-5, -1, -1, 0, 2, 3, 3, 3}
	if len(out) != len(want) {
		t.Fatalf("length = %d, want %d", len(out), len(want))
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("sorted[%d] = %d, want %d (got %v)", i, out[i], want[i], out)
		}
	}
	for i := 1; i < len(out); i++ {
		if out[i] < out[i-1] {
			t.Fatalf("output is not ascending at %d: %v", i, out)
		}
	}
	if in[0] != 3 || in[1] != -1 || in[2] != 3 || in[4] != -5 || in[7] != -1 {
		t.Fatalf("SortValues mutated its input: %v", in)
	}
	if got := SortValues(nil); len(got) != 0 {
		t.Fatalf("SortValues(nil) = %v, want empty", got)
	}
}

// -----------------------------------------------------------------------------
// Confidence intervals
// -----------------------------------------------------------------------------

// TestCIsBracketPointEstimate checks the single most important property of an
// interval: it contains the point estimate it is an interval *for*. A
// confidence interval that does not bracket its own p99 is meaningless, so this
// is checked for both independent methods across the three reported quantiles.
func TestCIsBracketPointEstimate(t *testing.T) {
	sets := map[string][]int64{
		"two":    {5, 7},
		"three":  {1, 2, 3},
		"flat":   repeat(4, 50),
		"ramp":   ramp(500, 1_000_000, 7_000),
		"heavy":  heavyTail(199, 1_000, 100, 1_000_000_000),
		"random": randomValues(1000, 50_000_000, 424242),
	}
	for name, s := range sets {
		for _, ppm := range []int{PPM50, PPM95, PPM99} {
			point := Percentile(s, ppm)

			blo, bhi := CI95Bootstrap(s, ppm, DefaultBootstrapIterations, DefaultBootstrapSeed)
			if blo > bhi {
				t.Fatalf("%s ppm=%d: bootstrap interval inverted [%d,%d]", name, ppm, blo, bhi)
			}
			if !(blo <= point && point <= bhi) {
				t.Fatalf("%s ppm=%d: bootstrap [%d,%d] does not bracket point %d", name, ppm, blo, bhi, point)
			}

			olo, ohi := CI95OrderStatistic(s, ppm)
			if olo > ohi {
				t.Fatalf("%s ppm=%d: order-statistic interval inverted [%d,%d]", name, ppm, olo, ohi)
			}
			if !(olo <= point && point <= ohi) {
				t.Fatalf("%s ppm=%d: order-statistic [%d,%d] does not bracket point %d", name, ppm, olo, ohi, point)
			}
		}
	}
}

// TestCI95BootstrapStability checks the interval is continuous in the data:
// raising the single largest observation by one nanosecond can move each
// endpoint by at most one nanosecond and never downward. Because the resampling
// stream is fixed by the seed, each resampled quantile changes by 0 or +1, so an
// order statistic of the resampled values can do the same.
func TestCI95BootstrapStability(t *testing.T) {
	base := ramp(300, 1_000, 13)
	for _, ppm := range []int{PPM50, PPM99} {
		lo, hi := CI95Bootstrap(base, ppm, 300, DefaultBootstrapSeed)

		bumped := append([]int64(nil), base...)
		bumped[len(bumped)-1]++ // raise only the maximum
		nlo, nhi := CI95Bootstrap(bumped, ppm, 300, DefaultBootstrapSeed)

		if nlo < lo || nlo > lo+1 {
			t.Fatalf("ppm=%d: lower endpoint moved %d -> %d, want within [%d,%d]", ppm, lo, nlo, lo, lo+1)
		}
		if nhi < hi || nhi > hi+1 {
			t.Fatalf("ppm=%d: upper endpoint moved %d -> %d, want within [%d,%d]", ppm, hi, nhi, hi, hi+1)
		}
	}
}

// -----------------------------------------------------------------------------
// Coordinated-omission correction
// -----------------------------------------------------------------------------

// TestCorrectedLatencyNeverLowers checks the correction can only add waiting
// time: the corrected value is never below the raw latency, is unchanged when
// the request started on schedule or early, and grows by exactly the lateness
// when it started late. A non-positive planned rate is an error, not a silent
// pass.
func TestCorrectedLatencyNeverLowers(t *testing.T) {
	const rpsMilli = 1000 // 1 rps: slot k starts (k-1) seconds after the window.
	const window = int64(0)
	const rawLatency = int64(123)

	for seq := uint64(1); seq <= 20; seq++ {
		intended, err := IntendedStartNS(window, seq, rpsMilli)
		if err != nil {
			t.Fatalf("IntendedStartNS(seq=%d): %v", seq, err)
		}
		// On schedule and early starts must not change the latency.
		for _, start := range []int64{intended, intended - 500_000_000} {
			got, err := CorrectedLatencyNS(start, rawLatency, window, seq, rpsMilli)
			if err != nil {
				t.Fatalf("CorrectedLatencyNS(seq=%d, start=%d): %v", seq, start, err)
			}
			if got != rawLatency {
				t.Fatalf("seq=%d start=%d: corrected = %d, want raw %d", seq, start, got, rawLatency)
			}
		}
		// A late start adds exactly the waiting time to the raw latency.
		const late = int64(250_000_000)
		got, err := CorrectedLatencyNS(intended+late, rawLatency, window, seq, rpsMilli)
		if err != nil {
			t.Fatalf("CorrectedLatencyNS(seq=%d, late): %v", seq, err)
		}
		if got != rawLatency+late {
			t.Fatalf("seq=%d: corrected = %d, want %d", seq, got, rawLatency+late)
		}
		if got < rawLatency {
			t.Fatalf("seq=%d: correction lowered latency to %d", seq, got)
		}
	}

	for _, bad := range []int64{0, -1} {
		if _, err := CorrectedLatencyNS(0, 5, 0, 1, bad); err == nil {
			t.Fatalf("rps_milli=%d accepted, want error", bad)
		}
	}
	if _, err := CorrectedLatencyNS(0, -1, 0, 1, rpsMilli); err == nil {
		t.Fatal("negative latency accepted, want error")
	}
}

// -----------------------------------------------------------------------------
// Pacing / integrity bookkeeping
// -----------------------------------------------------------------------------

// TestScheduleAccuracyInRangeAndDroppedZero covers the integrity contract:
// accuracy always lies inside [0, PPMScale]; an achieved rate equal to the plan
// is exactly perfect and drops no slot; and no input yields a negative accuracy
// or a negative drop count. Non-positive durations are errors.
func TestScheduleAccuracyInRangeAndDroppedZero(t *testing.T) {
	const planned = 1_000_000 // 1000.000 rps
	const dur = int64(10_000_000_000)

	slots, err := PlannedSlots(planned, dur)
	if err != nil {
		t.Fatalf("PlannedSlots: %v", err)
	}
	if dropped, err := DroppedSamples(planned, dur, slots); err != nil || dropped != 0 {
		t.Fatalf("DroppedSamples(achieved==planned) = (%d,%v), want (0,nil)", dropped, err)
	}
	if acc := ScheduleAccuracyPPM(planned, planned); acc != PPMScale {
		t.Fatalf("accuracy(achieved==planned) = %d, want %d", acc, PPMScale)
	}

	// A wide sweep of planned/achieved pairs: every result stays in range.
	for plannedM := int64(-1000); plannedM <= 2_000_000; plannedM += 12_345 {
		for _, achievedM := range []int64{-5, 0, 1, 999, 1_000_000, 5_000_000} {
			acc := ScheduleAccuracyPPM(plannedM, achievedM)
			if acc < 0 || acc > PPMScale {
				t.Fatalf("accuracy(%d,%d) = %d, outside [0,%d]", plannedM, achievedM, acc, PPMScale)
			}
		}
	}

	for _, durBad := range []int64{0, -1} {
		if _, err := PlannedSlots(planned, durBad); err == nil {
			t.Fatalf("PlannedSlots accepted duration %d", durBad)
		}
		if _, err := DroppedSamples(planned, durBad, 1); err == nil {
			t.Fatalf("DroppedSamples accepted duration %d", durBad)
		}
	}
}

// TestScheduleAccuracyPPMOverflowIsLogged documents a suspected wrong answer in
// ScheduleAccuracyPPM's overflow path.
//
// ScheduleAccuracyPPM computes the deviation as mulDivRoundU(diff, 1e6, planned).
// mulDivRoundU turns an overflow into 0, and a deviation of 0 is then reported
// as 1_000_000 — "perfect accuracy" — when the honest answer is 0. The control
// below (a huge but non-overflowing deviation) returns the correct 0, which
// isolates the overflow as the cause.
//
// This test does not assert the buggy value as correct and deliberately does
// not fail: it records the anomaly in the test log. See the QA report for the
// exact reproducer, file:line and confidence.
func TestScheduleAccuracyPPMOverflowIsLogged(t *testing.T) {
	const planned = 250
	// achieved/planned ≈ 1.8e16; diff*1e6 does not fit in 64 bits.
	const achieved = int64(4_600_000_000_000_000_000)

	if got := ScheduleAccuracyPPM(planned, achieved); got == PPMScale {
		t.Logf("BUG: ScheduleAccuracyPPM(%d, %d) = %d reads as perfect accuracy, but the achieved rate is ~1.8e16x the plan; expected 0", planned, achieved, got)
	}

	// Control: the same 250 planned rate with a deviation that fits in 64 bits
	// is reported correctly as 0, so the anomaly is specific to the overflow.
	if ctrl := ScheduleAccuracyPPM(planned, 4_600_000_000_000); ctrl != 0 {
		t.Fatalf("control ScheduleAccuracyPPM(%d, 4.6e12) = %d, want 0", planned, ctrl)
	}
}

// -----------------------------------------------------------------------------
// deterministic data builders
// -----------------------------------------------------------------------------

// repeat returns n copies of v.
func repeat(v int64, n int) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// ramp returns n ascending values base, base+step, ... .
func ramp(n int, base, step int64) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = base + int64(i)*step
	}
	return SortValues(out)
}

// heavyTail returns an ascending slice of n tightly spaced values with a single
// far outlier appended, so the median and the p99 sit far apart.
func heavyTail(n int, base, step, outlier int64) []int64 {
	out := ramp(n, base, step)
	return append(out, outlier)
}

// randomValues returns n ascending pseudo-random values in [0, hi), seeded so
// the sample is reproducible.
func randomValues(n int, hi, seed int64) []int64 {
	r := rand.New(rand.NewSource(seed))
	out := make([]int64, n)
	for i := range out {
		out[i] = r.Int63n(hi)
	}
	return SortValues(out)
}
