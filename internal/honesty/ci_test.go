package honesty

// ci_test.go — the deterministic bootstrap interval and its order-statistic
// cross-check.

import "testing"

func TestCI95Constants(t *testing.T) {
	if DefaultBootstrapIterations != 400 {
		t.Fatalf("DefaultBootstrapIterations = %d", DefaultBootstrapIterations)
	}
	if MaxBootstrapSamples != 10_000 {
		t.Fatalf("MaxBootstrapSamples = %d", MaxBootstrapSamples)
	}
	if DefaultBootstrapSeed != 0x9E3779B97F4A7C15 {
		t.Fatalf("DefaultBootstrapSeed = %#x", uint64(DefaultBootstrapSeed))
	}
}

func TestSortValuesDoesNotMutate(t *testing.T) {
	in := []int64{3, 1, 2}
	out := SortValues(in)
	for i, want := range []int64{1, 2, 3} {
		if out[i] != want {
			t.Fatalf("sorted[%d] = %d, want %d", i, out[i], want)
		}
	}
	if in[0] != 3 || in[1] != 1 || in[2] != 2 {
		t.Fatalf("SortValues mutated its input: %v", in)
	}
}

func TestCI95BootstrapEdges(t *testing.T) {
	if lo, hi := CI95Bootstrap(nil, PPM99, 100, DefaultBootstrapSeed); lo != 0 || hi != 0 {
		t.Fatalf("empty = (%d,%d), want (0,0)", lo, hi)
	}
	if lo, hi := CI95Bootstrap([]int64{42}, PPM99, 100, DefaultBootstrapSeed); lo != 42 || hi != 42 {
		t.Fatalf("single value = (%d,%d), want (42,42)", lo, hi)
	}
	// iterations <= 0 selects the default without changing the result shape.
	lo0, hi0 := CI95Bootstrap([]int64{1, 2, 3, 4, 5}, PPM50, 0, DefaultBootstrapSeed)
	if lo0 > hi0 {
		t.Fatalf("interval inverted: (%d,%d)", lo0, hi0)
	}
}

func TestCI95BootstrapDeterministic(t *testing.T) {
	values := make([]int64, 500)
	for i := range values {
		values[i] = int64(i * 7)
	}
	lo1, hi1 := CI95Bootstrap(values, PPM99, 400, DefaultBootstrapSeed)
	lo2, hi2 := CI95Bootstrap(values, PPM99, 400, DefaultBootstrapSeed)
	if lo1 != lo2 || hi1 != hi2 {
		t.Fatalf("bootstrap is not deterministic: (%d,%d) vs (%d,%d)", lo1, hi1, lo2, hi2)
	}
	if lo1 > hi1 {
		t.Fatalf("interval inverted: (%d,%d)", lo1, hi1)
	}
	if lo1 < values[0] || hi1 > values[len(values)-1] {
		t.Fatalf("interval [%d,%d] escapes the data range [%d,%d]", lo1, hi1, values[0], values[len(values)-1])
	}
	// A different seed produces a different stream (and so generally a different
	// interval) — a weak but useful sanity check on the constant.
	lo3, hi3 := CI95Bootstrap(values, PPM99, 400, 1)
	if lo3 == lo1 && hi3 == hi1 {
		t.Log("note: changing the seed produced the same interval (possible on smooth data)")
	}
}

func TestCI95BootstrapSubsampleDeterministic(t *testing.T) {
	values := make([]int64, MaxBootstrapSamples*3)
	for i := range values {
		values[i] = int64(i)
	}
	lo1, hi1 := CI95Bootstrap(values, PPM99, 200, DefaultBootstrapSeed)
	lo2, hi2 := CI95Bootstrap(values, PPM99, 200, DefaultBootstrapSeed)
	if lo1 != lo2 || hi1 != hi2 {
		t.Fatalf("subsampled bootstrap is not deterministic: (%d,%d) vs (%d,%d)", lo1, hi1, lo2, hi2)
	}
	if lo1 > hi1 {
		t.Fatalf("interval inverted: (%d,%d)", lo1, hi1)
	}
}

func TestCI95OrderStatistic(t *testing.T) {
	if lo, hi := CI95OrderStatistic(nil, PPM99); lo != 0 || hi != 0 {
		t.Fatalf("empty = (%d,%d)", lo, hi)
	}
	if lo, hi := CI95OrderStatistic([]int64{5}, PPM99); lo != 5 || hi != 5 {
		t.Fatalf("single = (%d,%d)", lo, hi)
	}
	values := make([]int64, 1000)
	for i := range values {
		values[i] = int64(i)
	}
	lo, hi := CI95OrderStatistic(values, PPM99)
	if lo > hi {
		t.Fatalf("interval inverted: (%d,%d)", lo, hi)
	}
	if lo < values[0] || hi > values[len(values)-1] {
		t.Fatalf("interval [%d,%d] escapes the data range", lo, hi)
	}
	if lo != values[0] && !isElement(values, lo) {
		t.Fatalf("lower bound %d is not an element", lo)
	}
	if !isElement(values, hi) {
		t.Fatalf("upper bound %d is not an element", hi)
	}
	if l, h := CI95OrderStatistic(values, 0); l != values[0] || h != values[0] {
		t.Fatalf("ppm 0 = (%d,%d)", l, h)
	}
	if l, h := CI95OrderStatistic(values, PPMScale); l != values[len(values)-1] || h != values[len(values)-1] {
		t.Fatalf("ppm full = (%d,%d)", l, h)
	}
}

func TestBootstrapAndOrderStatisticOverlap(t *testing.T) {
	// A skewed but not pathological distribution; the two independent methods
	// must produce overlapping intervals.
	values := make([]int64, 2000)
	for i := range values {
		values[i] = int64(i*i) / 10
	}
	blo, bhi := CI95Bootstrap(values, PPM99, 400, DefaultBootstrapSeed)
	olo, ohi := CI95OrderStatistic(values, PPM99)
	if blo > ohi || olo > bhi {
		t.Fatalf("bootstrap [%d,%d] and order-statistic [%d,%d] do not overlap", blo, bhi, olo, ohi)
	}
}

func isElement(sorted []int64, v int64) bool {
	for _, x := range sorted {
		if x == v {
			return true
		}
	}
	return false
}
