package honesty

// percentile_test.go — exact nearest-rank quantiles.

import "testing"

func TestPercentileNearestRank(t *testing.T) {
	sorted := []int64{10, 20, 30, 40}
	cases := []struct {
		ppm  int
		want int64
	}{
		{0, 10},         // min
		{PPM50, 20},     // ceil(0.5*4)=2 -> index 1
		{PPM95, 40},     // ceil(0.95*4)=4 -> index 3
		{PPM99, 40},     // ceil(0.99*4)=4
		{PPM999, 40},    // clamp to max
		{1_000_000, 40}, // explicit max
	}
	for _, tc := range cases {
		if got := Percentile(sorted, tc.ppm); got != tc.want {
			t.Fatalf("Percentile(...,%d) = %d, want %d", tc.ppm, got, tc.want)
		}
	}
}

func TestPercentileEdges(t *testing.T) {
	if got := Percentile(nil, PPM50); got != 0 {
		t.Fatalf("empty percentile = %d, want 0", got)
	}
	if got := Percentile([]int64{7}, PPM99); got != 7 {
		t.Fatalf("single-element percentile = %d, want 7", got)
	}
	// Large n: rank = ceil(0.95*100) = 95 -> index 94.
	big := make([]int64, 100)
	for i := range big {
		big[i] = int64(i)
	}
	if got := Percentile(big, PPM95); got != 94 {
		t.Fatalf("p95 of 0..99 = %d, want 94", got)
	}
	if got := Percentile(big, PPM50); got != 49 {
		t.Fatalf("p50 of 0..99 = %d, want 49", got)
	}
}

func TestPercentileFractionalRank(t *testing.T) {
	// n=3, p50: ceil(0.5*3)=2 -> index 1.
	if got := Percentile([]int64{1, 2, 3}, PPM50); got != 2 {
		t.Fatalf("p50 = %d, want 2", got)
	}
	// n=2, p990 is the max.
	if got := Percentile([]int64{1, 2}, PPM99); got != 2 {
		t.Fatalf("p99 = %d, want 2", got)
	}
}

func TestPercentileUint(t *testing.T) {
	got, ok := PercentileUint([]uint64{5, 10, 15}, PPM50)
	if !ok || got != 10 {
		t.Fatalf("PercentileUint = (%d,%v), want (10,true)", got, ok)
	}
	// A value above 2^62 cannot be represented as int64; fail closed.
	if _, ok := PercentileUint([]uint64{1 << 63}, PPM50); ok {
		t.Fatal("oversized uint accepted")
	}
}

func TestIsqrt(t *testing.T) {
	cases := map[uint64]uint64{
		0: 0, 1: 1, 2: 1, 3: 1, 4: 2, 8: 2, 9: 3, 15: 3, 16: 4,
		1_000_000:         1_000,
		999_999:           999,
		1<<62 + 1:         1 << 31,
		4_000_000_000_000: 2_000_000,
	}
	for in, want := range cases {
		if got := isqrt(in); got != want {
			t.Fatalf("isqrt(%d) = %d, want %d", in, got, want)
		}
	}
}
