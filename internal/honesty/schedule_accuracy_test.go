package honesty

import (
	"math"
	"testing"
)

// A run that misses its schedule by more than the representable range must be
// reported as the least accurate run, not the most accurate one. The overflow
// path used to fall through to "deviation = 0", so the worse the miss, the
// better the score — and the result is signed into a bundle that Validate()
// accepts, which makes it a silent lie rather than a loud failure.
func TestScheduleAccuracyReportsHugeMissesAsInaccurate(t *testing.T) {
	cases := []struct {
		name                        string
		plannedMilli, achievedMilli int64
		want                        int64
	}{
		{"exact", 300_000, 300_000, ppmScale},
		{"off by 10 percent", 300_000, 270_000, 900_000},
		{"off by half", 300_000, 150_000, 500_000},
		{"off by 100 percent", 300_000, 600_000, 0},
		{"off by more than 100 percent", 1_000, 500_000, 0},
		// The overflow regression: 1 * 1e6 / 1e15 previously wrapped to 0.
		{"astronomical overshoot", 1, 1_000_000_000_000_000, 0},
		{"astronomical undershoot", 1_000_000_000_000_000, 1, 0},
		// Extremes must not wrap into a flattering answer either.
		{"opposite ends of int64", math.MaxInt64, math.MinInt64, 0},
		{"zero plan, nothing achieved", 0, 0, ppmScale},
		{"zero plan, something achieved", 0, 5, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScheduleAccuracyPPM(tc.plannedMilli, tc.achievedMilli); got != tc.want {
				t.Errorf("ScheduleAccuracyPPM(%d, %d) = %d, want %d", tc.plannedMilli, tc.achievedMilli, got, tc.want)
			}
		})
	}
}

// Accuracy must fall monotonically as the achieved rate moves away from the
// plan, in both directions. The overflow branch broke exactly this.
func TestScheduleAccuracyIsMonotonicInTheMiss(t *testing.T) {
	const planned int64 = 100_000 // 100 rps
	last := int64(math.MaxInt64)
	for _, achieved := range []int64{100_000, 110_000, 150_000, 200_000, 300_000, 1_000_000,
		1_000_000_000, 1_000_000_000_000, 1_000_000_000_000_000} {
		got := ScheduleAccuracyPPM(planned, achieved)
		if got < 0 || got > ppmScale {
			t.Fatalf("achieved %d: accuracy %d outside [0, %d]", achieved, got, ppmScale)
		}
		if got > last {
			t.Errorf("accuracy rose while the miss grew: achieved %d gave %d, previous gave %d", achieved, got, last)
		}
		last = got
	}
}
