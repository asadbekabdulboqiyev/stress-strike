package honesty

// integrity_test.go — pacing bookkeeping and the coordinated-omission correction.

import "testing"

func TestPPMScaleConstant(t *testing.T) {
	if PPMScale != 1_000_000 {
		t.Fatalf("PPMScale = %d, want 1000000", PPMScale)
	}
}

func TestMulDivHelpers(t *testing.T) {
	if got, err := mulDivFloor(6, 7, 2); err != nil || got != 21 {
		t.Fatalf("mulDivFloor(6,7,2) = (%d,%v)", got, err)
	}
	if got, err := mulDivRound(1, 1, 2); err != nil || got != 1 {
		t.Fatalf("mulDivRound(1,1,2) = (%d,%v)", got, err)
	}
	if _, err := mulDivFloor(1, 1, 0); err == nil {
		t.Fatal("floor division by zero accepted")
	}
	if _, err := mulDivRound(1, 1, 0); err == nil {
		t.Fatal("round division by zero accepted")
	}
	// mulDivRoundU never panics: it returns 0 on overflow.
	if got := mulDivRoundU(1<<63, 2, 1); got != 0 {
		t.Fatalf("mulDivRoundU overflow = %d, want 0", got)
	}
}

func TestAchievedRPSMilli(t *testing.T) {
	cases := []struct {
		count    uint64
		duration int64
		want     int64
	}{
		{1000, 1_000_000_000, 1_000_000},
		{65, 10_000_000_000, 6_500},
		{0, 1_000_000_000, 0},
		{1, 1_000_000_000, 1_000},
	}
	for _, tc := range cases {
		got, err := AchievedRPSMilli(tc.count, tc.duration)
		if err != nil {
			t.Fatalf("AchievedRPSMilli(%d,%d): %v", tc.count, tc.duration, err)
		}
		if got != tc.want {
			t.Fatalf("AchievedRPSMilli(%d,%d) = %d, want %d", tc.count, tc.duration, got, tc.want)
		}
	}
	if _, err := AchievedRPSMilli(1, 0); err == nil {
		t.Fatal("zero duration accepted")
	}
	if _, err := AchievedRPSMilli(1, -1); err == nil {
		t.Fatal("negative duration accepted")
	}
}

func TestPlannedSlotsAndDropped(t *testing.T) {
	slots, err := PlannedSlots(1_000_000, 1_000_000_000)
	if err != nil || slots != 1000 {
		t.Fatalf("PlannedSlots(1e6,1e9) = (%d,%v), want 1000", slots, err)
	}
	if slots, _ := PlannedSlots(1000, 1_000_000_000); slots != 1 {
		t.Fatalf("1 rps over 1s = %d slots, want 1", slots)
	}
	if slots, _ := PlannedSlots(0, 1_000_000_000); slots != 0 {
		t.Fatalf("0 rps = %d slots", slots)
	}
	if _, err := PlannedSlots(-1, 1_000_000_000); err == nil {
		t.Fatal("negative planned rate accepted")
	}
	if _, err := PlannedSlots(1000, 0); err == nil {
		t.Fatal("zero duration accepted")
	}

	dropped, err := DroppedSamples(1_000_000, 1_000_000_000, 999)
	if err != nil || dropped != 1 {
		t.Fatalf("DroppedSamples = (%d,%v), want 1", dropped, err)
	}
	// More samples than slots never yields a negative drop count.
	if dropped, _ := DroppedSamples(1_000_000, 1_000_000_000, 5000); dropped != 0 {
		t.Fatalf("overcount drop = %d, want 0", dropped)
	}
}

func TestScheduleAccuracyPPM(t *testing.T) {
	cases := []struct {
		planned, achieved int64
		want              int64
	}{
		{1000, 1000, 1_000_000},
		{1000, 500, 500_000},  // 50% low
		{1000, 1500, 500_000}, // 50% high
		{1000, 2000, 0},       // 100% off
		{1000, 0, 0},          // nothing achieved
		{0, 0, 1_000_000},     // nothing planned, nothing achieved
		{0, 5, 0},             // nothing planned but something achieved
		{-5, 5, 0},            // non-positive planned rate
	}
	for _, tc := range cases {
		if got := ScheduleAccuracyPPM(tc.planned, tc.achieved); got != tc.want {
			t.Fatalf("ScheduleAccuracyPPM(%d,%d) = %d, want %d", tc.planned, tc.achieved, got, tc.want)
		}
	}
}

func TestIntendedStartNS(t *testing.T) {
	// Slot 1 (seq 1) begins at the window start.
	if got, err := IntendedStartNS(1000, 1, 1000); err != nil || got != 1000 {
		t.Fatalf("IntendedStartNS(1000,1,1000) = (%d,%v)", got, err)
	}
	// seq 0 is "before the first slot" and returns the window start.
	if got, err := IntendedStartNS(500, 0, 1000); err != nil || got != 500 {
		t.Fatalf("IntendedStartNS seq 0 = (%d,%v)", got, err)
	}
	// Slot 1000 at 1000 rps is 999 ms after the window start.
	if got, err := IntendedStartNS(0, 1000, 1_000_000); err != nil || got != 999_000_000 {
		t.Fatalf("IntendedStartNS(0,1000,1e6) = (%d,%v), want 999000000", got, err)
	}
	if _, err := IntendedStartNS(0, 1, 0); err == nil {
		t.Fatal("zero rate accepted")
	}
	if _, err := IntendedStartNS(-1, 1, 1000); err == nil {
		t.Fatal("negative window start accepted")
	}
}

func TestCorrectedLatencyNS(t *testing.T) {
	// On schedule: the raw latency is returned unchanged.
	if got, err := CorrectedLatencyNS(0, 5, 0, 1, 1000); err != nil || got != 5 {
		t.Fatalf("on-time correction = (%d,%v), want 5", got, err)
	}
	// Slot 2 is scheduled 1 s in; starting at 2 s adds 1 s of waiting.
	if got, err := CorrectedLatencyNS(2_000_000_000, 5, 0, 2, 1000); err != nil || got != 1_000_000_005 {
		t.Fatalf("late correction = (%d,%v), want 1000000005", got, err)
	}
	if _, err := CorrectedLatencyNS(0, -1, 0, 1, 1000); err == nil {
		t.Fatal("negative latency accepted")
	}
}

func TestSubsampleDeterministic(t *testing.T) {
	in := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	got := subsample(in, 4)
	if len(got) != 4 {
		t.Fatalf("subsample length = %d, want 4", len(got))
	}
	want := []int64{0, 2, 5, 7}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("subsample[%d] = %d, want %d", i, got[i], want[i])
		}
	}
	if full := subsample(in, 100); len(full) != len(in) {
		t.Fatalf("subsample larger than input returned %d values", len(full))
	}
}

func TestCeilScaleAndClamp(t *testing.T) {
	if got := ceilScale(0, 1000); got != 0 {
		t.Fatalf("ceilScale(0,1000) = %d", got)
	}
	if got := ceilScale(1, 1000); got != 1 {
		t.Fatalf("ceilScale(1,1000) = %d, want 1", got)
	}
	if got := ceilScale(1000, 1000); got != 1 {
		t.Fatalf("ceilScale(1000,1000) = %d, want 1", got)
	}
	if got := ceilScale(1001, 1000); got != 2 {
		t.Fatalf("ceilScale(1001,1000) = %d, want 2", got)
	}
	if got := ceilScale(-5, 1000); got != 0 {
		t.Fatalf("ceilScale(-5,1000) = %d, want 0", got)
	}
	if got := clamp(5, 1, 3); got != 3 {
		t.Fatalf("clamp(5,1,3) = %d", got)
	}
	if got := clamp(0, 1, 3); got != 1 {
		t.Fatalf("clamp(0,1,3) = %d", got)
	}
	if got := clamp(2, 1, 3); got != 2 {
		t.Fatalf("clamp(2,1,3) = %d", got)
	}
}
