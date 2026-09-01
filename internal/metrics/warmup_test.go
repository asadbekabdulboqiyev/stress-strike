package metrics

import (
	"testing"
	"time"
)

func TestTopErrorsSortedByCount(t *testing.T) {
	errs := map[string]uint64{
		"timeout":          5,
		"connection_error": 100,
		"status_4xx":       50,
		"assert_failed":    100,
	}

	top := TopErrors(errs, 0)
	if len(top) != 4 {
		t.Fatalf("len = %d, want 4", len(top))
	}
	if top[0].Name != "assert_failed" || top[1].Name != "connection_error" {
		t.Errorf("order wrong: %s then %s (tie must be alphabetical)", top[0].Name, top[1].Name)
	}
	if top[2].Name != "status_4xx" || top[3].Name != "timeout" {
		t.Errorf("tail order wrong: %s, %s", top[2].Name, top[3].Name)
	}

	top2 := TopErrors(errs, 2)
	if len(top2) != 2 || top2[0].Name != "assert_failed" {
		t.Errorf("limit broken: %+v", top2)
	}
}

func TestTelemetryWarmupGate(t *testing.T) {
	tel := NewTelemetry()
	if !tel.Recording() {
		t.Fatal("fresh telemetry must be recording")
	}

	tel.SetWarmup(50 * time.Millisecond)
	if tel.Recording() {
		t.Fatal("must not record during warmup window")
	}
	time.Sleep(60 * time.Millisecond)
	if !tel.Recording() {
		t.Fatal("must record after warmup elapses")
	}
}

func TestTelemetryWarmupZeroIsNoop(t *testing.T) {
	tel := NewTelemetry()
	tel.SetWarmup(0)
	if !tel.Recording() {
		t.Fatal("SetWarmup(0) must keep recording")
	}
}
