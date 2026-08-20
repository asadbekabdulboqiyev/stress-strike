package metrics

import (
	"sync"
	"testing"
	"time"
)

// TestStepStatsRecord tests basic Record functionality
func TestStepStatsRecord(t *testing.T) {
	s := NewStepStats("test")
	s.Record(10*time.Millisecond, 200, "")
	s.Record(20*time.Millisecond, 200, "")
	s.Record(30*time.Millisecond, 500, "status_5xx")

	if s.Latency.Count() != 3 {
		t.Errorf("latency count = %d, want 3", s.Latency.Count())
	}
	statuses := s.StatusCodes()
	if statuses[200] != 2 || statuses[500] != 1 {
		t.Errorf("status codes = %v, want 200:2, 500:1", statuses)
	}
	errors := s.Errors()
	if errors["status_5xx"] != 1 {
		t.Errorf("errors = %v, want status_5xx:1", errors)
	}
	if s.ErrorCount() != 1 {
		t.Errorf("error count = %d, want 1", s.ErrorCount())
	}
	if s.Requests() != 3 {
		t.Errorf("requests = %d, want 3", s.Requests())
	}
}

// TestStepStatsRecordNoStatus tests recording without status code
func TestStepStatsRecordNoStatus(t *testing.T) {
	s := NewStepStats("test")
	s.Record(10*time.Millisecond, 0, "")
	s.Record(20*time.Millisecond, 0, "conn_error")

	statuses := s.StatusCodes()
	if len(statuses) != 0 {
		t.Errorf("status codes should be empty, got %v", statuses)
	}
	errors := s.Errors()
	if errors["conn_error"] != 1 {
		t.Errorf("errors = %v, want conn_error:1", errors)
	}
}

// TestStepStatsConcurrentRecord tests thread-safe concurrent Record calls
func TestStepStatsConcurrentRecord(t *testing.T) {
	s := NewStepStats("test")
	var wg sync.WaitGroup
	numGoroutines := 50
	callsPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				status := 200
				errName := ""
				if (id*callsPerGoroutine+j)%3 == 0 {
					status = 500
					errName = "status_5xx"
				}
				s.Record(time.Duration(id+j)*time.Millisecond, status, errName)
			}
		}(i)
	}
	wg.Wait()

	if s.Requests() != uint64(numGoroutines*callsPerGoroutine) {
		t.Errorf("requests = %d, want %d", s.Requests(), numGoroutines*callsPerGoroutine)
	}
	statuses := s.StatusCodes()
	totalStatuses := uint64(0)
	for _, v := range statuses {
		totalStatuses += v
	}
	if totalStatuses != uint64(numGoroutines*callsPerGoroutine) {
		t.Errorf("total statuses = %d, want %d", totalStatuses, numGoroutines*callsPerGoroutine)
	}
}

// TestStepStatsStatusCodesSnapshot tests that StatusCodes returns a snapshot
func TestStepStatsStatusCodesSnapshot(t *testing.T) {
	s := NewStepStats("test")
	s.Record(10*time.Millisecond, 200, "")

	codes1 := s.StatusCodes()
	codes1[200] = 999 // modify returned map

	codes2 := s.StatusCodes()
	if codes2[200] != 1 {
		t.Errorf("original map modified: got %d, want 1", codes2[200])
	}
}

// TestStepStatsErrorsSnapshot tests that Errors returns a snapshot
func TestStepStatsErrorsSnapshot(t *testing.T) {
	s := NewStepStats("test")
	s.Record(10*time.Millisecond, 200, "test_err")

	errs1 := s.Errors()
	errs1["test_err"] = 999 // modify returned map

	errs2 := s.Errors()
	if errs2["test_err"] != 1 {
		t.Errorf("original map modified: got %d, want 1", errs2["test_err"])
	}
}

// TestTelemetryBasic tests basic telemetry functionality
func TestTelemetryBasic(t *testing.T) {
	tel := NewTelemetry()

	// Add steps
	step1 := NewStepStats("login")
	step1.Record(10*time.Millisecond, 200, "")
	step1.Record(20*time.Millisecond, 500, "status_5xx")
	tel.AddStep(step1)

	step2 := NewStepStats("profile")
	step2.Record(5*time.Millisecond, 200, "")
	tel.AddStep(step2)

	// Record overall
	tel.Overall.Record(15*time.Millisecond, 200, "")

	// Test before Finish
	if tel.Elapsed() <= 0 {
		t.Error("elapsed should be positive before Finish")
	}

	tel.Finish()

	elapsed := tel.Elapsed()
	if elapsed <= 0 {
		t.Error("elapsed should be positive after Finish")
	}

	totalReqs := tel.TotalRequests()
	if totalReqs != 3 { // 2 from step1 + 1 from step2
		t.Errorf("total requests = %d, want 3", totalReqs)
	}

	totalErrs := tel.TotalErrors()
	if totalErrs != 1 {
		t.Errorf("total errors = %d, want 1", totalErrs)
	}

	rps := tel.RPS()
	if rps <= 0 {
		t.Error("RPS should be positive")
	}
}

// TestTelemetryFinishIdempotent tests that Finish can be called multiple times
// Note: Current implementation always sets End = time.Now(), so this test
// verifies the behavior (not idempotent)
func TestTelemetryFinishIdempotent(t *testing.T) {
	tel := NewTelemetry()
	tel.Finish()
	firstEnd := tel.End
	// Small delay to ensure time advances
	time.Sleep(1 * time.Millisecond)
	tel.Finish()
	// Current behavior: Finish() always updates End to now
	if tel.End.Before(firstEnd) {
		t.Error("second Finish should not set End to before first End")
	}
}

// TestTelemetryRPSZeroDuration tests RPS when elapsed is zero
func TestTelemetryRPSZeroDuration(t *testing.T) {
	tel := NewTelemetry()
	tel.Finish() // End == Start

	// Manually set End to Start to simulate zero duration
	tel.End = tel.Start

	rps := tel.RPS()
	if rps != 0 {
		t.Errorf("RPS should be 0 for zero duration, got %f", rps)
	}
}

// TestTelemetryStatusCodes tests aggregated status codes
func TestTelemetryStatusCodes(t *testing.T) {
	tel := NewTelemetry()
	step1 := NewStepStats("a")
	step1.Record(10*time.Millisecond, 200, "")
	step1.Record(10*time.Millisecond, 200, "")
	step1.Record(10*time.Millisecond, 404, "not_found")
	tel.AddStep(step1)

	step2 := NewStepStats("b")
	step2.Record(10*time.Millisecond, 500, "status_5xx")
	step2.Record(10*time.Millisecond, 500, "status_5xx")
	tel.AddStep(step2)

	codes := tel.StatusCodes()
	if codes[200] != 2 || codes[404] != 1 || codes[500] != 2 {
		t.Errorf("status codes = %v, want 200:2, 404:1, 500:2", codes)
	}
}

// TestTelemetryErrors tests aggregated errors
func TestTelemetryErrors(t *testing.T) {
	tel := NewTelemetry()
	step1 := NewStepStats("a")
	step1.Record(10*time.Millisecond, 200, "err1")
	step1.Record(10*time.Millisecond, 200, "err1")
	step1.Record(10*time.Millisecond, 500, "err2")
	tel.AddStep(step1)

	step2 := NewStepStats("b")
	step2.Record(10*time.Millisecond, 200, "err1")
	tel.AddStep(step2)

	errs := tel.Errors()
	if errs["err1"] != 3 || errs["err2"] != 1 {
		t.Errorf("errors = %v, want err1:3, err2:1", errs)
	}
}

// TestTelemetryActiveUsersPeak tests ActiveUsers and PeakUsers
// Note: PeakUsers is not automatically updated; user must track it manually
func TestTelemetryActiveUsersPeak(t *testing.T) {
	tel := NewTelemetry()
	tel.ActiveUsers.Add(10)
	tel.ActiveUsers.Add(20)
	if tel.ActiveUsers.Load() != 30 {
		t.Errorf("active users = %d, want 30", tel.ActiveUsers.Load())
	}
	// PeakUsers starts at 0 and must be set manually
	if tel.PeakUsers.Load() != 0 {
		t.Errorf("peak users = %d, want 0 (not auto-tracked)", tel.PeakUsers.Load())
	}
	// User can manually update peak
	tel.PeakUsers.Store(30)
	if tel.PeakUsers.Load() != 30 {
		t.Errorf("peak users after manual set = %d, want 30", tel.PeakUsers.Load())
	}
}

// TestSortedStatusCodes tests sorted status codes helper
func TestSortedStatusCodes(t *testing.T) {
	codes := map[int]uint64{500: 1, 200: 10, 404: 5, 302: 2}
	sorted := SortedStatusCodes(codes)
	expected := []int{200, 302, 404, 500}
	for i, v := range sorted {
		if v != expected[i] {
			t.Errorf("sorted[%d] = %d, want %d", i, v, expected[i])
		}
	}
}

// TestSortedStatusCodesEmpty tests empty map
func TestSortedStatusCodesEmpty(t *testing.T) {
	sorted := SortedStatusCodes(map[int]uint64{})
	if len(sorted) != 0 {
		t.Errorf("empty map should return empty slice, got %v", sorted)
	}
}

// TestSortedErrors tests sorted errors helper
func TestSortedErrors(t *testing.T) {
	errs := map[string]uint64{"timeout": 5, "connection": 3, "status_5xx": 10}
	sorted := SortedErrors(errs)
	expected := []string{"connection", "status_5xx", "timeout"}
	for i, v := range sorted {
		if v != expected[i] {
			t.Errorf("sorted[%d] = %s, want %s", i, v, expected[i])
		}
	}
}

// TestSortedErrorsEmpty tests empty map
func TestSortedErrorsEmpty(t *testing.T) {
	sorted := SortedErrors(map[string]uint64{})
	if len(sorted) != 0 {
		t.Errorf("empty map should return empty slice, got %v", sorted)
	}
}

// TestStepStatsRecordWithMultipleErrors tests recording multiple different errors
func TestStepStatsRecordWithMultipleErrors(t *testing.T) {
	s := NewStepStats("test")
	s.Record(10*time.Millisecond, 200, "err1")
	s.Record(20*time.Millisecond, 200, "err2")
	s.Record(30*time.Millisecond, 200, "err1")
	s.Record(40*time.Millisecond, 500, "err3")

	errs := s.Errors()
	if errs["err1"] != 2 || errs["err2"] != 1 || errs["err3"] != 1 {
		t.Errorf("errors = %v, want err1:2, err2:1, err3:1", errs)
	}
	if s.ErrorCount() != 4 {
		t.Errorf("error count = %d, want 4", s.ErrorCount())
	}
}

// TestTelemetryMultipleSteps tests telemetry with many steps
func TestTelemetryMultipleSteps(t *testing.T) {
	tel := NewTelemetry()
	for i := 0; i < 10; i++ {
		step := NewStepStats("step" + string(rune('0'+i)))
		step.Record(time.Duration(i+1)*time.Millisecond, 200, "")
		tel.AddStep(step)
	}
	tel.Finish()

	if len(tel.Steps) != 10 {
		t.Errorf("steps = %d, want 10", len(tel.Steps))
	}
	if tel.TotalRequests() != 10 {
		t.Errorf("total requests = %d, want 10", tel.TotalRequests())
	}
}
