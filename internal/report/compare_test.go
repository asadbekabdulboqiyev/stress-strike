package report

import (
	"strings"
	"testing"
	"time"
)

func baseReport() *Report {
	return &Report{
		Name:         "baseline",
		TotalRequests: 50000,
		TotalErrors:   50,
		ErrorRatePct:  0.1,
		RPS:           5000,
		Overall: StepReport{
			Name: "overall", Requests: 50000, Errors: 50,
			Avg: 12 * time.Millisecond, P50: 10 * time.Millisecond,
			P95: 30 * time.Millisecond, P99: 45 * time.Millisecond,
			Max: 200 * time.Millisecond,
		},
	}
}

func TestCompareIdentical(t *testing.T) {
	base := baseReport()
	cur := baseReport()
	result := Compare(cur, base)

	if result.Regression {
		t.Error("Regression = true for identical reports")
	}
	if result.Grade != "A" {
		t.Errorf("Grade = %q, want A for identical reports", result.Grade)
	}
	if result.RequestDiff != 0 {
		t.Errorf("RequestDiff = %d, want 0", result.RequestDiff)
	}
	if result.P99Diff != 0 {
		t.Errorf("P99Diff = %f, want 0", result.P99Diff)
	}
	if result.RPSDiff != 0 {
		t.Errorf("RPSDiff = %f, want 0", result.RPSDiff)
	}
}

func TestCompareImproved(t *testing.T) {
	base := baseReport()
	cur := baseReport()
	cur.Overall.P99 = 30 * time.Millisecond  // -33%
	cur.Overall.P50 = 7 * time.Millisecond   // -30%
	cur.Overall.Avg = 8 * time.Millisecond   // -33%
	cur.RPS = 7000                           // +40%
	cur.TotalErrors = 10                     // -80%
	cur.ErrorRatePct = 0.02

	result := Compare(cur, base)

	if result.Regression {
		t.Error("Regression = true for improved report")
	}
	if result.Grade != "A" {
		t.Errorf("Grade = %q, want A", result.Grade)
	}
	if result.P99Diff >= 0 {
		t.Errorf("P99Diff = %f, want negative (improved)", result.P99Diff)
	}
	if result.RPSDiff <= 0 {
		t.Errorf("RPSDiff = %f, want positive (improved)", result.RPSDiff)
	}
}

func TestCompareRegressed(t *testing.T) {
	base := baseReport()
	cur := baseReport()
	cur.Overall.P99 = 90 * time.Millisecond  // +100%
	cur.RPS = 2500                           // -50%
	cur.TotalErrors = 200                    // +300%
	cur.ErrorRatePct = 0.4

	result := Compare(cur, base)

	if !result.Regression {
		t.Error("Regression = false for regressed report")
	}
	if result.RegressionPct <= 0 {
		t.Errorf("RegressionPct = %f, want positive", result.RegressionPct)
	}
}

func TestGradeCalculation(t *testing.T) {
	tests := []struct {
		worstPct float64
		want     string
	}{
		{0, "A"},
		{2, "A"},
		{5, "A"},
		{5.1, "B"},
		{10, "B"},
		{10.1, "C"},
		{20, "C"},
		{20.1, "D"},
		{30, "D"},
		{30.1, "F"},
		{100, "F"},
	}
	for _, tt := range tests {
		got := gradeForRegression(tt.worstPct)
		if got != tt.want {
			t.Errorf("gradeForRegression(%.1f) = %q, want %q", tt.worstPct, got, tt.want)
		}
	}
}

func TestCompareZeroBaseline(t *testing.T) {
	base := baseReport()
	base.TotalRequests = 0
	base.Overall.P99 = 0
	base.Overall.Avg = 0
	base.RPS = 0
	cur := baseReport()

	result := Compare(cur, base)
	if result.Regression {
		t.Error("Regression should not trigger when baseline is zero")
	}
}

func TestRenderOutput(t *testing.T) {
	base := baseReport()
	cur := baseReport()
	cur.Overall.P99 = 50 * time.Millisecond
	cur.RPS = 4500
	result := Compare(cur, base)
	out := result.Render()

	if !strings.Contains(out, "BASELINE COMPARISON") {
		t.Error("Render output missing header")
	}
	if !strings.Contains(out, "Metric") {
		t.Error("Render output missing column headers")
	}
	if !strings.Contains(out, "Requests") {
		t.Error("Render output missing Requests row")
	}
	if !strings.Contains(out, "P99 Latency") {
		t.Error("Render output missing P99 Latency row")
	}
	if !strings.Contains(out, "RPS") {
		t.Error("Render output missing RPS row")
	}
	if !strings.Contains(out, "VERDICT") {
		t.Error("Render output missing VERDICT")
	}
}

func TestRenderRegressed(t *testing.T) {
	base := baseReport()
	cur := baseReport()
	cur.Overall.P99 = 100 * time.Millisecond // +122%
	cur.RPS = 1000                           // -80%
	result := Compare(cur, base)
	out := result.Render()

	if !strings.Contains(out, "REGRESSED") {
		t.Error("Render should show REGRESSED verdict")
	}
}

func TestRenderImproved(t *testing.T) {
	base := baseReport()
	cur := baseReport()
	cur.Overall.P99 = 20 * time.Millisecond
	cur.RPS = 8000
	result := Compare(cur, base)
	out := result.Render()

	if !strings.Contains(out, "IMPROVED") {
		t.Error("Render should show IMPROVED verdict")
	}
}
