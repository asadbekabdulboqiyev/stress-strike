package report

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func sampleReport() *Report {
	return &Report{
		Name:         "test",
		RPS:          1000,
		ErrorRatePct: 0.5,
		Duration:     10 * time.Second,
		Overall: StepReport{
			Name: "overall", Requests: 10000, Errors: 50,
			Avg: 20 * time.Millisecond, P50: 15 * time.Millisecond,
			P95: 80 * time.Millisecond, P99: 150 * time.Millisecond,
			Max: 400 * time.Millisecond,
		},
	}
}

func TestEvaluateSLAAllPass(t *testing.T) {
	r := sampleReport()
	sla := &config.SLA{MaxP99Ms: 200, MaxAvgMs: 50, MaxErrorRatePct: 1, MinRPS: 500}
	res := EvaluateSLA(r, sla)
	if len(res) != 4 {
		t.Fatalf("checks = %d, want 4", len(res))
	}
	for _, chk := range res {
		if !chk.Pass {
			t.Errorf("check %q failed unexpectedly: %+v", chk.Metric, chk)
		}
	}
	if !SLAPassed(res) {
		t.Error("SLAPassed = false, want true")
	}
}

func TestEvaluateSLAFailures(t *testing.T) {
	r := sampleReport() // p99=150ms, err=0.5%, rps=1000
	sla := &config.SLA{MaxP99Ms: 100, MaxErrorRatePct: 0.2, MinRPS: 2000}
	res := EvaluateSLA(r, sla)
	failed := 0
	for _, chk := range res {
		if !chk.Pass {
			failed++
		}
	}
	if failed != 3 {
		t.Errorf("failed checks = %d, want 3 (all thresholds violated)", failed)
	}
	if SLAPassed(res) {
		t.Error("SLAPassed = true, want false")
	}
}

func TestEvaluateSLANil(t *testing.T) {
	if res := EvaluateSLA(sampleReport(), nil); res != nil {
		t.Errorf("nil SLA produced %d checks, want 0", len(res))
	}
}

func TestCompareRegressionAndImprovement(t *testing.T) {
	base := sampleReport()
	cur := sampleReport()
	cur.Overall.P99 = 300 * time.Millisecond // +100% vs baseline 150ms → regressed
	result := Compare(cur, base)

	if !result.Regression {
		t.Fatal("Regression = false, want true after p99 doubled")
	}
	if result.Grade != "F" {
		t.Errorf("Grade = %q, want F (100%% regression)", result.Grade)
	}

	// Improvement direction.
	cur2 := sampleReport()
	cur2.Overall.P95 = 40 * time.Millisecond // -50% vs 80ms → improved
	cur2.RPS = 2000                          // +100% → improved
	result2 := Compare(cur2, base)
	if result2.Regression {
		t.Error("Regression = true for an improved run")
	}
	if result2.Grade != "A" {
		t.Errorf("Grade = %q, want A for improved run", result2.Grade)
	}
}

func TestLoadReportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	r := sampleReport()
	r.Timeline = []metrics.TimelineSample{{Second: 1, Requests: 900}}
	path, err := r.SaveJSON(dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != r.Name || loaded.TotalRequests != r.TotalRequests {
		t.Errorf("round-trip mismatch: %+v", loaded)
	}
	if len(loaded.Timeline) != 1 {
		t.Errorf("timeline lost on save/load: %d samples", len(loaded.Timeline))
	}
}

func TestSaveCSVTimeline(t *testing.T) {
	dir := t.TempDir()
	r := sampleReport()
	r.Timeline = []metrics.TimelineSample{
		{Second: 1, Requests: 900, Errors: 1, ActiveUsers: 50},
		{Second: 2, Requests: 1900, Errors: 3, ActiveUsers: 60},
	}
	path, err := r.SaveCSV(dir)
	if err != nil {
		t.Fatal(err)
	}
	data := readFile(t, path)
	lines := strings.Split(strings.TrimSpace(data), "\n")
	if len(lines) != 3 {
		t.Fatalf("csv lines = %d, want header+2", len(lines))
	}
	if !strings.HasPrefix(lines[0], "second,requests_total") {
		t.Errorf("bad csv header: %q", lines[0])
	}
	// Delta check: second row requests_delta must be 1000.
	if !strings.Contains(lines[2], ",1000,") {
		t.Errorf("requests_delta wrong in %q", lines[2])
	}
}

func TestSaveCSVEmpty(t *testing.T) {
	path, err := sampleReport().SaveCSV(t.TempDir())
	if err != nil || path != "" {
		t.Errorf("empty timeline should return empty path, got %q, %v", path, err)
	}
}
