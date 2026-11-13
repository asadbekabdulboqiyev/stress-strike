package main

// main_helpers_test.go — coverage for the reporting/render helpers that main()
// uses after a distributed run finishes: quickScenario, printSummary,
// saveReports, compareReports, evaluateSLA and printLiveProgress.
//
// Everything here is filesystem- or stdout-only; no worker fleet is started.

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/dist/coordinator"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

// captureStdout redirects os.Stdout to a temp file for the duration of fn and
// returns everything written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatalf("temp stdout: %v", err)
	}
	prev := os.Stdout
	os.Stdout = f
	defer func() {
		os.Stdout = prev
		_ = f.Close()
	}()
	fn()
	if err := f.Sync(); err != nil {
		t.Fatalf("sync stdout: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek stdout: %v", err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(b)
}

func sampleReport() *report.Report {
	return &report.Report{
		Name:          "unit-run",
		TotalRequests: 1234,
		TotalErrors:   7,
		ErrorRatePct:  0.57,
		RPS:           250,
		Overall: report.StepReport{
			Avg: 12 * time.Millisecond,
			P50: 10 * time.Millisecond,
			P95: 30 * time.Millisecond,
			P99: 45 * time.Millisecond,
			Max: 90 * time.Millisecond,
		},
		Status: map[int]uint64{200: 1227, 500: 7},
		Errors: map[string]uint64{"http_500": 7},
	}
}

func TestQuickScenarioValid(t *testing.T) {
	sc, err := quickScenario("quick", "http://127.0.0.1:8080/health", 25, 5, "steady")
	if err != nil {
		t.Fatalf("quickScenario: %v", err)
	}
	if sc.Name != "quick" {
		t.Errorf("Name = %q, want quick", sc.Name)
	}
	if sc.Profile.Users != 25 || sc.Profile.Duration != 5 || sc.Profile.Timeout != 5 {
		t.Errorf("profile = %+v, want users=25 duration=5 timeout=5", sc.Profile)
	}
	if len(sc.Steps) != 1 || sc.Steps[0].URL != "http://127.0.0.1:8080/health" {
		t.Errorf("steps = %+v, want a single GET to the target", sc.Steps)
	}
}

func TestQuickScenarioInvalidURL(t *testing.T) {
	// An empty URL survives neither Normalize's step validation nor a run.
	if _, err := quickScenario("quick", "", 10, 5, "steady"); err == nil {
		t.Fatal("quickScenario(empty url) = nil error, want a Normalize failure")
	}
}

func TestPrintSummaryRendersTotals(t *testing.T) {
	out := captureStdout(t, func() { printSummary(sampleReport()) })
	for _, want := range []string{
		"DISTRIBUTED RUN COMPLETE: unit-run",
		"Requests: 1.2K",
		"Errors: 7 (0.57%)",
		"RPS: 250",
		"avg=12ms",
		"p99=45ms",
		"max=90ms",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printSummary output missing %q:\n%s", want, out)
		}
	}
}

func TestSaveReportsWritesBothFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	out := captureStdout(t, func() { saveReports(sampleReport(), "unit-run") })

	entries, err := os.ReadDir("reports")
	if err != nil {
		t.Fatalf("reports dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	joined := strings.Join(names, " ")
	if !strings.Contains(joined, ".json") || !strings.Contains(joined, ".txt") {
		t.Fatalf("reports dir = %v, want a .json and a .txt report", names)
	}
	if !strings.Contains(out, "Reports written:") {
		t.Errorf("saveReports output missing header:\n%s", out)
	}
}

func TestSaveReportsFailsWhenDirUnwritable(t *testing.T) {
	dir := t.TempDir()
	// A regular file named "reports" makes MkdirAll fail.
	if err := os.WriteFile(filepath.Join(dir, "reports"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	out := captureStdout(t, func() { saveReports(sampleReport(), "unit-run") })
	if !strings.Contains(out, "Reports written:") && out != "" {
		// saveReports returns early on MkdirAll failure; nothing should be printed.
		t.Logf("output on failure: %q", out)
	}
	if out != "" {
		t.Errorf("saveReports printed %q after a failed mkdir, want silence", out)
	}
}

func TestCompareReportsAgainstBaseline(t *testing.T) {
	dir := t.TempDir()
	baseline := sampleReport()
	baseline.Name = "baseline"
	path, err := baseline.SaveJSON(dir)
	if err != nil {
		t.Fatalf("SaveJSON: %v", err)
	}

	// A much slower current run crosses the default 20% regression threshold.
	current := sampleReport()
	current.Name = "current"
	current.Overall = report.StepReport{
		Avg: 200 * time.Millisecond,
		P50: 180 * time.Millisecond,
		P95: 400 * time.Millisecond,
		P99: 900 * time.Millisecond,
		Max: time.Second,
	}

	out := captureStdout(t, func() { compareReports(current, path, 20) })
	if !strings.Contains(out, "REGRESSION DETECTED") {
		t.Errorf("compareReports did not flag a regression:\n%s", out)
	}
}

func TestCompareReportsMissingBaseline(t *testing.T) {
	out := captureStdout(t, func() {
		compareReports(sampleReport(), filepath.Join(t.TempDir(), "absent.json"), 20)
	})
	if out != "" {
		t.Errorf("compareReports printed %q for a missing baseline, want silence", out)
	}
}

func TestEvaluateSLANilAndEmptyPass(t *testing.T) {
	if !evaluateSLA(sampleReport(), nil) {
		t.Error("evaluateSLA(nil SLA) = false, want true")
	}
	if !evaluateSLA(sampleReport(), &config.SLA{}) {
		t.Error("evaluateSLA(empty SLA) = false, want true")
	}
}

func TestEvaluateSLAPassAndFail(t *testing.T) {
	r := sampleReport()

	pass := &config.SLA{MaxP99Ms: 100, MaxErrorRatePct: 5, MinRPS: 100}
	out := captureStdout(t, func() {
		if !evaluateSLA(r, pass) {
			t.Error("evaluateSLA(loose SLA) = false, want true")
		}
	})
	if strings.Contains(out, "FAIL") {
		t.Errorf("loose SLA reported a failure:\n%s", out)
	}

	fail := &config.SLA{MaxP99Ms: 1, MaxAvgMs: 1, MaxErrorRatePct: 0.1, MinRPS: 10_000}
	out = captureStdout(t, func() {
		if evaluateSLA(r, fail) {
			t.Error("evaluateSLA(strict SLA) = true, want false")
		}
	})
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "SLA") && !strings.Contains(out, "p99") {
		t.Errorf("strict SLA output missing failure rows:\n%s", out)
	}
}

func TestPrintLiveProgressStops(t *testing.T) {
	master := coordinator.NewMaster(coordinator.MasterConfig{})
	stop := make(chan struct{})
	done := make(chan struct{})

	out := captureStdout(t, func() {
		go func() {
			printLiveProgress(master, stop)
			close(done)
		}()
		// One tick with no workers exercises the "workers == 0 → continue"
		// branch, then the closed channel exercises the cleanup branch.
		time.Sleep(1100 * time.Millisecond)
		close(stop)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("printLiveProgress did not return after stop closed")
		}
	})
	if !strings.Contains(out, "\r\x1b[K") {
		t.Errorf("printLiveProgress cleanup line missing from %q", out)
	}
}
