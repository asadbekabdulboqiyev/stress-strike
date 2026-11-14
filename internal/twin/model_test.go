package twin

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

// syntheticReport is a single clean operating point: 1,000 rps for 60 s with a
// 15/40/60 ms latency distribution and 0.1% errors. Every model test derives
// from it so failures point at the code, not at test-data drift.
func syntheticReport() report.Report {
	return report.Report{
		Name:          "api-baseline",
		BaseURL:       "https://api.example.test",
		LoadProfile:   "steady",
		StartedAt:     time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		EndedAt:       time.Date(2026, 1, 2, 3, 5, 5, 0, time.UTC),
		Duration:      60 * time.Second,
		ActiveUsers:   20,
		TotalRequests: 60_000,
		TotalErrors:   60,
		ErrorRatePct:  0.1,
		RPS:           1000,
		Overall: report.StepReport{
			Name:     "overall",
			Requests: 60_000,
			Errors:   60,
			Min:      5 * time.Millisecond,
			Avg:      20 * time.Millisecond,
			Max:      250 * time.Millisecond,
			P50:      15 * time.Millisecond,
			P95:      40 * time.Millisecond,
			P99:      60 * time.Millisecond,
		},
	}
}

func fittedModel(t *testing.T) Model {
	t.Helper()
	m, err := Fit(syntheticReport(), FitOptions{})
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	return m
}

func TestFitDerivesWorkload(t *testing.T) {
	m := fittedModel(t)

	if m.SchemaVersion != SchemaVersion {
		t.Errorf("schema = %q, want %q", m.SchemaVersion, SchemaVersion)
	}
	if math.Abs(m.Workload.RPS-1000) > 1e-6 {
		t.Errorf("rps = %v, want 1000", m.Workload.RPS)
	}
	// Little's law: 1000 rps * 0.020 s = 20 concurrent requests.
	if math.Abs(m.Workload.Concurrency-20) > 1e-6 {
		t.Errorf("concurrency = %v, want 20", m.Workload.Concurrency)
	}
	if math.Abs(m.Workload.ErrorRatePct-0.1) > 1e-9 {
		t.Errorf("error rate = %v, want 0.1", m.Workload.ErrorRatePct)
	}
	if m.Workload.OpenLoop {
		t.Error("steady profile must be modelled as closed loop")
	}
	if m.Source.ReportName != "api-baseline" || m.Source.DurationSeconds != 60 {
		t.Errorf("source metadata wrong: %+v", m.Source)
	}
	if !m.Calibration.FittedAt.Equal(syntheticReport().EndedAt) {
		t.Errorf("fit timestamp must come from the report, got %v", m.Calibration.FittedAt)
	}
}

func TestFitDerivesCapacity(t *testing.T) {
	m := fittedModel(t)

	// rhoRef = 1 - (p50/ln2)/p99 = 1 - 21.6404/60 = 0.63933.
	wantCapacity := 1000 / (1 - (15/math.Ln2)/60)
	if math.Abs(m.Curve.CapacityRPS-wantCapacity) > 0.01 {
		t.Errorf("capacity = %.4f, want %.4f", m.Curve.CapacityRPS, wantCapacity)
	}
	if m.Curve.CapacityLowRPS >= m.Curve.CapacityRPS || m.Curve.CapacityHighRPS <= m.Curve.CapacityRPS {
		t.Errorf("capacity bounds do not bracket the point estimate: %+v", m.Curve)
	}
	if m.Curve.ReferenceUtilization <= 0 || m.Curve.ReferenceUtilization >= 1 {
		t.Errorf("reference utilisation = %v, want (0,1)", m.Curve.ReferenceUtilization)
	}
	if m.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want %q for a 60 s / 60k request / 0.1%% error run", m.Confidence, ConfidenceHigh)
	}
	// Default target is max(1.5*p99, p99+50ms) = max(90, 110) = 110 ms.
	if math.Abs(m.Calibration.TargetP99MS-110) > 1e-9 {
		t.Errorf("default target p99 = %v, want 110", m.Calibration.TargetP99MS)
	}
	if math.Abs(m.Curve.Baseline.P99MS-60) > 1e-9 {
		t.Errorf("baseline p99 = %v, want 60", m.Curve.Baseline.P99MS)
	}
}

func TestFitHonoursTargetAndOpenLoop(t *testing.T) {
	rep := syntheticReport()
	rep.LoadProfile = "constant-rps"
	rep.TargetRPS = 1000

	m, err := Fit(rep, FitOptions{TargetP99MS: 250, Producer: "ci-runner"})
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	if !m.Workload.OpenLoop {
		t.Error("constant-rps must be modelled as open loop")
	}
	if m.Calibration.TargetP99MS != 250 {
		t.Errorf("target p99 = %v, want 250", m.Calibration.TargetP99MS)
	}
	if m.Source.Producer != "ci-runner" {
		t.Errorf("producer = %q, want ci-runner", m.Source.Producer)
	}
}

func TestFitClampsFlatTail(t *testing.T) {
	rep := syntheticReport()
	// A nearly flat tail makes the M/M/1 reference utilisation negative. The
	// fit must clamp it, cap capacity at 10x observed load and downgrade the
	// confidence grade.
	rep.Overall.P95 = 15 * time.Millisecond
	rep.Overall.P99 = 15500 * time.Microsecond // 15.5 ms vs p50 15 ms

	m, err := Fit(rep, FitOptions{})
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	if m.Curve.ReferenceUtilization != minReferenceUtilization {
		t.Errorf("reference utilisation = %v, want clamp %v", m.Curve.ReferenceUtilization, minReferenceUtilization)
	}
	if math.Abs(m.Curve.CapacityRPS-1000/minReferenceUtilization) > 1e-6 {
		t.Errorf("capacity = %v, want %v", m.Curve.CapacityRPS, 1000/minReferenceUtilization)
	}
	if m.Confidence == ConfidenceHigh {
		t.Error("a clamped fit must not carry the top confidence grade")
	}
	if !notesContain(m.Calibration.Notes, "clamped") {
		t.Errorf("notes should explain the clamp: %v", m.Calibration.Notes)
	}
}

func TestFitRejectsInvalidReports(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*report.Report)
		want   string
	}{
		{"zero duration", func(r *report.Report) { r.Duration = 0 }, "duration"},
		{"negative duration", func(r *report.Report) { r.Duration = -time.Second }, "duration"},
		{"no requests", func(r *report.Report) { r.TotalRequests = 0 }, "no completed requests"},
		{"non-monotonic p99", func(r *report.Report) { r.Overall.P99 = 10 * time.Millisecond }, "not monotonic"},
		{"zero p50", func(r *report.Report) { r.Overall.P50 = 0 }, "positive"},
		{"errors exceed requests", func(r *report.Report) { r.TotalErrors = 70_000 }, "error rate"},
		{"zero duration reported rps", func(r *report.Report) { r.Duration = 0; r.RPS = 1 }, "duration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := syntheticReport()
			tc.mutate(&rep)
			if _, err := Fit(rep, FitOptions{}); err == nil {
				t.Fatal("expected Fit to reject the report")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestModelValidateRejectsInconsistentValues(t *testing.T) {
	valid := fittedModel(t)

	cases := []struct {
		name   string
		mutate func(*Model)
	}{
		{"empty model", func(m *Model) { *m = Model{} }},
		{"zero capacity", func(m *Model) { m.Curve.CapacityRPS = 0 }},
		{"negative capacity", func(m *Model) { m.Curve.CapacityRPS = -1 }},
		{"nan capacity", func(m *Model) { m.Curve.CapacityRPS = math.NaN() }},
		{"inverted bounds", func(m *Model) { m.Curve.CapacityLowRPS = m.Curve.CapacityRPS * 2 }},
		{"reference at one", func(m *Model) { m.Curve.ReferenceUtilization = 1 }},
		{"zero baseline", func(m *Model) { m.Curve.Baseline.P99MS = 0 }},
		{"non-monotonic baseline", func(m *Model) { m.Curve.Baseline.P99MS = 1 }},
		{"unknown confidence", func(m *Model) { m.Confidence = "certain" }},
		{"zero workload", func(m *Model) { m.Workload.RPS = 0 }},
		{"error rate above 100", func(m *Model) { m.Workload.ErrorRatePct = 150 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := valid
			tc.mutate(&m)
			if err := m.Validate(); err == nil {
				t.Fatal("expected validation to fail")
			}
		})
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid model rejected: %v", err)
	}
}

func notesContain(notes []string, want string) bool {
	for _, n := range notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}
