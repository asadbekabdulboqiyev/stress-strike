package twin

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

// openScenario is a neutral base scenario: 300 rps against a model whose
// capacity is roughly 1,560 rps, so it sits well below the knee.
func openScenario() Scenario {
	return Scenario{
		Name:            "test",
		Mode:            LoopOpen,
		TargetRPS:       300,
		DurationSeconds: 60,
		SLAP99MS:        200,
		Iterations:      200,
		Seed:            42,
	}
}

func TestSimulateIsDeterministic(t *testing.T) {
	m := fittedModel(t)
	sc := openScenario()

	first, err := Simulate(m, sc, 12345)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	second, err := Simulate(m, sc, 12345)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("same seed produced different results")
	}
	if first.Scenario.Seed != 12345 {
		t.Errorf("result seed = %d, want 12345", first.Scenario.Seed)
	}
	if len(first.Iterations) != sc.Iterations {
		t.Errorf("iterations = %d, want %d", len(first.Iterations), sc.Iterations)
	}

	other, err := Simulate(m, sc, 999)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if reflect.DeepEqual(first, other) {
		t.Fatal("different seeds produced identical results")
	}
	if first.Summary.P99MS.P50 == other.Summary.P99MS.P50 {
		t.Errorf("different seeds produced the same p99 median %v", first.Summary.P99MS.P50)
	}
}

func TestHigherLoadRaisesLatencyAndBreaches(t *testing.T) {
	m := fittedModel(t)
	low := openScenario()
	low.Name = "low"
	low.TargetRPS = 300
	high := openScenario()
	high.Name = "high"
	high.TargetRPS = 1400 // ~90% of the fitted capacity: past the knee.

	lowRes, err := Simulate(m, low, 7)
	if err != nil {
		t.Fatalf("low: %v", err)
	}
	highRes, err := Simulate(m, high, 7)
	if err != nil {
		t.Fatalf("high: %v", err)
	}

	if lowRes.Summary.P99MS.P50 < m.Curve.Baseline.P99MS*0.85 {
		t.Errorf("sub-reference load predicted p99 %.2f below baseline %.2f", lowRes.Summary.P99MS.P50, m.Curve.Baseline.P99MS)
	}
	if highRes.Summary.P99MS.P50 <= lowRes.Summary.P99MS.P50 {
		t.Errorf("higher load did not raise p99: %.2f vs %.2f", highRes.Summary.P99MS.P50, lowRes.Summary.P99MS.P50)
	}
	if highRes.Summary.P99MS.P50 <= m.Curve.Baseline.P99MS*1.5 {
		t.Errorf("high load p99 %.2f shows no amplification over baseline", highRes.Summary.P99MS.P50)
	}
	if highRes.Summary.SLAProbabilityBreach <= lowRes.Summary.SLAProbabilityBreach {
		t.Errorf("breach probability did not rise: low %.3f high %.3f", lowRes.Summary.SLAProbabilityBreach, highRes.Summary.SLAProbabilityBreach)
	}
	if lowRes.Summary.SLAProbabilityBreach != 0 {
		t.Errorf("low load should not breach a 200 ms SLA, got %.3f", lowRes.Summary.SLAProbabilityBreach)
	}
	// Amplification is capped, so the p99 band must stay finite.
	if math.IsInf(highRes.Summary.P99MS.Max, 0) || math.IsNaN(highRes.Summary.P99MS.Max) {
		t.Errorf("capped p99 is not finite: %v", highRes.Summary.P99MS.Max)
	}
}

func TestLowLoadSanity(t *testing.T) {
	m := fittedModel(t)
	sc := openScenario()
	sc.TargetRPS = 5
	sc.SLAP99MS = 1000

	res, err := Simulate(m, sc, 3)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if res.Summary.SLAProbabilityBreach != 0 {
		t.Errorf("5 rps against a 1 s SLA breached in %.1f%% of draws", res.Summary.SLAProbabilityBreach*100)
	}
	if res.Summary.P99MS.P50 < m.Curve.Baseline.P99MS*0.8 || res.Summary.P99MS.P50 > m.Curve.Baseline.P99MS*1.25 {
		t.Errorf("low-load p99 %.2f should stay near baseline %.2f", res.Summary.P99MS.P50, m.Curve.Baseline.P99MS)
	}
	if res.Summary.Utilization.P50 >= m.Curve.ReferenceUtilization {
		t.Errorf("low-load utilisation %.3f should be below reference %.3f", res.Summary.Utilization.P50, m.Curve.ReferenceUtilization)
	}
}

func TestClosedLoopConvergesBelowCapacity(t *testing.T) {
	m := fittedModel(t)
	sc := openScenario()
	sc.Name = "closed"
	sc.Mode = LoopClosed
	sc.TargetRPS = 0
	sc.TargetUsers = 500

	res, err := Simulate(m, sc, 11)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	for _, it := range res.Iterations {
		if it.AchievedRPS <= 0 {
			t.Fatalf("iteration %d achieved non-positive throughput", it.Index)
		}
		if it.CapacityRPS <= 0 || it.Utilization >= 1 {
			t.Fatalf("iteration %d utilisation %.4f is not below 1", it.Index, it.Utilization)
		}
		if it.AchievedRPS > it.CapacityRPS {
			t.Fatalf("iteration %d achieved %.2f above capacity %.2f", it.Index, it.AchievedRPS, it.CapacityRPS)
		}
	}
	if res.Summary.AchievedRPS.P50 <= 0 {
		t.Errorf("closed-loop achieved rps = %v", res.Summary.AchievedRPS.P50)
	}

	// More users must not reduce throughput in a closed loop.
	fewer := sc
	fewer.TargetUsers = 50
	fewerRes, err := Simulate(m, fewer, 11)
	if err != nil {
		t.Fatalf("Simulate fewer: %v", err)
	}
	if res.Summary.AchievedRPS.P50 < fewerRes.Summary.AchievedRPS.P50 {
		t.Errorf("more users reduced throughput: %v < %v", res.Summary.AchievedRPS.P50, fewerRes.Summary.AchievedRPS.P50)
	}
}

func TestSaturationTimePredictedOnOverload(t *testing.T) {
	m := fittedModel(t)
	sc := openScenario()
	sc.Name = "worst"
	sc.TargetRPS = m.Curve.CapacityHighRPS * 1.2
	sc.RampSeconds = 10
	sc.SLAP99MS = m.Calibration.TargetP99MS
	sc.Iterations = 100

	res, err := Simulate(m, sc, 5)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if res.Summary.PredictedSaturationSeconds == nil {
		t.Fatal("overloaded ramp should predict a saturation time")
	}
	if got := *res.Summary.PredictedSaturationSeconds; got < 0 || got > sc.RampSeconds {
		t.Errorf("saturation time %.2fs outside [0,%.2fs]", got, sc.RampSeconds)
	}
	if res.Summary.SaturationProbability < 0.9 {
		t.Errorf("saturation probability = %.3f, want >= 0.9", res.Summary.SaturationProbability)
	}
	if !notesContain(res.Notes, "saturation") {
		t.Errorf("notes should mention saturation: %v", res.Notes)
	}

	// A comfortable load must not predict saturation.
	sc.TargetRPS = m.Curve.CapacityLowRPS * 0.2
	res, err = Simulate(m, sc, 5)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if res.Summary.PredictedSaturationSeconds != nil {
		t.Errorf("safe load predicted saturation at %v", *res.Summary.PredictedSaturationSeconds)
	}
}

func TestSimulateGuardRails(t *testing.T) {
	m := fittedModel(t)

	cases := []struct {
		name   string
		mutate func(*Scenario)
		want   string
	}{
		{"negative rps", func(s *Scenario) { s.TargetRPS = -1 }, "positive"},
		{"zero rps", func(s *Scenario) { s.TargetRPS = 0 }, "positive"},
		{"huge rps", func(s *Scenario) { s.TargetRPS = MaxRPS + 1 }, "limit"},
		{"zero iterations", func(s *Scenario) { s.Iterations = 0 }, "iterations"},
		{"too many iterations", func(s *Scenario) { s.Iterations = MaxIterations + 1 }, "iterations"},
		{"zero duration", func(s *Scenario) { s.DurationSeconds = 0 }, "duration"},
		{"huge duration", func(s *Scenario) { s.DurationSeconds = MaxDurationSeconds + 1 }, "duration"},
		{"unknown mode", func(s *Scenario) { s.Mode = "sideways" }, "loop mode"},
		{"negative sla", func(s *Scenario) { s.SLAP99MS = -1 }, "sla p99"},
		{"error rate above 100", func(s *Scenario) { s.MaxErrorRatePct = 101 }, "max error rate"},
		{"ramp longer than duration", func(s *Scenario) { s.RampSeconds = s.DurationSeconds + 1 }, "ramp"},
		{"empty name", func(s *Scenario) { s.Name = " " }, "name"},
		{"closed loop without users", func(s *Scenario) { s.Mode = LoopClosed; s.TargetRPS = 0 }, "target users"},
		{"closed loop too many users", func(s *Scenario) { s.Mode = LoopClosed; s.TargetUsers = MaxUsers + 1 }, "limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := openScenario()
			tc.mutate(&sc)
			if _, err := Simulate(m, sc, 1); err == nil {
				t.Fatal("expected Simulate to reject the scenario")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	if _, err := Simulate(Model{}, openScenario(), 1); err == nil {
		t.Fatal("expected Simulate to reject a zero model")
	}
}

func TestAmplificationShape(t *testing.T) {
	const ref = 0.5
	if got := amplification(ref, ref); got != 1 {
		t.Errorf("amp(ref) = %v, want 1", got)
	}
	if got := amplification(0.1, ref); got != 1 {
		t.Errorf("amp below reference = %v, want 1", got)
	}
	if got := amplification(maxUtilization, ref); got != maxAmplification {
		t.Errorf("amp at the pole = %v, want cap %v", got, maxAmplification)
	}
	if got := amplification(2, ref); got != maxAmplification {
		t.Errorf("amp above capacity = %v, want cap %v", got, maxAmplification)
	}
	prev := 0.0
	for _, rho := range []float64{0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99} {
		amp := amplification(rho, ref)
		if amp < prev {
			t.Fatalf("amplification is not monotonic at rho=%v: %v < %v", rho, amp, prev)
		}
		prev = amp
	}
}

func TestPresets(t *testing.T) {
	m := fittedModel(t)
	seen := make(map[string]float64, len(PresetNames()))
	for _, name := range PresetNames() {
		sc, err := Preset(name, m)
		if err != nil {
			t.Fatalf("Preset(%q): %v", name, err)
		}
		if sc.Name != name || sc.Mode != LoopOpen || sc.TargetRPS <= 0 {
			t.Errorf("preset %q is malformed: %+v", name, sc)
		}
		if sc.SLAP99MS != m.Calibration.TargetP99MS {
			t.Errorf("preset %q sla = %v, want %v", name, sc.SLAP99MS, m.Calibration.TargetP99MS)
		}
		if sc.Iterations != 200 || sc.Seed != 42 || sc.RampSeconds != 10 {
			t.Errorf("preset %q defaults drifted: %+v", name, sc)
		}
		seen[name] = sc.TargetRPS
	}
	if !(seen["best"] < seen["likely"] && seen["likely"] < seen["worst"]) {
		t.Errorf("presets are not ordered best < likely < worst: %v", seen)
	}
	if _, err := Preset("optimistic", m); err == nil {
		t.Fatal("expected an unknown preset to be rejected")
	}
	if _, err := Preset("best", Model{}); err == nil {
		t.Fatal("expected Preset to reject an invalid model")
	}
}

func TestRiskLevelVocabulary(t *testing.T) {
	cases := map[float64]string{
		0:    RiskLow,
		0.04: RiskLow,
		0.05: RiskElevated,
		0.49: RiskElevated,
		0.5:  RiskHigh,
		1:    RiskHigh,
	}
	for in, want := range cases {
		if got := riskLevel(in); got != want {
			t.Errorf("riskLevel(%v) = %q, want %q", in, got, want)
		}
	}
}
