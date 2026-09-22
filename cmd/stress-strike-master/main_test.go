package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
)

// --- String helpers ---------------------------------------------------------

func TestSplitAndTrim(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b ,,c", []string{"a", "b", "c"}},
		{" a ,\tb ", []string{"a", "b"}},
		{"", nil},
		{",,,", nil},
	}
	for _, c := range cases {
		got := splitAndTrim(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitAndTrim(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestTrimSpace(t *testing.T) {
	cases := []struct{ in, want string }{
		{"  hello  ", "hello"},
		{"\thello\t", "hello"},
		{"", ""},
		{"   ", ""},
		{"noSpace", "noSpace"},
	}
	for _, c := range cases {
		if got := trimSpace(c.in); got != c.want {
			t.Errorf("trimSpace(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSplitComma(t *testing.T) {
	if got := splitComma("x,y"); !reflect.DeepEqual(got, []string{"x", "y"}) {
		t.Errorf("splitComma = %v", got)
	}
	if got := splitComma(""); len(got) != 1 || got[0] != "" {
		t.Errorf("splitComma(\"\") = %v", got)
	}
}

// --- quickScenario ----------------------------------------------------------

func TestQuickScenario(t *testing.T) {
	sc, err := quickScenario("test-run", "http://example.com/health", 150, 60, "spike")
	if err != nil {
		t.Fatalf("quickScenario error: %v", err)
	}
	if sc.Name != "test-run" {
		t.Errorf("name = %q", sc.Name)
	}
	if sc.Profile.Type != "spike" || sc.Profile.Users != 150 || sc.Profile.Duration != 60 {
		t.Errorf("profile = %+v", sc.Profile)
	}
	if len(sc.Steps) != 1 {
		t.Fatalf("steps = %d", len(sc.Steps))
	}
	st := sc.Steps[0]
	if st.Method != "GET" || st.URL != "http://example.com/health" || st.Type != "http" {
		t.Errorf("step = %+v", st)
	}
}

func TestQuickScenarioDefaultsSteadyProfile(t *testing.T) {
	sc, err := quickScenario("n", "http://example.com", 0, 0, "")
	if err != nil {
		t.Fatalf("quickScenario error: %v", err)
	}
	if sc.Profile.Type != config.ProfileSteady {
		t.Errorf("default profile = %q", sc.Profile.Type)
	}
	if sc.Profile.Users != 10 || sc.Profile.Duration != 30 {
		t.Errorf("defaults not applied: users=%d duration=%d", sc.Profile.Users, sc.Profile.Duration)
	}
}

// --- Formatting helpers -----------------------------------------------------

func TestFormatCount(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1.0K"},
		{1500, "1.5K"},
		{999_999, "1000.0K"},
		{1_000_000, "1.0M"},
		{2_500_000, "2.5M"},
	}
	for _, c := range cases {
		if got := formatCount(c.in); got != c.want {
			t.Errorf("formatCount(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatRPS(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1.0K"},
		{1500, "1.5K"},
	}
	for _, c := range cases {
		if got := formatRPS(c.in); got != c.want {
			t.Errorf("formatRPS(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestErrorRate(t *testing.T) {
	if got := errorRate(0, 5); got != 0 {
		t.Errorf("errorRate(0,5) = %v", got)
	}
	if got := errorRate(100, 5); got != 5 {
		t.Errorf("errorRate(100,5) = %v", got)
	}
	if got := errorRate(100, 100); got != 100 {
		t.Errorf("errorRate(100,100) = %v", got)
	}
}

func TestMax64(t *testing.T) {
	if got := max64(5, 3); got != 5 {
		t.Errorf("max64(5,3) = %d", got)
	}
	if got := max64(3, 5); got != 5 {
		t.Errorf("max64(3,5) = %d", got)
	}
	if got := max64(7, 7); got != 7 {
		t.Errorf("max64(7,7) = %d", got)
	}
}

// --- SLA helpers ------------------------------------------------------------

func TestSlaEmpty(t *testing.T) {
	if !slaEmpty(nil) {
		t.Error("nil SLA should be empty")
	}
	if !slaEmpty(&config.SLA{}) {
		t.Error("zero SLA should be empty")
	}
	if slaEmpty(&config.SLA{MaxP99Ms: 100}) {
		t.Error("MaxP99Ms should make SLA non-empty")
	}
	if slaEmpty(&config.SLA{MaxAvgMs: 100}) {
		t.Error("MaxAvgMs should make SLA non-empty")
	}
	if slaEmpty(&config.SLA{MaxErrorRatePct: 1}) {
		t.Error("MaxErrorRatePct should make SLA non-empty")
	}
	if slaEmpty(&config.SLA{MinRPS: 1}) {
		t.Error("MinRPS should make SLA non-empty")
	}
}

func TestEvaluateSLAPassAndFail(t *testing.T) {
	// Passing SLA: p99 well under the limit.
	passing := &report.Report{
		Name: "r",
		Overall: report.StepReport{
			Requests: 100,
			P99:      50 * time.Millisecond,
			Avg:      10 * time.Millisecond,
		},
		ErrorRatePct: 0.5,
		RPS:          100,
	}
	if !evaluateSLA(passing, &config.SLA{MaxP99Ms: 200, MaxAvgMs: 100, MaxErrorRatePct: 1, MinRPS: 10}) {
		t.Error("expected SLA gate to pass")
	}

	// Failing SLA: p99 above the cap.
	failing := &report.Report{
		Overall: report.StepReport{P99: 500 * time.Millisecond},
	}
	if evaluateSLA(failing, &config.SLA{MaxP99Ms: 100}) {
		t.Error("expected SLA gate to fail")
	}

	// Empty / nil SLA always passes.
	if !evaluateSLA(failing, &config.SLA{}) {
		t.Error("empty SLA should always pass")
	}
}
