package coordinator

import (
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	distproto "github.com/asadbekabdulboqiyev/stress-strike/internal/dist/proto"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
)

func TestShareSumsToTotal(t *testing.T) {
	cases := []struct{ total, n int }{
		{100, 3}, {10, 4}, {7, 7}, {1, 5}, {0, 3}, {1000, 16},
	}
	for _, c := range cases {
		sum := 0
		for i := 0; i < c.n; i++ {
			sum += share(c.total, i, c.n)
		}
		if sum != c.total {
			t.Fatalf("share(%d,%d) summed to %d", c.total, c.n, sum)
		}
	}
}

func TestSplitScenarioDividesAllProfileFields(t *testing.T) {
	base := &config.Scenario{
		Name: "s",
		Profile: config.Profile{
			Type:       "spike",
			Users:      100,
			SpikeUsers: 50,
			RPS:        1000,
			TargetRPS:  900,
			Duration:   30,
		},
		Steps:     []config.Step{{Name: "a", URL: "http://x"}},
		Variables: map[string]string{"k": "v"},
	}
	var users, spike, rps, target int
	for i := 0; i < 3; i++ {
		sc := SplitScenario(base, i, 3)
		users += sc.Profile.Users
		spike += sc.Profile.SpikeUsers
		rps += sc.Profile.RPS
		target += sc.Profile.TargetRPS
		if sc.Profile.Duration != 30 {
			t.Fatalf("duration should be shared, got %d", sc.Profile.Duration)
		}
	}
	if users != 100 || spike != 50 || rps != 1000 || target != 900 {
		t.Fatalf("shares did not sum: users=%d spike=%d rps=%d target=%d", users, spike, rps, target)
	}

	// The base scenario must not be mutated by splitting.
	if base.Profile.Users != 100 {
		t.Fatalf("base scenario mutated: %d", base.Profile.Users)
	}
	// Slices/maps must be independent copies.
	split := SplitScenario(base, 0, 3)
	split.Steps[0].Name = "changed"
	split.Variables["k"] = "changed"
	if base.Steps[0].Name != "a" || base.Variables["k"] != "v" {
		t.Fatal("split shares underlying steps/variables with base")
	}
}

func TestAggregatorSumsLatestSnapshots(t *testing.T) {
	agg := NewAggregator()
	agg.Update("w1", &distproto.TelemetrySnapshot{
		TotalRequests: 100, TotalErrors: 5, ActiveUsers: 10, Rps: 50,
		ElapsedMs:   2000,
		StatusCodes: map[int32]int64{200: 95, 500: 5},
		ErrorTypes:  map[string]int64{"timeout": 5},
		Latency:     &distproto.LatencyPercentiles{P50Ms: 10, P95Ms: 40, P99Ms: 90, AvgMs: 20, MinMs: 1, MaxMs: 200},
		Steps: []*distproto.StepTelemetry{{
			Name: "s1", Requests: 100, Errors: 5,
			Latency: &distproto.LatencyPercentiles{P50Ms: 10, AvgMs: 20, MinMs: 1, MaxMs: 200},
		}},
	})
	// A second snapshot from the same worker must replace, not add to, the first.
	agg.Update("w1", &distproto.TelemetrySnapshot{
		TotalRequests: 200, TotalErrors: 8, ActiveUsers: 10, Rps: 60,
		ElapsedMs:   2500,
		StatusCodes: map[int32]int64{200: 192, 500: 8},
		Latency:     &distproto.LatencyPercentiles{P50Ms: 12, P95Ms: 45, P99Ms: 95, AvgMs: 25, MinMs: 1, MaxMs: 210},
		Steps: []*distproto.StepTelemetry{{
			Name: "s1", Requests: 200, Errors: 8,
			Latency: &distproto.LatencyPercentiles{P50Ms: 12, AvgMs: 25, MinMs: 1, MaxMs: 210},
		}},
	})
	agg.Update("w2", &distproto.TelemetrySnapshot{
		TotalRequests: 300, TotalErrors: 2, ActiveUsers: 20, Rps: 120,
		ElapsedMs:   2600,
		StatusCodes: map[int32]int64{200: 298, 503: 2},
		Latency:     &distproto.LatencyPercentiles{P50Ms: 15, P95Ms: 50, P99Ms: 120, AvgMs: 30, MinMs: 2, MaxMs: 300},
	})

	snap := agg.Snapshot()
	if snap.Workers != 2 {
		t.Fatalf("workers=%d", snap.Workers)
	}
	if snap.TotalRequests != 500 {
		t.Fatalf("requests=%d, want 500 (latest per worker)", snap.TotalRequests)
	}
	if snap.TotalErrors != 10 {
		t.Fatalf("errors=%d, want 10", snap.TotalErrors)
	}
	if snap.ActiveUsers != 30 {
		t.Fatalf("active=%d, want 30", snap.ActiveUsers)
	}
	if snap.RPS != 180 {
		t.Fatalf("rps=%v, want 180", snap.RPS)
	}
	if snap.Elapsed != 2600*time.Millisecond {
		t.Fatalf("elapsed=%s, want 2.6s", snap.Elapsed)
	}
	if snap.StatusCodes[200] != 490 || snap.StatusCodes[500] != 8 || snap.StatusCodes[503] != 2 {
		t.Fatalf("status merged incorrectly: %v", snap.StatusCodes)
	}
	// Percentiles take the worst worker; averages are request-weighted.
	if snap.P95 != 50*time.Millisecond || snap.P99 != 120*time.Millisecond {
		t.Fatalf("p95=%s p99=%s", snap.P95, snap.P99)
	}
	if snap.Min != 1*time.Millisecond || snap.Max != 300*time.Millisecond {
		t.Fatalf("min=%s max=%s", snap.Min, snap.Max)
	}
	wantAvg := time.Duration((25*200+30*300)/500) * time.Millisecond
	if snap.Avg != wantAvg {
		t.Fatalf("avg=%s, want %s", snap.Avg, wantAvg)
	}
	if snap.Steps["s1"] == nil || snap.Steps["s1"].Requests != 200 {
		t.Fatalf("step aggregate wrong: %+v", snap.Steps)
	}
}

func TestAggregatorForget(t *testing.T) {
	agg := NewAggregator()
	agg.Update("w1", &distproto.TelemetrySnapshot{TotalRequests: 10})
	agg.Update("w2", &distproto.TelemetrySnapshot{TotalRequests: 20})
	agg.Forget("w1")
	if got := agg.Snapshot().Workers; got != 1 {
		t.Fatalf("workers=%d, want 1 after forget", got)
	}
}

func TestMergeReportsCombinesStepsTimelineAndSLA(t *testing.T) {
	sc := &config.Scenario{SLA: &config.SLA{MaxErrorRatePct: 10, MinRPS: 0.0001}}
	start := time.Now().Add(-2 * time.Second)
	end := time.Now()

	r1 := &report.Report{
		Name: "r", StartedAt: start, EndedAt: end, Duration: 2 * time.Second,
		ActiveUsers: 5, TotalRequests: 100, TotalErrors: 4,
		Status: map[int]uint64{200: 96, 500: 4},
		Errors: map[string]uint64{"timeout": 4},
		Overall: report.StepReport{
			Name: "overall", Requests: 100, Errors: 4,
			Status: map[int]uint64{200: 96, 500: 4}, ErrorTypes: map[string]uint64{"timeout": 4},
			Min: 1 * time.Millisecond, Avg: 10 * time.Millisecond, Max: 50 * time.Millisecond,
			P50: 8 * time.Millisecond, P95: 30 * time.Millisecond, P99: 45 * time.Millisecond,
		},
		Steps:    []report.StepReport{{Name: "a", Requests: 100, Errors: 4, Avg: 10 * time.Millisecond, P99: 45 * time.Millisecond}},
		Timeline: []metrics.TimelineSample{{Second: 1, Requests: 50, Errors: 2, ActiveUsers: 5}},
	}
	r2 := &report.Report{
		Name: "r", StartedAt: start, EndedAt: end, Duration: 2 * time.Second,
		ActiveUsers: 5, TotalRequests: 200, TotalErrors: 6,
		Status: map[int]uint64{200: 194, 500: 6},
		Errors: map[string]uint64{"timeout": 6},
		Overall: report.StepReport{
			Name: "overall", Requests: 200, Errors: 6,
			Status: map[int]uint64{200: 194, 500: 6}, ErrorTypes: map[string]uint64{"timeout": 6},
			Min: 1 * time.Millisecond, Avg: 20 * time.Millisecond, Max: 80 * time.Millisecond,
			P50: 12 * time.Millisecond, P95: 40 * time.Millisecond, P99: 60 * time.Millisecond,
		},
		Steps:    []report.StepReport{{Name: "a", Requests: 200, Errors: 6, Avg: 20 * time.Millisecond, P99: 60 * time.Millisecond}},
		Timeline: []metrics.TimelineSample{{Second: 1, Requests: 100, Errors: 3, ActiveUsers: 5}},
	}

	merged := MergeReports(sc, []*report.Report{r1, r2})
	if merged.TotalRequests != 300 || merged.TotalErrors != 10 {
		t.Fatalf("totals wrong: %d/%d", merged.TotalRequests, merged.TotalErrors)
	}
	if merged.Status[200] != 290 || merged.Status[500] != 10 {
		t.Fatalf("status wrong: %v", merged.Status)
	}
	if merged.Overall.P99 != 60*time.Millisecond || merged.Overall.Max != 80*time.Millisecond {
		t.Fatalf("overall latency wrong: %+v", merged.Overall)
	}
	wantAvg := time.Duration((int64(10*time.Millisecond)*100 + int64(20*time.Millisecond)*200) / 300)
	if merged.Overall.Avg != wantAvg {
		t.Fatalf("avg=%s want %s", merged.Overall.Avg, wantAvg)
	}
	if len(merged.Steps) != 1 || merged.Steps[0].Requests != 300 {
		t.Fatalf("steps wrong: %+v", merged.Steps)
	}
	if len(merged.Timeline) != 1 || merged.Timeline[0].Requests != 150 {
		t.Fatalf("timeline wrong: %+v", merged.Timeline)
	}
	if merged.ErrorRatePct <= 0 || merged.RPS <= 0 {
		t.Fatalf("derived metrics wrong: err%%=%f rps=%f", merged.ErrorRatePct, merged.RPS)
	}
	if len(merged.SLA) == 0 {
		t.Fatal("SLA verdicts not recomputed")
	}
}

func TestScenarioRoundTrip(t *testing.T) {
	keep := true
	sc := &config.Scenario{
		Name: "round", BaseURL: "http://x", Variables: map[string]string{"a": "b"},
		Profile: config.Profile{Type: "ramp", Users: 12, Duration: 30, RampUp: 5, SpikeUsers: 3,
			SpikeWarmup: 2, SpikeHold: 4, WavePeriod: 7, RPS: 100, Timeout: 8, KeepAlive: &keep},
		Steps: []config.Step{{
			Name: "login", Type: "http", Method: "POST", URL: "/login", Headers: map[string]string{"X": "y"},
			Body: "{}", Timeout: 3, Session: true,
			Extract:    []config.Extract{{Name: "t", From: "body", Path: "$.token"}},
			Assertions: []config.Assertion{{Type: "status", Value: "200"}},
		}},
		SLA: &config.SLA{MaxP99Ms: 100, MaxErrorRatePct: 1, MinRPS: 10},
	}

	got, ok := ScenarioFromProto(ScenarioToProto(sc))
	if !ok {
		t.Fatal("round trip returned not-ok")
	}
	if got.Name != sc.Name || got.BaseURL != sc.BaseURL || got.Variables["a"] != "b" {
		t.Fatalf("scenario identity lost: %+v", got)
	}
	if got.Profile.Type != sc.Profile.Type || got.Profile.Users != sc.Profile.Users ||
		got.Profile.Duration != sc.Profile.Duration || got.Profile.RampUp != sc.Profile.RampUp ||
		got.Profile.SpikeUsers != sc.Profile.SpikeUsers || got.Profile.WavePeriod != sc.Profile.WavePeriod ||
		got.Profile.RPS != sc.Profile.RPS || got.Profile.Timeout != sc.Profile.Timeout {
		t.Fatalf("profile mismatch:\n got %+v\nwant %+v", got.Profile, sc.Profile)
	}
	if got.Profile.KeepAlive == nil || *got.Profile.KeepAlive != *sc.Profile.KeepAlive {
		t.Fatalf("keepalive mismatch: %v", got.Profile.KeepAlive)
	}
	if len(got.Steps) != 1 || got.Steps[0].Extract[0].Name != "t" || got.Steps[0].Assertions[0].Type != "status" {
		t.Fatalf("steps mismatch: %+v", got.Steps)
	}
	if got.SLA == nil || got.SLA.MaxP99Ms != 100 || got.SLA.MinRPS != 10 {
		t.Fatalf("sla mismatch: %+v", got.SLA)
	}
}
