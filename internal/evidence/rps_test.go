package evidence

import (
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/honesty"
)

// A rate is a number with a unit, and the bundle's unit is thousandths of a
// request per second. Getting the factor of 1000 wrong produces a bundle that
// still verifies, which is why the exact rendered decimal is asserted here.
func TestPlannedRPSMilliKeepsItsUnit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile config.Profile
		want    int64
		wantDec string
	}{
		{"constant rps paces at target_rps", config.Profile{Type: config.ProfileConstantRPS, TargetRPS: 300}, 300_000, "300.000"},
		{"one request per second", config.Profile{TargetRPS: 1}, 1_000, "1.000"},
		{"global cap", config.Profile{Type: config.ProfileSteady, RPS: 250}, 250_000, "250.000"},
		{"direct pace wins over the cap", config.Profile{Type: config.ProfileConstantRPS, TargetRPS: 40, RPS: 900}, 40_000, "40.000"},
		{"unpaced run has no schedule", config.Profile{Type: config.ProfileSteady}, 0, "0.000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := &config.Scenario{Name: "unit", Profile: tc.profile}
			got := PlannedRPSMilli(sc)
			if got != tc.want {
				t.Errorf("PlannedRPSMilli = %d, want %d", got, tc.want)
			}
			dec, err := attest.DecimalFromMilli(got)
			if err != nil {
				t.Fatalf("DecimalFromMilli(%d): %v", got, err)
			}
			if dec.String() != tc.wantDec {
				t.Errorf("planned_rps renders as %q, want %q", dec.String(), tc.wantDec)
			}
		})
	}
}

func TestPlannedRPSMilliHandlesNilScenario(t *testing.T) {
	if got := PlannedRPSMilli(nil); got != 0 {
		t.Errorf("PlannedRPSMilli(nil) = %d, want 0", got)
	}
}

// The honesty invariant of the whole correction: coordinated-omission
// correction exists to stop a saturated client from reporting latencies that
// look *better* than what users experienced. It may therefore never make the
// published tail look faster than the raw measurement.
//
// This is the assertion that catches a mis-specified schedule. A rate that is
// off by 1000 puts every intended start in the wrong place, and the "corrected"
// percentiles come out lower than the raw ones — a bundle that still passes
// verification, because the verifier recomputes the same mistake.
func TestCorrectedTailIsNeverBetterThanMeasuredTail(t *testing.T) {
	collector, _ := runAndCollect(t, 2)
	workerKey, coordKey := testKeys(t)

	run := attest.Run{
		Target:     "http://127.0.0.1:1",
		Profile:    config.ProfileConstantRPS,
		DurationNS: 2_000_000_000,
		PlannedRPS: mustMilli(t, 200),
	}
	b, err := BuildBundle(BundleInput{
		Collector:      collector,
		WorkerKey:      workerKey,
		CoordinatorKey: coordKey,
		Tool:           testTool(),
		Run:            run,
		COCorrected:    true,
	})
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	raw := b.Workers[0].Aggregate
	agg := b.Aggregate
	if !agg.COCorrected {
		t.Fatal("co_corrected = false, want the corrected aggregate")
	}
	if agg.Count != raw.Count {
		t.Fatalf("correction changed the request count: %d vs %d", agg.Count, raw.Count)
	}

	// Recompute both sides from the records, independently of the builder, so
	// the comparison cannot inherit a mistake the builder made.
	recs := collector.Records()
	var rawSum uint64
	rawVals := make([]int64, 0, len(recs))
	for _, r := range recs {
		rawSum += uint64(r.LatencyNS)
		rawVals = append(rawVals, r.LatencyNS)
	}
	rawSorted := honesty.SortValues(rawVals)
	rawP50 := honesty.Percentile(rawSorted, honesty.PPM50)
	rawP95 := honesty.Percentile(rawSorted, honesty.PPM95)
	rawP99 := honesty.Percentile(rawSorted, honesty.PPM99)

	// Per request, the correction may only add the time the client spent not
	// being served. A schedule off by a factor of 1000 puts every intended
	// start in the wrong place and pushes corrected values *below* the raw
	// measurement, which is exactly what this loop refuses to accept.
	plannedMilli, err := run.PlannedRPS.Milli()
	if err != nil {
		t.Fatalf("planned rate: %v", err)
	}
	windowStart := b.Workers[0].Commit.WindowStartNS
	for _, r := range recs {
		corrected, err := honesty.CorrectedLatencyNS(r.StartNS, r.LatencyNS, windowStart, r.Seq, plannedMilli)
		if err != nil {
			t.Fatalf("CorrectedLatencyNS: %v", err)
		}
		if corrected < r.LatencyNS {
			t.Fatalf("seq %d: corrected latency %d ns is below the measured %d ns — the correction made the run look better than it was (is the pacing rate right? planned=%d milli-ops/s)",
				r.Seq, corrected, r.LatencyNS, plannedMilli)
		}
	}

	if agg.P50NS < rawP50 || agg.P95NS < rawP95 || agg.P99NS < rawP99 {
		t.Errorf("corrected tail is faster than the measurement: corrected p50/p95/p99 %d/%d/%d, raw %d/%d/%d",
			agg.P50NS, agg.P95NS, agg.P99NS, rawP50, rawP95, rawP99)
	}
	if agg.COCI95NS.HighNS < agg.P99NS {
		t.Errorf("the committed 95%% interval [%d, %d] does not cover the published p99 %d",
			agg.COCI95NS.LowNS, agg.COCI95NS.HighNS, agg.P99NS)
	}
	// The correction is a claim about the tail, not a licence to rewrite how
	// long the requests took.
	if agg.SumLatencyNS != rawSum {
		t.Errorf("aggregate.sum_latency_ns %d does not equal the raw sum %d", agg.SumLatencyNS, rawSum)
	}
}

// An unpaced run still has to produce a bundle a stranger can verify: "we did
// not pace" is a legitimate claim, and the correction is simply not available.
func TestUnpacedBundleIsValidAndVerifiable(t *testing.T) {
	collector, _ := runAndCollect(t, 1)
	workerKey, coordKey := testKeys(t)

	zero, err := attest.DecimalFromMilli(0)
	if err != nil {
		t.Fatalf("planned rate: %v", err)
	}
	b, err := BuildBundle(BundleInput{
		Collector:      collector,
		WorkerKey:      workerKey,
		CoordinatorKey: coordKey,
		Tool:           testTool(),
		Run: attest.Run{
			Target:     "http://127.0.0.1:1",
			Profile:    config.ProfileSteady,
			DurationNS: 1_000_000_000,
			PlannedRPS: zero,
		},
		COCorrected: false,
	})
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("unpaced bundle does not validate: %v", err)
	}
	if b.Aggregate.COCorrected {
		t.Error("an unpaced bundle claims coordinated-omission correction")
	}
	if b.Aggregate.COCI95NS.LowNS != 0 || b.Aggregate.COCI95NS.HighNS != 0 {
		t.Errorf("an uncorrected bundle carries a non-zero interval [%d, %d]", b.Aggregate.COCI95NS.LowNS, b.Aggregate.COCI95NS.HighNS)
	}
	if got := b.Integrity.ScheduleAccuracyPPM; got < 0 || got > honesty.PPMScale {
		t.Errorf("schedule_accuracy_ppm = %d, want 0..%d", got, honesty.PPMScale)
	}
	res := attest.Verify(b, map[string][]attest.Record{b.Workers[0].ID: collector.Records()})
	if !res.Valid {
		t.Fatalf("an unpaced bundle did not verify: %v", res.ErrorLines())
	}
}

func mustMilli(t *testing.T, rps int64) attest.Decimal {
	t.Helper()
	d, err := attest.DecimalFromMilli(rps * 1000)
	if err != nil {
		t.Fatalf("DecimalFromMilli: %v", err)
	}
	return d
}
