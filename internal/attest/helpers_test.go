package attest

// helpers_test.go — shared fixtures for the attest package tests.
//
// Every fixture is built exclusively through the package's own producer API
// (BuildCommit, AggregateRecords, Bundle.Sign), so a fixture that verifies
// proves the producer and the verifier agree — it can never be right by
// accident.

import (
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/honesty"
)

// mustKey returns a fresh Ed25519 keypair or fails the test.
func mustKey(t *testing.T) *Keypair {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return kp
}

// mustMilli parses a Decimal into scaled milli units, failing the test on error.
func mustMilli(t *testing.T, d Decimal) int64 {
	t.Helper()
	m, err := d.Milli()
	if err != nil {
		t.Fatalf("Milli(%q): %v", d, err)
	}
	return m
}

// synthRecords builds n records for one worker. Record i (1-based seq i+1)
// starts at baseStart+i*stepNS and reports a latency of latBase+i*latStep. The
// records are already in canonical (start_ns, seq) order.
func synthRecords(id string, baseStart int64, n int, stepNS, latBase, latStep int64) []Record {
	recs := make([]Record, n)
	for i := 0; i < n; i++ {
		recs[i] = Record{
			Seq:       uint64(i + 1),
			Worker:    id,
			StartNS:   baseStart + int64(i)*stepNS,
			LatencyNS: latBase + int64(i)*latStep,
			Status:    200,
			Bytes:     1024 + int64(i),
		}
	}
	return recs
}

// workerSpec pairs a worker id and key with the records it measured.
type workerSpec struct {
	id   string
	kp   *Keypair
	recs []Record
}

// produceBundle builds a fully valid, signed bundle from the worker specs and
// returns it together with the sidecar map (keyed by worker id, records in
// canonical order). co selects the coordinated-omission-corrected percentile
// set and the bootstrap confidence interval; the uncorrected worker aggregates
// always publish raw latencies.
func produceBundle(t *testing.T, coord *Keypair, run Run, specs []workerSpec, co bool) (Bundle, map[string][]Record) {
	t.Helper()

	rpsMilli := mustMilli(t, run.PlannedRPS)
	samples := make(map[string][]Record, len(specs))
	workers := make([]WorkerBundle, 0, len(specs))

	var values []int64
	var count uint64
	var sum uint64

	for _, s := range specs {
		ordered := SortRecords(s.recs)
		samples[s.id] = ordered

		commit, err := BuildCommit(s.kp, s.recs)
		if err != nil {
			t.Fatalf("BuildCommit(%s): %v", s.id, err)
		}
		stats, err := AggregateRecords(ordered, 0, false, 0)
		if err != nil {
			t.Fatalf("AggregateRecords(%s): %v", s.id, err)
		}
		workers = append(workers, WorkerBundle{
			ID:        s.id,
			PublicKey: PublicKeyHex(s.kp.Public),
			Commit:    commit,
			Aggregate: WorkerAgg{
				Count:        stats.Count,
				SumLatencyNS: stats.SumLatencyNS,
				MinNS:        stats.MinNS,
				MaxNS:        stats.MaxNS,
				Hist:         stats.Hist,
			},
		})

		for _, r := range ordered {
			sum += uint64(r.LatencyNS)
			count++
			val := r.LatencyNS
			if co {
				corrected, err := honesty.CorrectedLatencyNS(r.StartNS, r.LatencyNS, commit.WindowStartNS, r.Seq, rpsMilli)
				if err != nil {
					t.Fatalf("CorrectedLatencyNS(%s, seq %d): %v", s.id, r.Seq, err)
				}
				val = corrected
			}
			values = append(values, val)
		}
	}

	achievedMilli, err := honesty.AchievedRPSMilli(count, run.DurationNS)
	if err != nil {
		t.Fatalf("AchievedRPSMilli: %v", err)
	}
	rps, err := DecimalFromMilli(achievedMilli)
	if err != nil {
		t.Fatalf("DecimalFromMilli: %v", err)
	}

	sorted := honesty.SortValues(values)
	agg := Aggregate{
		Count:        count,
		SumLatencyNS: sum,
		P50NS:        honesty.Percentile(sorted, honesty.PPM50),
		P95NS:        honesty.Percentile(sorted, honesty.PPM95),
		P99NS:        honesty.Percentile(sorted, honesty.PPM99),
		RPS:          rps,
		COCorrected:  co,
	}
	if co {
		lo, hi := honesty.CI95Bootstrap(sorted, honesty.PPM99, honesty.DefaultBootstrapIterations, honesty.DefaultBootstrapSeed)
		agg.COCI95NS = CI95{LowNS: lo, HighNS: hi}
	}

	dropped, err := honesty.DroppedSamples(rpsMilli, run.DurationNS, count)
	if err != nil {
		t.Fatalf("DroppedSamples: %v", err)
	}
	b := Bundle{
		Format:    FormatID,
		CreatedAt: "2026-10-13T18:00:00Z",
		Tool:      Tool{Name: "stress-strike", Version: "test"},
		Run:       run,
		Workers:   workers,
		Aggregate: agg,
		Integrity: Integrity{
			ScheduleAccuracyPPM: honesty.ScheduleAccuracyPPM(rpsMilli, achievedMilli),
			DroppedSamples:      dropped,
			AchievedRPS:         rps,
			PlannedRPS:          run.PlannedRPS,
		},
	}
	if err := b.Sign(coord); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return b, samples
}

// newFixture returns a valid two-worker bundle (40 + 25 = 65 records over 10 s),
// its sidecar map and the coordinator key so a test can re-sign a mutation.
func newFixture(t *testing.T, co bool) (Bundle, map[string][]Record, *Keypair) {
	t.Helper()
	coord := mustKey(t)
	w1 := mustKey(t)
	w2 := mustKey(t)

	planned := Decimal("6.500")
	if co {
		planned = Decimal("1000.000")
	}
	run := Run{
		Target:     "https://example.test/api",
		Profile:    "constant-rps",
		DurationNS: 10_000_000_000,
		PlannedRPS: planned,
	}
	specs := []workerSpec{
		{id: "w1", kp: w1, recs: synthRecords("w1", 1_000_000_000, 40, 1_000_000, 1_000_000, 10_000)},
		{id: "w2", kp: w2, recs: synthRecords("w2", 2_000_000_000, 25, 1_000_000, 2_000_000, 20_000)},
	}
	b, samples := produceBundle(t, coord, run, specs, co)
	return b, samples, coord
}

// mustResign re-seals a mutated bundle with the coordinator key so that a test
// can isolate a semantic failure from a signature failure.
func mustResign(t *testing.T, b *Bundle, coord *Keypair) {
	t.Helper()
	if err := b.Sign(coord); err != nil {
		t.Fatalf("re-sign bundle: %v", err)
	}
}

// cloneSamples deep-copies the sidecar map so a mutation cannot leak into
// another fixture.
func cloneSamples(samples map[string][]Record) map[string][]Record {
	out := make(map[string][]Record, len(samples))
	for k, v := range samples {
		cp := make([]Record, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// findErr returns the first failure with the given check name.
func findErr(res VerifyResult, check string) (CheckError, bool) {
	for _, e := range res.Errors {
		if e.Check == check {
			return e, true
		}
	}
	return CheckError{}, false
}

// hasCheck reports whether a worker report listed a check by name.
func hasCheck(checks []Check, name string) bool {
	for _, c := range checks {
		if c.Name == name {
			return true
		}
	}
	return false
}
