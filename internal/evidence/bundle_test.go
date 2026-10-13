package evidence

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
)

// runAndCollect drives a short live run against a local target and returns the
// collector together with the run description that matches it.
func runAndCollect(t *testing.T, durationSeconds int) (*Collector, attest.Run) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	sc := &config.Scenario{
		Name: "evidence-build",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    4,
			Duration: durationSeconds,
			Timeout:  2,
		},
		Steps: []config.Step{{Name: "health", Method: "GET", URL: srv.URL}},
	}
	eng, err := engine.New(sc)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := NewCollector("local-1")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := eng.Run(ctx, engine.RunOptions{Quiet: true, Samples: collector}); err != nil {
		t.Fatalf("run: %v", err)
	}

	planned, err := attest.DecimalFromMilli(200)
	if err != nil {
		t.Fatal(err)
	}
	return collector, attest.Run{
		Target:     srv.URL,
		Profile:    "steady",
		DurationNS: int64(durationSeconds) * int64(time.Second),
		PlannedRPS: planned,
	}
}

func testKeys(t *testing.T) (*attest.Keypair, *attest.Keypair) {
	t.Helper()
	worker, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	coord, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return worker, coord
}

func testTool() attest.Tool {
	return attest.Tool{Name: "stress-strike", Version: "test"}
}

// The whole point of the invention: a run sealed here must verify from the
// bundle and the sidecar alone, with nothing but the files.
func TestBuildBundleRoundTripVerifies(t *testing.T) {
	collector, run := runAndCollect(t, 2)
	workerKey, coordKey := testKeys(t)

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
	if err := b.Validate(); err != nil {
		t.Fatalf("the builder returned a bundle that does not validate: %v", err)
	}
	if err := b.VerifyCoordinatorSig(); err != nil {
		t.Fatalf("the coordinator seal does not verify: %v", err)
	}
	if b.Format != attest.FormatID {
		t.Errorf("format = %q, want %q", b.Format, attest.FormatID)
	}
	if b.Aggregate.Count != uint64(collector.Count()) {
		t.Errorf("aggregate.count = %d, want the %d collected requests", b.Aggregate.Count, collector.Count())
	}
	if b.Workers[0].ID != collector.Worker() {
		t.Errorf("worker id = %q, want %q", b.Workers[0].ID, collector.Worker())
	}
	if !b.Aggregate.COCorrected {
		t.Error("co_corrected = false, want true")
	}
	if b.Aggregate.P99NS <= 0 {
		t.Errorf("p99_ns = %d, want a positive measured percentile", b.Aggregate.P99NS)
	}
	if b.Aggregate.COCI95NS.HighNS < b.Aggregate.COCI95NS.LowNS {
		t.Errorf("committed interval [%d,%d] is inverted", b.Aggregate.COCI95NS.LowNS, b.Aggregate.COCI95NS.HighNS)
	}
	if b.Integrity.DroppedSamples != 0 {
		// 200 planned rps for 2s = 400 slots; a local run of 4 users should
		// fill at least that, but a slower machine may not. Only report it.
		t.Logf("dropped_samples = %d (planned slots not filled)", b.Integrity.DroppedSamples)
	}

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "run.json")
	sidecar, err := WriteBundle(b, collector.Records(), bundlePath)
	if err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	if want := filepath.Join(dir, "run.samples.jsonl"); sidecar != want {
		t.Errorf("sidecar path = %q, want %q", sidecar, want)
	}

	// Re-read from disk: nothing in memory may be required to verify.
	loaded, err := attest.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	samples, _, err := attest.LoadSamples(sidecar, attest.DefaultSampleLoadOptions())
	if err != nil {
		t.Fatalf("LoadSamples: %v", err)
	}

	res := attest.Verify(loaded, samples)
	if !res.Valid {
		for _, line := range res.ErrorLines() {
			t.Errorf("verify failed: %s", line)
		}
		t.Fatal("a freshly built bundle did not verify")
	}
	if res.Summary.WorkersOK != 1 || res.Summary.WorkersFailed != 0 {
		t.Errorf("workers ok/failed = %d/%d, want 1/0", res.Summary.WorkersOK, res.Summary.WorkersFailed)
	}
	if res.Summary.SamplesTotal != collector.Count() {
		t.Errorf("verified %d samples, want %d", res.Summary.SamplesTotal, collector.Count())
	}
	if res.Summary.ProofsVerified == 0 {
		t.Error("no inclusion proofs were verified")
	}
}

// min_ns and max_ns are signed statements about the evidence; they must be the
// true extremes of the committed records, not zeros or an off-by-one artefact.
func TestWorkerAggregateBoundsAreHonest(t *testing.T) {
	collector, run := runAndCollect(t, 1)
	workerKey, coordKey := testKeys(t)

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

	recs := collector.Records()
	if len(recs) == 0 {
		t.Fatal("the run produced no records")
	}
	min, max := int64(math.MaxInt64), int64(0)
	for _, r := range recs {
		if r.LatencyNS < min {
			min = r.LatencyNS
		}
		if r.LatencyNS > max {
			max = r.LatencyNS
		}
	}

	got := b.Workers[0].Aggregate
	if got.Count != uint64(len(recs)) {
		t.Fatalf("worker count = %d, want %d", got.Count, len(recs))
	}
	if got.MinNS != min {
		t.Errorf("worker min_ns = %d, want the true minimum %d", got.MinNS, min)
	}
	if got.MaxNS != max {
		t.Errorf("worker max_ns = %d, want the true maximum %d", got.MaxNS, max)
	}
	if got.MaxNS < got.MinNS {
		t.Errorf("max_ns %d is below min_ns %d", got.MaxNS, got.MinNS)
	}
	var histTotal uint64
	for _, n := range got.Hist {
		histTotal += n
	}
	if histTotal != got.Count {
		t.Errorf("histogram counts sum to %d, want %d", histTotal, got.Count)
	}
}

// The sidecar is the evidence; changing one number in it must break the
// verification, and the verifier must be able to say which leaf moved.
func TestTamperedSampleBreaksVerification(t *testing.T) {
	collector, run := runAndCollect(t, 1)
	workerKey, coordKey := testKeys(t)

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
	if res := attest.Verify(b, map[string][]attest.Record{b.Workers[0].ID: collector.Records()}); !res.Valid {
		t.Fatalf("test setup: the untouched evidence does not verify: %v", res.ErrorLines())
	}

	recs := collector.Records()
	tampered := make([]attest.Record, len(recs))
	copy(tampered, recs)
	tampered[len(tampered)/2].LatencyNS++

	res := attest.Verify(b, map[string][]attest.Record{b.Workers[0].ID: tampered})
	if res.Valid {
		t.Fatal("a sidecar with an altered latency still verified")
	}
	first, ok := res.FirstError()
	if !ok {
		t.Fatal("verification failed but reported no error")
	}
	if first.Index == nil {
		t.Errorf("the failure %q does not anchor to a leaf index", first.Check)
	}
}

// The seal covers every number in the bundle: editing one must be detectable
// without touching the sidecar at all.
func TestTamperedBundleBreaksTheSeal(t *testing.T) {
	collector, run := runAndCollect(t, 1)
	workerKey, coordKey := testKeys(t)

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

	// A prettier p99 that never happened.
	b.Aggregate.P99NS++
	if err := b.VerifyCoordinatorSig(); err == nil {
		t.Fatal("the coordinator seal accepted a rewritten percentile")
	}
	// And a rewritten request count.
	b.Aggregate.Count++
	if err := b.VerifyCoordinatorSig(); err == nil {
		t.Fatal("the coordinator seal accepted a rewritten count")
	}
}

// Evidence that is known to be incomplete must never be sealed: a bundle
// claiming a completeness the run does not have is worse than no bundle.
func TestBuildBundleRefusesIncompleteEvidence(t *testing.T) {
	collector, err := NewCollector("incomplete")
	if err != nil {
		t.Fatal(err)
	}
	collector.Emit(engine.Sample{Seq: 0, StartNS: 1000, LatencyNS: -1, Status: 200})
	if collector.Err() == nil {
		t.Fatal("test setup: the collector accepted an unusable sample")
	}
	workerKey, coordKey := testKeys(t)
	planned, err := attest.DecimalFromMilli(100)
	if err != nil {
		t.Fatal(err)
	}

	_, err = BuildBundle(BundleInput{
		Collector:      collector,
		WorkerKey:      workerKey,
		CoordinatorKey: coordKey,
		Tool:           testTool(),
		Run: attest.Run{
			Target:     "http://example.invalid",
			Profile:    "steady",
			DurationNS: int64(time.Second),
			PlannedRPS: planned,
		},
	})
	if err == nil {
		t.Fatal("evidence known to be incomplete was sealed anyway")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("error %q does not explain the refusal", err)
	}
}

// The coordinated-omission correction is defined against a pacing schedule, so
// it cannot be claimed for an unpaced run.
func TestCorrectionRequiresAPlannedRate(t *testing.T) {
	collector, err := NewCollector("unpaced")
	if err != nil {
		t.Fatal(err)
	}
	collector.Emit(engine.Sample{Seq: 0, StartNS: 1000, LatencyNS: 1000, Status: 200})
	workerKey, coordKey := testKeys(t)
	zero, err := attest.DecimalFromMilli(0)
	if err != nil {
		t.Fatal(err)
	}

	_, err = BuildBundle(BundleInput{
		Collector:      collector,
		WorkerKey:      workerKey,
		CoordinatorKey: coordKey,
		Tool:           testTool(),
		Run: attest.Run{
			Target:     "http://example.invalid",
			Profile:    "steady",
			DurationNS: int64(time.Second),
			PlannedRPS: zero,
		},
		COCorrected: true,
	})
	if err == nil {
		t.Fatal("a corrected claim was sealed with a zero planned rate")
	}
	if !strings.Contains(err.Error(), "planned rate") {
		t.Errorf("error %q does not name the missing rate", err)
	}
}

func TestSidecarPath(t *testing.T) {
	for _, tc := range []struct{ bundle, want string }{
		{"run.json", "run.samples.jsonl"},
		{"/tmp/a/bundle.json", "/tmp/a/bundle.samples.jsonl"},
		{"evidence", "evidence.samples.jsonl"},
		{"/tmp/evidence.bundle", "/tmp/evidence.bundle.samples.jsonl"},
	} {
		if got := SidecarPath(tc.bundle); got != tc.want {
			t.Errorf("SidecarPath(%q) = %q, want %q", tc.bundle, got, tc.want)
		}
	}
}
