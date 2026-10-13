package attest

// verify_test.go — the tamper-evidence contract.
//
// Each test here breaks exactly one thing and asserts that the verifier refuses
// the bundle for the right reason (fail closed), and that a bundle produced by
// the package's own producer verifies end to end.

import (
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/honesty"
)

// TestVerifyValidRoundTrip is the baseline: everything the producer wrote
// survives an independent replay.
func TestVerifyValidRoundTrip(t *testing.T) {
	b, samples, _ := newFixture(t, false)
	res := Verify(b, samples)

	if !res.Valid || !res.OK() {
		t.Fatalf("valid bundle rejected: %v", res.ErrorLines())
	}
	if res.SamplesAbsent {
		t.Fatal("SamplesAbsent is true with a sidecar present")
	}
	if res.Format != FormatID {
		t.Fatalf("format = %q", res.Format)
	}
	if res.BundleDigest == "" {
		t.Fatal("bundle digest is empty")
	}
	if got := res.Summary.Workers; got != 2 {
		t.Fatalf("workers = %d, want 2", got)
	}
	if got := res.Summary.WorkersOK; got != 2 {
		t.Fatalf("workers OK = %d, want 2", got)
	}
	if got := res.Summary.SamplesTotal; got != 65 {
		t.Fatalf("samples = %d, want 65", got)
	}
	// 40 + 25 leaves, and the default proof width (256) covers every leaf.
	if got := res.Summary.ProofsVerified; got != 65 {
		t.Fatalf("proofs verified = %d, want 65", got)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", res.Warnings)
	}
	for _, w := range res.Workers {
		if !w.RootMatches || !w.CommitSigOK || !w.AggregateOK {
			t.Fatalf("worker %s not fully verified: root=%v commitSig=%v agg=%v", w.ID, w.RootMatches, w.CommitSigOK, w.AggregateOK)
		}
		if !hasCheck(w.Checks, "proofs") || !hasCheck(w.Checks, "commit-root") {
			t.Fatalf("worker %s missing a core check: %+v", w.ID, w.Checks)
		}
	}
}

// TestVerifyValidRoundTripCorrected exercises the coordinated-omission path: the
// committed percentiles are the corrected ones and the bootstrap interval is
// reproduced.
func TestVerifyValidRoundTripCorrected(t *testing.T) {
	b, samples, _ := newFixture(t, true)
	if !b.Aggregate.COCorrected {
		t.Fatal("fixture should be marked coordinated-omission corrected")
	}
	res := Verify(b, samples)
	if !res.Valid {
		t.Fatalf("corrected bundle rejected: %v", res.ErrorLines())
	}
	if !hasCheck(res.Checks, "aggregate-ci") {
		t.Fatal("aggregate-ci check was not run")
	}
}

// TestVerifyCoordinatesOmissionCorrection proves the correction actually moves
// the distribution: the records are paced 2x slower than planned, so every
// record after the first is late and its corrected latency is larger.
func TestVerifyCoordinatesOmissionCorrection(t *testing.T) {
	coord := mustKey(t)
	w1 := mustKey(t)
	run := Run{
		Target:     "https://example.test/api",
		Profile:    "constant-rps",
		DurationNS: 10_000_000_000,
		PlannedRPS: Decimal("1000.000"),
	}
	// Intended spacing is 1 ms (1000 rps); records arrive every 2 ms, so record
	// k (k >= 2) waits (k-1) ms beyond its slot.
	specs := []workerSpec{
		{id: "w1", kp: w1, recs: synthRecords("w1", 1_000_000_000, 10, 2_000_000, 500_000, 0)},
	}
	b, samples := produceBundle(t, coord, run, specs, true)

	res := Verify(b, samples)
	if !res.Valid {
		t.Fatalf("late-record bundle rejected: %v", res.ErrorLines())
	}
	// The corrected p99 must exceed the raw p99 (raw is a constant 0.5 ms).
	if b.Aggregate.P99NS <= 500_000 {
		t.Fatalf("corrected p99 = %d, want > 500000 (raw)", b.Aggregate.P99NS)
	}
}

// TestVerifyDetectsSingleSampleChange flips one nanosecond of one record and
// expects a commit-root failure anchored to a leaf index.
func TestVerifyDetectsSingleSampleChange(t *testing.T) {
	b, samples, _ := newFixture(t, false)
	mutated := cloneSamples(samples)
	mutated["w1"][0].LatencyNS++

	res := Verify(b, mutated)
	if res.Valid {
		t.Fatal("a one-nanosecond sample change was accepted")
	}
	e, ok := findErr(res, "commit-root")
	if !ok {
		t.Fatalf("no commit-root failure: %v", res.ErrorLines())
	}
	if e.Worker != "w1" {
		t.Fatalf("commit-root failure on worker %q, want w1", e.Worker)
	}
	if e.Index == nil {
		t.Fatal("commit-root failure has no leaf index")
	}
	if !strings.Contains(e.Detail, "does not match the committed root") {
		t.Fatalf("unhelpful detail: %q", e.Detail)
	}
}

// TestVerifyDetectsBrokenWorkerAggregate keeps every structural cross-sum intact
// (max is only bounded below by min) and re-signs, so only the recomputed
// aggregate can fail.
func TestVerifyDetectsBrokenWorkerAggregate(t *testing.T) {
	b, samples, coord := newFixture(t, false)
	b.Workers[0].Aggregate.MaxNS += 1_000_000
	mustResign(t, &b, coord)

	res := Verify(b, samples)
	if res.Valid {
		t.Fatal("a falsified worker aggregate was accepted")
	}
	e, ok := findErr(res, "worker-aggregate")
	if !ok {
		t.Fatalf("no worker-aggregate failure: %v", res.ErrorLines())
	}
	if e.Worker != "w1" {
		t.Fatalf("worker-aggregate failure on %q, want w1", e.Worker)
	}
}

// TestVerifyDetectsBrokenCommitSignature corrupts one worker's commit signature
// and re-signs the bundle, so the coordinator seal is valid and only the commit
// signature is wrong.
func TestVerifyDetectsBrokenCommitSignature(t *testing.T) {
	b, samples, coord := newFixture(t, false)
	b.Workers[0].Commit.Signature = flipFirstHex(b.Workers[0].Commit.Signature)
	mustResign(t, &b, coord)

	res := Verify(b, samples)
	if res.Valid {
		t.Fatal("a broken commit signature was accepted")
	}
	e, ok := findErr(res, "commit-signature")
	if !ok {
		t.Fatalf("no commit-signature failure: %v", res.ErrorLines())
	}
	if e.Worker != "w1" {
		t.Fatalf("commit-signature failure on %q, want w1", e.Worker)
	}
}

// TestVerifyDetectsBrokenBundleSignature corrupts the coordinator seal and
// leaves the rest untouched.
func TestVerifyDetectsBrokenBundleSignature(t *testing.T) {
	b, samples, _ := newFixture(t, false)
	b.Signature.Sig = flipFirstHex(b.Signature.Sig)

	res := Verify(b, samples)
	if res.Valid {
		t.Fatal("a broken coordinator signature was accepted")
	}
	if _, ok := findErr(res, "bundle-signature"); !ok {
		t.Fatalf("no bundle-signature failure: %v", res.ErrorLines())
	}
}

// TestVerifyDetectsMixedUpWorkerIDs swaps the two workers' sidecars: each set of
// records then carries the wrong worker id.
func TestVerifyDetectsMixedUpWorkerIDs(t *testing.T) {
	b, samples, _ := newFixture(t, false)
	swapped := map[string][]Record{
		"w1": samples["w2"],
		"w2": samples["w1"],
	}

	res := Verify(b, swapped)
	if res.Valid {
		t.Fatal("swapped worker sidecars were accepted")
	}
	e, ok := findErr(res, "sample-worker")
	if !ok {
		t.Fatalf("no sample-worker failure: %v", res.ErrorLines())
	}
	if e.Index == nil {
		t.Fatal("sample-worker failure should point at the offending record")
	}
}

// TestVerifyEmptySamples covers the three "empty" shapes: an empty slice for a
// worker that committed nothing, an empty slice for a worker that committed
// samples, and a missing sidecar entry.
func TestVerifyEmptySamples(t *testing.T) {
	t.Run("empty_slice_for_empty_commit_is_valid", func(t *testing.T) {
		coord := mustKey(t)
		w1 := mustKey(t)
		run := Run{Target: "https://example.test/", Profile: "p", DurationNS: 1_000_000_000, PlannedRPS: Decimal("1000.000")}
		b, samples := produceBundle(t, coord, run, []workerSpec{{id: "w1", kp: w1}}, false)
		if got := len(samples["w1"]); got != 0 {
			t.Fatalf("fixture has %d records, want 0", got)
		}
		if res := Verify(b, samples); !res.Valid {
			t.Fatalf("empty-commit bundle rejected: %v", res.ErrorLines())
		}
	})

	t.Run("empty_slice_for_nonempty_commit_fails", func(t *testing.T) {
		b, samples, _ := newFixture(t, false)
		samples["w1"] = []Record{}
		res := Verify(b, samples)
		if res.Valid {
			t.Fatal("empty sidecar for a 40-sample commit was accepted")
		}
		if _, ok := findErr(res, "samples"); !ok {
			t.Fatalf("no samples failure: %v", res.ErrorLines())
		}
	})

	t.Run("missing_sidecar_entry_fails", func(t *testing.T) {
		b, samples, _ := newFixture(t, false)
		delete(samples, "w2")
		res := Verify(b, samples)
		if res.Valid {
			t.Fatal("missing sidecar entry was accepted")
		}
		if _, ok := findErr(res, "samples"); !ok {
			t.Fatalf("no samples failure: %v", res.ErrorLines())
		}
	})

	t.Run("nil_sidecar_validates_signature_only", func(t *testing.T) {
		b, _, _ := newFixture(t, false)
		res := Verify(b, nil)
		if !res.Valid {
			t.Fatalf("bundle without a sidecar rejected: %v", res.ErrorLines())
		}
		if !res.SamplesAbsent {
			t.Fatal("SamplesAbsent should be true when samples == nil")
		}
	})
}

// TestVerifySampleLimit checks the verifier refuses to hash more records than
// the configured per-worker cap.
func TestVerifySampleLimit(t *testing.T) {
	b, samples, _ := newFixture(t, false)
	res := VerifyWith(b, samples, VerifyOptions{MaxSamplesPerWorker: 10})
	if res.Valid {
		t.Fatal("per-worker sample limit was not enforced")
	}
	if _, ok := findErr(res, "samples-limit"); !ok {
		t.Fatalf("no samples-limit failure: %v", res.ErrorLines())
	}
}

// TestVerifyMalformedBundleNeverPanics feeds truncated and hostile JSON through
// the loader and asserts an error, never a panic.
func TestVerifyMalformedBundleNeverPanics(t *testing.T) {
	b, samples, _ := newFixture(t, false)
	raw, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if len(raw) < 40 {
		t.Fatalf("canonical bundle unexpectedly short: %d bytes", len(raw))
	}

	cases := map[string][]byte{
		"empty":            {},
		"truncated":        raw[:len(raw)/2],
		"trailing_garbage": append(append([]byte{}, raw...), []byte(`{"extra":1}`)...),
		"not_json":         []byte("this is not json at all"),
		"bad_types":        []byte(`{"format":123,"created_at":[],"workers":"nope"}`),
	}

	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %s: %v", name, r)
				}
			}()
			parsed, err := ParseBundle(blob)
			if err != nil {
				return // rejected at parse time: fine
			}
			// A blob that happens to parse must still fail closed on verify.
			res := Verify(parsed, samples)
			if res.Valid {
				t.Fatalf("%s parsed into a bundle that verified", name)
			}
		})
	}
}

// TestVerifyEmptyBundleNeverPanics verifies the zero Bundle fails cleanly.
func TestVerifyEmptyBundleNeverPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on empty bundle: %v", r)
		}
	}()
	res := Verify(Bundle{}, nil)
	if res.Valid {
		t.Fatal("the zero bundle verified")
	}
}

// TestVerifySkipsFullSweepOnBudget pins the behaviour when the proof budget is
// too small for a per-leaf sweep: the root is still checked.
func TestVerifySkipsFullSweepOnBudget(t *testing.T) {
	b, samples, _ := newFixture(t, false)
	mutated := cloneSamples(samples)
	mutated["w1"][3].LatencyNS++

	// A tiny proof budget forbids the O(n log n) sweep and the root mismatch is
	// then reported without a leaf index.
	res := VerifyWith(b, mutated, VerifyOptions{ProofVerifyLimit: 1, ProofSampleWidth: 1})
	if res.Valid {
		t.Fatal("tampered bundle accepted under a small budget")
	}
	e, ok := findErr(res, "commit-root")
	if !ok {
		t.Fatalf("no commit-root failure: %v", res.ErrorLines())
	}
	if e.Index != nil {
		t.Fatalf("expected no leaf index under a tiny budget, got %d", *e.Index)
	}
}

// TestVerifyGlobalAggregateMismatch corrupts the run-wide sum, which is only
// visible when the sidecar is replayed.
func TestVerifyGlobalAggregateMismatch(t *testing.T) {
	b, samples, coord := newFixture(t, false)
	b.Aggregate.SumLatencyNS++
	mustResign(t, &b, coord)

	res := Verify(b, samples)
	if res.Valid {
		t.Fatal("a falsified global sum was accepted")
	}
	if _, ok := findErr(res, "aggregate-sum"); !ok {
		t.Fatalf("no aggregate-sum failure: %v", res.ErrorLines())
	}
}

// TestAggregateRecordsMatchesFixture cross-checks the recomputation primitive
// the verifier relies on.
func TestAggregateRecordsMatchesFixture(t *testing.T) {
	_, samples, _ := newFixture(t, false)
	stats, err := AggregateRecords(samples["w1"], 0, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Count != 40 {
		t.Fatalf("count = %d, want 40", stats.Count)
	}
	if stats.MinNS != 1_000_000 || stats.MaxNS != 1_390_000 {
		t.Fatalf("latency bounds = %d..%d, want 1000000..1390000", stats.MinNS, stats.MaxNS)
	}
	var histTotal uint64
	for _, n := range stats.Hist {
		histTotal += n
	}
	if histTotal != 40 {
		t.Fatalf("histogram sums to %d, want 40", histTotal)
	}
	if len(stats.Values) != 40 {
		t.Fatalf("values = %d, want 40", len(stats.Values))
	}
	for i := 1; i < len(stats.Values); i++ {
		if stats.Values[i-1] > stats.Values[i] {
			t.Fatalf("values not sorted at %d", i)
		}
	}
}

// TestPercentileValueAndBucket pin the small helpers the verifier exports.
func TestPercentileValueAndBucket(t *testing.T) {
	sorted := []int64{10, 20, 30, 40}
	if got := PercentileValue(sorted, honesty.PPM50); got != 20 {
		t.Fatalf("p50 = %d, want 20", got)
	}
	if got := PercentileValue(sorted, honesty.PPM99); got != 40 {
		t.Fatalf("p99 = %d, want 40", got)
	}
	buckets := map[int64]int64{0: 0, 1: 1, 2: 3, 3: 3, 4: 7, 1000: 1023}
	for in, want := range buckets {
		if got := BucketUpperNS(in); got != want {
			t.Fatalf("BucketUpperNS(%d) = %d, want %d", in, got, want)
		}
	}
}

// flipFirstHex returns s with its first hex digit changed, preserving length and
// hex validity.
func flipFirstHex(s string) string {
	if s == "" {
		return s
	}
	repl := byte('0')
	if s[0] == '0' {
		repl = '1'
	}
	return string(repl) + s[1:]
}
