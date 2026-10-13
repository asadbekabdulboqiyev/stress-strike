package attest

// verify.go — the independent verifier.
//
// Verify takes a bundle and (optionally) the sidecar records, and replays every
// check from scratch:
//
//  1. the bundle's shape, its cross-sums, its rate identities and its pacing
//     bookkeeping (Validate);
//  2. the coordinator signature over the canonical bundle digest;
//  3. for every worker, the Ed25519 signature over its commit;
//  4. for every worker, the Merkle root recomputed from the sidecar — this is
//     what makes a single altered byte visible;
//  5. for every worker, the aggregate recomputed from the sidecar
//     (count, sum, min, max, histogram, and a spot-check of inclusion proofs);
//  6. the run-wide percentiles and rate recomputed from every sidecar record,
//     including the coordinated-omission correction and its confidence
//     interval.
//
// It never panics on malformed input: every failure is a CheckError carrying
// the worker, the check name, a human-readable detail and, where meaningful,
// the leaf index at which verification stopped.
//
// # Absent sidecar
//
// Verify(b, nil) is legal and useful: it establishes signature and internal
// consistency only, and sets SamplesAbsent on the result. It cannot prove that
// the committed evidence exists, only that the claim is coherent and signed.
//
// # Cost and limits
//
// Recomputing the Merkle root is O(n) hashes over the total number of records.
// Full per-leaf proof verification is O(n log n) hashes and is therefore bounded
// by VerifyOptions.ProofVerifyLimit; when a run is larger than that budget the
// verifier still recomputes the root, still verifies a bounded spread of
// inclusion proofs, and warns that it did not sweep every leaf.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sort"
	"strconv"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/honesty"
)

// ppmScale is 100% in parts per million. It mirrors honesty.PPMScale inside
// this package so the encoders do not need a cross-package constant.
const ppmScale = 1_000_000

// Default verification limits. They bound work, not correctness.
const (
	// DefaultProofVerifyLimit is the hash budget for a full per-leaf proof
	// sweep (a few hundred milliseconds of SHA-256).
	DefaultProofVerifyLimit = 25_000_000
	// DefaultProofSampleWidth is how many inclusion proofs are verified when
	// the full sweep is not affordable. A proof costs O(n) hashes, so the
	// effective width is reduced further on a large run.
	DefaultProofSampleWidth = 256
)

// VerifyOptions tunes work and limits. The zero value means "strict defaults".
type VerifyOptions struct {
	// MaxSamplesPerWorker rejects a worker whose sidecar slice is longer than
	// this without hashing it.
	MaxSamplesPerWorker int
	// MaxSamplesTotal rejects a verification whose combined record count
	// exceeds this.
	MaxSamplesTotal int
	// ProofVerifyLimit is the number of SHA-256 operations allowed for proof
	// verification.
	ProofVerifyLimit int
	// ProofSampleWidth is the maximum number of explicit inclusion proofs to
	// verify.
	ProofSampleWidth int
	// BootstrapIterations overrides the confidence-interval resample count.
	BootstrapIterations int
	// SkipCICheck disables the confidence-interval recomputation. The interval
	// is a reproducibility aid; skipping it is a documented speed/soundness
	// trade, not a correctness hole in the tamper-evidence property.
	SkipCICheck bool
}

func (o VerifyOptions) withDefaults() VerifyOptions {
	if o.MaxSamplesPerWorker <= 0 {
		o.MaxSamplesPerWorker = DefaultMaxSamplesPerWorker
	}
	if o.MaxSamplesTotal <= 0 {
		o.MaxSamplesTotal = DefaultMaxSamplesTotal
	}
	if o.ProofVerifyLimit <= 0 {
		o.ProofVerifyLimit = DefaultProofVerifyLimit
	}
	if o.ProofSampleWidth <= 0 {
		o.ProofSampleWidth = DefaultProofSampleWidth
	}
	if o.BootstrapIterations <= 0 {
		o.BootstrapIterations = honesty.DefaultBootstrapIterations
	}
	return o
}

// CheckError is one failed check. Index, when non-nil, is the leaf index the
// failure is anchored to (for a tampered sample, the first leaf whose inclusion
// proof no longer reaches the signed root).
type CheckError struct {
	// Worker is the worker id, or "" for a run-wide check.
	Worker string
	// Check is the stable check name (e.g. "commit-root").
	Check string
	// Detail explains the failure.
	Detail string
	// Index is the leaf index, when the failure refers to one.
	Index *int64
}

// Error renders the failure as a single line.
func (e CheckError) Error() string {
	loc := e.Check
	if e.Worker != "" {
		loc = e.Worker + "/" + e.Check
	}
	if e.Index != nil {
		return fmt.Sprintf("%s (leaf %d): %s", loc, *e.Index, e.Detail)
	}
	return fmt.Sprintf("%s: %s", loc, e.Detail)
}

// String is an alias for Error.
func (e CheckError) String() string { return e.Error() }

// Check is one check that passed or failed.
type Check struct {
	// Name is the stable check name.
	Name string
	// OK reports whether it passed.
	OK bool
	// Detail is a short human-readable explanation.
	Detail string
}

// WorkerReport is the per-worker outcome.
type WorkerReport struct {
	// ID is the worker id.
	ID string
	// PublicKey is the worker's hex public key.
	PublicKey string
	// Samples is the number of sidecar records seen, or -1 when the sidecar
	// was absent.
	Samples int
	// LeavesHashed is the number of leaves folded into the recomputed root.
	LeavesHashed int
	// RootMatches reports whether the recomputed root equalled the committed
	// one.
	RootMatches bool
	// CommitSigOK reports whether the commit signature verified.
	CommitSigOK bool
	// AggregateOK reports whether the recomputed aggregate matched the claim.
	AggregateOK bool
	// ProofsVerified is the number of inclusion proofs checked.
	ProofsVerified int
	// Checks lists this worker's checks.
	Checks []Check
	// Errors lists this worker's failures.
	Errors []CheckError
}

// Summary aggregates the outcome counters.
type Summary struct {
	// Workers is the number of workers examined.
	Workers int
	// WorkersOK and WorkersFailed split them by outcome.
	WorkersOK     int
	WorkersFailed int
	// SamplesTotal is the number of sidecar records examined.
	SamplesTotal int
	// ChecksRun and ChecksFailed count checks.
	ChecksRun    int
	ChecksFailed int
	// ProofsVerified is the number of inclusion proofs checked.
	ProofsVerified int
}

// VerifyResult is the outcome of a verification.
type VerifyResult struct {
	// Valid is true only when there are no failures at all.
	Valid bool
	// Format is the format id read from the bundle.
	Format string
	// SamplesAbsent reports that verification ran without a sidecar.
	SamplesAbsent bool
	// BundleDigest is the hex SHA-256 of the canonical bundle.
	BundleDigest string
	// Checks lists run-wide checks.
	Checks []Check
	// Workers lists per-worker outcomes.
	Workers []WorkerReport
	// Errors lists every failure, run-wide and per-worker.
	Errors []CheckError
	// Warnings lists non-fatal observations.
	Warnings []string
	// Summary holds the counters.
	Summary Summary
}

// OK reports whether verification passed. It is a convenience alias for Valid.
func (r VerifyResult) OK() bool { return r.Valid }

// FirstError returns the first failure, or the zero value and false.
func (r VerifyResult) FirstError() (CheckError, bool) {
	if len(r.Errors) == 0 {
		return CheckError{}, false
	}
	return r.Errors[0], true
}

// ErrorLines renders every failure as a line, for CLI output.
func (r VerifyResult) ErrorLines() []string {
	out := make([]string, 0, len(r.Errors))
	for _, e := range r.Errors {
		out = append(out, e.Error())
	}
	return out
}

// Verify is the frozen entry point: it verifies a bundle against an optional
// sidecar and applies strict default limits. A nil samples map means the
// sidecar was not supplied.
func Verify(b Bundle, samples map[string][]Record) VerifyResult {
	return VerifyWith(b, samples, VerifyOptions{})
}

// VerifyWith is Verify with explicit limits.
func VerifyWith(b Bundle, samples map[string][]Record, opts VerifyOptions) VerifyResult {
	opts = opts.withDefaults()
	v := &verifier{opts: opts}
	v.res.Format = b.Format
	v.res.SamplesAbsent = samples == nil
	v.run(b, samples)
	v.finish()
	return v.res
}

// verifier carries the running result and options.
type verifier struct {
	opts VerifyOptions
	res  VerifyResult
}

func (v *verifier) globalPass(name, detail string) {
	v.res.Checks = append(v.res.Checks, Check{Name: name, OK: true, Detail: detail})
}

func (v *verifier) globalFail(name, detail string) {
	v.res.Checks = append(v.res.Checks, Check{Name: name, OK: false, Detail: detail})
	v.res.Errors = append(v.res.Errors, CheckError{Check: name, Detail: detail})
}

func (v *verifier) warn(format string, args ...any) {
	v.res.Warnings = append(v.res.Warnings, fmt.Sprintf(format, args...))
}

func (v *verifier) workerPass(wr *WorkerReport, name, detail string) {
	wr.Checks = append(wr.Checks, Check{Name: name, OK: true, Detail: detail})
}

func (v *verifier) workerFail(wr *WorkerReport, name, detail string, index *int64) {
	wr.Checks = append(wr.Checks, Check{Name: name, OK: false, Detail: detail})
	e := CheckError{Worker: wr.ID, Check: name, Detail: detail, Index: index}
	wr.Errors = append(wr.Errors, e)
	v.res.Errors = append(v.res.Errors, e)
}

func (v *verifier) run(b Bundle, samples map[string][]Record) {
	// 1. format
	if b.Format == FormatID {
		v.globalPass("format", "format is "+FormatID)
	} else {
		v.globalFail("format", fmt.Sprintf("format is %q, want %q", b.Format, FormatID))
	}

	// 2. structure
	if err := b.Validate(); err != nil {
		v.globalFail("bundle-schema", err.Error())
	} else {
		v.globalPass("bundle-schema", "structure, cross-sums, rate identities and pacing bookkeeping hold")
	}

	// 3. digest, for reporting even when the signature is broken
	if digest, err := b.DigestHex(); err == nil {
		v.res.BundleDigest = digest
	}

	// 4. coordinator signature
	if err := b.VerifyCoordinatorSig(); err != nil {
		v.globalFail("bundle-signature", err.Error())
	} else {
		v.globalPass("bundle-signature", "Ed25519 signature verifies over "+shortHex(v.res.BundleDigest))
	}

	// 5. duplicate worker ids
	seen := make(map[string]int, len(b.Workers))
	for i := range b.Workers {
		id := b.Workers[i].ID
		if prev, dup := seen[id]; dup {
			v.globalFail("worker-id", fmt.Sprintf("duplicate worker id %q at positions %d and %d", id, prev, i))
			continue
		}
		seen[id] = i
	}
	if _, dup := seen[""]; !dup {
		v.globalPass("worker-id", fmt.Sprintf("%d distinct worker ids", len(seen)))
	}

	// 6. rate identity and pacing bookkeeping, checkable without the sidecar
	v.verifyRateIdentity(b)
	v.verifyIntegrity(b)

	// 7. workers
	total := 0
	for i := range b.Workers {
		n := v.verifyWorker(&b.Workers[i], samples)
		if n > 0 {
			total += n
		}
	}
	if total > v.opts.MaxSamplesTotal {
		v.globalFail("samples-limit", fmt.Sprintf("%d records exceed the %d record limit", total, v.opts.MaxSamplesTotal))
	}

	// 8. run-wide aggregate from the sidecar
	if samples != nil {
		v.verifyGlobalAggregate(b, samples)
	}
}

// verifyRateIdentity recomputes aggregate.rps from count and duration, and the
// pacing bookkeeping from the planned rate. Both are pure functions of values
// already inside the bundle, so they are checked even without the sidecar.
func (v *verifier) verifyRateIdentity(b Bundle) {
	achievedMilli, err := honesty.AchievedRPSMilli(b.Aggregate.Count, b.Run.DurationNS)
	if err != nil {
		v.globalFail("aggregate-rate", err.Error())
		return
	}
	want, err := DecimalFromMilli(achievedMilli)
	if err != nil {
		v.globalFail("aggregate-rate", err.Error())
		return
	}
	if want != b.Aggregate.RPS {
		v.globalFail("aggregate-rate", fmt.Sprintf("aggregate.rps %q does not equal %d requests over %d ns (%q)", b.Aggregate.RPS, b.Aggregate.Count, b.Run.DurationNS, want))
		return
	}
	v.globalPass("aggregate-rate", fmt.Sprintf("aggregate.rps %q equals %d requests over %d ns", b.Aggregate.RPS, b.Aggregate.Count, b.Run.DurationNS))
}

// verifyIntegrity recomputes the integrity block from the planned rate, the
// duration and the achieved count.
func (v *verifier) verifyIntegrity(b Bundle) {
	plannedMilli, err := b.Integrity.PlannedRPS.Milli()
	if err != nil {
		v.globalFail("integrity", fmt.Sprintf("planned_rps: %v", err))
		return
	}
	achievedMilli, err := b.Integrity.AchievedRPS.Milli()
	if err != nil {
		v.globalFail("integrity", fmt.Sprintf("achieved_rps: %v", err))
		return
	}
	wantDropped, err := honesty.DroppedSamples(plannedMilli, b.Run.DurationNS, b.Aggregate.Count)
	if err != nil {
		v.globalFail("integrity", err.Error())
		return
	}
	if wantDropped != b.Integrity.DroppedSamples {
		v.globalFail("integrity", fmt.Sprintf("dropped_samples %d does not equal the %d planned slots left empty", b.Integrity.DroppedSamples, wantDropped))
		return
	}
	wantAccuracy := honesty.ScheduleAccuracyPPM(plannedMilli, achievedMilli)
	if wantAccuracy != b.Integrity.ScheduleAccuracyPPM {
		v.globalFail("integrity", fmt.Sprintf("schedule_accuracy_ppm %d does not equal the %d recomputed from the rates", b.Integrity.ScheduleAccuracyPPM, wantAccuracy))
		return
	}
	v.globalPass("integrity", fmt.Sprintf("dropped_samples %d and schedule_accuracy_ppm %d reproduce from the rates", wantDropped, wantAccuracy))
}

// verifyWorker checks one worker and returns the number of samples it examined
// (0 when the sidecar was absent).
func (v *verifier) verifyWorker(w *WorkerBundle, samples map[string][]Record) int {
	wr := WorkerReport{ID: w.ID, PublicKey: w.PublicKey, Samples: -1}
	defer func() { v.res.Workers = append(v.res.Workers, wr) }()

	pub, keyErr := ParsePublicKeyHex(w.PublicKey)
	if keyErr != nil {
		v.workerFail(&wr, "worker-key", keyErr.Error(), nil)
	} else {
		v.workerPass(&wr, "worker-key", "public key is a 32-byte Ed25519 key")
	}

	if keyErr == nil {
		if err := VerifyCommit(pub, w.Commit); err != nil {
			v.workerFail(&wr, "commit-signature", err.Error(), nil)
		} else {
			wr.CommitSigOK = true
			v.workerPass(&wr, "commit-signature", "Ed25519 commit signature verifies")
		}
	}

	if samples == nil {
		v.workerPass(&wr, "samples", "sidecar absent: signature and internal consistency only")
		return 0
	}

	recs, ok := samples[w.ID]
	switch {
	case !ok && w.Commit.SampleCount == 0:
		v.workerPass(&wr, "samples", "no samples expected and none provided")
		return 0
	case !ok:
		v.workerFail(&wr, "samples", fmt.Sprintf("no sidecar records for a worker that committed %d samples", w.Commit.SampleCount), nil)
		return 0
	}

	if len(recs) == 0 {
		wr.Samples = 0
		if w.Commit.SampleCount == 0 {
			v.workerPass(&wr, "samples", "empty sidecar for a worker that committed nothing")
			return 0
		}
		v.workerFail(&wr, "samples", fmt.Sprintf("sidecar is empty but the commit claims %d samples", w.Commit.SampleCount), nil)
		return 0
	}
	if len(recs) > v.opts.MaxSamplesPerWorker {
		wr.Samples = len(recs)
		v.workerFail(&wr, "samples-limit", fmt.Sprintf("%d records exceed the %d record per-worker limit", len(recs), v.opts.MaxSamplesPerWorker), nil)
		return 0
	}
	wr.Samples = len(recs)

	v.verifyWorkerSamples(&wr, w, recs)
	return len(recs)
}

// verifyWorkerSamples does the sidecar-dependent checks for one worker.
func (v *verifier) verifyWorkerSamples(wr *WorkerReport, w *WorkerBundle, recs []Record) {
	// record-level validity and identity
	for i := range recs {
		r := recs[i]
		if err := r.Validate(); err != nil {
			idx := int64(i)
			v.workerFail(wr, "sample-validate", err.Error(), &idx)
			return
		}
		if r.Worker != w.ID {
			idx := int64(i)
			v.workerFail(wr, "sample-worker", fmt.Sprintf("record worker is %q, want %q", r.Worker, w.ID), &idx)
			return
		}
	}
	if !RecordsInFileOrder(recs) {
		v.warn("worker %q: sidecar records are not in canonical (start_ns, seq) order", w.ID)
	}

	ordered := SortRecords(recs)
	leaves := make([][]byte, len(ordered))
	for i := range ordered {
		line, err := CanonicalRecord(ordered[i])
		if err != nil {
			idx := int64(i)
			v.workerFail(wr, "sample-encode", err.Error(), &idx)
			return
		}
		leaves[i] = line
	}
	wr.LeavesHashed = len(leaves)

	// commit count
	if w.Commit.SampleCount == uint64(len(recs)) {
		v.workerPass(wr, "commit-count", fmt.Sprintf("%d records match commit.sample_count", len(recs)))
	} else {
		v.workerFail(wr, "commit-count", fmt.Sprintf("sidecar has %d records but commit.sample_count is %d", len(recs), w.Commit.SampleCount), nil)
	}

	// commit root
	recomputed := MerkleRootHex(leaves)
	if recomputed == w.Commit.MerkleRoot {
		wr.RootMatches = true
		v.workerPass(wr, "commit-root", fmt.Sprintf("%d leaves reproduce the committed Merkle root %s", len(leaves), shortHex(recomputed)))
		wr.ProofsVerified = v.verifySpreadProofs(wr, w.Commit.MerkleRoot, leaves)
	} else {
		wr.RootMatches = false
		idx, fails := v.findFirstFailingLeaf(w.Commit.MerkleRoot, leaves)
		detail := fmt.Sprintf("recomputed Merkle root %s does not match the committed root %s", shortHex(recomputed), shortHex(w.Commit.MerkleRoot))
		if idx != nil {
			detail += fmt.Sprintf("; %d of %d inclusion proofs fail against the signed root, first at leaf %d", fails, len(leaves), *idx)
		}
		v.workerFail(wr, "commit-root", detail, idx)
	}

	// worker aggregate (raw latencies: the worker summary is uncorrected)
	stats, err := AggregateRecords(ordered, 0, false, 0)
	if err != nil {
		v.workerFail(wr, "worker-aggregate", err.Error(), nil)
		return
	}
	if err := compareWorkerAgg(stats, w.Aggregate); err != nil {
		v.workerFail(wr, "worker-aggregate", err.Error(), nil)
		return
	}
	wr.AggregateOK = true
	v.workerPass(wr, "worker-aggregate", fmt.Sprintf("count %d, sum %d, min %d, max %d and histogram reproduce", stats.Count, stats.SumLatencyNS, stats.MinNS, stats.MaxNS))
}

// verifySpreadProofs verifies a bounded, deterministic spread of inclusion
// proofs against the committed root. It returns how many were checked.
//
// When the root already matched, a proof failing here would be an
// implementation defect rather than tampering, which is exactly why it is worth
// checking on a sample.
func (v *verifier) verifySpreadProofs(wr *WorkerReport, rootHex string, leaves [][]byte) int {
	root, err := hex.DecodeString(rootHex)
	if err != nil || len(root) != hashSize {
		return 0
	}
	n := len(leaves)
	if n == 0 {
		return 0
	}

	width := v.opts.ProofSampleWidth
	if maxByBudget := int(int64(v.opts.ProofVerifyLimit) / int64(maxInt(1, n))); width > maxByBudget {
		width = maxByBudget
	}
	if width < 1 {
		width = 1
	}

	indices := spreadIndices(n, width)
	checked := 0
	for _, i := range indices {
		proof, err := MerkleProof(leaves, i)
		if err != nil {
			v.workerFail(wr, "proofs", err.Error(), nil)
			return checked
		}
		if !VerifyProof(root, leaves[i], i, proof) {
			idx := int64(i)
			v.workerFail(wr, "proofs", "inclusion proof does not verify against the committed root", &idx)
			return checked
		}
		checked++
	}
	v.workerPass(wr, "proofs", fmt.Sprintf("%d inclusion proofs verify against the committed root", checked))
	return checked
}

// findFirstFailingLeaf sweeps every leaf's audit path against the signed root
// and returns the first leaf whose proof fails, plus the number of failures.
// It returns (nil, 0) when the sweep is not affordable or every proof passes.
func (v *verifier) findFirstFailingLeaf(rootHex string, leaves [][]byte) (*int64, int) {
	root, err := hex.DecodeString(rootHex)
	if err != nil || len(root) != hashSize {
		return nil, 0
	}
	n := len(leaves)
	if n == 0 {
		return nil, 0
	}
	cost := int64(n) * int64(ceilLog2(n))
	if cost > int64(v.opts.ProofVerifyLimit) {
		v.warn("worker: skipped the full inclusion-proof sweep for %d leaves (cost %d exceeds the %d hash budget)", n, cost, v.opts.ProofVerifyLimit)
		return nil, 0
	}
	first, fails, _ := verifyAllProofs(root, leaves)
	if first < 0 {
		return nil, 0
	}
	idx := int64(first)
	return &idx, fails
}

// verifyGlobalAggregate recomputes the run-wide percentiles, rate and confidence
// interval from every worker's sidecar records.
func (v *verifier) verifyGlobalAggregate(b Bundle, samples map[string][]Record) {
	rpsMilli, err := b.Run.PlannedRPS.Milli()
	if err != nil {
		v.globalFail("aggregate-percentiles", fmt.Sprintf("planned_rps: %v", err))
		return
	}
	co := b.Aggregate.COCorrected
	for i := range b.Workers {
		if _, ok := samples[b.Workers[i].ID]; !ok {
			v.warn("global aggregate not recomputed: worker %q has no sidecar records", b.Workers[i].ID)
			return
		}
	}

	values := make([]int64, 0, b.Aggregate.Count)
	var count uint64
	var sum uint64
	for i := range b.Workers {
		w := &b.Workers[i]
		ordered := SortRecords(samples[w.ID])
		for j := range ordered {
			r := ordered[j]
			// The run-wide sum is always the raw sum: the schema's
			// sum_latency_ns is checked against the workers' raw sums. Only the
			// distribution (percentiles, interval) is corrected.
			sum += uint64(r.LatencyNS)
			count++
			val := r.LatencyNS
			if co {
				corrected, err := honesty.CorrectedLatencyNS(r.StartNS, r.LatencyNS, w.Commit.WindowStartNS, r.Seq, rpsMilli)
				if err != nil {
					v.globalFail("aggregate-percentiles", "coordinated-omission correction: "+err.Error())
					return
				}
				val = corrected
			}
			values = append(values, val)
		}
	}

	if count != b.Aggregate.Count {
		v.globalFail("aggregate-count", fmt.Sprintf("sidecar holds %d records but aggregate.count is %d", count, b.Aggregate.Count))
	} else {
		v.globalPass("aggregate-count", fmt.Sprintf("%d records match aggregate.count", count))
	}
	if sum != b.Aggregate.SumLatencyNS {
		v.globalFail("aggregate-sum", fmt.Sprintf("sidecar latencies sum to %d but aggregate.sum_latency_ns is %d", sum, b.Aggregate.SumLatencyNS))
	}

	sorted := honesty.SortValues(values)
	p50 := honesty.Percentile(sorted, honesty.PPM50)
	p95 := honesty.Percentile(sorted, honesty.PPM95)
	p99 := honesty.Percentile(sorted, honesty.PPM99)
	if p50 != b.Aggregate.P50NS || p95 != b.Aggregate.P95NS || p99 != b.Aggregate.P99NS {
		v.globalFail("aggregate-percentiles", fmt.Sprintf("recomputed p50/p95/p99 %d/%d/%d do not match the claimed %d/%d/%d", p50, p95, p99, b.Aggregate.P50NS, b.Aggregate.P95NS, b.Aggregate.P99NS))
	} else {
		label := "raw"
		if co {
			label = "coordinated-omission-corrected"
		}
		v.globalPass("aggregate-percentiles", fmt.Sprintf("%s p50/p95/p99 %d/%d/%d reproduce exactly", label, p50, p95, p99))
	}

	v.verifyGlobalCI(b, sorted, co)
}

// verifyGlobalCI cross-checks the committed confidence interval.
func (v *verifier) verifyGlobalCI(b Bundle, sorted []int64, co bool) {
	if !co {
		if b.Aggregate.COCI95NS.LowNS != 0 || b.Aggregate.COCI95NS.HighNS != 0 {
			v.globalFail("aggregate-ci", "co_corrected is false but co_ci95_ns is not the zero interval")
		}
		return
	}
	if len(sorted) == 0 {
		return
	}
	lo, hi := honesty.CI95OrderStatistic(sorted, honesty.PPM99)
	if lo <= 0 && hi <= 0 {
		return
	}

	if v.opts.SkipCICheck {
		v.warn("confidence interval not recomputed (SkipCICheck): committed [%d, %d], order-statistic [%d, %d]", b.Aggregate.COCI95NS.LowNS, b.Aggregate.COCI95NS.HighNS, lo, hi)
		return
	}
	blo, bhi := honesty.CI95Bootstrap(sorted, honesty.PPM99, v.opts.BootstrapIterations, honesty.DefaultBootstrapSeed)
	if blo != b.Aggregate.COCI95NS.LowNS || bhi != b.Aggregate.COCI95NS.HighNS {
		v.globalFail("aggregate-ci", fmt.Sprintf("recomputed bootstrap interval [%d, %d] does not match the committed [%d, %d]", blo, bhi, b.Aggregate.COCI95NS.LowNS, b.Aggregate.COCI95NS.HighNS))
		return
	}
	v.globalPass("aggregate-ci", fmt.Sprintf("bootstrap interval [%d, %d] reproduces", blo, bhi))
	if b.Aggregate.COCI95NS.HighNS < lo || b.Aggregate.COCI95NS.LowNS > hi {
		v.warn("committed confidence interval [%d, %d] does not overlap the order-statistic interval [%d, %d]", b.Aggregate.COCI95NS.LowNS, b.Aggregate.COCI95NS.HighNS, lo, hi)
	}
}

func (v *verifier) finish() {
	for i := range v.res.Workers {
		wr := &v.res.Workers[i]
		if len(wr.Errors) == 0 {
			v.res.Summary.WorkersOK++
		} else {
			v.res.Summary.WorkersFailed++
		}
		if wr.Samples > 0 {
			v.res.Summary.SamplesTotal += wr.Samples
		}
		v.res.Summary.ProofsVerified += wr.ProofsVerified
	}
	v.res.Summary.Workers = len(v.res.Workers)
	v.res.Summary.ChecksRun = len(v.res.Checks)
	for i := range v.res.Workers {
		v.res.Summary.ChecksRun += len(v.res.Workers[i].Checks)
	}
	v.res.Summary.ChecksFailed = len(v.res.Errors)
	v.res.Valid = len(v.res.Errors) == 0
}

// -----------------------------------------------------------------------------
// Aggregation
// -----------------------------------------------------------------------------

// AggregateStats is a summary recomputed from sidecar records.
type AggregateStats struct {
	// Count is the number of records.
	Count uint64
	// SumLatencyNS is the sum of the (possibly corrected) latencies.
	SumLatencyNS uint64
	// MinNS and MaxNS bound the (possibly corrected) latencies.
	MinNS int64
	MaxNS int64
	// Hist is the power-of-two histogram keyed by bucket upper bound.
	Hist map[string]uint64
	// Values holds the (possibly corrected) latencies, sorted ascending.
	Values []int64
}

// AggregateRecords recomputes a summary from records.
//
// windowStartNS, co and rpsMilli control the coordinated-omission correction:
// when co is true each latency is replaced by its corrected value using the
// worker's window start and the planned rate. The worker-level bundle aggregate
// is uncorrected, so it is compared with co=false.
func AggregateRecords(recs []Record, windowStartNS int64, co bool, rpsMilli int64) (AggregateStats, error) {
	st := AggregateStats{Hist: make(map[string]uint64), Values: make([]int64, 0, len(recs))}
	for i := range recs {
		r := recs[i]
		if err := r.Validate(); err != nil {
			return AggregateStats{}, err
		}
		val := r.LatencyNS
		if co {
			corrected, err := honesty.CorrectedLatencyNS(r.StartNS, r.LatencyNS, windowStartNS, r.Seq, rpsMilli)
			if err != nil {
				return AggregateStats{}, err
			}
			val = corrected
		}
		if st.Count == 0 {
			// The first value seeds both bounds; comparing against a zero
			// initialised min would report 0 and comparing on the second value
			// would discard the first entirely.
			st.MinNS, st.MaxNS = val, val
		} else {
			if val < st.MinNS {
				st.MinNS = val
			}
			if val > st.MaxNS {
				st.MaxNS = val
			}
		}
		st.Count++
		if st.SumLatencyNS > math.MaxUint64-uint64(val) {
			return AggregateStats{}, errors.New("aggregate: latency sum overflows uint64")
		}
		st.SumLatencyNS += uint64(val)
		st.Hist[strconv.FormatInt(BucketUpperNS(val), 10)]++
		st.Values = append(st.Values, val)
	}
	if st.Count == 0 {
		st.Hist = make(map[string]uint64)
		st.Values = nil
		return st, nil
	}
	sort.Slice(st.Values, func(i, j int) bool { return st.Values[i] < st.Values[j] })
	return st, nil
}

// compareWorkerAgg compares a recomputed aggregate against a worker's claim.
func compareWorkerAgg(st AggregateStats, claim WorkerAgg) error {
	switch {
	case st.Count != claim.Count:
		return fmt.Errorf("aggregate: count %d does not match the claimed %d", st.Count, claim.Count)
	case st.SumLatencyNS != claim.SumLatencyNS:
		return fmt.Errorf("aggregate: sum_latency_ns %d does not match the claimed %d", st.SumLatencyNS, claim.SumLatencyNS)
	case st.MinNS != claim.MinNS:
		return fmt.Errorf("aggregate: min_ns %d does not match the claimed %d", st.MinNS, claim.MinNS)
	case st.MaxNS != claim.MaxNS:
		return fmt.Errorf("aggregate: max_ns %d does not match the claimed %d", st.MaxNS, claim.MaxNS)
	case !equalHist(st.Hist, claim.Hist):
		return fmt.Errorf("aggregate: histogram does not match the claim (%d vs %d buckets)", len(st.Hist), len(claim.Hist))
	}
	return nil
}

func equalHist(a, b map[string]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// PercentileValue returns the nearest-rank quantile of an ascending sorted
// slice, with the fraction given in parts per million (990_000 for p99). It is
// the recomputation primitive used for the bundle's p50/p95/p99.
func PercentileValue(sorted []int64, ppm int) int64 {
	return honesty.Percentile(sorted, ppm)
}

// BucketUpperNS returns the inclusive upper bound of the power-of-two histogram
// bucket that a latency falls in: (1 << bitLen(latency)) - 1. Latency 0 maps to
// bucket 0, latency 1 to bucket 1, latencies 2..3 to bucket 3, and so on.
func BucketUpperNS(latencyNS int64) int64 {
	if latencyNS <= 0 {
		return 0
	}
	return int64((uint64(1) << bits.Len64(uint64(latencyNS))) - 1)
}

// parseBucketUpperNS parses a histogram key and insists it is of the form
// 2^k - 1, so a bundle cannot smuggle in arbitrary buckets.
func parseBucketUpperNS(key string) (int64, error) {
	v, err := strconv.ParseInt(key, 10, 64)
	if err != nil {
		return 0, errors.New("is not a decimal integer")
	}
	if v < 0 {
		return 0, errors.New("is negative")
	}
	if strconv.FormatInt(v, 10) != key {
		return 0, errors.New("is not canonical decimal")
	}
	u := uint64(v) + 1
	if u == 0 || u&(u-1) != 0 {
		return 0, errors.New("is not of the form 2^k-1")
	}
	return v, nil
}

// -----------------------------------------------------------------------------
// Proof sweep
// -----------------------------------------------------------------------------

// verifyAllProofs checks every leaf's audit path against root in one sweep. It
// returns the first failing leaf index (-1 if none), the number of failures and
// the number of leaves examined.
//
// It reuses the level-folding of the tree and combines each leaf's accumulated
// hash with its sibling at every level, so the whole set of proofs costs
// O(n log n) hashes instead of O(n^2).
func verifyAllProofs(root []byte, leaves [][]byte) (int, int, int) {
	n := len(leaves)
	if n == 0 {
		return -1, 0, 0
	}
	h := newHasher()
	cur := make([][hashSize]byte, n)
	acc := make([][hashSize]byte, n)
	pos := make([]int, n)
	for i, leaf := range leaves {
		cur[i] = h.leaf(i, leaf)
		acc[i] = cur[i]
		pos[i] = i
	}
	for len(cur) > 1 {
		next := make([][hashSize]byte, (len(cur)+1)/2)
		for j := range next {
			left := &cur[2*j]
			right := left
			if 2*j+1 < len(cur) {
				right = &cur[2*j+1]
			}
			next[j] = h.node(left[:], right[:])
		}
		for i := 0; i < n; i++ {
			sib := pos[i] ^ 1
			if sib >= len(cur) {
				sib = len(cur) - 1
			}
			s := cur[sib]
			if pos[i]&1 == 0 {
				acc[i] = h.node(acc[i][:], s[:])
			} else {
				acc[i] = h.node(s[:], acc[i][:])
			}
			pos[i] >>= 1
		}
		cur = next
	}
	first := -1
	fails := 0
	for i := 0; i < n; i++ {
		if !equalBytes(acc[i][:], root) {
			fails++
			if first < 0 {
				first = i
			}
		}
	}
	return first, fails, n
}

// spreadIndices returns up to width distinct leaf indices spread across n,
// always including the first and last leaves. It is deterministic so two
// verifiers check the same proofs.
func spreadIndices(n, width int) []int {
	if n <= 0 {
		return nil
	}
	if width >= n {
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out
	}
	if width <= 1 {
		return []int{0}
	}
	out := make([]int, 0, width)
	for i := 0; i < width; i++ {
		idx := i * n / width
		if idx >= n {
			idx = n - 1
		}
		if len(out) > 0 && out[len(out)-1] == idx {
			continue
		}
		out = append(out, idx)
	}
	if out[len(out)-1] != n-1 {
		out = append(out, n-1)
	}
	return out
}

// ceilLog2 returns the smallest k with 2^k >= n, for n >= 1.
func ceilLog2(n int) int {
	if n <= 1 {
		return 0
	}
	return bits.Len(uint(n - 1))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// shortHex abbreviates a hex string for one-line messages.
func shortHex(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:8] + "…" + s[len(s)-8:]
}
