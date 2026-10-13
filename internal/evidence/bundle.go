package evidence

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/honesty"
)

// BundleInput is everything needed to seal one local run into an evidence
// bundle: the collected measurements, the two identities involved, and the
// description of the run.
type BundleInput struct {
	// Collector holds the measurements. Its worker id names the single worker
	// in the bundle.
	Collector *Collector
	// WorkerKey signs the worker's commitment to its own records.
	WorkerKey *attest.Keypair
	// CoordinatorKey seals the whole bundle. The coordinator is the party
	// making the claim; the worker is the party that measured it.
	CoordinatorKey *attest.Keypair
	// Tool identifies the producer (name and version).
	Tool attest.Tool
	// Run describes the scenario that was exercised.
	Run attest.Run
	// CreatedAt is the bundle timestamp. Zero means "now".
	CreatedAt time.Time
	// COCorrected applies the coordinated-omission correction to the run-wide
	// aggregate and commits a bootstrap confidence interval for the corrected
	// p99. The worker-level aggregate is always uncorrected: it is the raw
	// record of what was measured, and the correction is a claim the
	// coordinator makes on top of it.
	COCorrected bool
}

// BuildBundle seals a run into a signed bundle.
//
// The builder is total and fail-closed. It refuses to seal evidence that is
// incomplete (a sample the collector could not represent), that cannot be
// corrected (coordinated-omission correction needs a positive planned rate), or
// that comes out structurally inconsistent — every bundle it returns has
// already passed attest.Bundle.Validate, so a caller cannot accidentally
// publish a bundle that no verifier would accept.
//
// The numbers are recomputed from the records, never copied from the run's
// telemetry: the bundle is an independent statement about the same evidence the
// report was built from, and a mismatch between the two would be a bug in the
// report, not a licence to change the bundle.
func BuildBundle(in BundleInput) (attest.Bundle, error) {
	if in.Collector == nil {
		return attest.Bundle{}, errors.New("evidence: no collector to seal")
	}
	if in.WorkerKey == nil {
		return attest.Bundle{}, errors.New("evidence: a worker signing key is required")
	}
	if in.CoordinatorKey == nil {
		return attest.Bundle{}, errors.New("evidence: a coordinator signing key is required")
	}
	if err := in.Collector.Err(); err != nil {
		// Sealing now would produce a bundle that is missing requests the run
		// actually made: an incomplete claim dressed up as a complete one.
		return attest.Bundle{}, fmt.Errorf("evidence: refusing to seal incomplete evidence: %w", err)
	}
	if in.Run.DurationNS <= 0 {
		return attest.Bundle{}, fmt.Errorf("evidence: run.duration_ns %d must be positive", in.Run.DurationNS)
	}
	plannedMilli, err := in.Run.PlannedRPS.Milli()
	if err != nil {
		return attest.Bundle{}, fmt.Errorf("evidence: run.planned_rps %q: %w", in.Run.PlannedRPS, err)
	}
	if in.COCorrected && plannedMilli <= 0 {
		return attest.Bundle{}, fmt.Errorf("evidence: coordinated-omission correction needs a positive planned rate, got %q", in.Run.PlannedRPS)
	}

	recs := in.Collector.Records()

	commit, err := attest.BuildCommit(in.WorkerKey, recs)
	if err != nil {
		return attest.Bundle{}, fmt.Errorf("evidence: build commit: %w", err)
	}

	// The worker's own summary is the raw one: uncorrected latencies, exactly
	// as measured.
	raw, err := attest.AggregateRecords(recs, commit.WindowStartNS, false, plannedMilli)
	if err != nil {
		return attest.Bundle{}, fmt.Errorf("evidence: raw aggregate: %w", err)
	}
	workerAgg := attest.WorkerAgg{
		Count:        raw.Count,
		SumLatencyNS: raw.SumLatencyNS,
		MinNS:        raw.MinNS,
		MaxNS:        raw.MaxNS,
		Hist:         raw.Hist,
	}

	// The run-wide summary is the corrected one, which is what an honest report
	// of a paced run has to publish.
	corrected, err := attest.AggregateRecords(recs, commit.WindowStartNS, in.COCorrected, plannedMilli)
	if err != nil {
		return attest.Bundle{}, fmt.Errorf("evidence: corrected aggregate: %w", err)
	}

	achievedMilli, err := honesty.AchievedRPSMilli(corrected.Count, in.Run.DurationNS)
	if err != nil {
		return attest.Bundle{}, fmt.Errorf("evidence: achieved rate: %w", err)
	}
	achieved, err := attest.DecimalFromMilli(achievedMilli)
	if err != nil {
		return attest.Bundle{}, fmt.Errorf("evidence: achieved rate %d: %w", achievedMilli, err)
	}

	agg := attest.Aggregate{
		Count: corrected.Count,
		// The schema checks sum_latency_ns against the workers' raw sums, so
		// the run-wide sum stays raw even when the distribution is corrected:
		// the correction changes what the tail looked like, not how long the
		// requests took.
		SumLatencyNS: raw.SumLatencyNS,
		P50NS:        percentileOf(corrected.Values, honesty.PPM50),
		P95NS:        percentileOf(corrected.Values, honesty.PPM95),
		P99NS:        percentileOf(corrected.Values, honesty.PPM99),
		RPS:          achieved,
		COCorrected:  in.COCorrected,
	}
	if in.COCorrected && len(corrected.Values) > 0 {
		lo, hi := honesty.CI95Bootstrap(corrected.Values, honesty.PPM99, honesty.DefaultBootstrapIterations, honesty.DefaultBootstrapSeed)
		agg.COCI95NS = attest.CI95{LowNS: lo, HighNS: hi}
	}

	dropped, err := honesty.DroppedSamples(plannedMilli, in.Run.DurationNS, corrected.Count)
	if err != nil {
		return attest.Bundle{}, fmt.Errorf("evidence: dropped samples: %w", err)
	}

	created := in.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}

	b := attest.Bundle{
		Format:    attest.FormatID,
		CreatedAt: created.UTC().Format(time.RFC3339),
		Tool:      in.Tool,
		Run:       in.Run,
		Workers: []attest.WorkerBundle{{
			ID:        in.Collector.Worker(),
			PublicKey: attest.PublicKeyHex(in.WorkerKey.Public),
			Commit:    commit,
			Aggregate: workerAgg,
		}},
		Aggregate: agg,
		Integrity: attest.Integrity{
			ScheduleAccuracyPPM: honesty.ScheduleAccuracyPPM(plannedMilli, achievedMilli),
			DroppedSamples:      dropped,
			AchievedRPS:         achieved,
			PlannedRPS:          in.Run.PlannedRPS,
		},
	}

	// The seal is computed over the canonical bundle without it, so it can only
	// be applied once every other field is final.
	if err := b.Sign(in.CoordinatorKey); err != nil {
		return attest.Bundle{}, fmt.Errorf("evidence: sign bundle: %w", err)
	}
	if err := b.Validate(); err != nil {
		return attest.Bundle{}, fmt.Errorf("evidence: the built bundle does not validate (this is a producer bug): %w", err)
	}
	return b, nil
}

// percentileOf returns the nearest-rank percentile of ascending values,
// with the fraction in parts per million. It is the same primitive the verifier
// recomputes with.
func percentileOf(sorted []int64, ppm int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	return honesty.Percentile(sorted, ppm)
}

// SidecarPath returns the conventional path of a bundle's sample sidecar: the
// bundle file with ".json" replaced by ".samples.jsonl", and otherwise the
// bundle path with ".samples.jsonl" appended. The bundle and its sidecar must
// travel together — the bundle alone proves what was committed to, the sidecar
// proves what was committed.
func SidecarPath(bundlePath string) string {
	base := bundlePath
	if strings.HasSuffix(base, ".json") {
		base = strings.TrimSuffix(base, ".json")
	}
	return base + ".samples.jsonl"
}

// WriteBundle writes a bundle and its sample sidecar for a run. It returns the
// sidecar path it wrote.
//
// The sidecar is written first: if the process dies between the two writes, the
// leftover file is a sidecar with no bundle (harmless — nothing points at it),
// never a signed bundle whose evidence is missing.
func WriteBundle(b attest.Bundle, recs []attest.Record, bundlePath string) (string, error) {
	sidecar := SidecarPath(bundlePath)
	if err := writeSidecar(sidecar, recs); err != nil {
		return "", err
	}
	if err := attest.SaveBundle(b, bundlePath); err != nil {
		return "", err
	}
	return sidecar, nil
}

func writeSidecar(path string, recs []attest.Record) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("evidence: create %s: %w", dir, err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("evidence: create sidecar %s: %w", path, err)
	}
	if err := attest.WriteSamples(f, recs); err != nil {
		_ = f.Close()
		return fmt.Errorf("evidence: write sidecar %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("evidence: close sidecar %s: %w", path, err)
	}
	return nil
}
