// Package twin builds a capacity digital twin from a completed Sift load test
// and answers "what happens at load X?" without sending a single request.
//
// # What the twin is
//
// A Sift run measures one operating point: a throughput, a latency
// distribution and an error rate. The twin turns that point into a small,
// versioned model - observed workload, service curve, capacity estimate and
// confidence grade - and then extrapolates from it with a queueing
// approximation. It is a planning instrument: it tells an operator whether a
// target load is comfortably below the measured limit, near the knee, or
// beyond it, and it quantifies how much that answer is worth.
//
// # What the twin is not
//
// The twin is a model, not a measurement and not a guarantee. It assumes
// steady state, a single bottleneck, no autoscaling, no cache warm-up, no
// per-endpoint or per-payload effects, and a load whose distribution matches
// the run that produced the model. If any of those assumptions is false the
// answer is wrong in a direction the twin cannot detect. Every artifact the
// package writes repeats this in plain language.
//
// # Capacity derivation
//
// Capacity is extrapolated with an M/M/1 tail approximation. For an M/M/1
// queue the p99 sojourn time is approximately
//
//	p99(rho) = L0 / (1 - rho)
//
// where L0 is the scale of the service distribution and rho the utilisation.
// We estimate L0 from the measured median by inverting the exponential-service
// median (median = L0 * ln 2), so L0 = p50 / ln 2. Substituting the measured
// p99 gives the utilisation the run actually operated at:
//
//	rhoRef = 1 - L0 / p99
//
// and therefore capacity = observedRPS / rhoRef. The result is clamped to a
// utilisation band of [0.10, 0.98] so a flat or a very heavy tail cannot
// produce an absurd extrapolation; when the clamp engages the model says so in
// its calibration notes and its confidence is downgraded.
package twin

import (
	"fmt"
	"math"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

// SchemaVersion identifies the on-disk model and result format. Bump it when a
// change would make an old artifact unsafe to interpret with this code.
const SchemaVersion = "sift.twin/v1"

// Capacity model constants. They are exported through ServiceCurve and
// Calibration rather than as package API so callers see the fitted numbers,
// not the internal knobs.
const (
	// tailFraction is the share of a run treated as the p99 tail. A run with
	// 100k requests contributes roughly 1k observations to the estimate, which
	// bounds how well p99 can be known at all.
	tailFraction = 0.01

	// minReferenceUtilization and maxReferenceUtilization clamp the utilisation
	// implied by the measured tail. The lower clamp caps extrapolated capacity
	// at 10x the observed load when the tail is flat; the upper clamp stops a
	// single slow outlier from implying infinite capacity pressure.
	minReferenceUtilization = 0.10
	maxReferenceUtilization = 0.98

	// capacityUncertainty clamp: never claim better than +/-2% or worse than
	// +/-60% from a heuristic that only sees aggregate percentiles.
	minCapacityUncertainty = 0.02
	maxCapacityUncertainty = 0.60

	// openLoopProfile is the Sift load profile that enforces a fixed arrival
	// rate. Every other profile is closed-loop: virtual users wait for their
	// own response before issuing the next request.
	openLoopProfile = "constant-rps"

	// maxFitDurationSeconds and maxFitRequests are sanity limits for a report
	// being fitted. They are deliberately far above any practical run: they
	// exist to reject corrupt files, not to police test length.
	maxFitDurationSeconds = 7 * 24 * 60 * 60
	maxFitRequests        = 1_000_000_000_000
)

// Confidence is the grade attached to a fitted model.
type Confidence string

const (
	// ConfidenceHigh means the run was long enough and large enough that p99
	// rests on a meaningful number of tail observations.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium means the estimate is usable for planning but carries
	// visible sampling error.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow means the run was short or noisy; treat the capacity
	// estimate as an order of magnitude, not a number.
	ConfidenceLow Confidence = "low"
)

// Latency is a latency distribution in milliseconds.
type Latency struct {
	P50MS float64 `json:"p50_ms"`
	P95MS float64 `json:"p95_ms"`
	P99MS float64 `json:"p99_ms"`
	// AvgMS is the arithmetic mean. It is what Little's law needs; percentiles
	// alone cannot recover concurrency.
	AvgMS float64 `json:"avg_ms"`
}

// Source records where the model came from, so an artifact can be traced back
// to the exact report that produced it.
type Source struct {
	ReportName      string    `json:"report_name"`
	TargetURL       string    `json:"target_url"`
	LoadProfile     string    `json:"load_profile"`
	StartedAt       time.Time `json:"started_at"`
	EndedAt         time.Time `json:"ended_at"`
	DurationSeconds float64   `json:"duration_seconds"`
	Producer        string    `json:"producer"`
}

// Workload is the observed operating point the model was fitted to.
type Workload struct {
	RPS             float64 `json:"rps"`
	Concurrency     float64 `json:"concurrency"`
	ActiveUsers     int64   `json:"active_users"`
	DurationSeconds float64 `json:"duration_seconds"`
	// OpenLoop is true when the load generator enforced an arrival rate
	// instead of pacing a fixed number of virtual users.
	OpenLoop      bool    `json:"open_loop"`
	TotalRequests uint64  `json:"total_requests"`
	TotalErrors   uint64  `json:"total_errors"`
	ErrorRatePct  float64 `json:"error_rate_pct"`
}

// ServiceCurve is the fitted latency/capacity relation.
type ServiceCurve struct {
	// Baseline is the latency distribution measured at the observed load.
	Baseline Latency `json:"baseline_latency"`
	// CapacityRPS is the estimated throughput at which queueing delay diverges.
	CapacityRPS                 float64 `json:"capacity_rps"`
	CapacityLowRPS              float64 `json:"capacity_low_rps"`
	CapacityHighRPS             float64 `json:"capacity_high_rps"`
	CapacityRelativeUncertainty float64 `json:"capacity_relative_uncertainty"`
	// ReferenceUtilization is the utilisation the fitted run operated at. The
	// simulation anchors amplification here: at this load, predicted latency
	// equals the measured baseline.
	ReferenceUtilization float64 `json:"reference_utilization"`
	// DegradationShape names the approximation used to amplify latency.
	DegradationShape string `json:"degradation_shape"`
	// QueueScaleMS is L0 from the M/M/1 tail model (p50 / ln 2). It is stored
	// for transparency; simulations use ReferenceUtilization.
	QueueScaleMS float64 `json:"queue_scale_ms"`
}

// Calibration explains how the model was derived. Notes are human-readable
// caveats and are copied verbatim into the Markdown report.
type Calibration struct {
	Method      string    `json:"method"`
	FittedAt    time.Time `json:"fitted_at"`
	TargetP99MS float64   `json:"target_p99_ms"`
	Notes       []string  `json:"notes"`
}

// Model is the complete digital twin. It is JSON-serializable and versioned.
type Model struct {
	SchemaVersion string       `json:"schema_version"`
	Source        Source       `json:"source"`
	Workload      Workload     `json:"workload"`
	Curve         ServiceCurve `json:"service_curve"`
	Confidence    Confidence   `json:"confidence"`
	Calibration   Calibration  `json:"calibration"`
}

// FitOptions controls the fit.
type FitOptions struct {
	// TargetP99MS is the latency objective used to describe capacity headroom
	// and to seed scenario SLAs. Zero selects the documented default: the
	// larger of 1.5x the observed p99 and the observed p99 + 50 ms, i.e. the
	// headroom the measured run did not use.
	TargetP99MS float64
	// Producer names the tool that created the model. Empty means "sift".
	Producer string
}

// Fit derives a Model from a completed Sift report.
//
// It fails closed on any report that cannot support the derivation: a
// non-positive duration, no completed requests, non-monotonic or non-positive
// latency percentiles, or an error rate outside [0, 100].
func Fit(rep report.Report, opts FitOptions) (Model, error) {
	durationSec := rep.Duration.Seconds()
	if math.IsNaN(durationSec) || math.IsInf(durationSec, 0) || durationSec <= 0 {
		return Model{}, fmt.Errorf("twin: report duration must be a positive number, got %s", rep.Duration)
	}
	if durationSec > maxFitDurationSeconds {
		return Model{}, fmt.Errorf("twin: report duration %.0fs exceeds the %.0fs sanity limit", durationSec, float64(maxFitDurationSeconds))
	}
	if rep.TotalRequests == 0 {
		return Model{}, fmt.Errorf("twin: report %q contains no completed requests; nothing to fit", reportName(rep))
	}
	if rep.TotalRequests > maxFitRequests {
		return Model{}, fmt.Errorf("twin: report request count %d exceeds the %d sanity limit", rep.TotalRequests, uint64(maxFitRequests))
	}

	overall := rep.Overall
	p50 := durationMS(overall.P50)
	p95 := durationMS(overall.P95)
	p99 := durationMS(overall.P99)
	avg := durationMS(overall.Avg)
	switch {
	case p50 <= 0 || p95 <= 0 || p99 <= 0:
		return Model{}, fmt.Errorf("twin: report latency percentiles must all be positive (p50=%.3fms p95=%.3fms p99=%.3fms)", p50, p95, p99)
	case p95 < p50 || p99 < p95:
		return Model{}, fmt.Errorf("twin: report latency percentiles are not monotonic (p50=%.3fms p95=%.3fms p99=%.3fms)", p50, p95, p99)
	}
	// A report from a different producer may omit the mean. The median is a
	// conservative stand-in for Little's law: it understates concurrency for a
	// heavy tail, which makes the derived capacity estimate conservative too.
	if avg <= 0 {
		avg = p50
	}

	errPct := float64(rep.TotalErrors) / float64(rep.TotalRequests) * 100
	if math.IsNaN(errPct) || math.IsInf(errPct, 0) || errPct < 0 || errPct > 100 {
		return Model{}, fmt.Errorf("twin: report error rate is not in [0,100]%% (errors=%d requests=%d)", rep.TotalErrors, rep.TotalRequests)
	}

	rps := float64(rep.TotalRequests) / durationSec
	if math.IsNaN(rps) || math.IsInf(rps, 0) || rps <= 0 {
		return Model{}, fmt.Errorf("twin: derived throughput is not a positive finite number (requests=%d duration=%.3fs)", rep.TotalRequests, durationSec)
	}

	// Little's law: average concurrency equals arrival rate times time in
	// system. The mean latency is the time in system for a completed request.
	concurrency := rps * (avg / 1000)
	if concurrency <= 0 {
		return Model{}, fmt.Errorf("twin: derived concurrency is not positive (rps=%.3f avg=%.3fms)", rps, avg)
	}

	notes := make([]string, 0, 6)
	if rep.RPS > 0 {
		if rel := math.Abs(rep.RPS-rps) / rps; rel > 0.05 {
			notes = append(notes, fmt.Sprintf("report rps %.2f differs from requests/duration %.2f by %.1f%%; the derived value is used", rep.RPS, rps, rel*100))
		}
	}
	if rep.ErrorRatePct > 0 && math.Abs(rep.ErrorRatePct-errPct) > 0.01 {
		notes = append(notes, fmt.Sprintf("report error rate %.3f%% differs from counts-derived %.3f%%; the counts-derived value is used", rep.ErrorRatePct, errPct))
	}

	// M/M/1 tail approximation. See the package comment for the derivation.
	queueScale := p50 / math.Ln2
	rawRef := 1 - queueScale/p99
	ref := clamp(rawRef, minReferenceUtilization, maxReferenceUtilization)
	capacity := rps / ref
	uncertainty := capacityUncertainty(rep.TotalRequests, durationSec, errPct)
	if rawRef != ref {
		uncertainty = math.Min(uncertainty+0.05, maxCapacityUncertainty)
		notes = append(notes, fmt.Sprintf("reference utilisation %.3f was clamped to %.3f: the measured tail does not follow the M/M/1 shape, so capacity extrapolation is capped", rawRef, ref))
	}

	target := opts.TargetP99MS
	if target <= 0 {
		target = math.Max(p99*1.5, p99+50)
		notes = append(notes, fmt.Sprintf("no --target-p99-ms supplied; defaulting to %.2fms (max(1.5x observed p99, observed p99 + 50ms))", target))
	}

	openLoop := rep.LoadProfile == openLoopProfile
	if openLoop {
		notes = append(notes, "open-loop run: the generator fixed the arrival rate, so measured latency includes queueing delay")
	} else {
		notes = append(notes, "closed-loop run: virtual users paced the load, so throughput and concurrency reflect client-side pacing; capacity is estimated from the measured tail, not from the user count")
	}

	producer := opts.Producer
	if producer == "" {
		producer = "sift"
	}
	// FittedAt is derived from the report, never from the wall clock, so the
	// same report always produces byte-identical artifacts.
	fittedAt := rep.EndedAt

	m := Model{
		SchemaVersion: SchemaVersion,
		Source: Source{
			ReportName:      rep.Name,
			TargetURL:       rep.BaseURL,
			LoadProfile:     rep.LoadProfile,
			StartedAt:       rep.StartedAt,
			EndedAt:         rep.EndedAt,
			DurationSeconds: durationSec,
			Producer:        producer,
		},
		Workload: Workload{
			RPS:             rps,
			Concurrency:     concurrency,
			ActiveUsers:     rep.ActiveUsers,
			DurationSeconds: durationSec,
			OpenLoop:        openLoop,
			TotalRequests:   rep.TotalRequests,
			TotalErrors:     rep.TotalErrors,
			ErrorRatePct:    errPct,
		},
		Curve: ServiceCurve{
			Baseline:                    Latency{P50MS: p50, P95MS: p95, P99MS: p99, AvgMS: avg},
			CapacityRPS:                 capacity,
			CapacityLowRPS:              capacity * (1 - uncertainty),
			CapacityHighRPS:             capacity * (1 + uncertainty),
			CapacityRelativeUncertainty: uncertainty,
			ReferenceUtilization:        ref,
			DegradationShape:            "mm1-tail",
			QueueScaleMS:                queueScale,
		},
		Confidence: confidenceGrade(durationSec, rep.TotalRequests, errPct, rawRef != ref),
		Calibration: Calibration{
			Method:      "little-law + mm1-tail",
			FittedAt:    fittedAt,
			TargetP99MS: target,
			Notes:       notes,
		},
	}
	if err := m.Validate(); err != nil {
		return Model{}, fmt.Errorf("twin: fitted model failed validation: %w", err)
	}
	return m, nil
}

// Validate reports whether the model is internally consistent enough to
// simulate. A zero Model, a model from another schema version, or a model with
// non-positive capacity is rejected.
func (m Model) Validate() error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported model schema %q (want %q)", m.SchemaVersion, SchemaVersion)
	}
	c := m.Curve
	if !finite(c.CapacityRPS) || c.CapacityRPS <= 0 {
		return fmt.Errorf("capacity must be a positive finite number, got %v", c.CapacityRPS)
	}
	if c.CapacityLowRPS <= 0 || c.CapacityLowRPS > c.CapacityRPS || c.CapacityHighRPS < c.CapacityRPS {
		return fmt.Errorf("capacity bounds are inconsistent (low=%v point=%v high=%v)", c.CapacityLowRPS, c.CapacityRPS, c.CapacityHighRPS)
	}
	if !finite(c.ReferenceUtilization) || c.ReferenceUtilization <= 0 || c.ReferenceUtilization >= 1 {
		return fmt.Errorf("reference utilisation must be in (0,1), got %v", c.ReferenceUtilization)
	}
	b := c.Baseline
	if b.P50MS <= 0 || b.P95MS <= 0 || b.P99MS <= 0 || b.AvgMS <= 0 {
		return fmt.Errorf("baseline latencies must all be positive (p50=%v p95=%v p99=%v avg=%v)", b.P50MS, b.P95MS, b.P99MS, b.AvgMS)
	}
	if b.P95MS < b.P50MS || b.P99MS < b.P95MS {
		return fmt.Errorf("baseline latencies are not monotonic (p50=%v p95=%v p99=%v)", b.P50MS, b.P95MS, b.P99MS)
	}
	switch m.Confidence {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
	default:
		return fmt.Errorf("unknown confidence grade %q", m.Confidence)
	}
	if !finite(m.Workload.RPS) || m.Workload.RPS <= 0 {
		return fmt.Errorf("workload rps must be a positive finite number, got %v", m.Workload.RPS)
	}
	if m.Workload.ErrorRatePct < 0 || m.Workload.ErrorRatePct > 100 {
		return fmt.Errorf("workload error rate must be in [0,100]%%, got %v", m.Workload.ErrorRatePct)
	}
	return nil
}

// capacityUncertainty is a coarse, documented heuristic, not a confidence
// interval: it combines the standard error of a tail quantile (1/sqrt of the
// effective tail sample count), a short-run penalty, and a penalty for noisy
// runs. It is deliberately conservative because the alternatives imply a
// distribution the report does not carry.
func capacityUncertainty(requests uint64, durationSec, errPct float64) float64 {
	tail := math.Max(float64(requests)*tailFraction, 1)
	base := 1 / math.Sqrt(tail)
	runPenalty := 0.10 / math.Sqrt(math.Max(durationSec/60, 1))
	errPenalty := math.Min(errPct/100*0.5, 0.25)
	return clamp(base+runPenalty+errPenalty, minCapacityUncertainty, maxCapacityUncertainty)
}

// confidenceGrade maps run size, duration and noise onto a three-level grade.
// The thresholds are round numbers chosen so an operator can reason about them
// without a statistics background: a minute, ten thousand requests and one
// percent errors buys a "high".
func confidenceGrade(durationSec float64, requests uint64, errPct float64, clamped bool) Confidence {
	grade := ConfidenceLow
	switch {
	case durationSec >= 60 && requests >= 10_000 && errPct <= 1:
		grade = ConfidenceHigh
	case durationSec >= 20 && requests >= 1_000 && errPct <= 5:
		grade = ConfidenceMedium
	}
	// A clamp means the tail did not fit the assumed shape; the fit is still
	// usable but cannot deserve the top grade.
	if clamped && grade == ConfidenceHigh {
		grade = ConfidenceMedium
	}
	return grade
}

func reportName(rep report.Report) string {
	if rep.Name != "" {
		return rep.Name
	}
	return "unnamed"
}

func durationMS(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func finite(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
