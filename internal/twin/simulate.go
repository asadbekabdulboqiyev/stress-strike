package twin

// simulate.go — deterministic Monte Carlo over the fitted service curve.
//
// # The latency model
//
// The fit stores a reference utilisation rhoRef (the utilisation the measured
// run operated at) and the baseline percentile it measured. Above rhoRef the
// twin amplifies latency with the M/M/1 tail ratio
//
//	amp(rho) = (1 - rhoRef) / (1 - rho)      for rho > rhoRef
//	amp(rho) = 1                             for rho <= rhoRef
//
// so amp(rhoRef) = 1 exactly: at the fitted load the prediction reproduces the
// measurement, and from there it grows towards the pole at rho = 1. The ratio
// is algebraically the same as L0/(1-rho) normalised by its value at rhoRef,
// so it stays consistent with the capacity derivation in model.go. Below
// rhoRef the twin has no evidence of degradation and does not invent any.
//
// At or beyond rho = 0.999 the ratio is capped at maxAmplification (20x) so a
// single scenario cannot produce infinite latency or a division by zero. That
// cap is itself a statement: once the model is inside the last 0.1% of
// capacity, the number is a lower bound on the pain.
//
// # The error model
//
// Errors are not predicted from first principles. The twin carries the
// measured error rate forward, scales it with run-to-run noise, and adds a
// linear overload penalty above 90% utilisation (up to +30 percentage points
// at 100%). This is an assumption of monotonic degradation, documented in the
// output, not a queueing result.
//
// # The random stream
//
// All randomness comes from one math/rand/v2 PCG stream seeded from the
// scenario seed. Iterations draw, in a fixed order, a capacity perturbation, a
// latency noise factor and an error noise factor. The same seed therefore
// produces byte-identical results on every platform, which is what makes the
// output auditable and the tests meaningful.

import (
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
)

// Simulation guard rails. They bound worst-case runtime and reject inputs that
// are almost certainly mistakes rather than intent.
const (
	// MaxIterations caps a single simulation. 10k iterations at the default
	// iteration cost is well under a second and gives tail probabilities to
	// roughly 0.01% resolution.
	MaxIterations = 10_000
	// MaxDurationSeconds caps scenario length at 24 hours. The twin is a
	// steady-state model; day-long scenarios add no information.
	MaxDurationSeconds = 24 * 60 * 60
	// MaxRPS and MaxUsers cap open- and closed-loop load. They are far above
	// any load a single Sift fit can meaningfully extrapolate to.
	MaxRPS   = 1_000_000.0
	MaxUsers = 1_000_000.0

	// maxAmplification caps the M/M/1 ratio near the pole.
	maxAmplification = 20.0
	// maxUtilization keeps 1-rho away from zero in every division.
	maxUtilization = 0.999
	// overloadUtilization is where the error penalty starts.
	overloadUtilization = 0.90
	// overloadErrorCeilingPct is the additional error rate at rho = 1.
	overloadErrorCeilingPct = 30.0
	// capacityJitterFraction sets how much of the model's capacity
	// uncertainty is re-drawn per iteration: drawing the full uncertainty
	// would double-count it, half keeps it visible without swamping the trend.
	capacityJitterFraction = 0.5
	// latencyJitterSigma and errorJitterSigma are multiplicative run-to-run
	// noise on the measured baseline. 5% and 15% are deliberately small: the
	// dominant uncertainty is capacity, not per-run latency noise.
	latencyJitterSigma = 0.05
	errorJitterSigma   = 0.15
	// closedLoopMaxSteps and closedLoopDamping control the Little's-law fixed
	// point for closed-loop scenarios.
	closedLoopMaxSteps = 64
	closedLoopDamping  = 0.5
)

// LoopMode selects how the scenario applies load.
type LoopMode string

const (
	// LoopOpen applies a fixed arrival rate: requests arrive regardless of how
	// fast the service answers.
	LoopOpen LoopMode = "open"
	// LoopClosed applies a fixed number of users, each waiting for its own
	// response before issuing the next request.
	LoopClosed LoopMode = "closed"
)

// Risk levels derived from the estimated SLA breach probability.
const (
	// RiskLow means the estimated breach probability is below 5%.
	RiskLow = "low"
	// RiskElevated means it is between 5% and 50%.
	RiskElevated = "elevated"
	// RiskHigh means it is 50% or more.
	RiskHigh = "high"
)

// Scenario is one what-if question. Exactly one of TargetRPS (open loop) or
// TargetUsers (closed loop) is used, selected by Mode.
type Scenario struct {
	Name string `json:"name"`
	// Mode is "open" for a fixed arrival rate or "closed" for a fixed user
	// count. The zero value is invalid; callers must be explicit.
	Mode LoopMode `json:"mode"`
	// TargetRPS is the arrival rate for open-loop scenarios.
	TargetRPS float64 `json:"target_rps,omitempty"`
	// TargetUsers is the concurrency for closed-loop scenarios.
	TargetUsers float64 `json:"target_users,omitempty"`
	// DurationSeconds is the scenario length. The twin is steady-state, so
	// this affects reporting and the ramp, not the steady-state prediction.
	DurationSeconds float64 `json:"duration_seconds"`
	// RampSeconds is the time taken to reach the target load. Zero means an
	// immediate step; saturation time is only predicted when it is positive.
	RampSeconds float64 `json:"ramp_seconds"`
	// SLAP99MS is the p99 latency objective in milliseconds. Zero disables the
	// latency breach check.
	SLAP99MS float64 `json:"sla_p99_ms"`
	// MaxErrorRatePct is the error-rate objective in percent. Zero disables
	// the error breach check.
	MaxErrorRatePct float64 `json:"max_error_rate_pct"`
	Iterations      int     `json:"iterations"`
	Seed            int64   `json:"seed"`
}

// Iteration is one Monte Carlo draw. Latency values are the predicted
// distribution for the whole scenario, not a single request.
type Iteration struct {
	Index                 int      `json:"index"`
	AchievedRPS           float64  `json:"achieved_rps"`
	CapacityRPS           float64  `json:"capacity_rps"`
	Utilization           float64  `json:"utilization"`
	P50MS                 float64  `json:"p50_ms"`
	P95MS                 float64  `json:"p95_ms"`
	P99MS                 float64  `json:"p99_ms"`
	ErrorRatePct          float64  `json:"error_rate_pct"`
	P99Breach             bool     `json:"p99_breach"`
	ErrorBreach           bool     `json:"error_breach"`
	SLABreach             bool     `json:"sla_breach"`
	SaturationTimeSeconds *float64 `json:"saturation_time_seconds,omitempty"`
}

// Band summarises a value across iterations: the median (P50), the 95th
// percentile (P95) and the observed extremes. "P95 of p99" is the number to
// read when asking how bad a bad run gets.
type Band struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// Summary is the aggregate answer for a scenario.
type Summary struct {
	Iterations             int     `json:"iterations"`
	AchievedRPS            Band    `json:"achieved_rps"`
	Utilization            Band    `json:"utilization"`
	P50MS                  Band    `json:"p50_ms"`
	P95MS                  Band    `json:"p95_ms"`
	P99MS                  Band    `json:"p99_ms"`
	ErrorRatePct           Band    `json:"error_rate_pct"`
	P99BreachProbability   float64 `json:"p99_breach_probability"`
	ErrorBreachProbability float64 `json:"error_breach_probability"`
	SLAProbabilityBreach   float64 `json:"sla_breach_probability"`
	// PredictedSaturationSeconds is the median time at which the ramp crosses
	// the latency objective. Nil when no draw crossed it.
	PredictedSaturationSeconds *float64 `json:"predicted_saturation_seconds,omitempty"`
	SaturationProbability      float64  `json:"saturation_probability"`
	RiskLevel                  string   `json:"risk_level"`
}

// Result is the full simulation output: the scenario that was run, the
// aggregate, every draw, and human-readable caveats.
type Result struct {
	SchemaVersion string      `json:"schema_version"`
	Scenario      Scenario    `json:"scenario"`
	Summary       Summary     `json:"summary"`
	Iterations    []Iteration `json:"iterations"`
	Notes         []string    `json:"notes"`
}

// PresetNames lists the built-in scenarios in display order.
func PresetNames() []string {
	return []string{"best", "likely", "worst"}
}

// Preset builds one of the three built-in scenarios from a fitted model.
//
// The presets are anchored to the model's uncertainty band rather than to
// invented certainty:
//
//	best   - 50% of the LOW capacity bound, i.e. safe even if the fit
//	         overestimated capacity.
//	likely - 75% of the point estimate, the usual planning point.
//	worst  - 110% of the HIGH capacity bound, i.e. overloaded even if the fit
//	         underestimated capacity.
//
// All three use the same SLA (the fit's target p99), a 60 s horizon, a 10 s
// ramp, 200 iterations and seed 42, so a comparison isolates the load.
func Preset(name string, m Model) (Scenario, error) {
	if err := m.Validate(); err != nil {
		return Scenario{}, fmt.Errorf("twin: model is not usable: %w", err)
	}
	sla := m.Calibration.TargetP99MS
	if sla <= 0 {
		sla = m.Curve.Baseline.P99MS * 1.25
	}
	base := Scenario{
		Name:            name,
		Mode:            LoopOpen,
		DurationSeconds: 60,
		RampSeconds:     10,
		SLAP99MS:        sla,
		Iterations:      200,
		Seed:            42,
	}
	switch name {
	case "best":
		base.TargetRPS = math.Max(m.Curve.CapacityLowRPS*0.5, 0.1)
	case "likely":
		base.TargetRPS = m.Curve.CapacityRPS * 0.75
	case "worst":
		base.TargetRPS = m.Curve.CapacityHighRPS * 1.10
	default:
		return Scenario{}, fmt.Errorf("twin: unknown scenario preset %q (use %s)", name, strings.Join(PresetNames(), ", "))
	}
	return base, nil
}

// Simulate runs a seeded Monte Carlo over the fitted model.
//
// The seed argument is authoritative: it becomes Scenario.Seed in the result,
// so the artifact records exactly the stream that produced it. Iterations above
// MaxIterations are rejected and every input is validated before the first draw.
func Simulate(m Model, sc Scenario, seed int64) (Result, error) {
	if err := m.Validate(); err != nil {
		return Result{}, fmt.Errorf("twin: model is not usable: %w", err)
	}
	if err := sc.validate(); err != nil {
		return Result{}, err
	}
	sc.Seed = seed

	base := m.Curve.Baseline
	ref := m.Curve.ReferenceUtilization
	capacitySigma := math.Max(minCapacityUncertainty, m.Curve.CapacityRelativeUncertainty*capacityJitterFraction)

	// #nosec G404 G115 -- deterministic Monte Carlo for capacity planning, not
	// a security-sensitive random source; a negative seed is converted to its
	// two's-complement uint64 deliberately so every int64 seed names a stream.
	rng := rand.New(rand.NewPCG(uint64(seed), 0x9E3779B97F4A7C15))

	iterations := make([]Iteration, 0, sc.Iterations)
	p50s := make([]float64, 0, sc.Iterations)
	p95s := make([]float64, 0, sc.Iterations)
	p99s := make([]float64, 0, sc.Iterations)
	errs := make([]float64, 0, sc.Iterations)
	achieved := make([]float64, 0, sc.Iterations)
	utilizations := make([]float64, 0, sc.Iterations)
	saturationTimes := make([]float64, 0, sc.Iterations)

	var p99Breaches, errBreaches, slaBreaches int

	for i := 0; i < sc.Iterations; i++ {
		// Draw order is part of the reproducibility contract: capacity, then
		// latency noise, then error noise. Do not reorder without a schema
		// bump.
		capacityFactor := 1 + truncNormal(rng, capacitySigma)
		capacity := m.Curve.CapacityRPS * capacityFactor
		latencyNoise := math.Exp(rng.NormFloat64() * latencyJitterSigma)
		errorNoise := math.Exp(rng.NormFloat64() * errorJitterSigma)

		achievedRPS := sc.TargetRPS
		if sc.Mode == LoopClosed {
			achievedRPS = closedLoopRPS(sc.TargetUsers, capacity, base, ref, latencyNoise)
		}
		rho := 0.0
		if capacity > 0 {
			rho = achievedRPS / capacity
		}
		amp := amplification(rho, ref) * latencyNoise

		p50 := base.P50MS * amp
		p95 := base.P95MS * amp
		p99 := base.P99MS * amp

		// Errors: measured rate carried forward, then overload penalty.
		errorRate := m.Workload.ErrorRatePct * errorNoise
		if rho > overloadUtilization {
			errorRate += overloadErrorCeilingPct * (rho - overloadUtilization) / (1 - overloadUtilization)
		}
		errorRate = clamp(errorRate, 0, 100)

		saturation := saturationTime(sc, capacity, ref, base.P99MS)
		p99Breach := sc.SLAP99MS > 0 && p99 > sc.SLAP99MS
		errorBreach := sc.MaxErrorRatePct > 0 && errorRate > sc.MaxErrorRatePct
		slaBreach := p99Breach || errorBreach

		if p99Breach {
			p99Breaches++
		}
		if errorBreach {
			errBreaches++
		}
		if slaBreach {
			slaBreaches++
		}

		iterations = append(iterations, Iteration{
			Index:                 i,
			AchievedRPS:           achievedRPS,
			CapacityRPS:           capacity,
			Utilization:           rho,
			P50MS:                 p50,
			P95MS:                 p95,
			P99MS:                 p99,
			ErrorRatePct:          errorRate,
			P99Breach:             p99Breach,
			ErrorBreach:           errorBreach,
			SLABreach:             slaBreach,
			SaturationTimeSeconds: saturation,
		})
		p50s = append(p50s, p50)
		p95s = append(p95s, p95)
		p99s = append(p99s, p99)
		errs = append(errs, errorRate)
		achieved = append(achieved, achievedRPS)
		utilizations = append(utilizations, rho)
		if saturation != nil {
			saturationTimes = append(saturationTimes, *saturation)
		}
	}

	n := float64(sc.Iterations)
	summary := Summary{
		Iterations:             sc.Iterations,
		AchievedRPS:            makeBand(achieved),
		Utilization:            makeBand(utilizations),
		P50MS:                  makeBand(p50s),
		P95MS:                  makeBand(p95s),
		P99MS:                  makeBand(p99s),
		ErrorRatePct:           makeBand(errs),
		P99BreachProbability:   float64(p99Breaches) / n,
		ErrorBreachProbability: float64(errBreaches) / n,
		SLAProbabilityBreach:   float64(slaBreaches) / n,
		SaturationProbability:  float64(len(saturationTimes)) / n,
		RiskLevel:              riskLevel(float64(slaBreaches) / n),
	}
	if len(saturationTimes) > 0 {
		sorted := slices.Clone(saturationTimes)
		slices.Sort(sorted)
		median := percentileValue(sorted, 0.5)
		summary.PredictedSaturationSeconds = &median
	}

	return Result{
		SchemaVersion: SchemaVersion,
		Scenario:      sc,
		Summary:       summary,
		Iterations:    iterations,
		Notes:         simulationNotes(sc, summary),
	}, nil
}

// validate rejects scenarios that cannot be simulated. Every message names the
// offending field so a CI log is actionable without the source.
func (s Scenario) validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("twin: scenario name is required")
	}
	switch s.Mode {
	case LoopOpen:
		if !finite(s.TargetRPS) || s.TargetRPS <= 0 {
			return fmt.Errorf("twin: scenario %q: target rps must be a positive finite number, got %v", s.Name, s.TargetRPS)
		}
		if s.TargetRPS > MaxRPS {
			return fmt.Errorf("twin: scenario %q: target rps %v exceeds the %v limit", s.Name, s.TargetRPS, MaxRPS)
		}
	case LoopClosed:
		if !finite(s.TargetUsers) || s.TargetUsers <= 0 {
			return fmt.Errorf("twin: scenario %q: target users must be a positive finite number, got %v", s.Name, s.TargetUsers)
		}
		if s.TargetUsers > MaxUsers {
			return fmt.Errorf("twin: scenario %q: target users %v exceeds the %v limit", s.Name, s.TargetUsers, MaxUsers)
		}
	default:
		return fmt.Errorf("twin: scenario %q: unknown loop mode %q (use %q or %q)", s.Name, s.Mode, LoopOpen, LoopClosed)
	}
	if !finite(s.DurationSeconds) || s.DurationSeconds <= 0 {
		return fmt.Errorf("twin: scenario %q: duration must be a positive number of seconds, got %v", s.Name, s.DurationSeconds)
	}
	if s.DurationSeconds > MaxDurationSeconds {
		return fmt.Errorf("twin: scenario %q: duration %.0fs exceeds the %.0fs limit", s.Name, s.DurationSeconds, float64(MaxDurationSeconds))
	}
	if !finite(s.RampSeconds) || s.RampSeconds < 0 || s.RampSeconds > s.DurationSeconds {
		return fmt.Errorf("twin: scenario %q: ramp must be in [0, duration] seconds, got %v", s.Name, s.RampSeconds)
	}
	if !finite(s.SLAP99MS) || s.SLAP99MS < 0 {
		return fmt.Errorf("twin: scenario %q: sla p99 must be a non-negative number of milliseconds, got %v", s.Name, s.SLAP99MS)
	}
	if !finite(s.MaxErrorRatePct) || s.MaxErrorRatePct < 0 || s.MaxErrorRatePct > 100 {
		return fmt.Errorf("twin: scenario %q: max error rate must be in [0,100]%%, got %v", s.Name, s.MaxErrorRatePct)
	}
	if s.Iterations < 1 || s.Iterations > MaxIterations {
		return fmt.Errorf("twin: scenario %q: iterations must be in [1,%d], got %d", s.Name, MaxIterations, s.Iterations)
	}
	return nil
}

// amplification returns the latency multiplier at utilisation rho, anchored so
// that amp(rhoRef) = 1. See the file comment for the derivation.
func amplification(rho, ref float64) float64 {
	if !finite(rho) || rho <= ref {
		return 1
	}
	if rho >= maxUtilization {
		return maxAmplification
	}
	return math.Min((1-ref)/(1-rho), maxAmplification)
}

// closedLoopRPS solves N users against Little's law: throughput = users /
// mean-latency. Because latency itself depends on throughput, the twin iterates
// with damping until the fixed point settles. A closed loop cannot exceed
// capacity in this model: as throughput approaches capacity, latency diverges
// and the implied throughput collapses, so the iteration converges below it.
func closedLoopRPS(users, capacity float64, base Latency, ref, latencyNoise float64) float64 {
	baseAvg := math.Max(base.AvgMS, base.P50MS) * latencyNoise
	if baseAvg <= 0 || capacity <= 0 {
		return 0
	}
	rps := users * 1000 / baseAvg
	for i := 0; i < closedLoopMaxSteps; i++ {
		avg := baseAvg * amplification(rps/capacity, ref)
		if avg <= 0 || !finite(avg) {
			break
		}
		next := users * 1000 / avg
		next = closedLoopDamping*rps + (1-closedLoopDamping)*next
		if math.Abs(next-rps) <= 1e-9*math.Max(rps, 1) {
			rps = next
			break
		}
		rps = next
	}
	// The fixed point is mathematically below capacity, but rounding can put
	// it a hair above; clamp so utilisation never exceeds the pole.
	return math.Min(rps, capacity*maxUtilization)
}

// saturationTime predicts when a linear ramp crosses the latency objective.
//
// Solving amp(rho) = SLA / baselineP99 for rho gives
//
//	rho* = 1 - (1 - rhoRef) * baselineP99 / SLA
//
// and the ramp reaches rho* after ramp * rps*/target seconds. The result is
// nil when the target load never reaches rps*, when there is no ramp, or when
// there is no latency objective.
func saturationTime(sc Scenario, capacity, ref, baselineP99 float64) *float64 {
	if sc.Mode != LoopOpen || sc.RampSeconds <= 0 || sc.SLAP99MS <= 0 || sc.TargetRPS <= 0 {
		return nil
	}
	rhoStar := 1 - (1-ref)*baselineP99/sc.SLAP99MS
	rhoStar = clamp(rhoStar, ref, maxUtilization)
	rpsStar := rhoStar * capacity
	if sc.TargetRPS <= rpsStar {
		return nil
	}
	t := sc.RampSeconds * rpsStar / sc.TargetRPS
	return &t
}

// truncNormal draws a standard normal and clamps it to +/-3 sigma so one
// unlucky draw cannot produce a negative capacity.
func truncNormal(rng *rand.Rand, sigma float64) float64 {
	z := rng.NormFloat64()
	if z < -3 {
		z = -3
	}
	if z > 3 {
		z = 3
	}
	return z * sigma
}

// makeBand computes the band summary of values. The input is copied before
// sorting so callers retain their slice order.
func makeBand(values []float64) Band {
	if len(values) == 0 {
		return Band{}
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	return Band{
		P50: percentileValue(sorted, 0.5),
		P95: percentileValue(sorted, 0.95),
		Min: sorted[0],
		Max: sorted[len(sorted)-1],
	}
}

// percentileValue is the nearest-rank quantile of an ascending slice: the
// answer is always an observed value, never an interpolation. This mirrors the
// definition Sift uses in its reports.
func percentileValue(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[n-1]
	}
	rank := int(math.Ceil(p * float64(n)))
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

// riskLevel maps a breach probability to a vocabulary that does not overclaim.
func riskLevel(breach float64) string {
	switch {
	case breach < 0.05:
		return RiskLow
	case breach < 0.5:
		return RiskElevated
	default:
		return RiskHigh
	}
}

// simulationNotes returns deterministic, scenario-specific caveats. They are
// part of the artifact so a reader who only sees the JSON still sees the
// assumptions.
func simulationNotes(sc Scenario, s Summary) []string {
	notes := []string{
		"results are model-based estimates, not guarantees: the twin extrapolates from one measured operating point",
	}
	if sc.SLAP99MS <= 0 && sc.MaxErrorRatePct <= 0 {
		notes = append(notes, "no SLA thresholds were supplied; breach probabilities are zero by definition")
	}
	if s.Utilization.P95 >= 1 {
		notes = append(notes, fmt.Sprintf("the requested load reaches or exceeds the estimated capacity in at least 5%% of draws (p95 utilisation %.2f); latency amplification is capped at %.0fx and the true latency at that load is likely worse", s.Utilization.P95, maxAmplification))
	}
	if sc.Mode == LoopClosed {
		notes = append(notes, "closed-loop scenario: achieved throughput is solved from the user count via Little's law, so adding users past capacity yields no extra throughput")
	}
	if s.SaturationProbability > 0 {
		notes = append(notes, fmt.Sprintf("the ramp crosses the latency objective in %.1f%% of draws; the reported saturation time is the median of those draws", s.SaturationProbability*100))
	}
	return notes
}
