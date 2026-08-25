package report

import (
	"fmt"

	"stress-strike/internal/config"
)

// SLAResult is the outcome of a single service-level check.
type SLAResult struct {
	Metric string `json:"metric"`
	Target string `json:"target"`
	Actual string `json:"actual"`
	Pass   bool   `json:"pass"`
}

// EvaluateSLA checks the run against configured thresholds and returns one
// result per non-zero threshold, in a stable display order.
func EvaluateSLA(r *Report, sla *config.SLA) []SLAResult {
	if sla == nil || sla.Empty() {
		return nil
	}
	var out []SLAResult

	if sla.MaxP99Ms > 0 {
		limit := msDuration(sla.MaxP99Ms)
		out = append(out, SLAResult{
			Metric: "p99 latency",
			Target: fmt.Sprintf("<= %s", limit),
			Actual: r.Overall.P99.String(),
			Pass:   r.Overall.P99 <= limit,
		})
	}
	if sla.MaxAvgMs > 0 {
		limit := msDuration(sla.MaxAvgMs)
		out = append(out, SLAResult{
			Metric: "avg latency",
			Target: fmt.Sprintf("<= %s", limit),
			Actual: r.Overall.Avg.String(),
			Pass:   r.Overall.Avg <= limit,
		})
	}
	if sla.MaxErrorRatePct > 0 {
		out = append(out, SLAResult{
			Metric: "error rate",
			Target: fmt.Sprintf("<= %.2f%%", sla.MaxErrorRatePct),
			Actual: fmt.Sprintf("%.2f%%", r.ErrorRatePct),
			Pass:   r.ErrorRatePct <= sla.MaxErrorRatePct,
		})
	}
	if sla.MinRPS > 0 {
		out = append(out, SLAResult{
			Metric: "throughput",
			Target: fmt.Sprintf(">= %.1f rps", sla.MinRPS),
			Actual: formatRPS(r.RPS) + " rps",
			Pass:   r.RPS >= sla.MinRPS,
		})
	}
	return out
}

// SLAPassed reports whether every evaluated check passed.
func SLAPassed(results []SLAResult) bool {
	for _, res := range results {
		if !res.Pass {
			return false
		}
	}
	return true
}

// CompareRow is one line of the baseline comparison table.
type CompareRow struct {
	Metric   string `json:"metric"`
	Baseline string `json:"baseline"`
	Current  string `json:"current"`
	Delta    string `json:"delta"`
	Status   string `json:"status"` // improved | ok | regressed
}

// Compare evaluates current results against a baseline report. Rows whose
// degradation exceeds regressPct percent (or an error-rate increase beyond it,
// in percentage points) are flagged as regressed.
func Compare(current, baseline *Report, regressPct float64) ([]CompareRow, bool) {
	rows := make([]CompareRow, 0, 6)
	regressed := false

	pctDelta := func(cur, base float64) float64 {
		if base == 0 {
			return 0
		}
		return (cur - base) / base * 100
	}

	addDur := func(metric string, cur, base int64) {
		delta := pctDelta(float64(cur), float64(base))
		status := "ok"
		switch {
		case delta > regressPct:
			status = "regressed"
			regressed = true
		case delta < -regressPct:
			status = "improved"
		}
		rows = append(rows, CompareRow{
			Metric: metric, Baseline: timeMillis(base), Current: timeMillis(cur),
			Delta: fmt.Sprintf("%+.1f%%", delta), Status: status,
		})
	}

	o, b := current.Overall, baseline.Overall
	addDur("p50", o.P50.Milliseconds(), b.P50.Milliseconds())
	addDur("p95", o.P95.Milliseconds(), b.P95.Milliseconds())
	addDur("p99", o.P99.Milliseconds(), b.P99.Milliseconds())

	// Throughput: higher is better.
	rpsDelta := pctDelta(current.RPS, baseline.RPS)
	rpsStatus := "ok"
	switch {
	case -rpsDelta > regressPct:
		rpsStatus = "regressed"
		regressed = true
	case rpsDelta > regressPct:
		rpsStatus = "improved"
	}
	rows = append(rows, CompareRow{
		Metric: "rps", Baseline: formatRPS(baseline.RPS), Current: formatRPS(current.RPS),
		Delta: fmt.Sprintf("%+.1f%%", rpsDelta), Status: rpsStatus,
	})

	// Error rate: absolute percentage-point movement; any increase beyond the
	// threshold regresses.
	errDelta := current.ErrorRatePct - baseline.ErrorRatePct
	errStatus := "ok"
	switch {
	case errDelta > regressPct:
		errStatus = "regressed"
		regressed = true
	case errDelta < -regressPct:
		errStatus = "improved"
	}
	rows = append(rows, CompareRow{
		Metric: "error_rate", Baseline: fmt.Sprintf("%.2f%%", baseline.ErrorRatePct),
		Current: fmt.Sprintf("%.2f%%", current.ErrorRatePct),
		Delta:   fmt.Sprintf("%+.2fpp", errDelta), Status: errStatus,
	})

	return rows, regressed
}
