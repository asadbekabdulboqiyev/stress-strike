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


