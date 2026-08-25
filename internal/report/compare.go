package report

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// CompareResult holds the diff between two reports.
type CompareResult struct {
	BaselineName string
	CurrentName  string

	// Request comparison
	RequestDiff      int64
	RequestChangePct float64

	// Latency comparison (ms deltas — positive = current is slower)
	P50Diff float64
	P95Diff float64
	P99Diff float64
	AvgDiff float64

	// Error comparison
	ErrorDiff      int64
	ErrorChangePct float64

	// RPS comparison
	RPSDiff      float64
	RPSChangePct float64

	// Verdict
	Regression    bool
	RegressionPct float64
	Grade         string

	// Stored for rendering
	baselineReq uint64
	currentReq  uint64
	baselineAvg time.Duration
	currentAvg  time.Duration
	baselineP99 time.Duration
	currentP99  time.Duration
	baselineErr float64
	currentErr  float64
	baselineRPS float64
	currentRPS  float64
}

// Compare evaluates current results against a baseline report.
func Compare(current, baseline *Report) *CompareResult {
	cr := &CompareResult{
		BaselineName: baseline.Name,
		CurrentName:  current.Name,
	}

	cr.RequestDiff = int64(current.TotalRequests) - int64(baseline.TotalRequests)
	cr.RequestChangePct = pctChange(float64(current.TotalRequests), float64(baseline.TotalRequests))

	cr.P50Diff = msOf(current.Overall.P50) - msOf(baseline.Overall.P50)
	cr.P95Diff = msOf(current.Overall.P95) - msOf(baseline.Overall.P95)
	cr.P99Diff = msOf(current.Overall.P99) - msOf(baseline.Overall.P99)
	cr.AvgDiff = msOf(current.Overall.Avg) - msOf(baseline.Overall.Avg)

	cr.ErrorDiff = int64(current.TotalErrors) - int64(baseline.TotalErrors)
	cr.ErrorChangePct = pctChange(float64(current.TotalErrors), float64(baseline.TotalErrors))

	cr.RPSDiff = current.RPS - baseline.RPS
	cr.RPSChangePct = pctChange(current.RPS, baseline.RPS)

	cr.baselineReq = baseline.TotalRequests
	cr.currentReq = current.TotalRequests
	cr.baselineAvg = baseline.Overall.Avg
	cr.currentAvg = current.Overall.Avg
	cr.baselineP99 = baseline.Overall.P99
	cr.currentP99 = current.Overall.P99
	cr.baselineErr = baseline.ErrorRatePct
	cr.currentErr = current.ErrorRatePct
	cr.baselineRPS = baseline.RPS
	cr.currentRPS = current.RPS

	// Worst regression: latency positive = slower, RPS negative = less throughput, errors positive = more.
	worstPct := 0.0
	baseP50 := msOf(baseline.Overall.P50)
	baseP95 := msOf(baseline.Overall.P95)
	baseP99 := msOf(baseline.Overall.P99)
	baseAvg := msOf(baseline.Overall.Avg)
	candidates := []float64{}
	if baseP50 > 0 {
		candidates = append(candidates, cr.P50Diff/baseP50*100)
	}
	if baseP95 > 0 {
		candidates = append(candidates, cr.P95Diff/baseP95*100)
	}
	if baseP99 > 0 {
		candidates = append(candidates, cr.P99Diff/baseP99*100)
	}
	if baseAvg > 0 {
		candidates = append(candidates, cr.AvgDiff/baseAvg*100)
	}
	if baseline.RPS > 0 {
		candidates = append(candidates, -cr.RPSChangePct)
	}
	if baseline.TotalErrors > 0 {
		candidates = append(candidates, cr.ErrorChangePct)
	}
	for _, pct := range candidates {
		if pct > worstPct {
			worstPct = pct
		}
	}

	cr.RegressionPct = worstPct
	cr.Regression = worstPct > 0
	cr.Grade = gradeForRegression(worstPct)
	return cr
}

// Render produces a human-readable comparison table string.
func (cr *CompareResult) Render() string {
	var b strings.Builder
	sep := strings.Repeat("═", 57)
	line := strings.Repeat("─", 57)

	fmt.Fprintf(&b, "\n%s\n", sep)
	fmt.Fprintf(&b, "  BASELINE COMPARISON: %s vs %s\n", cr.BaselineName, cr.CurrentName)
	fmt.Fprintf(&b, "%s\n", sep)
	fmt.Fprintf(&b, "  %-14s %-12s %-12s %-11s %s\n", "Metric", "Baseline", "Current", "Change", "Grade")
	fmt.Fprintf(&b, "  %s\n", line)

	b.WriteString(cr.renderRow("Requests", formatCount(cr.baselineReq), formatCount(cr.currentReq), cr.RequestChangePct))
	b.WriteString(cr.renderRow("Avg Latency", cr.baselineAvg.Round(time.Millisecond).String(), cr.currentAvg.Round(time.Millisecond).String(), cr.AvgDiff/max1(msOf(cr.baselineAvg), 0.001)*100))
	b.WriteString(cr.renderRow("P99 Latency", cr.baselineP99.Round(time.Millisecond).String(), cr.currentP99.Round(time.Millisecond).String(), cr.P99Diff/max1(msOf(cr.baselineP99), 0.001)*100))
	b.WriteString(cr.renderRow("Error Rate", fmt.Sprintf("%.2f%%", cr.baselineErr), fmt.Sprintf("%.2f%%", cr.currentErr), cr.ErrorChangePct))
	b.WriteString(cr.renderRow("RPS", formatRPS(cr.baselineRPS), formatRPS(cr.currentRPS), cr.RPSChangePct))

	fmt.Fprintf(&b, "  %s\n", line)
	if cr.Regression {
		fmt.Fprintf(&b, "  VERDICT: REGRESSED — worst metric %.1f%% beyond baseline\n", cr.RegressionPct)
	} else {
		fmt.Fprintf(&b, "  VERDICT: IMPROVED — All metrics within threshold\n")
	}
	fmt.Fprintf(&b, "%s\n\n", sep)
	return b.String()
}

func (cr *CompareResult) renderRow(metric, baseVal, curVal string, changePct float64) string {
	pctStr := fmt.Sprintf("%+.1f%%", changePct)
	g := gradeForChangePct(math.Abs(changePct))
	return fmt.Sprintf("  %-14s %-12s %-12s %-11s %s\n", metric, baseVal, curVal, pctStr, g)
}

// gradeForRegression assigns A-F based on how bad the worst regression is.
func gradeForRegression(worstPct float64) string {
	switch {
	case worstPct <= 5:
		return "A"
	case worstPct <= 10:
		return "B"
	case worstPct <= 20:
		return "C"
	case worstPct <= 30:
		return "D"
	default:
		return "F"
	}
}

func gradeForChangePct(absPct float64) string {
	return gradeForRegression(absPct)
}

func msOf(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func pctChange(current, baseline float64) float64 {
	if baseline == 0 {
		return 0
	}
	return (current - baseline) / baseline * 100
}

func max1(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
