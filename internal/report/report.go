package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"stress-strike/internal/config"
	"stress-strike/internal/metrics"
)

type StepReport struct {
	Name       string            `json:"name"`
	Requests   uint64            `json:"requests"`
	Errors     uint64            `json:"errors"`
	Status     map[int]uint64    `json:"status_codes"`
	ErrorTypes map[string]uint64 `json:"error_types"`
	Min        time.Duration     `json:"min"`
	Avg        time.Duration     `json:"avg"`
	Max        time.Duration     `json:"max"`
	P50        time.Duration     `json:"p50"`
	P95        time.Duration     `json:"p95"`
	P99        time.Duration     `json:"p99"`
}

type Report struct {
	Name          string            `json:"name"`
	BaseURL       string            `json:"base_url"`
	LoadProfile   string            `json:"load_profile"`
	StartedAt     time.Time         `json:"started_at"`
	EndedAt       time.Time         `json:"ended_at"`
	Duration      time.Duration     `json:"duration"`
	ActiveUsers   int64             `json:"active_users"`
	TotalRequests uint64            `json:"total_requests"`
	TotalErrors   uint64            `json:"total_errors"`
	ErrorRatePct  float64           `json:"error_rate_pct"`
	RPS           float64           `json:"rps"`
	Status        map[int]uint64    `json:"status_codes"`
	Errors        map[string]uint64 `json:"errors"`
	Overall       StepReport        `json:"overall"`
	Steps         []StepReport      `json:"steps"`
}

func fromStepStats(name string, s *metrics.StepStats) StepReport {
	snap := s.Latency.Snapshot()
	return StepReport{
		Name:       name,
		Requests:   snap.Count,
		Errors:     s.ErrorCount(),
		Status:     s.StatusCodes(),
		ErrorTypes: s.Errors(),
		Min:        snap.Min,
		Avg:        snap.Average,
		Max:        snap.Max,
		P50:        snap.Percentile(0.50),
		P95:        snap.Percentile(0.95),
		P99:        snap.Percentile(0.99),
	}
}

func Build(t *metrics.Telemetry, scenario *config.Scenario) Report {
	reqs := t.TotalRequests()
	errs := t.TotalErrors()
	errPct := 0.0
	if reqs > 0 {
		errPct = float64(errs) / float64(reqs) * 100
	}
	r := Report{
		Name:          scenario.Name,
		BaseURL:       target(scenario),
		LoadProfile:   scenario.Profile.Type,
		StartedAt:     t.Start,
		EndedAt:       t.End,
		Duration:      t.Elapsed(),
		ActiveUsers:   t.PeakUsers.Load(),
		TotalRequests: reqs,
		TotalErrors:   errs,
		ErrorRatePct:  errPct,
		RPS:           t.RPS(),
		Status:        t.StatusCodes(),
		Errors:        t.Errors(),
		Overall:       fromStepStats("overall", t.Overall),
	}
	for _, s := range t.Steps {
		r.Steps = append(r.Steps, fromStepStats(s.Name, s))
	}
	return r
}

// Render writes a premium, colorized report to w.
// Colors are only used when w is a terminal (detected via isTerminal).
func (r Report) Render(w io.Writer) {
	c := isTerminal(w) // color enabled?
	rc := rateColor(r.ErrorRatePct)
	health, hColor := healthLabel(r.ErrorRatePct)

	sep := colorize(colorBold, c, "═══════════════════════════════════════════════════════════════════════════════════════")

	// ── Header ──────────────────────────────────────────────────────────
	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	title := colorize(colorBold, c, fmt.Sprintf("  STRESS TEST REPORT: %s", r.Name))
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w)

	// ── Target & Config ─────────────────────────────────────────────────
	fmt.Fprintf(w, "  %s\n", colorize(colorCyan, c, fmt.Sprintf("Target:     %s", r.BaseURL)))
	fmt.Fprintf(w, "  %s\n", colorize(colorCyan, c, fmt.Sprintf("Profile:    %s | Peak users: %d", r.LoadProfile, r.ActiveUsers)))
	fmt.Fprintf(w, "  %s\n", colorize(colorCyan, c, fmt.Sprintf("Duration:   %s | Started: %s",
		r.Duration.Round(time.Millisecond), r.StartedAt.Format(time.RFC3339))))
	fmt.Fprintln(w)

	// ── Overall ─────────────────────────────────────────────────────────
	overall := r.Overall
	fmt.Fprintln(w, colorize(colorBold, c, "  ┌──────────────────────────────────────────────────────────────┐"))
	fmt.Fprintf(w, "  │  %-58s │\n", colorize(colorBold, c, "OVERALL RESULTS"))
	fmt.Fprintln(w, colorize(colorBold, c, "  ├──────────────────────────────────────────────────────────────┤"))

	reqLine := fmt.Sprintf("  Requests: %s | Errors: %s | RPS: %s",
		formatCount(r.TotalRequests),
		colorize(rc, c, fmt.Sprintf("%s (%.2f%%)", formatCount(r.TotalErrors), r.ErrorRatePct)),
		formatRPS(r.RPS))
	fmt.Fprintf(w, "  │  %-58s │\n", reqLine)

	latLine := fmt.Sprintf("  Latency:  avg=%s  p50=%s  p95=%s  p99=%s  max=%s",
		overall.Avg, overall.P50, overall.P95, overall.P99, overall.Max)
	fmt.Fprintf(w, "  │  %-58s │\n", latLine)

	healthLine := fmt.Sprintf("  Server health: %s", colorize(hColor, c, health))
	fmt.Fprintf(w, "  │  %-58s │\n", healthLine)

	fmt.Fprintln(w, colorize(colorBold, c, "  └──────────────────────────────────────────────────────────────┘"))
	fmt.Fprintln(w)

	// ── Steps table ─────────────────────────────────────────────────────
	if len(r.Steps) > 0 {
		fmt.Fprintln(w, colorize(colorBold, c, "  STEP BREAKDOWN"))
		fmt.Fprintln(w, colorize(colorBold, c, "  ──────────────────────────────────────────────────────────────"))

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		header := colorize(colorBold, c, "STEP\tREQUESTS\tERRORS\tAVG\tP50\tP95\tP99\tMAX")
		fmt.Fprintln(tw, header)
		for _, s := range r.Steps {
			stepErrPct := 0.0
			if s.Requests > 0 {
				stepErrPct = float64(s.Errors) / float64(s.Requests) * 100
			}
			stepRC := rateColor(stepErrPct)
			errDisplay := colorize(stepRC, c, fmt.Sprintf("%d", s.Errors))
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				s.Name, formatCount(s.Requests), errDisplay, s.Avg, s.P50, s.P95, s.P99, s.Max)
		}
		tw.Flush()
		fmt.Fprintln(w)
	}

	// ── Status codes ────────────────────────────────────────────────────
	if len(r.Status) > 0 {
		fmt.Fprintln(w, colorize(colorBold, c, "  STATUS CODES"))
		fmt.Fprintln(w, colorize(colorBold, c, "  ──────────────────────────────────────────────────────────────"))
		for _, code := range metrics.SortedStatusCodes(r.Status) {
			sc := statusColor(code)
			label := colorize(sc, c, fmt.Sprintf("%d", code))
			fmt.Fprintf(w, "    %s  %s\n", label, formatCount(r.Status[code]))
		}
		fmt.Fprintln(w)
	}

	// ── Errors ──────────────────────────────────────────────────────────
	if len(r.Errors) > 0 {
		fmt.Fprintln(w, colorize(colorBold, c, "  ERRORS"))
		fmt.Fprintln(w, colorize(colorBold, c, "  ──────────────────────────────────────────────────────────────"))
		for _, name := range metrics.SortedErrors(r.Errors) {
			fmt.Fprintf(w, "    %s  %s\n",
				colorize(colorRed, c, name), formatCount(r.Errors[name]))
		}
		fmt.Fprintln(w)
	}

	// ── Summary ─────────────────────────────────────────────────────────
	fmt.Fprintln(w, colorize(colorBold, c, "  SUMMARY"))
	fmt.Fprintln(w, colorize(colorBold, c, "  ──────────────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "    Total requests:  %s\n", formatCount(r.TotalRequests))
	fmt.Fprintf(w, "    Total errors:    %s (%.2f%%)\n", formatCount(r.TotalErrors), r.ErrorRatePct)
	fmt.Fprintf(w, "    Requests/sec:    %s\n", formatRPS(r.RPS))
	fmt.Fprintf(w, "    Latency range:   %s — %s\n", overall.Min, overall.Max)
	fmt.Fprintf(w, "    Duration:        %s\n", r.Duration.Round(time.Millisecond))
	fmt.Fprintln(w)

	fmt.Fprintln(w, sep)
	verdict := colorize(hColor, c, fmt.Sprintf("  VERDICT: %s", health))
	fmt.Fprintln(w, verdict)
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w)
}

func (r Report) SaveJSON(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := uniquePath(dir, reportFilename(r.Name, "json"))
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (r Report) SaveTXT(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := uniquePath(dir, reportFilename(r.Name, "txt"))
	var sb strings.Builder
	r.Render(&sb)
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func uniquePath(dir, filename string) string {
	path := filepath.Join(dir, filename)
	for i := 1; ; i++ {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return path
		}
		ext := filepath.Ext(filename)
		base := strings.TrimSuffix(filename, ext)
		path = filepath.Join(dir, fmt.Sprintf("%s-%d%s", base, i, ext))
	}
}

func target(scenario *config.Scenario) string {
	if scenario.BaseURL != "" {
		return scenario.BaseURL
	}
	if len(scenario.Steps) > 0 {
		return scenario.Steps[0].URL
	}
	return "n/a"
}

func reportFilename(name, ext string) string {
	safe := sanitizeFilename(name)
	if safe == "" {
		safe = "report"
	}
	if len(safe) > 64 {
		safe = safe[:64]
	}
	return fmt.Sprintf("%s_%s.%s", safe, time.Now().Format("20060102-150405"), ext)
}

var filenameSanitizer = strings.NewReplacer(
	"..", "_",
	"/", "_",
	"\\", "_",
	":", "_",
	" ", "_",
	"%", "_",
	"~", "_",
	"*", "_",
	"?", "_",
	"'", "_",
	`"`, "_",
	"<", "_",
	">", "_",
	"&", "_",
	"|", "_",
	"\x00", "_",
	"\n", "_",
	"\r", "_",
	"\t", "_",
)

func sanitizeFilename(name string) string {
	cleaned := filenameSanitizer.Replace(name)
	var b strings.Builder
	for _, r := range cleaned {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
