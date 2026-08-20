package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"stress-strike/internal/metrics"
)

func StartLive(t *metrics.Telemetry, total time.Duration, out io.Writer) func() {
	if !isTerminal(out) {
		return func() {}
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				fmt.Fprintf(out, "\r%s\r", strings.Repeat(" ", 120))
				return
			case <-ticker.C:
				snap := t.Overall.Latency.Snapshot()
				errs := t.TotalErrors()
				reqs := t.TotalRequests()
				errPct := 0.0
				if reqs > 0 {
					errPct = float64(errs) / float64(reqs) * 100
				}

				elapsed := t.Elapsed()
				elapsedSec := elapsed.Seconds()
				totalSec := total.Seconds()
				pct := 0.0
				if totalSec > 0 {
					pct = elapsedSec / totalSec * 100
					if pct > 100 {
						pct = 100
					}
				}

				bar := renderProgressBar(pct, 20)
				rc := rateColor(errPct)

				// Build the line with color segments
				var line strings.Builder
				line.WriteString("\r")
				line.WriteString(colorize(rc, true, bar))
				line.WriteString(fmt.Sprintf(" %5.1f%% ", pct))
				line.WriteString(colorize(colorCyan, true,
					fmt.Sprintf("[%s/%s]", formatDuration(elapsed), formatDuration(total))))
				line.WriteString(" ")
				line.WriteString(fmt.Sprintf("rps=%s ", formatRPS(t.RPS())))
				line.WriteString(fmt.Sprintf("active=%d ", t.ActiveUsers.Load()))
				line.WriteString(fmt.Sprintf("req=%s ", formatCount(reqs)))
				line.WriteString(colorize(rc, true,
					fmt.Sprintf("err=%d (%.1f%%)", errs, errPct)))
				line.WriteString(fmt.Sprintf(" p50=%s p95=%s p99=%s",
					snap.Percentile(0.50), snap.Percentile(0.95), snap.Percentile(0.99)))

				fmt.Fprint(out, line.String())
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// renderProgressBar renders a text progress bar like [████████░░░░░░░░░░░░]
func renderProgressBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < width; i++ {
		if i < filled {
			b.WriteString("█")
		} else {
			b.WriteString("░")
		}
	}
	b.WriteString("]")
	return b.String()
}

// formatCount formats a uint64 with k/m suffixes for readability.
func formatCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fm", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// formatRPS formats RPS with k suffix.
func formatRPS(rps float64) string {
	if rps >= 1_000 {
		return fmt.Sprintf("%.1fk", rps/1_000)
	}
	return fmt.Sprintf("%.0f", rps)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	m := d % time.Hour / time.Minute
	s := d % time.Minute / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	return fmt.Sprintf("%dm%ds", m, s)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
