package report

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
)

// liveLines tracks how many terminal rows the panel occupies so it can be
// redrawn in place with ANSI cursor movement.
const liveLines = 3

// sparklineChars renders RPS history; ordered from lowest to highest bar.
const sparklineChars = "▁▁▂▂▃▃▄▄▅▅▆▆▇▇█"

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
		var rpsHistory []float64
		first := true
		for {
			select {
			case <-stop:
				fmt.Fprintf(out, "\r\x1b[%dA\x1b[J", liveLines)
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

				rps := t.RPS()
				rpsHistory = append(rpsHistory, rps)
				const maxHistory = 24
				if len(rpsHistory) > maxHistory {
					rpsHistory = rpsHistory[len(rpsHistory)-maxHistory:]
				}

				bar := renderProgressBar(pct, 20)
				rc := rateColor(errPct)

				// Redraw the panel in place: move cursor to its top-left and
				// clear everything below before painting fresh content.
				if first {
					first = false
				} else {
					fmt.Fprintf(out, "\r\x1b[%dA\x1b[J", liveLines)
				}

				// Line 1 — headline progress.
				fmt.Fprint(out, "\r")
				fmt.Fprint(out, colorize(colorCyan, true, "⚡ "))
				fmt.Fprint(out, colorize(rc, true, bar))
				fmt.Fprintf(out, " %5.1f%% ", pct)
				fmt.Fprintln(out, colorize(colorCyan, true,
					fmt.Sprintf("[%s/%s]", formatDuration(elapsed), formatDuration(total))))

				// Line 2 — throughput and errors, with an RPS sparkline.
				fmt.Fprint(out, "\r")
				fmt.Fprintf(out, "  rps=%s ", colorize(colorBold, true, formatRPS(rps)))
				fmt.Fprintf(out, "%s │ ", sparkline(rpsHistory))
				fmt.Fprintf(out, "req=%s ", formatCount(reqs))
				fmt.Fprintln(out, colorize(rc, true,
					fmt.Sprintf("err=%d (%.2f%%)", errs, errPct)))

				// Line 3 — latency percentiles and active users.
				fmt.Fprint(out, "\r")
				fmt.Fprintf(out, "  p50=%s p95=%s p99=%s",
					snap.Percentile(0.50), snap.Percentile(0.95), snap.Percentile(0.99))
				fmt.Fprintln(out, colorize(colorCyan, true,
					fmt.Sprintf(" │ active=%d", t.ActiveUsers.Load())))
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// sparkline renders a compact bar-chart of recent throughput samples using
// block glyphs; an empty history yields a placeholder dash.
func sparkline(history []float64) string {
	if len(history) == 0 {
		return "—"
	}
	minV, maxV := math.Inf(1), math.Inf(-1)
	for _, v := range history {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	span := maxV - minV
	if span <= 0 {
		span = 1
	}
	var b strings.Builder
	for _, v := range history {
		idx := int((v - minV) / span * float64(len(sparklineChars)-1))
		b.WriteByte(sparklineChars[idx])
	}
	return b.String()
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
