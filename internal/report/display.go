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
				fmt.Fprintf(out, "\r%s\r", strings.Repeat(" ", 80))
				return
			case <-ticker.C:
				snap := t.Overall.Latency.Snapshot()
				errs := t.TotalErrors()
				reqs := t.TotalRequests()
				errPct := 0.0
				if reqs > 0 {
					errPct = float64(errs) / float64(reqs) * 100
				}
				line := fmt.Sprintf(
					"\r[%s/%s] rps=%.0f active=%d req=%d err=%d (%.1f%%) p50=%s p95=%s p99=%s",
					formatDuration(t.Elapsed()), formatDuration(total),
					t.RPS(), t.ActiveUsers.Load(), reqs, errs, errPct,
					snap.Percentile(0.50), snap.Percentile(0.95), snap.Percentile(0.99),
				)
				fmt.Fprint(out, line)
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
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
