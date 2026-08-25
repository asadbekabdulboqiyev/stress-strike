package engine

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	progressBarWidth = 30
	boxWidth         = 60
	progressBoxLines = 5
)

const (
	pReset  = "\x1b[0m"
	pBold   = "\x1b[1m"
	pRed    = "\x1b[31m"
	pGreen  = "\x1b[32m"
	pYellow = "\x1b[33m"
	pCyan   = "\x1b[36m"
)

type ProgressTracker struct {
	startTime  time.Time
	duration   time.Duration
	totalUsers int

	totalReqs   atomic.Uint64
	totalErrors atomic.Uint64
	latencySum  atomic.Uint64
	latencyMax  atomic.Uint64
	snapCount   atomic.Uint64

	mu             sync.Mutex
	lastRenderReqs uint64
	lastRenderErrs uint64
	lastRenderTime time.Time

	isTerminal bool
	out        io.Writer
	quiet      bool
	first      bool
	stop       chan struct{}
	done       chan struct{}
	finishOnce sync.Once
}

func NewProgressTracker(duration time.Duration, users int) *ProgressTracker {
	return newProgressTracker(duration, users, os.Stderr)
}

func newProgressTracker(duration time.Duration, users int, out io.Writer) *ProgressTracker {
	pt := &ProgressTracker{
		startTime:  time.Now(),
		duration:   duration,
		totalUsers: users,
		out:        out,
		first:      true,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	pt.isTerminal = isTerminalFile(out)
	if pt.isTerminal {
		go pt.loop()
	}
	return pt
}

func (pt *ProgressTracker) Update(totalReqs, totalErrors uint64, latency time.Duration) {
	pt.totalReqs.Store(totalReqs)
	pt.totalErrors.Store(totalErrors)

	nsec := uint64(latency.Nanoseconds())
	for {
		old := pt.latencySum.Load()
		if pt.latencySum.CompareAndSwap(old, old+nsec) {
			break
		}
	}

	nsMax := uint64(latency.Nanoseconds())
	for {
		old := pt.latencyMax.Load()
		if nsMax <= old || pt.latencyMax.CompareAndSwap(old, nsMax) {
			break
		}
	}

	pt.snapCount.Add(1)
}

func (pt *ProgressTracker) Finish() {
	pt.finishOnce.Do(func() {
		if !pt.isTerminal {
			return
		}
		close(pt.stop)
		<-pt.done
		if !pt.quiet {
			pt.renderFinal()
			fmt.Fprintln(pt.out)
		}
	})
}

func (pt *ProgressTracker) SetQuiet(q bool) {
	pt.quiet = q
}

func (pt *ProgressTracker) loop() {
	defer close(pt.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-pt.stop:
			return
		case <-ticker.C:
			if !pt.quiet {
				pt.render()
			}
		}
	}
}

func (pt *ProgressTracker) render() {
	if pt.quiet {
		return
	}
	reqs := pt.totalReqs.Load()
	errs := pt.totalErrors.Load()
	sumNs := pt.latencySum.Load()
	maxNs := pt.latencyMax.Load()
	count := pt.snapCount.Load()

	now := time.Now()
	elapsed := now.Sub(pt.startTime)
	totalSec := pt.duration.Seconds()
	elapsedSec := elapsed.Seconds()

	pct := 0.0
	if totalSec > 0 {
		pct = elapsedSec / totalSec * 100
		if pct > 100 {
			pct = 100
		}
	}

	pt.mu.Lock()
	lastReqs := pt.lastRenderReqs
	lastTime := pt.lastRenderTime
	pt.lastRenderReqs = reqs
	pt.lastRenderErrs = errs
	pt.lastRenderTime = now
	pt.mu.Unlock()

	recentRPS := 0.0
	if !lastTime.IsZero() {
		dt := now.Sub(lastTime).Seconds()
		if dt > 0 {
			recentRPS = float64(reqs-lastReqs) / dt
		}
	} else if elapsedSec > 0 {
		recentRPS = float64(reqs) / elapsedSec
	}

	avgLat := time.Duration(0)
	if count > 0 {
		avgLat = time.Duration(sumNs / count)
	}
	maxLat := time.Duration(maxNs)

	errPct := 0.0
	if reqs > 0 {
		errPct = float64(errs) / float64(reqs) * 100
	}

	remaining := pt.duration - elapsed
	if remaining < 0 {
		remaining = 0
	}

	c := pt.isTerminal

	if !pt.first {
		fmt.Fprintf(pt.out, "\r\x1b[%dA\x1b[J", progressBoxLines)
	}
	pt.first = false

	fmt.Fprintln(pt.out, boxTop())

	barStr := ptBar(pct, c)
	line1 := fmt.Sprintf("  %s  %s%%  |  %s / %s",
		barStr,
		fmt.Sprintf("%.0f", pct),
		ptFmtDur(elapsed),
		ptFmtDur(pt.duration),
	)
	fmt.Fprintln(pt.out, ptBoxLine(line1))

	errStr := ptFmtErr(errPct, c)
	line2 := fmt.Sprintf("  RPS: %s  |  Avg: %s  |  Max: %s  |  Err: %s",
		ptFmtRPS(recentRPS),
		ptFmtDur(avgLat),
		ptFmtDur(maxLat),
		errStr,
	)
	fmt.Fprintln(pt.out, ptBoxLine(line2))

	line3 := fmt.Sprintf("  Active: %d users  |  Requests: %s  |  Elapsed: %s",
		pt.totalUsers,
		ptFmtCount(reqs),
		ptFmtDur(elapsed),
	)
	fmt.Fprintln(pt.out, ptBoxLine(line3))

	fmt.Fprintln(pt.out, boxBottom())
}

func (pt *ProgressTracker) renderFinal() {
	reqs := pt.totalReqs.Load()
	errs := pt.totalErrors.Load()
	sumNs := pt.latencySum.Load()
	maxNs := pt.latencyMax.Load()
	count := pt.snapCount.Load()

	elapsed := time.Since(pt.startTime)
	elapsedSec := elapsed.Seconds()

	avgLat := time.Duration(0)
	if count > 0 {
		avgLat = time.Duration(sumNs / count)
	}
	maxLat := time.Duration(maxNs)

	errPct := 0.0
	if reqs > 0 {
		errPct = float64(errs) / float64(reqs) * 100
	}

	overallRPS := 0.0
	if elapsedSec > 0 {
		overallRPS = float64(reqs) / elapsedSec
	}

	c := pt.isTerminal

	fmt.Fprintln(pt.out, boxTop())

	barStr := ptBar(100, c)
	line1 := fmt.Sprintf("  %s  100%%  |  %s / %s",
		barStr,
		ptFmtDur(elapsed),
		ptFmtDur(pt.duration),
	)
	fmt.Fprintln(pt.out, ptBoxLine(line1))

	errStr := ptFmtErr(errPct, c)
	line2 := fmt.Sprintf("  RPS: %s  |  Avg: %s  |  Max: %s  |  Err: %s",
		ptFmtRPS(overallRPS),
		ptFmtDur(avgLat),
		ptFmtDur(maxLat),
		errStr,
	)
	fmt.Fprintln(pt.out, ptBoxLine(line2))

	line3 := fmt.Sprintf("  Active: %d users  |  Requests: %s  |  Elapsed: %s",
		pt.totalUsers,
		ptFmtCount(reqs),
		ptFmtDur(elapsed),
	)
	fmt.Fprintln(pt.out, ptBoxLine(line3))

	fmt.Fprintln(pt.out, boxBottom())
}

func boxTop() string    { return "┌" + strings.Repeat("─", boxWidth) + "┐" }
func boxBottom() string { return "└" + strings.Repeat("─", boxWidth) + "┘" }

func ptBoxLine(content string) string {
	vis := visibleLen(content)
	pad := boxWidth - vis
	if pad < 0 {
		pad = 0
	}
	return "│" + content + strings.Repeat(" ", pad) + "│"
}

func visibleLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		if r == '\x1b' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEsc = false
			}
			continue
		}
		n++
	}
	return n
}

func ptBar(pct float64, color bool) string {
	filled := int(pct / 100 * float64(progressBarWidth))
	if filled > progressBarWidth {
		filled = progressBarWidth
	}
	if color {
		return pCyan + strings.Repeat("█", filled) + pReset + strings.Repeat("░", progressBarWidth-filled)
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", progressBarWidth-filled)
}

func ptFmtErr(errPct float64, color bool) string {
	s := fmt.Sprintf("%.1f%%", errPct)
	if !color {
		return s
	}
	var c string
	switch {
	case errPct < 1:
		c = pGreen
	case errPct <= 5:
		c = pYellow
	default:
		c = pRed
	}
	return c + s + pReset
}

func ptFmtDur(d time.Duration) string {
	d = d.Round(time.Millisecond)
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	m := d / time.Minute
	s := d%time.Minute / time.Second
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func ptFmtRPS(rps float64) string {
	if rps >= 1_000_000 {
		return fmt.Sprintf("%.1fM", rps/1_000_000)
	}
	if rps >= 1_000 {
		return fmt.Sprintf("%.1fK", rps/1_000)
	}
	return fmt.Sprintf("%.0f", rps)
}

func ptFmtCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func isTerminalFile(w io.Writer) bool {
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
