package engine

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProgressTracker_Creation(t *testing.T) {
	var buf bytes.Buffer
	pt := newProgressTracker(10*time.Second, 50, &buf)
	if pt == nil {
		t.Fatal("expected non-nil tracker")
	}
	if pt.duration != 10*time.Second {
		t.Errorf("duration = %v, want 10s", pt.duration)
	}
	if pt.totalUsers != 50 {
		t.Errorf("totalUsers = %d, want 50", pt.totalUsers)
	}
	if pt.isTerminal {
		t.Error("buffer should not be detected as terminal")
	}
}

func TestProgressTracker_Update(t *testing.T) {
	var buf bytes.Buffer
	pt := newProgressTracker(30*time.Second, 100, &buf)

	pt.Update(100, 5, 10*time.Millisecond)
	pt.Update(200, 8, 20*time.Millisecond)

	if v := pt.totalReqs.Load(); v != 200 {
		t.Errorf("totalReqs = %d, want 200", v)
	}
	if v := pt.totalErrors.Load(); v != 8 {
		t.Errorf("totalErrors = %d, want 8", v)
	}
	if v := pt.snapCount.Load(); v != 2 {
		t.Errorf("snapCount = %d, want 2", v)
	}
}

func TestProgressTracker_UpdateMaxLatency(t *testing.T) {
	var buf bytes.Buffer
	pt := newProgressTracker(30*time.Second, 10, &buf)

	pt.Update(1, 0, 5*time.Millisecond)
	pt.Update(2, 0, 15*time.Millisecond)
	pt.Update(3, 0, 8*time.Millisecond)

	maxNs := pt.latencyMax.Load()
	max := time.Duration(maxNs)
	if max != 15*time.Millisecond {
		t.Errorf("max latency = %v, want 15ms", max)
	}
}

func TestProgressTracker_Render(t *testing.T) {
	var buf bytes.Buffer
	pt := newProgressTracker(30*time.Second, 100, &buf)

	pt.Update(1500, 3, 10*time.Millisecond)
	pt.render()

	output := buf.String()

	if !strings.Contains(output, "┌") {
		t.Error("missing box top border")
	}
	if !strings.Contains(output, "└") {
		t.Error("missing box bottom border")
	}
	if !strings.Contains(output, "│") {
		t.Error("missing box side borders")
	}
	if !strings.Contains(output, "100 users") {
		t.Error("missing active users count")
	}
	if !strings.Contains(output, "1.5K") {
		t.Errorf("missing formatted request count, got: %s", output)
	}
	if !strings.Contains(output, "30.0s") {
		t.Error("missing total duration")
	}
}

func TestProgressTracker_RenderFinal(t *testing.T) {
	var buf bytes.Buffer
	pt := newProgressTracker(10*time.Second, 50, &buf)

	pt.Update(5000, 10, 5*time.Millisecond)
	pt.renderFinal()

	output := buf.String()
	if !strings.Contains(output, "100%") {
		t.Error("final render should show 100%")
	}
	if !strings.Contains(output, "50 users") {
		t.Error("missing active users")
	}
	if !strings.Contains(output, "5.0K") {
		t.Errorf("missing request count, got: %s", output)
	}
}

func TestProgressTracker_FinishNonTerminal(t *testing.T) {
	var buf bytes.Buffer
	pt := newProgressTracker(10*time.Second, 10, &buf)

	pt.Update(100, 0, 5*time.Millisecond)
	pt.Finish()

	if buf.Len() > 0 {
		t.Error("non-terminal Finish should not write output")
	}
}

func TestProgressTracker_FinishIdempotent(t *testing.T) {
	var buf bytes.Buffer
	pt := newProgressTracker(10*time.Second, 10, &buf)

	pt.Finish()
	pt.Finish()
	pt.Finish()
}

func TestProgressTracker_Quiet(t *testing.T) {
	var buf bytes.Buffer
	pt := newProgressTracker(10*time.Second, 10, &buf)
	pt.SetQuiet(true)

	pt.Update(100, 0, 5*time.Millisecond)
	pt.render()

	if buf.Len() > 0 {
		t.Error("quiet mode should suppress render output")
	}
}

func TestProgressTracker_UpdateRace(t *testing.T) {
	var buf bytes.Buffer
	pt := newProgressTracker(60*time.Second, 200, &buf)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			pt.Update(uint64(n*10), uint64(n%5), time.Duration(n)*time.Millisecond)
		}(i)
	}
	wg.Wait()

	if v := pt.snapCount.Load(); v != 100 {
		t.Errorf("snapCount = %d, want 100", v)
	}
}

func TestProgressBar_Build(t *testing.T) {
	tests := []struct {
		name   string
		pct    float64
		color  bool
		filled int
		empty  int
	}{
		{"zero", 0, false, 0, 30},
		{"half", 50, false, 15, 15},
		{"full", 100, false, 30, 0},
		{"over", 150, false, 30, 0},
		{"quarter", 25, false, 7, 23},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bar := ptBar(tt.pct, tt.color)
			filled := strings.Count(bar, "█")
			empty := strings.Count(bar, "░")
			if filled != tt.filled {
				t.Errorf("filled = %d, want %d", filled, tt.filled)
			}
			if empty != tt.empty {
				t.Errorf("empty = %d, want %d", empty, tt.empty)
			}
		})
	}
}

func TestProgressBar_Color(t *testing.T) {
	bar := ptBar(50, true)
	if !strings.Contains(bar, pCyan) {
		t.Error("colored bar should contain cyan escape")
	}
	if !strings.Contains(bar, pReset) {
		t.Error("colored bar should contain reset escape")
	}

	barPlain := ptBar(50, false)
	if strings.Contains(barPlain, "\x1b") {
		t.Error("plain bar should not contain ANSI escapes")
	}
}

func TestBoxLine_Format(t *testing.T) {
	line := ptBoxLine("hello")
	runes := []rune(line)
	if runes[0] != '│' {
		t.Error("box line should start with │")
	}
	if runes[len(runes)-1] != '│' {
		t.Error("box line should end with │")
	}
	vis := visibleLen(line)
	if vis != boxWidth+2 {
		t.Errorf("visible width = %d, want %d", vis, boxWidth+2)
	}
	if !strings.HasPrefix(line, "│hello") {
		t.Error("inner should start with content")
	}
}

func TestBoxLine_LongContent(t *testing.T) {
	long := strings.Repeat("x", boxWidth+10)
	line := ptBoxLine(long)
	runes := []rune(line)
	if runes[0] != '│' || runes[len(runes)-1] != '│' {
		t.Error("box line should still have borders with long content")
	}
}

func TestVisibleLen_Plain(t *testing.T) {
	if n := visibleLen("hello"); n != 5 {
		t.Errorf("visibleLen = %d, want 5", n)
	}
	if n := visibleLen(""); n != 0 {
		t.Errorf("visibleLen of empty = %d, want 0", n)
	}
}

func TestVisibleLen_ANSI(t *testing.T) {
	colored := pGreen + "hello" + pReset
	if n := visibleLen(colored); n != 5 {
		t.Errorf("visibleLen of colored string = %d, want 5", n)
	}
}

func TestPtFmtRPS(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{0, "0"},
		{5, "5"},
		{999, "999"},
		{1000, "1.0K"},
		{1500, "1.5K"},
		{45200, "45.2K"},
		{1000000, "1.0M"},
		{2500000, "2.5M"},
	}
	for _, tt := range tests {
		got := ptFmtRPS(tt.input)
		if got != tt.want {
			t.Errorf("ptFmtRPS(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPtFmtCount(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0"},
		{5, "5"},
		{999, "999"},
		{1000, "1.0K"},
		{1500, "1.5K"},
		{1000000, "1.0M"},
		{2500000, "2.5M"},
	}
	for _, tt := range tests {
		got := ptFmtCount(tt.input)
		if got != tt.want {
			t.Errorf("ptFmtCount(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPtFmtDur(t *testing.T) {
	tests := []struct {
		input time.Duration
		want  string
	}{
		{0, "0ms"},
		{500 * time.Millisecond, "500ms"},
		{1500 * time.Millisecond, "1.5s"},
		{10 * time.Second, "10.0s"},
		{65 * time.Second, "1m5s"},
	}
	for _, tt := range tests {
		got := ptFmtDur(tt.input)
		if got != tt.want {
			t.Errorf("ptFmtDur(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPtFmtErr(t *testing.T) {
	green := ptFmtErr(0.5, true)
	if !strings.Contains(green, pGreen) {
		t.Error("0.5%% should be green")
	}

	yellow := ptFmtErr(2.5, true)
	if !strings.Contains(yellow, pYellow) {
		t.Error("2.5%% should be yellow")
	}

	red := ptFmtErr(10, true)
	if !strings.Contains(red, pRed) {
		t.Error("10%% should be red")
	}

	plain := ptFmtErr(3.0, false)
	if strings.Contains(plain, "\x1b") {
		t.Error("non-colored error should not have ANSI escapes")
	}
}

func TestPtFmtErr_Boundaries(t *testing.T) {
	g1 := ptFmtErr(0.9, true)
	if !strings.Contains(g1, pGreen) {
		t.Error("0.9%% should be green")
	}

	y1 := ptFmtErr(1.0, true)
	if !strings.Contains(y1, pYellow) {
		t.Error("1.0%% should be yellow")
	}

	y5 := ptFmtErr(5.0, true)
	if !strings.Contains(y5, pYellow) {
		t.Error("5.0%% should be yellow")
	}

	r5 := ptFmtErr(5.1, true)
	if !strings.Contains(r5, pRed) {
		t.Error("5.1%% should be red")
	}
}

func TestProgressTracker_SetQuiet(t *testing.T) {
	var buf bytes.Buffer
	pt := newProgressTracker(10*time.Second, 10, &buf)
	pt.SetQuiet(true)
	if !pt.quiet {
		t.Error("SetQuiet(true) did not set quiet")
	}
	pt.SetQuiet(false)
	if pt.quiet {
		t.Error("SetQuiet(false) did not clear quiet")
	}
}
