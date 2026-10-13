package verigate

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// testAdaptiveOptions returns controller settings that react quickly, so the
// tests do not have to simulate seconds of traffic.
func testAdaptiveOptions() AdaptiveOptions {
	return AdaptiveOptions{
		StepInterval: time.Millisecond,
		HalfLife:     50 * time.Millisecond,
		HighWaterRPS: 100,
		LowWaterRPS:  10,
	}
}

// --- controller unit behaviour ----------------------------------------------

// Sustained traffic faster than HighWaterRPS must raise the level one step at a
// time, and never past Max.
func TestControllerRaisesUnderLoadUpToMax(t *testing.T) {
	c := newDifficultyController(4, testAdaptiveOptions())
	base := time.Unix(1_700_000_000, 0)
	// 1ms apart = 1000 rps, ten times HighWaterRPS.
	for i := 0; i < 400; i++ {
		c.observe(base.Add(time.Duration(i) * time.Millisecond))
	}

	if got := c.difficulty(); got != MaxDifficulty {
		t.Fatalf("difficulty under load = %d, want MaxDifficulty (%d)", got, MaxDifficulty)
	}
	up, down := c.counters()
	if want := uint64(MaxDifficulty - 4); up != want {
		t.Errorf("up steps = %d, want %d", up, want)
	}
	if down != 0 {
		t.Errorf("down steps = %d, want 0 under sustained load", down)
	}
}

// The operator's baseline is a floor: quiet traffic must not make the gate
// easier than it was configured to be.
func TestControllerNeverFallsBelowBaseline(t *testing.T) {
	c := newDifficultyController(4, testAdaptiveOptions())
	if c.opts.Min != 4 {
		t.Fatalf("Min = %d, want the baseline 4 when unset", c.opts.Min)
	}

	base := time.Unix(1_700_000_000, 0)
	// One request per second, far below LowWaterRPS.
	for i := 0; i < 50; i++ {
		c.observe(base.Add(time.Duration(i) * time.Second))
	}

	if got := c.difficulty(); got != 4 {
		t.Fatalf("difficulty when quiet = %d, want the baseline floor 4", got)
	}
	if _, down := c.counters(); down != 0 {
		t.Errorf("down steps = %d, want 0 — the baseline is a floor", down)
	}
	if s := c.scheduleSnapshot(); len(s) != 0 {
		t.Errorf("schedule = %v, want empty when nothing changed", s)
	}
}

// An operator who explicitly lowers Min wants protection to relax when the
// pressure passes, all the way down to that Min.
func TestControllerFallsBackToExplicitMin(t *testing.T) {
	opts := testAdaptiveOptions()
	opts.Min, opts.Max = 2, 6

	c := newDifficultyController(4, opts)
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 400; i++ {
		c.observe(base.Add(time.Duration(i) * time.Millisecond))
	}
	if got := c.difficulty(); got != opts.Max {
		t.Fatalf("difficulty under load = %d, want %d", got, opts.Max)
	}

	// The load passes: one request per second afterwards.
	after := base.Add(time.Second)
	for i := 0; i < 2000; i++ {
		c.observe(after.Add(time.Duration(i) * time.Second))
	}
	if got := c.difficulty(); got != opts.Min {
		t.Fatalf("difficulty after the load passed = %d, want Min %d", got, opts.Min)
	}
	if _, down := c.counters(); down == 0 {
		t.Error("no downward steps recorded after the load passed")
	}
}

// StepInterval is the hysteresis: however fast the traffic, the level moves at
// most once per interval.
func TestControllerRateLimitsChanges(t *testing.T) {
	opts := testAdaptiveOptions()
	opts.StepInterval = time.Hour
	opts.Min, opts.Max = 2, 6

	c := newDifficultyController(4, opts)
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 500; i++ {
		c.observe(base.Add(time.Duration(i) * time.Millisecond))
	}

	if up, _ := c.counters(); up != 1 {
		t.Fatalf("up steps = %d, want exactly 1 with a 1h StepInterval", up)
	}
	if got := c.difficulty(); got != 5 {
		t.Fatalf("difficulty = %d, want 5 (a single step up from 4)", got)
	}
}

// The recorded schedule is bounded and never goes backwards in time: a verifier
// reading it must be able to walk it in order.
func TestDifficultyScheduleIsBoundedAndOrdered(t *testing.T) {
	opts := testAdaptiveOptions()
	opts.Min, opts.Max = 1, 6
	opts.ScheduleCap = 3

	c := newDifficultyController(1, opts)
	base := time.Unix(1_700_000_000, 0)
	at := base
	// Alternate a fast phase (raise) and a slow phase (fall back) so the level
	// keeps moving.
	for cycle := 0; cycle < 6; cycle++ {
		for i := 0; i < 200; i++ {
			at = at.Add(time.Millisecond)
			c.observe(at)
		}
		for i := 0; i < 200; i++ {
			at = at.Add(10 * time.Millisecond)
			c.observe(at)
		}
	}

	s := c.scheduleSnapshot()
	if len(s) == 0 {
		t.Fatal("no changes recorded across oscillating traffic")
	}
	if len(s) > opts.ScheduleCap {
		t.Fatalf("schedule has %d entries, cap is %d", len(s), opts.ScheduleCap)
	}
	for i, e := range s {
		if e.Difficulty < opts.Min || e.Difficulty > opts.Max {
			t.Errorf("entry %d difficulty = %d, outside [%d,%d]", i, e.Difficulty, opts.Min, opts.Max)
		}
		if i > 0 && e.UnixMS < s[i-1].UnixMS {
			t.Errorf("entry %d goes backwards in time: %d after %d", i, e.UnixMS, s[i-1].UnixMS)
		}
	}
}

func TestControllerClampsBounds(t *testing.T) {
	// Min defaults to the baseline, Max defaults to MaxDifficulty.
	c := newDifficultyController(3, AdaptiveOptions{})
	if c.opts.Min != 3 || c.opts.Max != MaxDifficulty {
		t.Fatalf("bounds = [%d,%d], want [3,%d]", c.opts.Min, c.opts.Max, MaxDifficulty)
	}
	if c.difficulty() != 3 {
		t.Errorf("initial difficulty = %d, want 3", c.difficulty())
	}

	// A Max below Min is raised, not left inverted.
	c = newDifficultyController(4, AdaptiveOptions{Min: 5, Max: 3})
	if c.opts.Max < c.opts.Min {
		t.Fatalf("bounds = [%d,%d], Max must not sit below Min", c.opts.Min, c.opts.Max)
	}

	// Out-of-range values are clamped to the protocol's limits.
	c = newDifficultyController(2, AdaptiveOptions{Min: -3, Max: 99})
	if c.opts.Min != 2 {
		t.Errorf("Min = %d, want the baseline 2 (negative Min falls back)", c.opts.Min)
	}
	if c.opts.Max != MaxDifficulty {
		t.Errorf("Max = %d, want %d", c.opts.Max, MaxDifficulty)
	}

	// DefaultAdaptiveOptions must produce a usable configuration.
	c = newDifficultyController(4, DefaultAdaptiveOptions())
	if c.opts.Min != 4 || c.opts.Max != MaxDifficulty {
		t.Errorf("defaults gave bounds [%d,%d]", c.opts.Min, c.opts.Max)
	}
}

// --- gate integration -------------------------------------------------------

// The difficulty a challenge was issued with is bound into the signed payload:
// a client is judged by the price it was quoted.
func TestAdaptiveChallengeBindsQuotedDifficulty(t *testing.T) {
	g, err := New(Options{
		Difficulty: 4,
		Secret:     []byte("adaptive-binding"),
		Adaptive:   &AdaptiveOptions{StepInterval: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}

	prefix, quoted, err := g.makeChallenge("203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if quoted != 4 {
		t.Fatalf("quoted difficulty = %d, want the baseline 4", quoted)
	}
	got, ok := g.verifyChallengeDetailed(prefix, "203.0.113.9")
	if !ok {
		t.Fatal("a freshly issued challenge did not verify")
	}
	if got != quoted {
		t.Fatalf("verified difficulty = %d, want the quoted %d", got, quoted)
	}
	// The plain predicate must agree with the detailed form.
	if !g.verifyChallenge(prefix, "203.0.113.9") {
		t.Fatal("verifyChallenge disagreed with verifyChallengeDetailed")
	}

	// Rewriting the bound difficulty must break the signature.
	parts := strings.Split(prefix, "|")
	if len(parts) != 5 {
		t.Fatalf("challenge has %d parts, want 5", len(parts))
	}
	parts[3] = "1"
	if _, ok := g.verifyChallengeDetailed(strings.Join(parts, "|"), "203.0.113.9"); ok {
		t.Fatal("a challenge with a rewritten difficulty was accepted")
	}

	// A proof solved for a cheaper difficulty must not satisfy the quoted one.
	if nonce := solveProof(prefix, 1); nonce != "" {
		if validProof(prefix, nonce, quoted) {
			t.Fatalf("a difficulty-1 proof satisfied difficulty %d", quoted)
		}
	}
}

// The correctness property that makes adaptive difficulty safe to run: a client
// that was quoted a price keeps that price even if the controller moves while
// it is solving.
func TestQuotedDifficultySurvivesControllerChange(t *testing.T) {
	adaptiveOpts := testAdaptiveOptions()
	g, err := New(Options{
		Difficulty: 2,
		Secret:     []byte("in-flight"),
		Adaptive:   &adaptiveOpts,
	})
	if err != nil {
		t.Fatal(err)
	}

	prefix, quoted, err := g.makeChallenge("198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}

	// The origin comes under load while the client is solving.
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 400; i++ {
		g.adaptive.observe(base.Add(time.Duration(i) * time.Millisecond))
	}
	if g.Difficulty() <= quoted {
		t.Fatalf("controller did not raise the difficulty: %d", g.Difficulty())
	}

	got, ok := g.verifyChallengeDetailed(prefix, "198.51.100.7")
	if !ok {
		t.Fatal("the in-flight challenge stopped verifying when the level moved")
	}
	if got != quoted {
		t.Fatalf("in-flight difficulty = %d, want the quoted %d", got, quoted)
	}
	nonce := solveProof(prefix, got)
	if nonce == "" {
		t.Fatal("could not solve the in-flight challenge")
	}
	if !validProof(prefix, nonce, got) {
		t.Fatal("a proof solved for the quoted difficulty was rejected")
	}
}

// A gate without an Adaptive option keeps its old behaviour exactly: fixed
// difficulty, no schedule, no steps.
func TestStaticGateIsUnaffectedByTheController(t *testing.T) {
	g, err := New(Options{Difficulty: 5, Secret: []byte("static")})
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Difficulty(); got != 5 {
		t.Errorf("Difficulty = %d, want 5", got)
	}
	if s := g.DifficultySchedule(); s != nil {
		t.Errorf("schedule = %v, want nil in static mode", s)
	}
	if up, down := g.DifficultySteps(); up != 0 || down != 0 {
		t.Errorf("steps = (%d,%d), want (0,0) in static mode", up, down)
	}
	if r := g.AdaptiveRateRPS(); r != 0 {
		t.Errorf("rate = %v, want 0 in static mode", r)
	}
	// Every challenge quotes the fixed difficulty.
	for i := 0; i < 3; i++ {
		_, d, err := g.makeChallenge("203.0.113.1")
		if err != nil {
			t.Fatal(err)
		}
		if d != 5 {
			t.Fatalf("quoted difficulty = %d, want 5", d)
		}
	}
}

// Reset returns an adaptive gate to its baseline and clears the schedule.
func TestResetRestoresBaseline(t *testing.T) {
	g, err := New(Options{
		Difficulty: 3,
		Secret:     []byte("reset"),
		Adaptive:   &AdaptiveOptions{StepInterval: time.Millisecond, HalfLife: time.Millisecond, HighWaterRPS: 10, LowWaterRPS: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 300; i++ {
		g.adaptive.observe(base.Add(time.Duration(i) * time.Millisecond))
	}
	if g.Difficulty() == 3 {
		t.Fatal("the controller never moved, so the reset cannot be observed")
	}

	g.Reset()
	if got := g.Difficulty(); got != 3 {
		t.Errorf("difficulty after reset = %d, want the baseline 3", got)
	}
	if s := g.DifficultySchedule(); len(s) != 0 {
		t.Errorf("schedule after reset = %v, want empty", s)
	}
	if up, down := g.DifficultySteps(); up != 0 || down != 0 {
		t.Errorf("steps after reset = (%d,%d), want (0,0)", up, down)
	}
}

// The controller sits on the request path, so it must be race free under real
// concurrent traffic.
func TestAdaptiveControllerIsSafeForConcurrentTraffic(t *testing.T) {
	g, err := New(Options{
		Difficulty: 3,
		Secret:     []byte("concurrent-adaptive"),
		Adaptive:   &AdaptiveOptions{StepInterval: time.Microsecond, HalfLife: time.Millisecond, HighWaterRPS: 10, LowWaterRPS: 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				g.adaptive.observe(time.Now())
				_ = g.Difficulty()
				_ = g.verifyChallenge("not|a|challenge", "203.0.113.5")
			}
		}()
	}
	wg.Wait()

	schedule := g.DifficultySchedule()
	for i := 1; i < len(schedule); i++ {
		if schedule[i].UnixMS < schedule[i-1].UnixMS {
			t.Fatalf("schedule entry %d goes backwards in time", i)
		}
	}
	up, down := g.DifficultySteps()
	if up+down == 0 {
		t.Error("no steps at all across 4000 concurrent observations at ~ns intervals")
	}
}
