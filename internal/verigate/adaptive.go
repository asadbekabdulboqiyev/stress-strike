package verigate

// adaptive.go — the load-aware proof-of-work difficulty controller.
//
// A gate with a fixed difficulty charges every client the same price whether
// the origin is idle or saturated. This controller makes the price a function
// of measured pressure: as the request rate through the middleware rises, the
// difficulty steps up; as the pressure falls away, it steps back down.
//
// Three properties make it safe to enable on a real site:
//
//   - The operator's baseline difficulty (Options.Difficulty) is a FLOOR.
//     Adaptive mode can only make the gate stricter than the operator asked
//     for, never laxer. An idle site behaves exactly like a static gate.
//   - Changes are rate limited by StepInterval and driven by a smoothed rate,
//     so a single burst of traffic cannot oscillate the gate.
//   - Every change is recorded with a timestamp. The schedule is evidence: a
//     load generator cannot claim the target was under pressure if the target
//     never charged anyone for it.
//
// The difficulty charged for a challenge is bound into the signed challenge
// itself, so a client that is mid-solve when the controller moves is judged by
// the price it was quoted, not by a price that changed under its feet.

import (
	"math"
	"sync"
	"time"
)

// DifficultyEntry is one recorded difficulty change.
type DifficultyEntry struct {
	// UnixMS is when the change took effect, in Unix milliseconds.
	UnixMS int64 `json:"unix_ms"`
	// Difficulty is the level in force from that instant until the next entry.
	Difficulty int `json:"difficulty"`
}

// AdaptiveOptions configures the load-aware difficulty controller. It is passed
// as Options.Adaptive; a nil pointer leaves the gate's difficulty fixed.
//
// Zero values fall back to the defaults below, and a baseline that is unset is
// taken from Options.Difficulty.
type AdaptiveOptions struct {
	// Min is the lowest difficulty the controller may charge. Default: the
	// gate's baseline Difficulty, which makes the baseline an absolute floor.
	Min int
	// Max is the highest difficulty the controller may charge. Default
	// MaxDifficulty.
	Max int
	// StepInterval is the minimum time between two changes. Default 500ms.
	StepInterval time.Duration
	// HalfLife is the smoothing half-life of the rate estimate. Default 2s.
	HalfLife time.Duration
	// HighWaterRPS is the request rate at or above which difficulty rises.
	// Default 100.
	HighWaterRPS float64
	// LowWaterRPS is the request rate at or below which difficulty falls back
	// toward Min. Default 25.
	LowWaterRPS float64
	// ScheduleCap bounds the retained schedule length. Default 1024.
	ScheduleCap int
}

// Defaults for the adaptive controller.
const (
	DefaultAdaptiveStepInterval = 500 * time.Millisecond
	DefaultAdaptiveHalfLife     = 2 * time.Second
	DefaultAdaptiveHighWaterRPS = 100
	DefaultAdaptiveLowWaterRPS  = 25
	DefaultAdaptiveScheduleCap  = 1024
)

// DefaultAdaptiveOptions returns the defaults with Min and Max left for the
// gate to fill in from its baseline difficulty.
func DefaultAdaptiveOptions() AdaptiveOptions {
	return AdaptiveOptions{
		StepInterval: DefaultAdaptiveStepInterval,
		HalfLife:     DefaultAdaptiveHalfLife,
		HighWaterRPS: DefaultAdaptiveHighWaterRPS,
		LowWaterRPS:  DefaultAdaptiveLowWaterRPS,
		ScheduleCap:  DefaultAdaptiveScheduleCap,
	}
}

// normalize fills unset fields from the defaults and clamps the level bounds to
// the protocol's limits. The baseline is the gate's configured difficulty and
// becomes the default floor.
func (o *AdaptiveOptions) normalize(baseline int) {
	if o.StepInterval <= 0 {
		o.StepInterval = DefaultAdaptiveStepInterval
	}
	if o.HalfLife <= 0 {
		o.HalfLife = DefaultAdaptiveHalfLife
	}
	if o.HighWaterRPS <= 0 {
		o.HighWaterRPS = DefaultAdaptiveHighWaterRPS
	}
	if o.LowWaterRPS < 0 {
		o.LowWaterRPS = DefaultAdaptiveLowWaterRPS
	}
	if o.LowWaterRPS >= o.HighWaterRPS {
		// Hysteresis requires a gap; without one the gate would oscillate.
		o.LowWaterRPS = o.HighWaterRPS / 4
	}
	if o.ScheduleCap <= 0 {
		o.ScheduleCap = DefaultAdaptiveScheduleCap
	}
	if o.Min <= 0 {
		o.Min = baseline
	}
	if o.Max <= 0 {
		o.Max = MaxDifficulty
	}
	o.Min = clampDifficulty(o.Min)
	o.Max = clampDifficulty(o.Max)
	if o.Max < o.Min {
		o.Max = o.Min
	}
}

func clampDifficulty(d int) int {
	if d < 1 {
		return 1
	}
	if d > MaxDifficulty {
		return MaxDifficulty
	}
	return d
}

// difficultyController tracks the request rate seen by the gate and steps the
// charged difficulty between a floor and a ceiling.
type difficultyController struct {
	opts     AdaptiveOptions
	baseline int

	mu        sync.Mutex
	level     int
	rate      float64
	lastAt    time.Time
	lastStep  time.Time
	schedule  []DifficultyEntry
	stepsUp   uint64
	stepsDown uint64
}

func newDifficultyController(baseline int, opts AdaptiveOptions) *difficultyController {
	opts.normalize(baseline)
	level := baseline
	if level < opts.Min {
		level = opts.Min
	}
	if level > opts.Max {
		level = opts.Max
	}
	return &difficultyController{opts: opts, baseline: baseline, level: level}
}

// observe accounts for one request arriving at now and, when the smoothed rate
// has crossed a threshold and enough time has passed since the last change,
// steps the difficulty. It is called on the request path and must stay cheap:
// it takes one lock, does constant work, and returns.
func (c *difficultyController) observe(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lastAt.IsZero() {
		c.lastAt = now
		return
	}
	dt := now.Sub(c.lastAt)
	if dt <= 0 {
		// Non-monotonic or duplicate timestamp: keep the last estimate.
		return
	}
	c.lastAt = now

	// Exponentially weighted moving average of the request rate. The
	// instantaneous rate of one inter-arrival gap enters with a weight set by
	// how much of a half-life that gap represents, so bursty arrivals are
	// smoothed rather than followed.
	inst := 1 / dt.Seconds()
	alpha := 1 - math.Exp(-dt.Seconds()/c.opts.HalfLife.Seconds())
	if alpha < 0 {
		alpha = 0
	} else if alpha > 1 {
		alpha = 1
	}
	c.rate += alpha * (inst - c.rate)

	if now.Sub(c.lastStep) < c.opts.StepInterval {
		return
	}
	switch {
	case c.rate >= c.opts.HighWaterRPS && c.level < c.opts.Max:
		c.step(now, c.level+1)
		c.stepsUp++
	case c.rate <= c.opts.LowWaterRPS && c.level > c.opts.Min:
		c.step(now, c.level-1)
		c.stepsDown++
	}
}

// step records a change to level at now, trimming the schedule to its cap.
// The caller holds c.mu.
func (c *difficultyController) step(now time.Time, level int) {
	c.level = level
	c.lastStep = now
	c.schedule = append(c.schedule, DifficultyEntry{UnixMS: now.UnixMilli(), Difficulty: level})
	if len(c.schedule) > c.opts.ScheduleCap {
		trimmed := make([]DifficultyEntry, c.opts.ScheduleCap)
		copy(trimmed, c.schedule[len(c.schedule)-c.opts.ScheduleCap:])
		c.schedule = trimmed
	}
}

// difficulty returns the level currently charged.
func (c *difficultyController) difficulty() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.level
}

// rateEstimate returns the current smoothed request rate, for diagnostics.
func (c *difficultyController) rateEstimate() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rate
}

// scheduleSnapshot returns a copy of the recorded changes, oldest first.
func (c *difficultyController) scheduleSnapshot() []DifficultyEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]DifficultyEntry, len(c.schedule))
	copy(out, c.schedule)
	return out
}

// counters returns the number of upward and downward steps taken so far.
func (c *difficultyController) counters() (up, down uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stepsUp, c.stepsDown
}

// reset returns the controller to its baseline with no recorded history.
func (c *difficultyController) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.level = c.baseline
	if c.level < c.opts.Min {
		c.level = c.opts.Min
	}
	if c.level > c.opts.Max {
		c.level = c.opts.Max
	}
	c.rate = 0
	c.lastAt = time.Time{}
	c.lastStep = time.Time{}
	c.schedule = nil
	c.stepsUp = 0
	c.stepsDown = 0
}
