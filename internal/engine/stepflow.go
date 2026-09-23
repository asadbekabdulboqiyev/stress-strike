package engine

// stepflow.go — step control-flow engine.
//
// Owned by the "Qudratli Funksiyalar" backend team. Implements the advanced
// scenario semantics on top of the existing per-protocol clients:
//
//	think_time       pause after a step (seconds, fractional allowed)
//	on_error         "continue" | "stop" (default "stop") — what happens to
//	                 the iteration when this step fails
//	skip_on_error    skip this step when the previous step errored, but let
//	                 the iteration continue
//	retries          extra attempts on failure (default 0 = none)
//	retry_backoff    seconds between attempts (default 0.1)
//	stop_on_status   halt the whole run when a status family / code arrives
//	type: if         conditional branching on a single comparison
//	grpc_stream      client-streaming gRPC (see grpc_stream.go)

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// stopFlags is a package-level registry of per-Engine run-stop state. The
// Engine struct itself is owned by another team (client.go / New() work), so we
// deliberately attach the stop flag here instead of adding a field to Engine.
// One entry per Engine instance — a CLI process creates only a handful.
var stopFlags sync.Map // *Engine → *runStop

// runStop records that a run was halted early (stop_on_status fired).
type runStop struct {
	mu     sync.Mutex
	set    bool
	reason string
	done   chan struct{}
	once   sync.Once
}

func (s *runStop) mark(reason string) {
	s.mu.Lock()
	s.set = true
	s.reason = reason
	s.mu.Unlock()
	// Wake the Run() watcher (idempotent) so the run window closes early.
	s.once.Do(func() { close(s.done) })
}

func (s *runStop) armed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set
}

// notifyChan returns the channel closed when the run is halted early. A nil
// receiver (never constructed) blocks forever, which is the "no stop" case.
func (s *runStop) notifyChan() <-chan struct{} {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.done
}

// reset clears the flag for a fresh run on the same Engine instance.
// Must only be called between runs (all workers drained).
func (s *runStop) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.set = false
	s.reason = ""
	s.done = make(chan struct{})
	s.once = sync.Once{}
}

// stopFlag returns (creating on first use) the run-stop flag for this engine.
func (e *Engine) stopFlag() *runStop {
	v, _ := stopFlags.LoadOrStore(e, &runStop{done: make(chan struct{})})
	return v.(*runStop)
}

// flowState carries per-iteration control state across a step sequence.
type flowState struct {
	prevErr    bool   // the previous executed step failed
	firstErr   string // first error name observed in this iteration
	lastStatus int    // status of the last successful step
	stopRun    bool   // stop_on_status fired → stop issuing requests globally
}

// runStepSequence walks a list of steps applying control-flow semantics.
// statsIdx selects the stepStats slot: -1 means "top-level sequence" and the
// slot equals the position in the list; otherwise it is the slot of the nearest
// enclosing top-level step (nested branch steps aggregate into their parent).
// It returns true when the iteration must stop (on_error: stop, stop_on_status,
// or a canceled context).
func (e *Engine) runStepSequence(ctx context.Context, steps []config.Step, vars map[string]string, userIndex, statsIdx, depth int, state *flowState) (abort bool) {
	for i := range steps {
		if state.stopRun || ctx.Err() != nil {
			return false
		}
		slot := statsIdx
		if slot < 0 {
			slot = i
		}
		// skip_on_error: the previous step errored → park this step. The
		// error state persists (a skipped step didn't clear anything), so a
		// cascade of skip_on_error steps is skipped in turn.
		if state.prevErr && steps[i].SkipOnError {
			continue
		}
		if abort := e.runControlStep(ctx, steps[i], vars, userIndex, slot, depth, state); abort {
			return true
		}
	}
	return false
}

// runControlStep executes a single step (or an if-branch) with retry, policy
// and think-time semantics. It returns true when the iteration must stop.
func (e *Engine) runControlStep(ctx context.Context, step config.Step, vars map[string]string, userIndex, slot, depth int, state *flowState) (abort bool) {
	if step.Type == "if" {
		return e.runIfStep(ctx, step, vars, userIndex, slot, depth, state)
	}

	var res stepResult
	if step.GrpcStream && step.Type == "grpc" {
		timeout := e.timeout
		if step.Timeout > 0 {
			timeout = time.Duration(step.Timeout) * time.Second
		}
		// runStepForUser applies assertions/extract for regular steps; the
		// streaming client bypasses it, so apply both here (per attempt, so
		// recorded stats reflect the final outcome like regular steps do).
		res, _ = e.runWithRetries(ctx, step, slot, func() (stepResult, []byte) {
			r, b := e.grpcStreamClient(ctx, step, vars, timeout)
			if r.errName == "" && len(step.Assertions) > 0 {
				if err := checkAssertions(step.Assertions, r.status, b); err != nil {
					r.errName = errAssert
				}
			}
			if r.errName == "" {
				for _, ex := range step.Extract {
					value, exErr := extractValue(ex.From, ex.Path, b, "")
					if exErr != nil {
						r.errName = errExtract
						break
					}
					vars[ex.Name] = value
				}
			}
			return r, b
		})
		return e.finishControlStep(ctx, step, vars, res, state)
	}

	res, _ = e.runWithRetries(ctx, step, slot, func() (stepResult, []byte) {
		res := e.runStepForUser(ctx, step, vars, userIndex)
		return res, nil
	})
	return e.finishControlStep(ctx, step, vars, res, state)
}

// runWithRetries dispatches a step up to 1+Retries times, sleeping
// retry_backoff seconds between failed attempts. Every attempt is recorded in
// the stepStats slot (retried requests really did hit the server); the final
// attempt's result drives iteration-level state. A zero/negative retry_backoff
// falls back to the documented 0.1s default.
func (e *Engine) runWithRetries(ctx context.Context, step config.Step, slot int, dispatch func() (stepResult, []byte)) (stepResult, []byte) {
	attempts := 1 + step.Retries
	var last stepResult
	var body []byte
	for attempt := 0; attempt < attempts; attempt++ {
		last, body = dispatch()
		if e.telemetry.Recording() {
			e.stepStats[slot].Record(last.latency, last.status, last.errName)
		}
		if last.errName == "" {
			break
		}
		if attempt < attempts-1 {
			backoff := step.RetryBackoff
			if backoff <= 0 {
				backoff = 0.1 // documented default
			}
			sleepCtx(ctx, time.Duration(backoff*float64(time.Second)))
		}
	}
	return last, body
}

// finishControlStep applies post-execution policy: built-in per-step variables,
// stop_on_status, on_error continue/stop and think_time.
func (e *Engine) finishControlStep(ctx context.Context, step config.Step, vars map[string]string, res stepResult, state *flowState) (abort bool) {
	// Expose per-step outcomes as variables for branching below, e.g.
	// "${login_status} == 200", "${login_error} == ''", "${login_latency_ms} > 500".
	if res.status > 0 {
		vars[step.Name+"_status"] = strconv.Itoa(res.status)
	}
	vars[step.Name+"_error"] = res.errName
	vars[step.Name+"_latency_ms"] = strconv.FormatFloat(res.latency.Seconds()*1000, 'g', 4, 64)

	// stop_on_status: a matching status (e.g. a rate-limit 429) halts the
	// entire run — every worker stops issuing new requests.
	if step.StopStatusLower != 0 && res.status >= step.StopStatusLower && res.status <= step.StopStatusUpper {
		state.stopRun = true
		state.lastStatus = res.status
		return true
	}

	if res.errName != "" {
		if state.firstErr == "" {
			state.firstErr = res.errName
		}
		state.prevErr = true
		if step.OnError == "stop" {
			// Legacy behavior: abort this iteration at the first error.
			return true
		}
	} else {
		state.prevErr = false
		state.lastStatus = res.status
	}

	if step.ThinkTime > 0 {
		sleepCtx(ctx, time.Duration(step.ThinkTime*float64(time.Second)))
	}
	return false
}

// runIfStep evaluates a type: if condition. When it holds, nested steps run
// with the same control-flow semantics (think_time, on_error, skip_on_error,
// retries, stop_on_status); results aggregate into the if-step's stats slot.
// A false condition skips the branch without clearing a pending previous-step
// error, so skip_on_error cascades naturally.
func (e *Engine) runIfStep(ctx context.Context, step config.Step, vars map[string]string, userIndex, slot, depth int, state *flowState) (abort bool) {
	if cond := step.Cond; cond != nil && cond.Eval(vars) {
		if abort := e.runStepSequence(ctx, step.Steps, vars, userIndex, slot, depth+1, state); abort {
			return true
		}
	}
	if step.ThinkTime > 0 {
		sleepCtx(ctx, time.Duration(step.ThinkTime*float64(time.Second)))
	}
	return false
}

// sleepCtx sleeps for d, aborting early when ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
