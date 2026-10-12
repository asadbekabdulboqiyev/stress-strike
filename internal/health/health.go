// Package health provides liveness and readiness probes for the stress-strike
// control plane and workers.
//
// A Checker holds a set of named checks registered at startup. Liveness is
// unconditional (the process is running), while readiness runs every check
// concurrently under a bounded per-check timeout and reports failure if any
// check fails. The package is safe for concurrent use: checks may be registered
// while a probe is in flight.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Status values used in probe responses.
const (
	// StatusOK means the component is healthy.
	StatusOK = "ok"
	// StatusDegraded means at least one check failed or timed out.
	StatusDegraded = "degraded"
)

// defaultCheckTimeout bounds every individual readiness check. A check that
// overruns it is reported as failed and abandoned rather than blocking the
// probe forever (a Kubernetes probe would otherwise time out the whole request).
const defaultCheckTimeout = 5 * time.Second

// CheckResult is the outcome of a single named check.
type CheckResult struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Result is the aggregate outcome of a readiness probe.
type Result struct {
	Status string                 `json:"status"`
	Checks map[string]CheckResult `json:"checks"`
}

// CheckFunc reports whether a dependency is healthy. It must honour ctx
// cancellation for the timeout to be effective.
type CheckFunc func(ctx context.Context) error

// Checker runs a named set of health checks.
type Checker struct {
	mu      sync.Mutex
	checks  map[string]CheckFunc
	timeout time.Duration
}

// NewChecker returns an empty Checker with the default per-check timeout.
func NewChecker() *Checker {
	return &Checker{
		checks:  make(map[string]CheckFunc),
		timeout: defaultCheckTimeout,
	}
}

// NewCheckerWithTimeout returns an empty Checker whose per-check timeout is d.
// A non-positive d falls back to the default.
func NewCheckerWithTimeout(d time.Duration) *Checker {
	c := NewChecker()
	if d > 0 {
		c.timeout = d
	}
	return c
}

// Register adds (or replaces) a named check. Nil checks and empty names are
// ignored. It is safe to call concurrently with Check and other Registers.
func (c *Checker) Register(name string, check func(ctx context.Context) error) {
	if name == "" || check == nil {
		return
	}
	c.mu.Lock()
	c.checks[name] = CheckFunc(check)
	c.mu.Unlock()
}

// Names returns the registered check names in sorted order. It is safe to call
// concurrently with Register and Check.
func (c *Checker) Names() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sortedNames(c.checks)
}

// SetTimeout changes the per-check timeout. A non-positive value restores the
// default. It is safe to call concurrently with Check.
func (c *Checker) SetTimeout(d time.Duration) {
	if d <= 0 {
		d = defaultCheckTimeout
	}
	c.mu.Lock()
	c.timeout = d
	c.mu.Unlock()
}

// Check runs every registered check concurrently and returns the aggregate
// result. The overall Status is StatusOK only when every check passed;
// otherwise it is StatusDegraded. Checks map is always non-nil. The supplied
// context bounds the whole probe in addition to each check's own timeout.
func (c *Checker) Check(ctx context.Context) Result {
	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()
	snapshot := make(map[string]CheckFunc, len(c.checks))
	for name, fn := range c.checks {
		snapshot[name] = fn
	}
	timeout := c.timeout
	c.mu.Unlock()

	results := make(map[string]CheckResult, len(snapshot))
	if len(snapshot) == 0 {
		return Result{Status: StatusOK, Checks: results}
	}

	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	for name, fn := range snapshot {
		wg.Add(1)
		go func(name string, fn CheckFunc) {
			defer wg.Done()
			res := runCheck(ctx, timeout, fn)
			mu.Lock()
			results[name] = res
			mu.Unlock()
		}(name, fn)
	}
	wg.Wait()

	return Result{Status: aggregate(results), Checks: results}
}

// runCheck executes one check with a bounded timeout. The check runs in its own
// goroutine so that a non-cooperative implementation cannot block the probe:
// when the timeout (or the parent context) fires, the result is reported as a
// failure and the goroutine is abandoned. The result channel is buffered so the
// abandoned goroutine never blocks on send.
func runCheck(parent context.Context, timeout time.Duration, fn CheckFunc) CheckResult {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic: %v", r)
			}
		}()
		done <- fn(ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			return CheckResult{Status: StatusDegraded, Error: err.Error()}
		}
		return CheckResult{Status: StatusOK}
	case <-ctx.Done():
		return CheckResult{Status: StatusDegraded, Error: ctx.Err().Error()}
	}
}

func aggregate(results map[string]CheckResult) string {
	for _, r := range results {
		if r.Status != StatusOK {
			return StatusDegraded
		}
	}
	return StatusOK
}

// LivenessHandler reports that the process is alive. It always answers 200 with
// {"status":"ok"} regardless of the result of any registered check, which is
// what a Kubernetes liveness probe needs (a failed liveness probe restarts the
// pod, so it must only reflect the process itself).
func (c *Checker) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !allowedMethod(r.Method) {
			methodNotAllowed(w)
			return
		}
		writeJSON(w, r, http.StatusOK, struct {
			Status string `json:"status"`
		}{Status: StatusOK})
	}
}

// ReadinessHandler runs every registered check and answers 200 with the JSON
// result when they all pass, or 503 when any fails or times out. It is what a
// Kubernetes readiness probe hits: a non-ready pod stops receiving traffic
// without being restarted.
func (c *Checker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !allowedMethod(r.Method) {
			methodNotAllowed(w)
			return
		}
		res := c.Check(r.Context())
		status := http.StatusOK
		if res.Status != StatusOK {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, r, status, res)
	}
}

// Checker also implements http.Handler as an alias for ReadinessHandler.
func (c *Checker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.ReadinessHandler()(w, r)
}

// --- helpers ----------------------------------------------------------------

func allowedMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead
}

func methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// writeJSON marshals v with a stable key order (encoding/json sorts map keys)
// and writes it with the given status. It sets a no-store Cache-Control so
// probes are never answered from a cache.
func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// sortedNames returns the check names in a stable order. Kept for callers and
// tests that want a deterministic view; Check itself does not need it because
// the results map is marshalled with sorted keys.
func sortedNames(m map[string]CheckFunc) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
