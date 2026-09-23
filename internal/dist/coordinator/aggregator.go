package coordinator

import (
	"sort"
	"sync"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	distproto "github.com/asadbekabdulboqiyev/stress-strike/internal/dist/proto"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
)

// Aggregator accumulates the latest cumulative telemetry snapshot from each
// worker and exposes a fleet-wide view. Snapshots are cumulative per worker, so
// only the most recent one is kept — summing every tick would double-count.
type Aggregator struct {
	mu     sync.Mutex
	latest map[string]*distproto.TelemetrySnapshot
}

// NewAggregator returns an empty Aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{latest: make(map[string]*distproto.TelemetrySnapshot)}
}

// Update stores the newest snapshot reported by a worker.
func (a *Aggregator) Update(worker string, snap *distproto.TelemetrySnapshot) {
	if snap == nil {
		return
	}
	a.mu.Lock()
	a.latest[worker] = snap
	a.mu.Unlock()
}

// Forget drops a worker's telemetry (used when it disconnects mid-run).
func (a *Aggregator) Forget(worker string) {
	a.mu.Lock()
	delete(a.latest, worker)
	a.mu.Unlock()
}

// StepAggregate is the fleet-wide view of one named step.
type StepAggregate struct {
	Name        string
	Requests    int64
	Errors      int64
	StatusCodes map[int]uint64
	ErrorTypes  map[string]uint64
	Min         time.Duration
	Avg         time.Duration
	Max         time.Duration
	P50         time.Duration
	P95         time.Duration
	P99         time.Duration
}

// Aggregate is the combined live view across all reporting workers.
type Aggregate struct {
	Workers       int
	Elapsed       time.Duration
	TotalRequests int64
	TotalErrors   int64
	ActiveUsers   int64
	RPS           float64
	StatusCodes   map[int]uint64
	ErrorTypes    map[string]uint64
	Min           time.Duration
	Avg           time.Duration
	Max           time.Duration
	P50           time.Duration
	P95           time.Duration
	P99           time.Duration
	Steps         map[string]*StepAggregate
}

// Snapshot computes the current combined view.
func (a *Aggregator) Snapshot() Aggregate {
	a.mu.Lock()
	defer a.mu.Unlock()

	agg := Aggregate{
		StatusCodes: make(map[int]uint64),
		ErrorTypes:  make(map[string]uint64),
		Steps:       make(map[string]*StepAggregate),
	}
	var elapsedMax int64
	var avgNum, avgDen int64
	var minSet bool

	for _, snap := range a.latest {
		agg.Workers++
		agg.TotalRequests += snap.TotalRequests
		agg.TotalErrors += snap.TotalErrors
		agg.ActiveUsers += snap.ActiveUsers
		agg.RPS += snap.Rps
		if snap.ElapsedMs > elapsedMax {
			elapsedMax = snap.ElapsedMs
		}
		for code, n := range snap.StatusCodes {
			agg.StatusCodes[int(code)] += uint64(n)
		}
		for name, n := range snap.ErrorTypes {
			agg.ErrorTypes[name] += uint64(n)
		}
		lat := snap.Latency
		if lat != nil {
			if lat.P50Ms > agg.P50.Milliseconds() {
				agg.P50 = time.Duration(lat.P50Ms) * time.Millisecond
			}
			if lat.P95Ms > agg.P95.Milliseconds() {
				agg.P95 = time.Duration(lat.P95Ms) * time.Millisecond
			}
			if lat.P99Ms > agg.P99.Milliseconds() {
				agg.P99 = time.Duration(lat.P99Ms) * time.Millisecond
			}
			if lat.MaxMs > agg.Max.Milliseconds() {
				agg.Max = time.Duration(lat.MaxMs) * time.Millisecond
			}
			if lat.MinMs > 0 && (!minSet || lat.MinMs < agg.Min.Milliseconds()) {
				agg.Min = time.Duration(lat.MinMs) * time.Millisecond
				minSet = true
			}
			avgNum += lat.AvgMs * snap.TotalRequests
			avgDen += snap.TotalRequests
		}
		for _, step := range snap.Steps {
			sa := agg.Steps[step.Name]
			if sa == nil {
				sa = &StepAggregate{
					Name:        step.Name,
					StatusCodes: make(map[int]uint64),
					ErrorTypes:  make(map[string]uint64),
				}
				agg.Steps[step.Name] = sa
			}
			mergeLiveStep(sa, step)
		}
	}
	agg.Elapsed = time.Duration(elapsedMax) * time.Millisecond
	if avgDen > 0 {
		agg.Avg = time.Duration(avgNum/avgDen) * time.Millisecond
	}
	return agg
}

func mergeLiveStep(sa *StepAggregate, step *distproto.StepTelemetry) {
	sa.Requests += step.Requests
	sa.Errors += step.Errors
	for code, n := range step.StatusCodes {
		sa.StatusCodes[int(code)] += uint64(n)
	}
	for name, n := range step.ErrorTypes {
		sa.ErrorTypes[name] += uint64(n)
	}
	lat := step.Latency
	if lat == nil {
		return
	}
	if lat.P50Ms > sa.P50.Milliseconds() {
		sa.P50 = time.Duration(lat.P50Ms) * time.Millisecond
	}
	if lat.P95Ms > sa.P95.Milliseconds() {
		sa.P95 = time.Duration(lat.P95Ms) * time.Millisecond
	}
	if lat.P99Ms > sa.P99.Milliseconds() {
		sa.P99 = time.Duration(lat.P99Ms) * time.Millisecond
	}
	if lat.MaxMs > sa.Max.Milliseconds() {
		sa.Max = time.Duration(lat.MaxMs) * time.Millisecond
	}
	if lat.MinMs > 0 && (sa.Min == 0 || lat.MinMs < sa.Min.Milliseconds()) {
		sa.Min = time.Duration(lat.MinMs) * time.Millisecond
	}
}

// MergeReports folds per-worker final reports into a single fleet report. It
// sums counters, unions status/error histograms, merges steps by name, rebuilds
// the timeline by second, and recomputes SLA verdicts against the original
// scenario.
func MergeReports(sc *config.Scenario, reports []*report.Report) *report.Report {
	if len(reports) == 0 {
		return nil
	}

	merged := &report.Report{
		Status: make(map[int]uint64),
		Errors: make(map[string]uint64),
	}
	overall := newStepAccumulator(reports[0].Overall.Name)
	stepAccs := make(map[string]*stepAccumulator)
	var stepOrder []string
	timeline := make(map[int]metrics.TimelineSample)
	var startedAt, endedAt time.Time
	var durationMax time.Duration

	for _, r := range reports {
		if r == nil {
			continue
		}
		if merged.Name == "" {
			merged.Name = r.Name
			merged.BaseURL = r.BaseURL
			merged.LoadProfile = r.LoadProfile
			merged.TargetRPS = r.TargetRPS
		}
		if startedAt.IsZero() || (!r.StartedAt.IsZero() && r.StartedAt.Before(startedAt)) {
			startedAt = r.StartedAt
		}
		if r.EndedAt.After(endedAt) {
			endedAt = r.EndedAt
		}
		if r.Duration > durationMax {
			durationMax = r.Duration
		}
		merged.ActiveUsers += r.ActiveUsers
		merged.TotalRequests += r.TotalRequests
		merged.TotalErrors += r.TotalErrors
		for code, n := range r.Status {
			merged.Status[code] += n
		}
		for name, n := range r.Errors {
			merged.Errors[name] += n
		}
		overall.add(r.Overall)
		for i := range r.Steps {
			name := r.Steps[i].Name
			acc := stepAccs[name]
			if acc == nil {
				acc = newStepAccumulator(name)
				stepAccs[name] = acc
				stepOrder = append(stepOrder, name)
			}
			acc.add(r.Steps[i])
		}
		for _, s := range r.Timeline {
			t := timeline[s.Second]
			t.Second = s.Second
			t.Requests += s.Requests
			t.Errors += s.Errors
			t.ActiveUsers += s.ActiveUsers
			timeline[s.Second] = t
		}
	}

	merged.StartedAt = startedAt
	merged.EndedAt = endedAt
	if !startedAt.IsZero() && endedAt.After(startedAt) {
		merged.Duration = endedAt.Sub(startedAt)
	} else {
		merged.Duration = durationMax
	}
	if merged.Duration > 0 {
		merged.RPS = float64(merged.TotalRequests) / merged.Duration.Seconds()
	}
	if merged.TotalRequests > 0 {
		merged.ErrorRatePct = float64(merged.TotalErrors) / float64(merged.TotalRequests) * 100
	}
	merged.Overall = overall.result()
	for _, name := range stepOrder {
		merged.Steps = append(merged.Steps, stepAccs[name].result())
	}

	seconds := make([]int, 0, len(timeline))
	for sec := range timeline {
		seconds = append(seconds, sec)
	}
	sort.Ints(seconds)
	for _, sec := range seconds {
		merged.Timeline = append(merged.Timeline, timeline[sec])
	}

	if sc != nil && sc.SLA != nil {
		merged.SLA = report.EvaluateSLA(merged, sc.SLA)
	}
	return merged
}

// stepAccumulator merges latency statistics across workers. Percentiles are
// approximated by the worst worker (max) and averages are request-weighted,
// which is the best possible without shipping raw histograms over the wire.
type stepAccumulator struct {
	name          string
	requests      uint64
	errors        uint64
	status        map[int]uint64
	errTypes      map[string]uint64
	min           time.Duration
	max           time.Duration
	avgNum        int64
	avgDen        uint64
	p50, p95, p99 time.Duration
}

func newStepAccumulator(name string) *stepAccumulator {
	return &stepAccumulator{
		name:     name,
		status:   make(map[int]uint64),
		errTypes: make(map[string]uint64),
	}
}

func (a *stepAccumulator) add(s report.StepReport) {
	a.requests += s.Requests
	a.errors += s.Errors
	for code, n := range s.Status {
		a.status[code] += n
	}
	for name, n := range s.ErrorTypes {
		a.errTypes[name] += n
	}
	if s.Min > 0 && (a.min == 0 || s.Min < a.min) {
		a.min = s.Min
	}
	if s.Max > a.max {
		a.max = s.Max
	}
	if s.P50 > a.p50 {
		a.p50 = s.P50
	}
	if s.P95 > a.p95 {
		a.p95 = s.P95
	}
	if s.P99 > a.p99 {
		a.p99 = s.P99
	}
	a.avgNum += int64(s.Avg) * int64(s.Requests)
	a.avgDen += s.Requests
}

func (a *stepAccumulator) result() report.StepReport {
	out := report.StepReport{
		Name:       a.name,
		Requests:   a.requests,
		Errors:     a.errors,
		Status:     a.status,
		ErrorTypes: a.errTypes,
		Min:        a.min,
		Max:        a.max,
		P50:        a.p50,
		P95:        a.p95,
		P99:        a.p99,
	}
	if a.avgDen > 0 {
		out.Avg = time.Duration(a.avgNum / int64(a.avgDen))
	}
	return out
}
