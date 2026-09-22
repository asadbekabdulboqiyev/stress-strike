package dashboard

import (
	"fmt"
	"sync"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
)

// EngineBridge connects the load engine to the dashboard
type EngineBridge struct {
	server *Server

	mu        sync.Mutex
	stopCh    chan struct{}
	stopped   bool
	finished  bool
	config    *RunConfig
	startTime time.Time
	lastSnap  *LiveSnapshot

	// Per-request bookkeeping (RecordRequest path). Snapshots pushed from the
	// engine telemetry already carry authoritative totals, so these are only
	// used when the caller drives the bridge with RecordRequest instead.
	hist        metrics.Histogram
	totalReqs   uint64
	totalErrors uint64
	statusCodes map[int]uint64
}

func NewEngineBridge(server *Server) *EngineBridge {
	return &EngineBridge{
		server:      server,
		stopCh:      make(chan struct{}),
		statusCodes: make(map[int]uint64),
	}
}

// StartRun initializes a new load test run. It fully resets the run state —
// counters, last snapshot, stopped/finished flags and the stop channel — so a
// new run can always be started after a previous run completed, stopped or
// failed.
func (b *EngineBridge) StartRun(config *RunConfig) {
	if config == nil {
		config = &RunConfig{}
	}
	b.mu.Lock()
	b.stopCh = make(chan struct{})
	b.stopped = false
	b.finished = false
	b.config = config
	b.startTime = time.Now()
	b.lastSnap = nil
	b.hist = metrics.Histogram{}
	b.totalReqs = 0
	b.totalErrors = 0
	b.statusCodes = make(map[int]uint64)
	b.mu.Unlock()

	b.server.SetRunState(&RunState{
		Status:    "running",
		Config:    config,
		StartTime: b.startTime,
		Duration:  time.Duration(config.DurationSeconds) * time.Second,
	})
}

// StopRun stops the current run — safe to call multiple times and across runs.
// Each StartRun installs a fresh stop channel, so a second run can always be
// stopped even if a previous one already hit StopRun. A stop request that
// races a completed/failed run is ignored so it cannot overwrite the terminal
// state.
func (b *EngineBridge) StopRun() {
	b.mu.Lock()
	if b.stopped || b.finished {
		b.mu.Unlock()
		return
	}
	b.stopped = true
	stop := b.stopCh
	b.mu.Unlock()

	select {
	case <-stop:
	default:
		close(stop)
	}
	b.pushState("stopped")
}

// IsStopped returns true if the current run was stopped via StopRun
func (b *EngineBridge) IsStopped() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopped
}

// PushSnapshot receives a live snapshot from the engine and forwards it to the
// dashboard. Snapshots should be built from engine telemetry via
// SnapshotFromTelemetry (or any other source that already carries the latency
// percentiles stored on LiveSnapshot).
func (b *EngineBridge) PushSnapshot(snap *LiveSnapshot) {
	if snap == nil {
		return
	}
	b.mu.Lock()
	if b.config == nil || b.stopped || b.finished {
		b.mu.Unlock()
		return
	}
	b.lastSnap = snap
	b.mu.Unlock()

	b.server.UpdateSnapshot(snap)
	b.pushState("running")
}

// RecordRequest records a single request result (per-request counting path).
// Bounded latency samples are accumulated in a histogram so the emitted
// snapshot carries real P50/P95/P99/Avg/Max values instead of zeros.
func (b *EngineBridge) RecordRequest(statusCode int, latency time.Duration, isError bool) {
	b.mu.Lock()
	if b.config == nil {
		b.mu.Unlock()
		return
	}
	b.hist.Add(latency)
	b.totalReqs++
	if statusCode > 0 {
		b.statusCodes[statusCode]++
	}
	if isError {
		b.totalErrors++
	}
	elapsed := time.Since(b.startTime)
	elapsedSec := elapsed.Seconds()
	if elapsedSec <= 0 {
		elapsedSec = 0.001 // avoid division by zero
	}
	rps := float64(b.totalReqs) / elapsedSec
	var errorRate float64
	if b.totalReqs > 0 {
		errorRate = float64(b.totalErrors) / float64(b.totalReqs) * 100
	}
	hs := b.hist.Snapshot()
	snap := &LiveSnapshot{
		Timestamp:   time.Now(),
		RPS:         rps,
		TotalReq:    b.totalReqs,
		TotalErrors: b.totalErrors,
		ErrorRate:   errorRate,
		P50Latency:  latencyMillis(hs.Percentile(0.50)),
		P95Latency:  latencyMillis(hs.Percentile(0.95)),
		P99Latency:  latencyMillis(hs.Percentile(0.99)),
		AvgLatency:  latencyMillis(hs.Average),
		MaxLatency:  latencyMillis(hs.Max),
		StatusCodes: cloneStatusCodes(b.statusCodes),
	}
	b.mu.Unlock()

	b.server.UpdateSnapshot(snap)
	b.pushState("running")
}

// SnapshotFromTelemetry converts the engine's live telemetry into a dashboard
// LiveSnapshot, filling every latency metric (P50/P95/P99/Avg/Max) plus RPS,
// error rate, active users and status codes.
func (b *EngineBridge) SnapshotFromTelemetry(tel *metrics.Telemetry) *LiveSnapshot {
	if tel == nil {
		return nil
	}
	reqs := tel.TotalRequests()
	errs := tel.TotalErrors()
	var errorRate float64
	if reqs > 0 {
		errorRate = float64(errs) / float64(reqs) * 100
	}
	hs := tel.Overall.Latency.Snapshot()
	return &LiveSnapshot{
		Timestamp:   time.Now(),
		RPS:         tel.RPS(),
		TotalReq:    reqs,
		TotalErrors: errs,
		ErrorRate:   errorRate,
		P50Latency:  latencyMillis(hs.Percentile(0.50)),
		P95Latency:  latencyMillis(hs.Percentile(0.95)),
		P99Latency:  latencyMillis(hs.Percentile(0.99)),
		AvgLatency:  latencyMillis(hs.Average),
		MaxLatency:  latencyMillis(hs.Max),
		ActiveUsers: int(tel.ActiveUsers.Load()),
		StatusCodes: tel.StatusCodes(),
	}
}

// RunComplete marks the run as finished. When the run was stopped it keeps the
// "stopped" state and still records a (partial) history entry; otherwise the
// state becomes "completed". Safe to call once per run.
func (b *EngineBridge) RunComplete() {
	b.mu.Lock()
	if b.finished {
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()
	b.finish(false, "")
}

// RunFailed marks the run as failed, surfacing the error message on the run
// state. Nothing is added to history for a failed run.
func (b *EngineBridge) RunFailed(err error) {
	b.mu.Lock()
	if b.finished {
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	b.finish(true, msg)
}

// finish records the final run state and, unless the run failed, adds a
// history entry derived from the last pushed snapshot.
func (b *EngineBridge) finish(failed bool, errMsg string) {
	b.mu.Lock()
	if b.finished || b.config == nil {
		b.mu.Unlock()
		return
	}
	b.finished = true
	stopped := b.stopped
	config := b.config
	startTime := b.startTime
	snap := b.lastSnap
	elapsed := time.Since(startTime)
	b.mu.Unlock()

	if failed {
		b.server.SetRunState(&RunState{
			Status:    "failed",
			Config:    config,
			StartTime: startTime,
			EndTime:   time.Now(),
			Elapsed:   elapsed,
			Error:     errMsg,
		})
		return
	}

	status := "completed"
	if stopped {
		status = "stopped"
	}

	progress := 100.0
	if config.DurationSeconds > 0 {
		p := elapsed.Seconds() / float64(config.DurationSeconds) * 100
		if p > 0 && p < 100 {
			progress = p
		}
	}

	totalReqs, totalErrors := uint64(0), uint64(0)
	var rps, p50, p95, p99, avg, maxLat float64
	statusCodes := map[int]uint64{}
	if snap != nil {
		totalReqs = snap.TotalReq
		totalErrors = snap.TotalErrors
		rps = snap.RPS
		p50 = snap.P50Latency
		p95 = snap.P95Latency
		p99 = snap.P99Latency
		avg = snap.AvgLatency
		maxLat = snap.MaxLatency
		statusCodes = snap.StatusCodes
	}

	duration := time.Duration(config.DurationSeconds) * time.Second
	b.server.SetRunState(&RunState{
		Status:    status,
		Config:    config,
		StartTime: startTime,
		EndTime:   time.Now(),
		Elapsed:   elapsed,
		Duration:  duration,
		Progress:  progress,
	})

	entry := HistoryEntry{
		ID:        fmt.Sprintf("run-%d", startTime.UnixMilli()),
		Timestamp: startTime,
		Config:    *config,
		Result: RunResult{
			TotalRequests: totalReqs,
			TotalErrors:   totalErrors,
			RPS:           rps,
			P50Latency:    p50,
			P95Latency:    p95,
			P99Latency:    p99,
			AvgLatency:    avg,
			MaxLatency:    maxLat,
			StatusCodes:   statusCodes,
		},
		Duration: elapsed.Round(time.Millisecond).String(),
	}
	b.server.AddHistoryEntry(entry)
}

// pushState broadcasts a RunState derived from the bridge's config and start
// time, computing elapsed time and progress.
func (b *EngineBridge) pushState(status string) {
	b.mu.Lock()
	config := b.config
	start := b.startTime
	b.mu.Unlock()

	elapsed := time.Since(start)
	progress := 0.0
	if config != nil && config.DurationSeconds > 0 {
		progress = elapsed.Seconds() / float64(config.DurationSeconds) * 100
		if progress > 100 {
			progress = 100
		}
	}
	var duration time.Duration
	if config != nil {
		duration = time.Duration(config.DurationSeconds) * time.Second
	}

	b.server.SetRunState(&RunState{
		Status:    status,
		Config:    config,
		StartTime: start,
		Elapsed:   elapsed,
		Duration:  duration,
		Progress:  progress,
	})
}

func latencyMillis(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func cloneStatusCodes(in map[int]uint64) map[int]uint64 {
	out := make(map[int]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
