package dashboard

import (
	"fmt"
	"sync"
	"time"
)

// EngineBridge connects the load testing engine to the dashboard
type EngineBridge struct {
	server      *Server
	snapshotCh  chan *LiveSnapshot
	stopCh      chan struct{}
	stopOnce    sync.Once
	wg          sync.WaitGroup
	startTime   time.Time
	config      *RunConfig
	totalUsers  int
	totalReqs   uint64
	totalErrors uint64
	statusCodes map[int]uint64
	mu          sync.Mutex
}

func NewEngineBridge(server *Server) *EngineBridge {
	return &EngineBridge{
		server:      server,
		snapshotCh:  make(chan *LiveSnapshot, 100),
		stopCh:      make(chan struct{}),
		statusCodes: make(map[int]uint64),
	}
}

// StartRun initializes a new load test run
func (b *EngineBridge) StartRun(config *RunConfig) {
	b.mu.Lock()
	b.startTime = time.Now()
	b.config = config
	b.totalUsers = config.Users
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

// StopRun stops the current run — safe to call multiple times
func (b *EngineBridge) StopRun() {
	b.stopOnce.Do(func() {
		close(b.stopCh)
	})
	b.server.SetRunState(&RunState{Status: "stopped"})
}

// IsStopped returns true if StopRun was called
func (b *EngineBridge) IsStopped() bool {
	select {
	case <-b.stopCh:
		return true
	default:
		return false
	}
}

// PushSnapshot receives a live snapshot from the engine
func (b *EngineBridge) PushSnapshot(snap *LiveSnapshot) {
	select {
	case b.snapshotCh <- snap:
	default:
		// drop if channel full
	}
}

// RecordRequest records a single request result
func (b *EngineBridge) RecordRequest(statusCode int, latency time.Duration, isError bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.totalReqs++
	b.statusCodes[statusCode]++

	if isError {
		b.totalErrors++
	}

	// Compute live snapshot
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

	progress := float64(0)
	if b.config != nil && b.config.DurationSeconds > 0 {
		progress = elapsedSec / float64(b.config.DurationSeconds) * 100
		if progress > 100 {
			progress = 100
		}
	}

	snap := &LiveSnapshot{
		Timestamp:   time.Now(),
		RPS:         rps,
		TotalReq:    b.totalReqs,
		TotalErrors: b.totalErrors,
		ErrorRate:   errorRate,
		ActiveUsers: b.totalUsers,
		StatusCodes: b.statusCodes,
	}

	b.server.UpdateSnapshot(snap)

	// Update run state progress
	b.server.SetRunState(&RunState{
		Status:    "running",
		Config:    b.config,
		StartTime: b.startTime,
		Duration:  time.Duration(b.config.DurationSeconds) * time.Second,
		Elapsed:   elapsed,
		Progress:  progress,
	})
}

// RunComplete marks the run as completed using the bridge's own record
// counters (the simulated path). Real-engine flows should call
// RunCompleteFromSnapshot instead so final telemetry lands in history.
func (b *EngineBridge) RunComplete() {
	b.RunCompleteFromSnapshot(nil)
}

// RunCompleteFromSnapshot marks the run as completed. When a final live
// snapshot (e.g. from real engine telemetry) is provided, its totals take
// precedence over the bridge's record counters, so history reflects real
// traffic.
func (b *EngineBridge) RunCompleteFromSnapshot(snap *LiveSnapshot) {
	b.mu.Lock()
	elapsed := time.Since(b.startTime)
	elapsedSec := elapsed.Seconds()
	if elapsedSec <= 0 {
		elapsedSec = 0.001
	}
	config := b.config
	startTime := b.startTime
	totalReqs := b.totalReqs
	totalErrors := b.totalErrors
	statusCodes := make(map[int]uint64, len(b.statusCodes))
	for k, v := range b.statusCodes {
		statusCodes[k] = v
	}
	b.mu.Unlock()

	if snap != nil {
		totalReqs = snap.TotalReq
		totalErrors = snap.TotalErrors
		if snap.StatusCodes != nil {
			statusCodes = snap.StatusCodes
		}
	}
	rps := float64(totalReqs) / elapsedSec

	if config == nil {
		b.server.SetRunState(&RunState{
			Status:  "completed",
			EndTime: time.Now(),
		})
		return
	}

	b.server.SetRunState(&RunState{
		Status:    "completed",
		Config:    config,
		StartTime: startTime,
		EndTime:   time.Now(),
		Elapsed:   elapsed,
		Duration:  time.Duration(config.DurationSeconds) * time.Second,
		Progress:  100,
	})

	// Add to history
	entry := HistoryEntry{
		ID:        fmt.Sprintf("run-%d", startTime.UnixMilli()),
		Timestamp: startTime,
		Config:    *config,
		Result: RunResult{
			TotalRequests: totalReqs,
			TotalErrors:   totalErrors,
			RPS:           rps,
			StatusCodes:   statusCodes,
		},
		Duration: elapsed.String(),
	}
	b.server.AddHistoryEntry(entry)
}

// RunFailed marks the run as failed
func (b *EngineBridge) RunFailed(err error) {
	b.mu.Lock()
	config := b.config
	startTime := b.startTime
	b.mu.Unlock()

	b.server.SetRunState(&RunState{
		Status:    "failed",
		Config:    config,
		StartTime: startTime,
		EndTime:   time.Now(),
		Elapsed:   time.Since(startTime),
	})
}
