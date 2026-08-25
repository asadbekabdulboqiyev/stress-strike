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

// StopRun stops the current run
func (b *EngineBridge) StopRun() {
	close(b.stopCh)
	b.server.SetRunState(&RunState{Status: "stopped"})
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
	rps := float64(b.totalReqs) / elapsed.Seconds()

	var errorRate float64
	if b.totalReqs > 0 {
		errorRate = float64(b.totalErrors) / float64(b.totalReqs) * 100
	}

	progress := float64(0)
	if b.config != nil && b.config.DurationSeconds > 0 {
		progress = elapsed.Seconds() / float64(b.config.DurationSeconds) * 100
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

// RunComplete marks the run as completed
func (b *EngineBridge) RunComplete() {
	elapsed := time.Since(b.startTime)
	rps := float64(b.totalReqs) / elapsed.Seconds()

	b.server.SetRunState(&RunState{
		Status:    "completed",
		Config:    b.config,
		StartTime: b.startTime,
		EndTime:   time.Now(),
		Elapsed:   elapsed,
		Duration:  time.Duration(b.config.DurationSeconds) * time.Second,
		Progress:  100,
	})

	// Add to history
	entry := HistoryEntry{
		ID:        fmt.Sprintf("run-%d", b.startTime.UnixMilli()),
		Timestamp: b.startTime,
		Config:    *b.config,
		Result: RunResult{
			TotalRequests: b.totalReqs,
			TotalErrors:   b.totalErrors,
			RPS:           rps,
			StatusCodes:   b.statusCodes,
		},
		Duration: elapsed.String(),
	}
	b.server.AddHistoryEntry(entry)
}

// RunFailed marks the run as failed
func (b *EngineBridge) RunFailed(err error) {
	b.server.SetRunState(&RunState{
		Status:    "failed",
		Config:    b.config,
		StartTime: b.startTime,
		EndTime:   time.Now(),
		Elapsed:   time.Since(b.startTime),
	})
}
