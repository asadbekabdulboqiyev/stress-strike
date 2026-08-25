package metrics

import (
	"sync"
	"time"
)

// TimelineSample is one per-second observation of cumulative progress.
type TimelineSample struct {
	Second      int    `json:"second"`
	Requests    uint64 `json:"requests"` // cumulative since start
	Errors      uint64 `json:"errors"`   // cumulative since start
	ActiveUsers int64  `json:"active_users"`
}

// Timeline collects periodic samples in a race-safe slice.
type Timeline struct {
	mu      sync.Mutex
	samples []TimelineSample
}

// Record appends a sample for the given second of the run.
func (tl *Timeline) Record(s TimelineSample) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.samples = append(tl.samples, s)
}

// Snapshot returns a copy of all recorded samples.
func (tl *Timeline) Snapshot() []TimelineSample {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	out := make([]TimelineSample, len(tl.samples))
	copy(out, tl.samples)
	return out
}

// StartSampling launches a background sampler recording one sample per second
// until done is closed or the context finishes. The final partial second is
// captured by calling StopSampling.
func StartSampling(t *Telemetry, tl *Timeline, done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for i := 1; ; i++ {
			select {
			case <-done:
				return
			case <-ticker.C:
				tl.Record(TimelineSample{
					Second:      i,
					Requests:    t.TotalRequests(),
					Errors:      t.TotalErrors(),
					ActiveUsers: t.ActiveUsers.Load(),
				})
			}
		}
	}()
}
