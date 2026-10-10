package metrics

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// statusArraySize covers the whole HTTP status range (100-599). Codes inside it
// are counted in a plain array of atomics, so recording one takes no lock at
// all; anything outside the range falls back to a map.
const statusArraySize = 600

type StepStats struct {
	Name    string
	Latency *Histogram
	status  [statusArraySize]atomic.Uint64
	// statusOther holds codes outside the HTTP range (protocol-level results
	// from the gRPC, WebSocket and raw TCP/UDP clients).
	statusOther map[int]*atomic.Uint64
	// errCount is a running total maintained by Record. ErrorCount reads it
	// directly instead of summing the per-name map, which is what the live
	// progress display and the dashboard call several times a second.
	errCount atomic.Uint64
	errors  map[string]*atomic.Uint64
	mu      sync.Mutex
}

func NewStepStats(name string) *StepStats {
	return &StepStats{
		Name:        name,
		Latency:     &Histogram{},
		statusOther: make(map[int]*atomic.Uint64),
		errors:      make(map[string]*atomic.Uint64),
	}
}

func (s *StepStats) Record(latency time.Duration, status int, errName string) {
	s.Latency.Add(latency)
	if status > 0 {
		if status < statusArraySize {
			// The common case: an HTTP code, counted without locking.
			s.status[status].Add(1)
		} else {
			s.mu.Lock()
			c, ok := s.statusOther[status]
			if !ok {
				c = &atomic.Uint64{}
				s.statusOther[status] = c
			}
			s.mu.Unlock()
			c.Add(1)
		}
	}
	if errName != "" {
		// The counter is bumped before the per-name lookup so a reader that
		// races this update never sees a total lower than the names it sums.
		s.errCount.Add(1)
		s.mu.Lock()
		c, ok := s.errors[errName]
		if !ok {
			c = &atomic.Uint64{}
			s.errors[errName] = c
		}
		s.mu.Unlock()
		c.Add(1)
	}
}

func (s *StepStats) StatusCodes() map[int]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int]uint64, len(s.statusOther)+4)
	for code := range s.status {
		if n := s.status[code].Load(); n > 0 {
			out[code] = n
		}
	}
	for code, c := range s.statusOther {
		out[code] = c.Load()
	}
	return out
}

func (s *StepStats) Errors() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.errors))
	for name, c := range s.errors {
		out[name] = c.Load()
	}
	return out
}

// ErrorCount returns the total number of errored requests recorded for this
// step. It is a single atomic load: the counter is maintained by Record, so
// this no longer walks the per-error-name map.
func (s *StepStats) ErrorCount() uint64 {
	return s.errCount.Load()
}

func (s *StepStats) Requests() uint64 {
	return s.Latency.Count()
}

type Telemetry struct {
	Start       time.Time
	End         time.Time
	Overall     *StepStats
	Steps       []*StepStats
	ActiveUsers atomic.Int64
	PeakUsers   atomic.Int64
	Timeline    Timeline
	warmupUntil atomic.Int64
	// endUnixNano mirrors End for lock-free reads while a run is still live:
	// Elapsed() must be safe to call concurrently with Finish().
	endUnixNano atomic.Int64
}

func NewTelemetry() *Telemetry {
	return &Telemetry{
		Start:   time.Now(),
		Overall: NewStepStats("overall"),
	}
}

func (t *Telemetry) SetWarmup(d time.Duration) {
	if d <= 0 {
		return
	}
	t.warmupUntil.Store(time.Now().Add(d).UnixNano())
}

func (t *Telemetry) Recording() bool {
	until := t.warmupUntil.Load()
	if until == 0 {
		return true
	}
	return time.Now().UnixNano() >= until
}

func (t *Telemetry) AddStep(stats *StepStats) {
	t.Steps = append(t.Steps, stats)
}

func (t *Telemetry) Finish() {
	now := time.Now()
	t.End = now
	t.endUnixNano.Store(now.UnixNano())
}

func (t *Telemetry) Elapsed() time.Duration {
	if n := t.endUnixNano.Load(); n != 0 {
		return time.Unix(0, n).Sub(t.Start)
	}
	return time.Since(t.Start)
}

func (t *Telemetry) TotalRequests() uint64 {
	var n uint64
	for _, s := range t.Steps {
		n += s.Requests()
	}
	return n
}

func (t *Telemetry) TotalErrors() uint64 {
	var n uint64
	for _, s := range t.Steps {
		n += s.ErrorCount()
	}
	return n
}

func (t *Telemetry) RPS() float64 {
	d := t.Elapsed().Seconds()
	if d <= 0 {
		return 0
	}
	return float64(t.TotalRequests()) / d
}

func (t *Telemetry) StatusCodes() map[int]uint64 {
	out := make(map[int]uint64)
	for _, s := range t.Steps {
		for code, n := range s.StatusCodes() {
			out[code] += n
		}
	}
	return out
}

func (t *Telemetry) Errors() map[string]uint64 {
	out := make(map[string]uint64)
	for _, s := range t.Steps {
		for name, n := range s.Errors() {
			out[name] += n
		}
	}
	return out
}

func SortedStatusCodes(codes map[int]uint64) []int {
	keys := make([]int, 0, len(codes))
	for code := range codes {
		keys = append(keys, code)
	}
	sort.Ints(keys)
	return keys
}

func SortedErrors(errs map[string]uint64) []string {
	keys := make([]string, 0, len(errs))
	for name := range errs {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys
}

type ErrorStat struct {
	Name  string
	Count uint64
}

func TopErrors(errs map[string]uint64, n int) []ErrorStat {
	list := make([]ErrorStat, 0, len(errs))
	for name, count := range errs {
		list = append(list, ErrorStat{Name: name, Count: count})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count == list[j].Count {
			return list[i].Name < list[j].Name
		}
		return list[i].Count > list[j].Count
	})
	if n > 0 && len(list) > n {
		list = list[:n]
	}
	return list
}
