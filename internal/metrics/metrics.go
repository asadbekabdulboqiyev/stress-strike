package metrics

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type StepStats struct {
	Name    string
	Latency *Histogram
	status  map[int]*atomic.Uint64
	errors  map[string]*atomic.Uint64
	mu      sync.Mutex
}

func NewStepStats(name string) *StepStats {
	return &StepStats{
		Name:    name,
		Latency: &Histogram{},
		status:  make(map[int]*atomic.Uint64),
		errors:  make(map[string]*atomic.Uint64),
	}
}

func (s *StepStats) Record(latency time.Duration, status int, errName string) {
	s.Latency.Add(latency)
	if status > 0 {
		s.mu.Lock()
		c, ok := s.status[status]
		if !ok {
			c = &atomic.Uint64{}
			s.status[status] = c
		}
		s.mu.Unlock()
		c.Add(1)
	}
	if errName != "" {
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
	out := make(map[int]uint64, len(s.status))
	for code, c := range s.status {
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

func (s *StepStats) ErrorCount() uint64 {
	var n uint64
	for _, c := range s.Errors() {
		n += c
	}
	return n
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
}

func NewTelemetry() *Telemetry {
	return &Telemetry{
		Start:   time.Now(),
		Overall: NewStepStats("overall"),
	}
}

func (t *Telemetry) AddStep(stats *StepStats) {
	t.Steps = append(t.Steps, stats)
}

func (t *Telemetry) Finish() {
	t.End = time.Now()
}

func (t *Telemetry) Elapsed() time.Duration {
	if t.End.IsZero() {
		return time.Since(t.Start)
	}
	return t.End.Sub(t.Start)
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
