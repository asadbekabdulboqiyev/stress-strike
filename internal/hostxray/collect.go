package hostxray

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync/atomic"
	"time"
)

// The paths below are compile-time constants. Capability detection and the
// Linux collector only ever read these fixed locations, which is why the
// package takes no path flags and cannot be pointed at arbitrary files.
const (
	procMount    = "/proc"
	procLoadAvg  = "/proc/loadavg"
	procMemInfo  = "/proc/meminfo"
	procNetDev   = "/proc/net/dev"
	procStat     = "/proc/stat"
	procPressure = "/proc/pressure"
	btfVMLinux   = "/sys/kernel/btf/vmlinux"
)

// Collector is the platform-specific sampling backend. Collect returns one
// aggregate Sample; successive calls may derive deltas from the previous one,
// so a Collector is stateful and must not be shared between goroutines.
type Collector interface {
	Collect(ctx context.Context) (Sample, error)
	Capabilities() Capabilities
	Close() error
}

// Agent owns an opt-in collector and enforces the sampling bounds. It is safe
// to run only one collection at a time; Run and Stream return an error if
// another collection is already in flight.
type Agent struct {
	opts      Options
	collector Collector
	running   atomic.Bool
}

// New validates opts and constructs an Agent. It returns ErrNotOptedIn when
// opts.OptIn is false, before touching the host, so an accidental invocation
// collects nothing at all.
//
// Defaults: Interval 2s, Duration 30s, Redact false (the CLI defaults it on).
// A caller that sets neither Duration nor MaxSamples gets the 30s default; a
// caller that wants to stream indefinitely must set MaxSamples and cancel the
// context.
func New(opts Options) (*Agent, error) {
	if !opts.OptIn {
		return nil, ErrNotOptedIn
	}
	opts = normalizeOptions(opts)
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	collector, err := newPlatformCollector(opts)
	if err != nil {
		return nil, fmt.Errorf("host xray: init collector: %w", err)
	}
	return &Agent{opts: opts, collector: collector}, nil
}

// Options returns a copy of the normalized options in force.
func (a *Agent) Options() Options {
	out := a.opts
	out.Labels = cloneLabels(a.opts.Labels)
	return out
}

// Capabilities reports what evidence this host could provide. It is a pure
// read-only probe; it does not start a collection.
func (a *Agent) Capabilities() Capabilities {
	return a.collector.Capabilities()
}

// Close releases collector state. It is nil-safe and safe to call twice.
func (a *Agent) Close() error {
	if a == nil || a.collector == nil {
		return nil
	}
	return a.collector.Close()
}

// Run collects up to the configured sample limit and returns the samples
// gathered so far. On context cancellation it returns the partial result
// together with ctx.Err(); callers that treat an interrupt as a normal stop
// should compare with errors.Is(err, context.Canceled).
func (a *Agent) Run(ctx context.Context) ([]Sample, error) {
	if a == nil {
		return nil, errors.New("host xray: nil agent")
	}
	samples := make([]Sample, 0, a.expectedSamples())
	err := a.Stream(ctx, func(s Sample) error {
		samples = append(samples, s)
		return nil
	})
	return samples, err
}

// Stream calls fn with every sample. fn returning an error stops collection and
// that error is returned unchanged. The method never starts a goroutine, so
// there is nothing to leak: cancellation is observed by the same goroutine that
// waits on the ticker.
func (a *Agent) Stream(ctx context.Context, fn func(Sample) error) error {
	if a == nil {
		return errors.New("host xray: nil agent")
	}
	if fn == nil {
		return errors.New("host xray: nil sample callback")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !a.running.CompareAndSwap(false, true) {
		return errors.New("host xray: collection already in progress")
	}
	defer a.running.Store(false)

	interval, limit := a.schedule()

	// The first read primes the delta state (CPU jiffies, network counters)
	// and is not emitted: a first sample would report utilization 0%. On a
	// host where even the runtime is the only source, this call still cannot
	// fail, so a missing /proc never prevents collection.
	if _, err := a.collector.Collect(ctx); err != nil {
		return fmt.Errorf("host xray: prime sample: %w", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	emitted := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := ctx.Err(); err != nil {
				return err
			}
			sample, err := a.collector.Collect(ctx)
			if err != nil {
				return fmt.Errorf("host xray: collect sample: %w", err)
			}
			if sample.Timestamp.IsZero() {
				sample.Timestamp = time.Now().UTC()
			}
			if a.opts.Redact {
				sample = redactSample(sample)
			}
			sample.Labels = mergeLabels(a.opts.Labels, sample.Labels)
			if err := fn(sample); err != nil {
				return err
			}
			emitted++
			if emitted >= limit {
				return nil
			}
		}
	}
}

// expectedSamples returns the number of samples a bounded run will emit. It is
// used only to size the result slice, so a small estimate is harmless.
func (a *Agent) expectedSamples() int {
	_, limit := a.schedule()
	if limit <= 0 {
		return 0
	}
	return limit
}

// schedule resolves the effective tick interval and sample limit. A window
// shorter than one interval produces exactly one sample at the window boundary
// instead of silently producing none.
func (a *Agent) schedule() (time.Duration, int) {
	interval := a.opts.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	limit := -1
	if a.opts.Duration > 0 {
		if interval > a.opts.Duration {
			interval = a.opts.Duration
		}
		limit = int(a.opts.Duration / interval) // #nosec G115 -- validateOptions bounds Duration/Interval to 864000
		if limit < 1 {
			limit = 1
		}
	}
	if a.opts.MaxSamples > 0 && (limit < 0 || a.opts.MaxSamples < limit) {
		limit = a.opts.MaxSamples
	}
	if limit < 1 {
		limit = 1
	}
	return interval, limit
}

func normalizeOptions(opts Options) Options {
	if opts.Interval == 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Duration == 0 && opts.MaxSamples == 0 {
		opts.Duration = DefaultDuration
	}
	opts.Labels = cloneLabels(opts.Labels)
	return opts
}

func validateOptions(opts Options) error {
	if opts.Interval < MinInterval {
		return fmt.Errorf("host xray: interval %s is below the %s minimum", opts.Interval, MinInterval)
	}
	if opts.Interval > MaxInterval {
		return fmt.Errorf("host xray: interval %s exceeds the %s maximum", opts.Interval, MaxInterval)
	}
	if opts.Duration < 0 {
		return errors.New("host xray: duration must not be negative")
	}
	if opts.Duration > MaxDuration {
		return fmt.Errorf("host xray: duration %s exceeds the %s maximum", opts.Duration, MaxDuration)
	}
	if opts.Duration == 0 && opts.MaxSamples == 0 {
		return errors.New("host xray: collection must be bounded by duration or max samples")
	}
	if opts.MaxSamples < 0 {
		return errors.New("host xray: max samples must not be negative")
	}
	if opts.MaxSamples > MaxSamplesLimit {
		return fmt.Errorf("host xray: max samples %d exceeds the %d maximum", opts.MaxSamples, MaxSamplesLimit)
	}
	return nil
}

// DetectCapabilities reports which evidence sources exist on this host. It
// stats fixed paths only, reads no file contents, and requires no opt-in.
//
// DeepTracingPossible means "a future eBPF backend would have the kernel type
// information it needs", not "Sift may load eBPF programs here". Loading would
// additionally require CAP_BPF/CAP_PERFMON, an unprivileged-bpf policy or
// root, and explicit operator authorization; this build never attempts it.
func DetectCapabilities() Capabilities {
	caps := Capabilities{
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		DetectedAt: time.Now().UTC(),
	}
	if runtime.GOOS == "linux" {
		caps.Source = SourceLinuxProc
		caps.ProcAvailable = exists(procMount)
		caps.ProcLoadAvg = exists(procLoadAvg)
		caps.ProcMemInfo = exists(procMemInfo)
		caps.ProcNetDev = exists(procNetDev)
		caps.ProcStat = exists(procStat)
		caps.ProcPressure = exists(procPressure)
		caps.BTFVMLinux = exists(btfVMLinux)
		caps.DeepTracingPossible = caps.ProcAvailable && caps.BTFVMLinux

		switch {
		case !caps.ProcAvailable:
			caps.Notes = append(caps.Notes, "/proc is not mounted; only Go runtime metrics are available")
		default:
			if !caps.ProcPressure {
				caps.Notes = append(caps.Notes, "/proc/pressure is not exposed, so memory/IO stall rules cannot fire")
			}
		}
		if !caps.BTFVMLinux {
			caps.Notes = append(caps.Notes, "/sys/kernel/btf/vmlinux is absent; a future eBPF backend would need BTF or kernel headers")
		}
		caps.Notes = append(caps.Notes, "this build never loads eBPF programs: it reads aggregate /proc counters and reports capability facts only")
		return caps
	}

	caps.Source = SourceRuntime
	caps.Notes = append(caps.Notes,
		"this platform has no /proc or BTF, so host x-ray samples Go runtime metrics of the Sift process",
		"kernel-level evidence requires a Linux host and a future eBPF backend; no program is loaded",
	)
	return caps
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// runtimeSnapshot reads the Go runtime view. It is always cheap and always
// available, which makes it a useful baseline even when /proc works.
func runtimeSnapshot() RuntimeStats {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	lastPause := uint64(0)
	if mem.NumGC > 0 {
		idx := (uint64(mem.NumGC) + 255) % 256
		lastPause = mem.PauseNs[idx]
	}
	return RuntimeStats{
		Goroutines:        runtime.NumGoroutine(),
		GOMAXPROCS:        runtime.GOMAXPROCS(0),
		HeapAllocBytes:    mem.HeapAlloc,
		HeapInuseBytes:    mem.HeapInuse,
		HeapObjects:       mem.HeapObjects,
		GCCount:           mem.NumGC,
		GCPauseTotalNanos: mem.PauseTotalNs,
		GCPauseLastNanos:  lastPause,
		Available:         true,
	}
}

// redactSample replaces interface names with aliases that preserve the
// per-sample ordering but reveal nothing about the host's network layout. The
// alias mapping is derived from the sorted names, so "iface-0" refers to the
// same interface across samples of one collection.
func redactSample(s Sample) Sample {
	if len(s.Net.Interfaces) > 0 {
		names := make([]string, 0, len(s.Net.Interfaces))
		unique := make(map[string]struct{}, len(s.Net.Interfaces))
		for _, iface := range s.Net.Interfaces {
			if _, ok := unique[iface.Name]; ok {
				continue
			}
			unique[iface.Name] = struct{}{}
			names = append(names, iface.Name)
		}
		sort.Strings(names)
		aliases := make(map[string]string, len(names))
		for i, name := range names {
			aliases[name] = fmt.Sprintf("iface-%d", i)
		}
		interfaces := make([]InterfaceCounters, len(s.Net.Interfaces))
		copy(interfaces, s.Net.Interfaces)
		for i := range interfaces {
			if alias, ok := aliases[interfaces[i].Name]; ok {
				interfaces[i].Name = alias
			}
		}
		s.Net.Interfaces = interfaces
	}
	s.Net.Aggregate.Name = "aggregate"
	return s
}

func mergeLabels(optsLabels, sampleLabels map[string]string) map[string]string {
	if len(optsLabels) == 0 && len(sampleLabels) == 0 {
		return nil
	}
	out := make(map[string]string, len(optsLabels)+len(sampleLabels))
	for k, v := range optsLabels {
		out[k] = v
	}
	for k, v := range sampleLabels {
		out[k] = v
	}
	return out
}

func cloneLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
