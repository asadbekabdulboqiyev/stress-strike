package hostxray

import (
	"errors"
	"time"
)

// Collection bounds. A caller cannot widen these without changing the package:
// a very small interval would turn a diagnostic sampler into a hot loop, and a
// multi-day window would accumulate an unbounded artifact by default.
const (
	// MinInterval is the fastest allowed sampling interval.
	MinInterval = 100 * time.Millisecond
	// MaxInterval is the slowest allowed sampling interval.
	MaxInterval = 60 * time.Second
	// MaxDuration caps a single collection window at 24 hours.
	MaxDuration = 24 * time.Hour
	// MaxSamplesLimit caps the number of emitted samples regardless of flags.
	MaxSamplesLimit = 100_000

	// DefaultInterval is used when Options.Interval is zero.
	DefaultInterval = 2 * time.Second
	// DefaultDuration is used when both Duration and MaxSamples are zero.
	DefaultDuration = 30 * time.Second
)

// Correlation defaults.
const (
	// DefaultCorrelateWindow is how far before an external signal the agent
	// looks for host evidence.
	DefaultCorrelateWindow = 5 * time.Second
	// DefaultMinOverlap is the number of qualifying signal windows that must
	// also show host evidence before an indicator is emitted.
	DefaultMinOverlap = 2
	// DefaultMinSamples is the minimum number of samples *and* signals needed
	// before correlation is attempted at all.
	DefaultMinSamples = 2
)

// Evidence sources recorded on every Sample.
const (
	// SourceLinuxProc means the sample came from aggregate /proc counters.
	SourceLinuxProc = "linux-proc"
	// SourceRuntime means the sample came from Go runtime metrics only.
	SourceRuntime = "go-runtime"
)

// Indicator severity levels. They describe how strongly the evidence reads,
// not how certain the cause is.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Confidence levels. Confidence is derived from how many qualifying windows
// overlap, never from a causal model.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// ErrNotOptedIn is returned by New when Options.OptIn is false. The CLI maps
// it to a refused-exit with an explanation instead of collecting silently.
var ErrNotOptedIn = errors.New("host x-ray collection is opt-in: set Options.OptIn (CLI: pass --allow)")

// Options configures an Agent. The zero value is intentionally invalid: it is
// not opted in, so New returns ErrNotOptedIn rather than starting collection.
type Options struct {
	// Interval is the sampling period. Zero means DefaultInterval; values
	// outside [MinInterval, MaxInterval] are rejected.
	Interval time.Duration
	// Duration bounds the whole collection window. Zero means DefaultDuration
	// unless MaxSamples is set. Negative or greater than MaxDuration is
	// rejected.
	Duration time.Duration
	// MaxSamples stops collection after this many samples. Zero derives the
	// limit from Duration. Values outside [1, MaxSamplesLimit] are rejected.
	MaxSamples int
	// Redact replaces network interface names with stable aliases
	// (iface-0, iface-1, ...) in emitted samples. The CLI defaults this to
	// true. Even when false, no host identifier beyond the interface name is
	// ever exposed, because nothing else is collected.
	Redact bool
	// OptIn must be true. It records that the operator was told what is
	// collected and confirmed they are authorized to observe the host.
	OptIn bool
	// Labels are operator-supplied annotations (run id, scenario, worker)
	// copied onto every sample. They are never read from the host.
	Labels map[string]string
}

// Sample is one aggregate observation of the host, or of the Go runtime when
// kernel evidence is unavailable. Every field is a counter or a summary; there
// is no per-process, per-connection, or per-packet data.
type Sample struct {
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Platform  string            `json:"platform"`
	Load      LoadAverage       `json:"load"`
	CPU       CPUStats          `json:"cpu"`
	Mem       MemoryStats       `json:"memory"`
	Net       NetStats          `json:"network"`
	PSI       PSIStats          `json:"psi"`
	Runtime   RuntimeStats      `json:"runtime"`
	Labels    map[string]string `json:"labels,omitempty"`
	Notes     []string          `json:"notes,omitempty"`
}

// LoadAverage mirrors /proc/loadavg.
type LoadAverage struct {
	One       float64 `json:"one"`
	Five      float64 `json:"five"`
	Fifteen   float64 `json:"fifteen"`
	Runnable  int     `json:"runnable"`
	Processes int     `json:"processes"`
	Available bool    `json:"available"`
}

// CPUJiffies holds the aggregate "cpu" line from /proc/stat. The values are
// cumulative kernel clock ticks, useful only as deltas between two samples.
type CPUJiffies struct {
	User      uint64 `json:"user_jiffies"`
	Nice      uint64 `json:"nice_jiffies"`
	System    uint64 `json:"system_jiffies"`
	Idle      uint64 `json:"idle_jiffies"`
	IOWait    uint64 `json:"iowait_jiffies"`
	IRQ       uint64 `json:"irq_jiffies"`
	SoftIRQ   uint64 `json:"softirq_jiffies"`
	Steal     uint64 `json:"steal_jiffies"`
	Guest     uint64 `json:"guest_jiffies"`
	GuestNice uint64 `json:"guest_nice_jiffies"`
}

// Total returns the sum of all jiffy buckets. Guest time is already included
// in User/Nice on Linux, so it is not counted again here.
func (c CPUJiffies) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// CPUStats is the derived CPU view: the raw counters plus the utilization
// delta since the previous sample. UtilizationPct counts every tick that was
// not idle, which includes iowait; IOWaitPct isolates the storage-stall share.
type CPUStats struct {
	CPUJiffies
	UtilizationPct float64       `json:"utilization_pct"`
	IOWaitPct      float64       `json:"iowait_pct"`
	Interval       time.Duration `json:"interval_ns"`
	Available      bool          `json:"available"`
}

// MemoryStats mirrors the handful of /proc/meminfo keys the agent uses. Values
// are bytes; Linux reports kB and the parser converts.
type MemoryStats struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	FreeBytes      uint64  `json:"free_bytes"`
	BuffersBytes   uint64  `json:"buffers_bytes"`
	CachedBytes    uint64  `json:"cached_bytes"`
	UsedPct        float64 `json:"used_pct"`
	Available      bool    `json:"available"`
}

// InterfaceCounters is one interface's cumulative counters from /proc/net/dev.
// Name is the only host identifier in a sample and is redacted by default.
type InterfaceCounters struct {
	Name      string `json:"name"`
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	RxDrops   uint64 `json:"rx_drops"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
	TxDrops   uint64 `json:"tx_drops"`
}

// NetStats holds per-interface counters plus an aggregate. The aggregate sums
// every interface the kernel exposes, loopback included: these are real host
// I/O counters, and consumers that need to exclude loopback can subtract the
// "lo" entry themselves. Errors and drops are summed separately from bytes.
type NetStats struct {
	Interfaces []InterfaceCounters `json:"interfaces,omitempty"`
	Aggregate  InterfaceCounters   `json:"aggregate"`
	Available  bool                `json:"available"`
}

// Pressure is one /proc/pressure resource line. Avg10/60/300 are percentages
// of wall-clock time in which tasks stalled on the resource; TotalMicros is the
// cumulative stall time. HasFull reports whether the kernel exposes the "full"
// line (CPU pressure does not).
type Pressure struct {
	Some10          float64 `json:"some_avg10"`
	Some60          float64 `json:"some_avg60"`
	Some300         float64 `json:"some_avg300"`
	SomeTotalMicros uint64  `json:"some_total_micros"`
	Full10          float64 `json:"full_avg10,omitempty"`
	Full60          float64 `json:"full_avg60,omitempty"`
	Full300         float64 `json:"full_avg300,omitempty"`
	FullTotalMicros uint64  `json:"full_total_micros,omitempty"`
	HasSome         bool    `json:"has_some"`
	HasFull         bool    `json:"has_full"`
}

// PSIStats holds whichever pressure files exist. A missing file is nil, not an
// error: PSI is optional in the kernel config and absent on many hosts.
type PSIStats struct {
	CPU    *Pressure `json:"cpu,omitempty"`
	Memory *Pressure `json:"memory,omitempty"`
	IO     *Pressure `json:"io,omitempty"`
}

// RuntimeStats is the Go runtime fallback view. It is always populated because
// it is cheap and it is the only evidence available off Linux.
type RuntimeStats struct {
	Goroutines        int    `json:"goroutines"`
	GOMAXPROCS        int    `json:"gomaxprocs"`
	HeapAllocBytes    uint64 `json:"heap_alloc_bytes"`
	HeapInuseBytes    uint64 `json:"heap_inuse_bytes"`
	HeapObjects       uint64 `json:"heap_objects"`
	GCCount           uint32 `json:"gc_count"`
	GCPauseTotalNanos uint64 `json:"gc_pause_total_nanos"`
	GCPauseLastNanos  uint64 `json:"gc_pause_last_nanos"`
	Available         bool   `json:"available"`
}

// Capabilities is the result of read-only capability detection. It records
// what evidence *could* be gathered; it never implies that anything was
// loaded or that privilege is available.
type Capabilities struct {
	OS                  string    `json:"os"`
	Arch                string    `json:"arch"`
	Source              string    `json:"source"`
	ProcAvailable       bool      `json:"proc_available"`
	ProcLoadAvg         bool      `json:"proc_loadavg"`
	ProcMemInfo         bool      `json:"proc_meminfo"`
	ProcNetDev          bool      `json:"proc_net_dev"`
	ProcStat            bool      `json:"proc_stat"`
	ProcPressure        bool      `json:"proc_pressure"`
	BTFVMLinux          bool      `json:"btf_vmlinux"`
	DeepTracingPossible bool      `json:"deep_tracing_possible"`
	Notes               []string  `json:"notes,omitempty"`
	DetectedAt          time.Time `json:"detected_at"`
}

// Indicator is one explainable correlation finding. It deliberately carries no
// causal verdict: Title and Evidence describe co-occurrence, Explanation states
// the blind spots, and Confidence is derived from overlap counts.
type Indicator struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence"`
	Title          string   `json:"title"`
	Evidence       []string `json:"evidence"`
	Explanation    string   `json:"explanation"`
	OverlapWindows int      `json:"overlap_windows"`
	WindowSeconds  float64  `json:"window_seconds"`
}

// Signal is one external Sift observation used for correlation (a step, an
// endpoint, or a whole run measured from outside the host). ErrorRate is a
// fraction in [0, 1], not a percentage.
type Signal struct {
	Timestamp time.Time `json:"timestamp"`
	RPS       float64   `json:"rps"`
	P99Ms     float64   `json:"p99_ms"`
	ErrorRate float64   `json:"error_rate"`
	Step      string    `json:"step,omitempty"`
	Endpoint  string    `json:"endpoint,omitempty"`
	Label     string    `json:"label,omitempty"`
}
