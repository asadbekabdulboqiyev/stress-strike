package hostxray

import (
	"fmt"
	"sort"
	"time"
)

// Conservative thresholds for the correlation rules. They are deliberately
// high: the point is to surface strong co-occurrence worth investigating, not
// to page on every wobble.
const (
	cpuSaturationPct = 85.0
	memUsedPct       = 90.0
	psiMemoryStall   = 1.0
	minErrorRate     = 0.01
	minLatencyRiseMs = 20.0
	minGCPauseMs     = 1.0
)

// nonCausalityNote is appended to every indicator. Correlation over aggregate
// counters cannot establish causation, and every report must say so where the
// finding is, not only in a distant limitations section.
const nonCausalityNote = "Correlated evidence only: co-occurrence in time does not establish that the host condition caused the observed symptom, and aggregate counters do not identify a responsible process."

// CorrelateOptions tunes the correlation join.
// The zero value is valid and applies the documented defaults.
type CorrelateOptions struct {
	// Window is how far *before* each external signal the agent looks for host
	// evidence. Default 5s, clamped to [1s, 5m].
	Window time.Duration
	// MinOverlap is the minimum number of qualifying signal windows that must
	// also contain host evidence. Default 2. Raising it trades recall for
	// precision.
	MinOverlap int
	// MinSamples is the minimum number of samples *and* of signals required
	// before any rule is evaluated. Default 2: a single pair of points is not
	// enough to call anything a pattern.
	MinSamples int
}

// Correlate joins host samples with external Sift signals and returns
// explainable indicators. It returns nil when there is not enough data for a
// conservative finding; an empty result is the normal outcome of a healthy or
// short-lived run, not an error.
//
// The join is temporal: for every signal, the agent aggregates the samples in
// [signal.Timestamp-Window, signal.Timestamp]. A signal "qualifies" for a rule
// when its own external values cross that rule's threshold; an indicator is
// emitted only when at least MinOverlap qualifying signals also had host
// evidence in their window. Confidence reflects overlap count and coverage,
// never a causal model.
func Correlate(samples []Sample, signals []Signal, opts CorrelateOptions) []Indicator {
	opts = normalizeCorrelateOptions(opts)
	events := buildSampleEvents(samples)
	sigs := normalizeSignals(signals)
	if len(events) < opts.MinSamples || len(sigs) < opts.MinSamples {
		return nil
	}

	latencyBaseline := median(positiveP99(sigs))
	errorBaseline := median(errorRates(sigs))
	gcBaseline := median(gcPauses(events))

	rules := correlationRules(latencyBaseline, errorBaseline, gcBaseline)
	indicators := make([]Indicator, 0, len(rules))
	for _, rule := range rules {
		if indicator, ok := rule.evaluate(events, sigs, opts); ok {
			indicators = append(indicators, indicator)
		}
	}
	sort.SliceStable(indicators, func(i, j int) bool {
		ri, rj := severityRank(indicators[i].Severity), severityRank(indicators[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return indicators[i].ID < indicators[j].ID
	})
	return indicators
}

func normalizeCorrelateOptions(opts CorrelateOptions) CorrelateOptions {
	if opts.Window <= 0 {
		opts.Window = DefaultCorrelateWindow
	}
	if opts.Window < time.Second {
		opts.Window = time.Second
	}
	if opts.Window > 5*time.Minute {
		opts.Window = 5 * time.Minute
	}
	if opts.MinOverlap <= 0 {
		opts.MinOverlap = DefaultMinOverlap
	}
	if opts.MinOverlap > 20 {
		opts.MinOverlap = 20
	}
	if opts.MinSamples <= 0 {
		opts.MinSamples = DefaultMinSamples
	}
	return opts
}

// sampleEvent is one sample with the deltas that only make sense between two
// consecutive samples already computed.
type sampleEvent struct {
	ts        time.Time
	cpuPct    float64
	cpuValid  bool
	memUsed   float64
	psiMem    float64
	faults    uint64
	gcPauseMs float64
	gcValid   bool
}

func buildSampleEvents(samples []Sample) []sampleEvent {
	valid := make([]Sample, 0, len(samples))
	for _, sample := range samples {
		if sample.Timestamp.IsZero() {
			continue
		}
		valid = append(valid, sample)
	}
	sort.SliceStable(valid, func(i, j int) bool { return valid[i].Timestamp.Before(valid[j].Timestamp) })

	events := make([]sampleEvent, 0, len(valid))
	for i, sample := range valid {
		event := sampleEvent{ts: sample.Timestamp}
		if sample.CPU.Available {
			event.cpuPct = sample.CPU.UtilizationPct
			event.cpuValid = true
		}
		if sample.Mem.Available {
			event.memUsed = sample.Mem.UsedPct
		}
		if sample.PSI.Memory != nil {
			event.psiMem = sample.PSI.Memory.Some10
		}
		if i > 0 {
			prev := valid[i-1]
			if cur, ok := netFaults(sample.Net); ok {
				if before, prevOK := netFaults(prev.Net); prevOK && cur >= before {
					event.faults = cur - before
				}
			}
			if sample.Runtime.Available && prev.Runtime.Available &&
				sample.Runtime.GCCount >= prev.Runtime.GCCount &&
				sample.Runtime.GCPauseTotalNanos >= prev.Runtime.GCPauseTotalNanos {
				if cycles := sample.Runtime.GCCount - prev.Runtime.GCCount; cycles > 0 {
					stall := sample.Runtime.GCPauseTotalNanos - prev.Runtime.GCPauseTotalNanos
					event.gcPauseMs = float64(stall) / float64(cycles) / 1e6
					event.gcValid = true
				}
			}
		}
		events = append(events, event)
	}
	return events
}

// windowStat aggregates the samples inside one signal window. Maxima are used
// for pressure because a single saturated interval is what an operator needs to
// see; the sum/count pair keeps the mean available for evidence text.
type windowStat struct {
	samples    int
	cpuMax     float64
	cpuSum     float64
	cpuCount   int
	memUsedMax float64
	psiMemMax  float64
	faults     uint64
	gcSumMs    float64
	gcCount    int
}

func aggregateWindow(events []sampleEvent) windowStat {
	var stat windowStat
	for _, event := range events {
		stat.samples++
		if event.cpuValid {
			stat.cpuSum += event.cpuPct
			stat.cpuCount++
			if event.cpuPct > stat.cpuMax {
				stat.cpuMax = event.cpuPct
			}
		}
		if event.memUsed > stat.memUsedMax {
			stat.memUsedMax = event.memUsed
		}
		if event.psiMem > stat.psiMemMax {
			stat.psiMemMax = event.psiMem
		}
		stat.faults = saturatingAdd(stat.faults, event.faults)
		if event.gcValid {
			stat.gcSumMs += event.gcPauseMs
			stat.gcCount++
		}
	}
	return stat
}

func (s windowStat) meanCPU() float64 {
	if s.cpuCount == 0 {
		return 0
	}
	return s.cpuSum / float64(s.cpuCount)
}

func (s windowStat) meanGCPauseMs() float64 {
	if s.gcCount == 0 {
		return 0
	}
	return s.gcSumMs / float64(s.gcCount)
}

type correlationRule struct {
	id           string
	title        string
	explanation  string
	host         func(windowStat) bool
	hostDetail   func([]windowStat) string
	signal       func(Signal) bool
	signalDetail func([]Signal) string
	severity     func([]windowStat) string
}

func (r correlationRule) evaluate(events []sampleEvent, signals []Signal, opts CorrelateOptions) (Indicator, bool) {
	denominator := 0
	var hostWindows []windowStat
	var matchedSignals []Signal

	for _, signal := range signals {
		if !r.signal(signal) {
			continue
		}
		denominator++
		from := signal.Timestamp.Add(-opts.Window)
		lo := sort.Search(len(events), func(i int) bool { return !events[i].ts.Before(from) })
		hi := sort.Search(len(events), func(i int) bool { return events[i].ts.After(signal.Timestamp) })
		if lo >= hi {
			continue
		}
		stat := aggregateWindow(events[lo:hi])
		if !r.host(stat) {
			continue
		}
		hostWindows = append(hostWindows, stat)
		matchedSignals = append(matchedSignals, signal)
	}

	overlap := len(hostWindows)
	if denominator == 0 || overlap < opts.MinOverlap {
		return Indicator{}, false
	}
	coverage := float64(overlap) / float64(denominator)
	confidence := confidenceFor(overlap, coverage)
	if confidence == "" {
		return Indicator{}, false
	}

	evidence := make([]string, 0, 4)
	evidence = append(evidence, fmt.Sprintf(
		"%d of %d signal windows meeting the external condition also contained host evidence (%.0f%% overlap, %.0fs lookback window)",
		overlap, denominator, coverage*100, opts.Window.Seconds(),
	))
	if detail := r.hostDetail(hostWindows); detail != "" {
		evidence = append(evidence, detail)
	}
	if detail := r.signalDetail(matchedSignals); detail != "" {
		evidence = append(evidence, detail)
	}

	return Indicator{
		ID:             r.id,
		Severity:       r.severity(hostWindows),
		Confidence:     confidence,
		Title:          r.title,
		Evidence:       evidence,
		Explanation:    r.explanation + " " + nonCausalityNote,
		OverlapWindows: overlap,
		WindowSeconds:  opts.Window.Seconds(),
	}, true
}

func correlationRules(latencyBaseline, errorBaseline, gcBaseline float64) []correlationRule {
	return []correlationRule{
		{
			id:    "hostxray.cpu-latency",
			title: "CPU utilization saturating while Sift p99 latency spikes",
			explanation: fmt.Sprintf(
				"Windows where Sift observed p99 latency at least 1.5x its median (minimum +%.0f ms) were checked against host CPU utilization. CPU utilization counts every non-idle tick, including iowait; a high value can mean useful load, a busy neighbour, or a kernel-side stall.",
				minLatencyRiseMs,
			),
			host: func(stat windowStat) bool {
				return stat.cpuCount > 0 && stat.cpuMax >= cpuSaturationPct
			},
			hostDetail: func(windows []windowStat) string {
				peak, mean, count := 0.0, 0.0, 0
				for _, stat := range windows {
					if stat.cpuMax > peak {
						peak = stat.cpuMax
					}
					mean += stat.cpuSum
					count += stat.cpuCount
				}
				if count == 0 {
					return ""
				}
				return fmt.Sprintf("Host evidence: peak CPU utilization %.1f%%, mean %.1f%% across overlapping windows (threshold %.0f%%).", peak, mean/float64(count), cpuSaturationPct)
			},
			signal: func(signal Signal) bool {
				return latencySpike(signal.P99Ms, latencyBaseline)
			},
			signalDetail: func(signals []Signal) string {
				return fmt.Sprintf("External evidence: peak p99 %.1f ms, median p99 baseline %.1f ms.", peakP99(signals), latencyBaseline)
			},
			severity: func(windows []windowStat) string {
				sum, count := 0.0, 0
				for _, stat := range windows {
					sum += stat.cpuSum
					count += stat.cpuCount
				}
				if count > 0 && sum/float64(count) >= 95 {
					return SeverityCritical
				}
				return SeverityWarning
			},
		},
		{
			id:    "hostxray.memory-latency-errors",
			title: "Memory pressure or high memory use while Sift errors rise",
			explanation: fmt.Sprintf(
				"Windows where Sift's error rate rose by at least one percentage point (and doubled from its median) were checked against memory pressure stall information and memory utilization (%.0f%% threshold). PSI measures the share of wall-clock time tasks stalled waiting for memory reclaim.",
				memUsedPct,
			),
			host: func(stat windowStat) bool {
				return stat.psiMemMax >= psiMemoryStall || stat.memUsedMax >= memUsedPct
			},
			hostDetail: func(windows []windowStat) string {
				psiPeak, memPeak := 0.0, 0.0
				for _, stat := range windows {
					if stat.psiMemMax > psiPeak {
						psiPeak = stat.psiMemMax
					}
					if stat.memUsedMax > memPeak {
						memPeak = stat.memUsedMax
					}
				}
				return fmt.Sprintf("Host evidence: peak memory PSI some avg10 %.2f%% (threshold %.2f%%), peak memory used %.1f%% (threshold %.0f%%).", psiPeak, psiMemoryStall, memPeak, memUsedPct)
			},
			signal: func(signal Signal) bool {
				return errorRise(signal.ErrorRate, errorBaseline)
			},
			signalDetail: func(signals []Signal) string {
				return fmt.Sprintf("External evidence: peak error rate %.2f%%, median error-rate baseline %.2f%%.", peakErrorRate(signals)*100, errorBaseline*100)
			},
			severity: func(windows []windowStat) string {
				peak := 0.0
				for _, stat := range windows {
					if stat.psiMemMax > peak {
						peak = stat.psiMemMax
					}
				}
				if peak >= 5 {
					return SeverityCritical
				}
				return SeverityWarning
			},
		},
		{
			id:          "hostxray.network-errors",
			title:       "Network interface errors or drops while Sift failures rise",
			explanation: "Windows where Sift's error rate rose by at least one percentage point (and doubled from its median) were checked against new rx/tx errors and drops on the host's network interfaces. Counters are summed across every interface the kernel exposes, loopback included, and cannot say which socket, peer, or process was affected.",
			host: func(stat windowStat) bool {
				return stat.faults >= 1
			},
			hostDetail: func(windows []windowStat) string {
				total := uint64(0)
				for _, stat := range windows {
					total = saturatingAdd(total, stat.faults)
				}
				return fmt.Sprintf("Host evidence: %d new interface errors/drops were counted inside the overlapping windows.", total)
			},
			signal: func(signal Signal) bool {
				return errorRise(signal.ErrorRate, errorBaseline)
			},
			signalDetail: func(signals []Signal) string {
				return fmt.Sprintf("External evidence: peak error rate %.2f%% across matched windows.", peakErrorRate(signals)*100)
			},
			severity: func([]windowStat) string { return SeverityWarning },
		},
		{
			id:    "hostxray.gc-latency",
			title: "Go GC pause growth alongside Sift latency inflation",
			explanation: fmt.Sprintf(
				"Windows where Sift observed p99 latency at least 1.5x its median were checked against the Sift process's own GC pause time, derived from runtime.MemStats deltas (minimum %.0f ms mean pause). This is process-local evidence: it is meaningful only when Sift and the measured service share a process or host, which is the non-Linux fallback case.",
				minGCPauseMs,
			),
			host: func(stat windowStat) bool {
				if stat.gcCount == 0 {
					return false
				}
				threshold := minGCPauseMs
				if gcBaseline*1.5 > threshold {
					threshold = gcBaseline * 1.5
				}
				return stat.meanGCPauseMs() >= threshold
			},
			hostDetail: func(windows []windowStat) string {
				sum, count := 0.0, 0
				for _, stat := range windows {
					sum += stat.gcSumMs
					count += stat.gcCount
				}
				if count == 0 {
					return ""
				}
				return fmt.Sprintf("Runtime evidence: mean GC pause %.2f ms across overlapping windows (baseline %.2f ms).", sum/float64(count), gcBaseline)
			},
			signal: func(signal Signal) bool {
				return latencySpike(signal.P99Ms, latencyBaseline)
			},
			signalDetail: func(signals []Signal) string {
				return fmt.Sprintf("External evidence: peak p99 %.1f ms, median p99 baseline %.1f ms.", peakP99(signals), latencyBaseline)
			},
			severity: func(windows []windowStat) string {
				sum, count := 0.0, 0
				for _, stat := range windows {
					sum += stat.gcSumMs
					count += stat.gcCount
				}
				if count > 0 && sum/float64(count) >= 10 {
					return SeverityWarning
				}
				return SeverityInfo
			},
		},
	}
}

// confidenceFor maps overlap counts to a confidence label. High needs breadth
// (four or more windows) and coverage (most qualifying windows); medium needs
// two windows and at least 40% coverage; anything weaker is low. A low
// indicator is still emitted only when MinOverlap is satisfied.
func confidenceFor(overlap int, coverage float64) string {
	switch {
	case overlap >= 4 && coverage >= 0.6:
		return ConfidenceHigh
	case overlap >= 2 && coverage >= 0.4:
		return ConfidenceMedium
	case overlap >= 1:
		return ConfidenceLow
	default:
		return ""
	}
}

func severityRank(severity string) int {
	switch severity {
	case SeverityCritical:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

func latencySpike(value, baseline float64) bool {
	if value <= 0 || baseline <= 0 {
		return false
	}
	return value >= baseline*1.5 && value-baseline >= minLatencyRiseMs
}

func errorRise(value, baseline float64) bool {
	if value < minErrorRate {
		return false
	}
	return value >= baseline*2 && value-baseline >= minErrorRate
}

func netFaults(net NetStats) (uint64, bool) {
	if !net.Available {
		return 0, false
	}
	total := saturatingAdd(net.Aggregate.RxErrors, net.Aggregate.RxDrops)
	total = saturatingAdd(total, net.Aggregate.TxErrors)
	total = saturatingAdd(total, net.Aggregate.TxDrops)
	return total, true
}

func normalizeSignals(signals []Signal) []Signal {
	out := make([]Signal, 0, len(signals))
	for _, signal := range signals {
		if signal.Timestamp.IsZero() {
			continue
		}
		signal.ErrorRate = clampFraction(signal.ErrorRate)
		if signal.RPS < 0 {
			signal.RPS = 0
		}
		if signal.P99Ms < 0 {
			signal.P99Ms = 0
		}
		out = append(out, signal)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out
}

func clampFraction(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

func positiveP99(signals []Signal) []float64 {
	out := make([]float64, 0, len(signals))
	for _, signal := range signals {
		if signal.P99Ms > 0 {
			out = append(out, signal.P99Ms)
		}
	}
	return out
}

func errorRates(signals []Signal) []float64 {
	out := make([]float64, 0, len(signals))
	for _, signal := range signals {
		out = append(out, clampFraction(signal.ErrorRate))
	}
	return out
}

func gcPauses(events []sampleEvent) []float64 {
	out := make([]float64, 0, len(events))
	for _, event := range events {
		if event.gcValid && event.gcPauseMs > 0 {
			out = append(out, event.gcPauseMs)
		}
	}
	return out
}

func peakP99(signals []Signal) float64 {
	peak := 0.0
	for _, signal := range signals {
		if signal.P99Ms > peak {
			peak = signal.P99Ms
		}
	}
	return peak
}

func peakErrorRate(signals []Signal) float64 {
	peak := 0.0
	for _, signal := range signals {
		if rate := clampFraction(signal.ErrorRate); rate > peak {
			peak = rate
		}
	}
	return peak
}

// median returns 0 for an empty slice and the lower-middle value for an even
// count, which keeps the baseline from being pulled up by a single outlier.
func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	if len(sorted)%2 == 1 {
		return sorted[len(sorted)/2]
	}
	return sorted[len(sorted)/2-1]
}
