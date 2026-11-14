package hostxray

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxTimelineRows caps the host timeline in a Markdown report. A 100k-sample
// collection would otherwise produce a document no one can open; the JSONL
// artifact keeps every sample.
const maxTimelineRows = 300

// Report is the input to WriteMarkdown. Indicators are expected to come from
// Correlate over the same Samples and Signals; WriteMarkdown does not
// recompute them, so a report shows exactly the findings the caller accepted.
type Report struct {
	Title        string
	GeneratedAt  time.Time
	Capabilities Capabilities
	Options      Options
	Window       time.Duration
	Samples      []Sample
	Signals      []Signal
	Indicators   []Indicator
}

// LoadSignals reads a Sift-like signal file used as the external side of the
// correlation. Three shapes are accepted, and the editor-friendly one is
// recommended:
//
//  1. JSON array: [{"timestamp":"2026-11-14T10:00:00Z","p99_ms":210,...}, ...]
//  2. JSON object wrapper: {"signals":[...same objects...]}
//  3. JSON Lines: one object per line, blank lines and lines starting with
//     "#" ignored (JSON has no comments; the loader allows a leading # so an
//     operator can annotate a hand-written fixture).
//
// Recognized fields per object:
//
//	timestamp or ts  RFC3339 string, or a Unix timestamp as a number
//	                 (seconds, milliseconds, microseconds, or nanoseconds,
//	                 detected by magnitude)
//	rps              requests per second at that moment
//	p99_ms or p99    p99 latency in milliseconds
//	error_rate       fraction in [0,1] — 0.02 means 2%, not 2
//	step, endpoint   free-form labels copied into the report
//
// A missing timestamp is an error: signals without a time cannot be joined.
// Negative values and out-of-range error rates are rejected so a
// percent-vs-fraction mistake fails loudly instead of skewing a report.
func LoadSignals(path string) ([]Signal, error) {
	data, err := readArtifact(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("host xray: signal file %s is empty", filepath.Clean(path))
	}

	if trimmed[0] == '{' {
		var wrapper struct {
			Signals []rawSignal `json:"signals"`
		}
		wrapperErr := json.Unmarshal(trimmed, &wrapper)
		if wrapperErr == nil && len(wrapper.Signals) > 0 {
			return convertSignals(wrapper.Signals)
		}
		if wrapperErr == nil && len(wrapper.Signals) == 0 {
			return nil, fmt.Errorf("host xray: signal file %s contains no signals", filepath.Clean(path))
		}
		var single rawSignal
		if err := json.Unmarshal(trimmed, &single); err == nil {
			// convertSignals reports the missing-timestamp case with a clear
			// message instead of silently producing an unjoinable signal.
			return convertSignals([]rawSignal{single})
		}
	}

	if trimmed[0] == '[' {
		var raws []rawSignal
		if err := json.Unmarshal(trimmed, &raws); err != nil {
			return nil, fmt.Errorf("host xray: parse signals in %s: %w", filepath.Clean(path), err)
		}
		return convertSignals(raws)
	}

	return loadSignalLines(path, data)
}

func loadSignalLines(path string, data []byte) ([]Signal, error) {
	clean := filepath.Clean(path)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)

	var raws []rawSignal
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var raw rawSignal
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("host xray: %s line %d: %w", clean, lineNo, err)
		}
		raws = append(raws, raw)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("host xray: read %s: %w", clean, err)
	}
	if len(raws) == 0 {
		return nil, fmt.Errorf("host xray: signal file %s contains no signals", clean)
	}
	return convertSignals(raws)
}

func convertSignals(raws []rawSignal) ([]Signal, error) {
	out := make([]Signal, 0, len(raws))
	for i, raw := range raws {
		signal, err := raw.toSignal(i + 1)
		if err != nil {
			return nil, fmt.Errorf("host xray: %w", err)
		}
		out = append(out, signal)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out, nil
}

// LoadJSONL reads a sample artifact produced by WriteJSONL (or an equivalent
// JSON array). Empty lines are skipped; a malformed line reports its line
// number. Samples are returned sorted by timestamp.
func LoadJSONL(path string) ([]Sample, error) {
	data, err := readArtifact(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("host xray: sample file %s is empty", filepath.Clean(path))
	}
	if trimmed[0] == '[' {
		var samples []Sample
		if err := json.Unmarshal(trimmed, &samples); err != nil {
			return nil, fmt.Errorf("host xray: parse samples in %s: %w", filepath.Clean(path), err)
		}
		return sortedSamples(samples), nil
	}

	clean := filepath.Clean(path)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)

	var samples []Sample
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var sample Sample
		if err := json.Unmarshal([]byte(line), &sample); err != nil {
			return nil, fmt.Errorf("host xray: %s line %d: %w", clean, lineNo, err)
		}
		if sample.Timestamp.IsZero() {
			return nil, fmt.Errorf("host xray: %s line %d: sample has no timestamp", clean, lineNo)
		}
		samples = append(samples, sample)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("host xray: read %s: %w", clean, err)
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("host xray: sample file %s contains no samples", clean)
	}
	return sortedSamples(samples), nil
}

// WriteJSONL writes one JSON object per sample with mode 0600 inside a 0750
// directory. Samples are sorted by timestamp so two runs over the same data
// produce byte-identical artifacts, except for the timestamps themselves.
func WriteJSONL(path string, samples []Sample) error {
	ordered := sortedSamples(samples)
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	for i := range ordered {
		if err := encoder.Encode(ordered[i]); err != nil {
			return fmt.Errorf("host xray: encode sample %d: %w", i, err)
		}
	}
	return writeArtifact(path, buf.Bytes())
}

// WriteMarkdown renders the human-readable report. Output ordering is
// deterministic: samples and signals are sorted by time, indicators by
// severity then id, interface names never appear (redaction or not, they are
// omitted from the prose), and the timeline is evenly subsampled when it
// exceeds maxTimelineRows.
func WriteMarkdown(path string, report Report) error {
	title := report.Title
	if strings.TrimSpace(title) == "" {
		title = "Sift Host X-Ray Report"
	}
	generated := report.GeneratedAt
	if generated.IsZero() {
		generated = time.Now().UTC()
	}
	window := report.Window
	if window <= 0 {
		window = DefaultCorrelateWindow
	}
	samples := sortedSamples(report.Samples)
	signals := append([]Signal(nil), report.Signals...)
	sort.SliceStable(signals, func(i, j int) bool { return signals[i].Timestamp.Before(signals[j].Timestamp) })
	indicators := append([]Indicator(nil), report.Indicators...)
	sort.SliceStable(indicators, func(i, j int) bool {
		ri, rj := severityRank(indicators[i].Severity), severityRank(indicators[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return indicators[i].ID < indicators[j].ID
	})

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "_Generated %s by Sift host x-ray (opt-in, aggregate-only observability)._\n\n", generated.UTC().Format(time.RFC3339))

	b.WriteString("## Scope and safety\n\n")
	b.WriteString("This report contains aggregate host counters and, where kernel evidence is unavailable, Go runtime metrics of the Sift process. Collection was explicitly opted in by the operator. No eBPF program was loaded, no kernel module was installed, no privilege was requested, and no cgo is involved.\n\n")
	b.WriteString("It never contains process names, PIDs, command lines, environment variables, user names, file contents, packet payloads, HTTP bodies, remote addresses, or secrets. Network interface names are omitted from this prose; the JSONL artifact can contain either raw names or stable aliases depending on redaction.\n\n")
	b.WriteString("Every correlation below is **correlated evidence**, not a causal finding. Aggregate counters cannot identify a responsible process, and temporal alignment cannot rule out a third factor.\n\n")

	b.WriteString("## Capabilities\n\n")
	b.WriteString("| Check | Result |\n|---|---|\n")
	writeCapabilityRow(&b, "Platform", fmt.Sprintf("%s/%s", report.Capabilities.OS, report.Capabilities.Arch))
	writeCapabilityRow(&b, "Evidence source", report.Capabilities.Source)
	writeCapabilityRow(&b, "/proc available", boolWord(report.Capabilities.ProcAvailable))
	writeCapabilityRow(&b, "/proc/loadavg", boolWord(report.Capabilities.ProcLoadAvg))
	writeCapabilityRow(&b, "/proc/meminfo", boolWord(report.Capabilities.ProcMemInfo))
	writeCapabilityRow(&b, "/proc/net/dev", boolWord(report.Capabilities.ProcNetDev))
	writeCapabilityRow(&b, "/proc/stat", boolWord(report.Capabilities.ProcStat))
	writeCapabilityRow(&b, "/proc/pressure", boolWord(report.Capabilities.ProcPressure))
	writeCapabilityRow(&b, "BTF (/sys/kernel/btf/vmlinux)", boolWord(report.Capabilities.BTFVMLinux))
	writeCapabilityRow(&b, "Deeper eBPF backend possible (not loaded)", boolWord(report.Capabilities.DeepTracingPossible))
	b.WriteString("\n")
	for _, note := range report.Capabilities.Notes {
		fmt.Fprintf(&b, "- %s\n", note)
	}
	if len(report.Capabilities.Notes) > 0 {
		b.WriteString("\n")
	}

	b.WriteString("## Collection\n\n")
	b.WriteString("| Setting | Value |\n|---|---|\n")
	writeCapabilityRow(&b, "Samples", strconv.Itoa(len(samples)))
	writeCapabilityRow(&b, "Interval", report.Options.Interval.String())
	writeCapabilityRow(&b, "Duration", durationLabel(report.Options.Duration, report.Options.MaxSamples))
	writeCapabilityRow(&b, "Max samples", maxSamplesLabel(report.Options.MaxSamples))
	writeCapabilityRow(&b, "Redaction", boolWord(report.Options.Redact))
	writeCapabilityRow(&b, "Correlation window", window.String())
	if len(samples) > 0 {
		writeCapabilityRow(&b, "First sample", samples[0].Timestamp.UTC().Format(time.RFC3339))
		writeCapabilityRow(&b, "Last sample", samples[len(samples)-1].Timestamp.UTC().Format(time.RFC3339))
	}
	b.WriteString("\n")

	b.WriteString("## Correlated indicators\n\n")
	if len(indicators) == 0 {
		fmt.Fprintf(&b, "No indicator met the conservative evidence threshold. A rule needs at least %d qualifying signal windows with overlapping host evidence, so an empty section on a healthy or short run is expected and is not evidence that nothing happened.\n\n", DefaultMinOverlap)
	} else {
		for i, indicator := range indicators {
			fmt.Fprintf(&b, "### %d. %s / %s confidence — %s\n\n", i+1, indicator.Severity, indicator.Confidence, indicator.Title)
			fmt.Fprintf(&b, "%s\n\n", indicator.Explanation)
			if len(indicator.Evidence) > 0 {
				b.WriteString("Evidence:\n")
				for _, line := range indicator.Evidence {
					if strings.TrimSpace(line) == "" {
						continue
					}
					fmt.Fprintf(&b, "- %s\n", line)
				}
				b.WriteString("\n")
			}
		}
	}

	b.WriteString("## External signals\n\n")
	if len(signals) == 0 {
		b.WriteString("No external signal file was supplied, so no rules were evaluated.\n\n")
	} else {
		b.WriteString("| Metric | Value |\n|---|---|\n")
		writeCapabilityRow(&b, "Signals", strconv.Itoa(len(signals)))
		writeCapabilityRow(&b, "First signal", signals[0].Timestamp.UTC().Format(time.RFC3339))
		writeCapabilityRow(&b, "Last signal", signals[len(signals)-1].Timestamp.UTC().Format(time.RFC3339))
		writeCapabilityRow(&b, "Peak p99", fmt.Sprintf("%.1f ms", peakP99(signals)))
		writeCapabilityRow(&b, "Median p99", fmt.Sprintf("%.1f ms", median(positiveP99(signals))))
		writeCapabilityRow(&b, "Peak error rate", fmt.Sprintf("%.2f%%", peakErrorRate(signals)*100))
		writeCapabilityRow(&b, "Median error rate", fmt.Sprintf("%.2f%%", median(errorRates(signals))*100))
		b.WriteString("\n")
	}

	b.WriteString("## Host timeline\n\n")
	if len(samples) == 0 {
		b.WriteString("No samples were collected.\n\n")
	} else {
		step := 1
		if len(samples) > maxTimelineRows {
			step = (len(samples) + maxTimelineRows - 1) / maxTimelineRows
			fmt.Fprintf(&b, "Showing every %dth sample of %d to keep the table readable; the JSONL artifact has all of them.\n\n", step, len(samples))
		}
		b.WriteString("| Time (UTC) | load1 | CPU % | iowait % | mem used % | PSI mem avg10 % | net err/drop | goroutines | p99 near (ms) |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
		for i := 0; i < len(samples); i += step {
			sample := samples[i]
			load, cpu, iowait, mem, psi, faults, p99 := "-", "-", "-", "-", "-", "-", "-"
			if sample.Load.Available {
				load = fmt.Sprintf("%.2f", sample.Load.One)
			}
			if sample.CPU.Available {
				cpu = fmt.Sprintf("%.1f", sample.CPU.UtilizationPct)
				iowait = fmt.Sprintf("%.1f", sample.CPU.IOWaitPct)
			}
			if sample.Mem.Available {
				mem = fmt.Sprintf("%.1f", sample.Mem.UsedPct)
			}
			if sample.PSI.Memory != nil {
				psi = fmt.Sprintf("%.2f", sample.PSI.Memory.Some10)
			}
			if delta, ok := netFaultDelta(samples, i); ok {
				faults = strconv.FormatUint(delta, 10)
			}
			if signal, ok := nearestSignal(signals, sample.Timestamp, window); ok {
				p99 = fmt.Sprintf("%.1f", signal.P99Ms)
			}
			fmt.Fprintf(&b,
				"| %s | %s | %s | %s | %s | %s | %s | %d | %s |\n",
				sample.Timestamp.UTC().Format("15:04:05.000"), load, cpu, iowait, mem, psi, faults, sample.Runtime.Goroutines, p99,
			)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Limitations and blind spots\n\n")
	b.WriteString("- No eBPF program, kernel module, or privileged call is involved in this release. The artifact is only as deep as /proc and the Go runtime allow.\n")
	b.WriteString("- Counters are sampled, so a short spike between two ticks is invisible. Narrow the interval deliberately and keep the window bounded.\n")
	b.WriteString("- PSI is optional in kernel configuration; absent pressure files disable the memory and IO stall rules rather than guessing.\n")
	b.WriteString("- Interface counters aggregate every interface, including loopback and virtual devices, so they cannot attribute a drop to a peer or process.\n")
	b.WriteString("- Off Linux the agent reports Go runtime metrics only; GC pauses describe the Sift process, not the measured service.\n")
	b.WriteString("- Time alignment uses the local wall clock of each side; clock skew between the Sift runner and the observed host is not corrected.\n")
	b.WriteString("- Correlation thresholds are conservative heuristics. A missing indicator means the evidence did not clear the bar, not that the host was healthy.\n")

	return writeArtifact(path, []byte(b.String()))
}

func writeCapabilityRow(b *strings.Builder, label, value string) {
	if strings.TrimSpace(value) == "" {
		value = "-"
	}
	fmt.Fprintf(b, "| %s | %s |\n", label, value)
}

func boolWord(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func durationLabel(duration time.Duration, maxSamples int) string {
	if duration > 0 {
		return duration.String()
	}
	if maxSamples > 0 {
		return "not set (bounded by max samples)"
	}
	return "-"
}

func maxSamplesLabel(maxSamples int) string {
	if maxSamples <= 0 {
		return "derived from duration"
	}
	return strconv.Itoa(maxSamples)
}

// netFaultDelta returns the new rx/tx errors and drops between sample i and
// its predecessor. A counter that went backwards (interface reset) yields no
// delta rather than a huge one.
func netFaultDelta(samples []Sample, i int) (uint64, bool) {
	if i <= 0 || i >= len(samples) {
		return 0, false
	}
	cur, ok := netFaults(samples[i].Net)
	if !ok {
		return 0, false
	}
	prev, prevOK := netFaults(samples[i-1].Net)
	if !prevOK || cur < prev {
		return 0, false
	}
	return cur - prev, true
}

// nearestSignal finds the closest external signal within window of ts. It is
// used only for the timeline annotation; correlation itself always looks
// backwards from the signal.
func nearestSignal(signals []Signal, ts time.Time, window time.Duration) (Signal, bool) {
	if len(signals) == 0 {
		return Signal{}, false
	}
	idx := sort.Search(len(signals), func(i int) bool { return !signals[i].Timestamp.Before(ts) })
	best := Signal{}
	bestDelta := time.Duration(0)
	found := false
	consider := func(i int) {
		if i < 0 || i >= len(signals) {
			return
		}
		delta := signals[i].Timestamp.Sub(ts)
		if delta < 0 {
			delta = -delta
		}
		if delta > window {
			return
		}
		if !found || delta < bestDelta {
			found = true
			bestDelta = delta
			best = signals[i]
		}
	}
	consider(idx)
	consider(idx - 1)
	if !found {
		return Signal{}, false
	}
	return best, true
}

func sortedSamples(samples []Sample) []Sample {
	out := make([]Sample, len(samples))
	copy(out, samples)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].Timestamp.Equal(out[j].Timestamp) {
			return out[i].Timestamp.Before(out[j].Timestamp)
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func readArtifact(path string) ([]byte, error) {
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return nil, errors.New("host xray: artifact path is empty or not a file")
	}
	data, err := os.ReadFile(clean) // #nosec G304 -- operator-supplied artifact path, cleaned above
	if err != nil {
		return nil, fmt.Errorf("host xray: read %s: %w", clean, err)
	}
	return data, nil
}

func writeArtifact(path string, data []byte) error {
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return errors.New("host xray: artifact path is empty or not a file")
	}
	if dir := filepath.Dir(clean); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("host xray: create artifact directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(clean, data, 0o600); err != nil {
		return fmt.Errorf("host xray: write %s: %w", clean, err)
	}
	// os.WriteFile does not tighten the mode of an existing file, so enforce
	// 0600 explicitly: artifacts can contain host topology hints.
	if err := os.Chmod(clean, 0o600); err != nil {
		return fmt.Errorf("host xray: restrict permissions on %s: %w", clean, err)
	}
	return nil
}

// rawSignal is the on-disk shape. Pointers distinguish "absent" from "zero" so
// a missing error_rate is not mistaken for a measured 0%.
type rawSignal struct {
	Timestamp flexibleTime `json:"timestamp"`
	TS        flexibleTime `json:"ts"`
	RPS       *float64     `json:"rps"`
	P99Ms     *float64     `json:"p99_ms"`
	P99Alt    *float64     `json:"p99"`
	ErrorRate *float64     `json:"error_rate"`
	Step      string       `json:"step"`
	Endpoint  string       `json:"endpoint"`
	Label     string       `json:"label"`
}

func (r rawSignal) toSignal(index int) (Signal, error) {
	ts := r.Timestamp.Time
	if ts.IsZero() {
		ts = r.TS.Time
	}
	if ts.IsZero() {
		return Signal{}, fmt.Errorf("signal %d: missing timestamp (RFC3339 string or Unix seconds/milliseconds)", index)
	}
	signal := Signal{
		Timestamp: ts.UTC(),
		Step:      r.Step,
		Endpoint:  r.Endpoint,
		Label:     r.Label,
	}
	if r.RPS != nil {
		signal.RPS = *r.RPS
	}
	switch {
	case r.P99Ms != nil:
		signal.P99Ms = *r.P99Ms
	case r.P99Alt != nil:
		signal.P99Ms = *r.P99Alt
	}
	if r.ErrorRate != nil {
		signal.ErrorRate = *r.ErrorRate
	}
	if signal.RPS < 0 || signal.P99Ms < 0 {
		return Signal{}, fmt.Errorf("signal %d: rps and p99 must not be negative", index)
	}
	if signal.ErrorRate < 0 || signal.ErrorRate > 1 {
		return Signal{}, fmt.Errorf("signal %d: error_rate %v must be a fraction between 0 and 1 (use 0.02 for 2%%)", index, signal.ErrorRate)
	}
	return signal, nil
}

// flexibleTime accepts RFC3339 strings and numeric Unix timestamps in seconds,
// milliseconds, microseconds, or nanoseconds. Magnitude detection is safe for
// any date this product cares about: seconds are ~1.7e9, nanoseconds ~1.7e18.
type flexibleTime struct {
	time.Time
}

// UnmarshalJSON implements json.Unmarshaler. A JSON null leaves the zero time.
func (t *flexibleTime) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "null" {
		return nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return nil
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", time.DateTime} {
			if parsed, err := time.Parse(layout, s); err == nil {
				t.Time = parsed
				return nil
			}
		}
		return fmt.Errorf("unrecognized timestamp %q (want RFC3339 or a Unix timestamp)", s)
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value <= 0 {
		return fmt.Errorf("invalid timestamp %q", raw)
	}
	if value > 9.2e18 {
		return fmt.Errorf("timestamp %q is out of range", raw)
	}
	var nanos int64
	switch {
	case value >= 1e17: // nanoseconds since the epoch
		nanos = int64(value) // #nosec G115 -- guarded above; value < 9.2e18
	case value >= 1e14: // microseconds
		nanos = int64(value) * 1e3 // #nosec G115 -- bounded: values below 1e17
	case value >= 1e11: // milliseconds
		nanos = int64(value) * 1e6 // #nosec G115 -- bounded: values below 1e14
	default: // seconds
		nanos = int64(value) * 1e9 // #nosec G115 -- bounded: values below 1e11
	}
	t.Time = time.Unix(0, nanos).UTC()
	return nil
}
