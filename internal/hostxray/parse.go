package hostxray

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// This file holds pure parsers for Linux /proc formats. They take an io.Reader
// and have no build tags on purpose:
//
//   - the Linux collector uses them directly;
//   - their unit tests run on every platform, including the darwin dev
//     machines where /proc does not exist.
//
// Every parser validates as much as it can and returns a descriptive error
// instead of panicking or silently producing zeros. The collector decides
// whether an error is fatal (nothing was readable at all) or a note (the file
// is not exposed on this host).

// ParseLoadAvg parses the single line of /proc/loadavg:
//
//	0.42 0.35 0.30 1/523 12345
//
// The runnable/total pair and the last PID are optional in practice; a kernel
// always emits them, but the parser tolerates their absence. The last PID is
// intentionally not returned: it is a process identifier and adds nothing to
// aggregate correlation.
func ParseLoadAvg(r io.Reader) (LoadAverage, error) {
	var out LoadAverage
	line, err := firstLine(r)
	if err != nil {
		return out, err
	}
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return out, fmt.Errorf("loadavg: want at least 3 fields, got %d", len(fields))
	}
	one, err := parseFloat(fields[0])
	if err != nil {
		return out, fmt.Errorf("loadavg: 1-minute value: %w", err)
	}
	five, err := parseFloat(fields[1])
	if err != nil {
		return out, fmt.Errorf("loadavg: 5-minute value: %w", err)
	}
	fifteen, err := parseFloat(fields[2])
	if err != nil {
		return out, fmt.Errorf("loadavg: 15-minute value: %w", err)
	}
	out.One, out.Five, out.Fifteen = one, five, fifteen
	if len(fields) >= 4 {
		if runnable, total, ok := strings.Cut(fields[3], "/"); ok {
			if n, err := strconv.Atoi(runnable); err == nil && n >= 0 {
				out.Runnable = n
			}
			if n, err := strconv.Atoi(total); err == nil && n >= 0 {
				out.Processes = n
			}
		}
	}
	out.Available = true
	return out, nil
}

// ParseMemInfo extracts the memory keys the agent uses from /proc/meminfo.
// Values are converted from the kernel's kB (or any kB/MB/GB suffix) to bytes.
//
// MemAvailable is missing on kernels older than 3.14; the parser then
// approximates it as MemFree + Buffers + Cached, which is the documented
// pre-3.14 heuristic and is recorded as an approximation by the collector via
// a note.
func ParseMemInfo(r io.Reader) (MemoryStats, error) {
	var out MemoryStats
	values := make(map[string]uint64, 16)

	scanner := newScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return out, fmt.Errorf("meminfo: %s: %w", key, err)
		}
		mult := uint64(1)
		if len(fields) > 1 {
			mult, err = memoryUnit(fields[1])
			if err != nil {
				return out, fmt.Errorf("meminfo: %s: %w", key, err)
			}
		}
		if mult != 0 && n > ^uint64(0)/mult {
			return out, fmt.Errorf("meminfo: %s overflows uint64", key)
		}
		values[key] = n * mult
	}
	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("meminfo: %w", err)
	}

	total, ok := values["MemTotal"]
	if !ok || total == 0 {
		return out, errors.New("meminfo: MemTotal is missing or zero")
	}
	out.TotalBytes = total
	out.FreeBytes = values["MemFree"]
	out.BuffersBytes = values["Buffers"]
	out.CachedBytes = values["Cached"]

	available, hasAvailable := values["MemAvailable"]
	if !hasAvailable {
		available = out.FreeBytes + out.BuffersBytes + out.CachedBytes
		if available > total {
			available = total
		}
	}
	out.AvailableBytes = available
	out.UsedPct = float64(total-available) / float64(total) * 100
	out.Available = true
	return out, nil
}

// ParseNetDev parses /proc/net/dev. The two header lines are skipped by
// ignoring every line without a colon, which also tolerates the kernel
// changing header wording.
//
// Ordering follows the file so the output is deterministic for a given kernel.
// Aggregation is provided separately by AggregateNetDev.
func ParseNetDev(r io.Reader) ([]InterfaceCounters, error) {
	scanner := newScanner(r)
	var out []InterfaceCounters
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, errors.New("netdev: interface name is empty")
		}
		// Skip /proc/net/dev header rows. The kernel emits two header lines
		// ("Inter-|..." and " face |..."); synthetic fixtures may also use an
		// "Interfaces:" banner. Real interface names never start with "Inter-"
		// or contain a pipe.
		if strings.HasPrefix(name, "Inter-") || strings.EqualFold(name, "face") || strings.EqualFold(name, "Interfaces") || strings.Contains(name, "|") {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 16 {
			return nil, fmt.Errorf("netdev: interface %q: want 16 counters, got %d", name, len(fields))
		}
		var n [16]uint64
		for i := range n {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("netdev: interface %q column %d: %w", name, i+1, err)
			}
			n[i] = v
		}
		out = append(out, InterfaceCounters{
			Name:      name,
			RxBytes:   n[0],
			RxPackets: n[1],
			RxErrors:  n[2],
			RxDrops:   n[3],
			TxBytes:   n[8],
			TxPackets: n[9],
			TxErrors:  n[10],
			TxDrops:   n[11],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("netdev: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("netdev: no interface counters found")
	}
	return out, nil
}

// AggregateNetDev sums the counters of every interface, including loopback,
// and names the result "aggregate". Saturating addition keeps a pathological
// kernel counter from wrapping into a tiny value.
func AggregateNetDev(ifaces []InterfaceCounters) InterfaceCounters {
	agg := InterfaceCounters{Name: "aggregate"}
	for _, iface := range ifaces {
		agg.RxBytes = saturatingAdd(agg.RxBytes, iface.RxBytes)
		agg.RxPackets = saturatingAdd(agg.RxPackets, iface.RxPackets)
		agg.RxErrors = saturatingAdd(agg.RxErrors, iface.RxErrors)
		agg.RxDrops = saturatingAdd(agg.RxDrops, iface.RxDrops)
		agg.TxBytes = saturatingAdd(agg.TxBytes, iface.TxBytes)
		agg.TxPackets = saturatingAdd(agg.TxPackets, iface.TxPackets)
		agg.TxErrors = saturatingAdd(agg.TxErrors, iface.TxErrors)
		agg.TxDrops = saturatingAdd(agg.TxDrops, iface.TxDrops)
	}
	return agg
}

// ParsePSI parses one pressure file, e.g. /proc/pressure/memory:
//
//	some avg10=0.00 avg60=0.13 avg300=0.04 total=123456
//	full avg10=0.00 avg60=0.00 avg300=0.00 total=65432
//
// The "full" line is absent for CPU pressure. Unknown resource prefixes are
// ignored for forward compatibility; a file without a "some" line is an error.
func ParsePSI(r io.Reader) (Pressure, error) {
	var out Pressure
	scanner := newScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		kind, rest, ok := strings.Cut(line, " ")
		if !ok {
			return out, fmt.Errorf("psi: malformed line %q", line)
		}
		vals, err := parsePressureValues(rest)
		if err != nil {
			return out, fmt.Errorf("psi: %s line: %w", kind, err)
		}
		switch kind {
		case "some":
			out.Some10 = vals.avg10
			out.Some60 = vals.avg60
			out.Some300 = vals.avg300
			out.SomeTotalMicros = vals.total
			out.HasSome = true
		case "full":
			out.Full10 = vals.avg10
			out.Full60 = vals.avg60
			out.Full300 = vals.avg300
			out.FullTotalMicros = vals.total
			out.HasFull = true
		}
	}
	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("psi: %w", err)
	}
	if !out.HasSome {
		return out, errors.New(`psi: missing "some" line`)
	}
	return out, nil
}

type pressureValues struct {
	avg10  float64
	avg60  float64
	avg300 float64
	total  uint64
}

func parsePressureValues(s string) (pressureValues, error) {
	var out pressureValues
	for _, field := range strings.Fields(s) {
		key, raw, ok := strings.Cut(field, "=")
		if !ok {
			return out, fmt.Errorf("malformed field %q", field)
		}
		switch key {
		case "avg10", "avg60", "avg300":
			v, err := parseFloat(raw)
			if err != nil {
				return out, fmt.Errorf("%s: %w", key, err)
			}
			switch key {
			case "avg10":
				out.avg10 = v
			case "avg60":
				out.avg60 = v
			case "avg300":
				out.avg300 = v
			}
		case "total":
			v, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return out, fmt.Errorf("total: %w", err)
			}
			out.total = v
		}
	}
	return out, nil
}

// ParseProcStat reads the aggregate "cpu" line from /proc/stat. Per-CPU lines
// ("cpu0" etc.) are ignored: the aggregate is enough for a host-level view and
// keeps the artifact small on large machines.
func ParseProcStat(r io.Reader) (CPUJiffies, error) {
	scanner := newScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		// user nice system idle iowait irq softirq steal guest guest_nice
		values := make([]uint64, 10)
		for i := 0; i < len(values) && i+1 < len(fields); i++ {
			v, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return CPUJiffies{}, fmt.Errorf("procstat: column %d: %w", i+1, err)
			}
			values[i] = v
		}
		return CPUJiffies{
			User:      values[0],
			Nice:      values[1],
			System:    values[2],
			Idle:      values[3],
			IOWait:    values[4],
			IRQ:       values[5],
			SoftIRQ:   values[6],
			Steal:     values[7],
			Guest:     values[8],
			GuestNice: values[9],
		}, nil
	}
	if err := scanner.Err(); err != nil {
		return CPUJiffies{}, fmt.Errorf("procstat: %w", err)
	}
	return CPUJiffies{}, errors.New(`procstat: aggregate "cpu" line not found`)
}

// Utilization derives the CPU utilization percentage between two cumulative
// /proc/stat snapshots. ok is false when the counters went backwards (the
// machine rebooted or the file was replaced) or the interval had no ticks.
//
// UtilizationPct is 100 * (1 - idle), so iowait counts as utilization; use
// IOWaitPct to see how much of that time was storage stall.
func Utilization(prev, cur CPUJiffies) (utilPct, iowaitPct float64, ok bool) {
	dTotal, okTotal := counterDelta(prev.Total(), cur.Total())
	dIdle, okIdle := counterDelta(prev.Idle, cur.Idle)
	dIOWait, okIOWait := counterDelta(prev.IOWait, cur.IOWait)
	if !okTotal || !okIdle || !okIOWait || dTotal == 0 {
		return 0, 0, false
	}
	if dIdle > dTotal {
		dIdle = dTotal
	}
	if dIOWait > dTotal {
		dIOWait = dTotal
	}
	utilPct = float64(dTotal-dIdle) / float64(dTotal) * 100
	iowaitPct = float64(dIOWait) / float64(dTotal) * 100
	utilPct = clampPercent(utilPct)
	iowaitPct = clampPercent(iowaitPct)
	return utilPct, iowaitPct, true
}

func counterDelta(prev, cur uint64) (uint64, bool) {
	if cur < prev {
		return 0, false
	}
	return cur - prev, true
}

func clampPercent(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 100:
		return 100
	default:
		return v
	}
}

func firstLine(r io.Reader) (string, error) {
	scanner := newScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			return line, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("empty input")
}

// newScanner returns a line scanner with a larger-than-default token limit:
// a /proc/stat line on a large host is short, but a future proc format should
// not fail with bufio.ErrTooLong.
func newScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 4096), 1<<20)
	return s
}

func parseFloat(s string) (float64, error) {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number: %w", s, err)
	}
	return v, nil
}

func memoryUnit(unit string) (uint64, error) {
	switch strings.ToLower(unit) {
	case "b", "bytes":
		return 1, nil
	case "kb", "kib":
		return 1024, nil
	case "mb", "mib":
		return 1024 * 1024, nil
	case "gb", "gib":
		return 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("unknown memory unit %q", unit)
	}
}

func saturatingAdd(a, b uint64) uint64 {
	sum := a + b
	if sum < a {
		return ^uint64(0)
	}
	return sum
}
