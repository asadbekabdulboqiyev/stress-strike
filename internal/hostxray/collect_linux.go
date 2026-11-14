//go:build linux

package hostxray

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// procCollector samples aggregate counters from the world-readable Linux /proc
// filesystem. It opens no sockets, loads no BPF programs, and reads no
// per-process data. A missing or unreadable file becomes a note on the sample
// rather than a failure, because containers routinely mount a trimmed /proc.
type procCollector struct {
	root string
	caps Capabilities

	mu       sync.Mutex
	prevStat *CPUJiffies
	prevAt   time.Time
}

func newPlatformCollector(_ Options) (Collector, error) {
	return &procCollector{root: procMount, caps: DetectCapabilities()}, nil
}

// Capabilities returns the detection result computed once at construction.
func (c *procCollector) Capabilities() Capabilities { return c.caps }

// Close releases nothing: every read opens and closes its own file, so there
// is no file descriptor or ticker to reclaim.
func (c *procCollector) Close() error { return nil }

// Collect reads the aggregate host view. It never returns an error for a
// missing proc file: only context cancellation and unexpected I/O failures that
// leave the sample unusable propagate.
func (c *procCollector) Collect(ctx context.Context) (Sample, error) {
	if err := ctx.Err(); err != nil {
		return Sample{}, err
	}
	now := time.Now().UTC()
	sample := Sample{
		Timestamp: now,
		Source:    SourceLinuxProc,
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		Runtime:   runtimeSnapshot(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if la, err := c.loadLoadAvg(ctx); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Sample{}, ctxErr
		}
		sample.Notes = append(sample.Notes, fmt.Sprintf("loadavg unavailable: %v", err))
	} else {
		sample.Load = la
	}

	if mem, err := c.loadMemInfo(ctx); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Sample{}, ctxErr
		}
		sample.Notes = append(sample.Notes, fmt.Sprintf("meminfo unavailable: %v", err))
	} else {
		sample.Mem = mem
	}

	if net, err := c.loadNet(ctx); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Sample{}, ctxErr
		}
		sample.Notes = append(sample.Notes, fmt.Sprintf("net/dev unavailable: %v", err))
	} else {
		sample.Net = net
	}

	cpu, err := c.loadCPU(ctx, now)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Sample{}, ctxErr
		}
		sample.Notes = append(sample.Notes, fmt.Sprintf("stat unavailable: %v", err))
	}
	sample.CPU = cpu

	sample.PSI = c.loadPSI(ctx, &sample.Notes)

	return sample, nil
}

func (c *procCollector) loadLoadAvg(ctx context.Context) (LoadAverage, error) {
	data, err := c.read(ctx, "loadavg")
	if err != nil {
		return LoadAverage{}, err
	}
	return ParseLoadAvg(bytes.NewReader(data))
}

func (c *procCollector) loadMemInfo(ctx context.Context) (MemoryStats, error) {
	data, err := c.read(ctx, "meminfo")
	if err != nil {
		return MemoryStats{}, err
	}
	return ParseMemInfo(bytes.NewReader(data))
}

func (c *procCollector) loadNet(ctx context.Context) (NetStats, error) {
	data, err := c.read(ctx, "net/dev")
	if err != nil {
		return NetStats{}, err
	}
	interfaces, err := ParseNetDev(bytes.NewReader(data))
	if err != nil {
		return NetStats{}, err
	}
	return NetStats{
		Interfaces: interfaces,
		Aggregate:  AggregateNetDev(interfaces),
		Available:  true,
	}, nil
}

func (c *procCollector) loadCPU(ctx context.Context, now time.Time) (CPUStats, error) {
	data, err := c.read(ctx, "stat")
	if err != nil {
		return CPUStats{}, err
	}
	stat, err := ParseProcStat(bytes.NewReader(data))
	if err != nil {
		return CPUStats{}, err
	}
	cpu := CPUStats{CPUJiffies: stat}
	if c.prevStat != nil {
		util, iowait, ok := Utilization(*c.prevStat, stat)
		cpu.UtilizationPct = util
		cpu.IOWaitPct = iowait
		cpu.Available = ok
		cpu.Interval = now.Sub(c.prevAt)
	}
	prev := stat
	c.prevStat = &prev
	c.prevAt = now
	return cpu, nil
}

func (c *procCollector) loadPSI(ctx context.Context, notes *[]string) PSIStats {
	var out PSIStats
	if !c.caps.ProcPressure {
		*notes = append(*notes, "/proc/pressure is not exposed by this kernel; memory/IO stall evidence is unavailable")
		return out
	}
	if pressure, err := c.loadPressure(ctx, "pressure/cpu"); err != nil {
		if ctx.Err() == nil {
			*notes = append(*notes, fmt.Sprintf("pressure/cpu unavailable: %v", err))
		}
	} else {
		out.CPU = &pressure
	}
	if pressure, err := c.loadPressure(ctx, "pressure/memory"); err != nil {
		if ctx.Err() == nil {
			*notes = append(*notes, fmt.Sprintf("pressure/memory unavailable: %v", err))
		}
	} else {
		out.Memory = &pressure
	}
	if pressure, err := c.loadPressure(ctx, "pressure/io"); err != nil {
		if ctx.Err() == nil {
			*notes = append(*notes, fmt.Sprintf("pressure/io unavailable: %v", err))
		}
	} else {
		out.IO = &pressure
	}
	return out
}

func (c *procCollector) loadPressure(ctx context.Context, name string) (Pressure, error) {
	data, err := c.read(ctx, name)
	if err != nil {
		return Pressure{}, err
	}
	return ParsePSI(bytes.NewReader(data))
}

// read opens one fixed /proc entry under the compile-time mount point. The
// path is never built from user input.
func (c *procCollector) read(ctx context.Context, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := filepath.Join(c.root, name) // #nosec G304 -- c.root is the fixed /proc mount; name is a compile-time constant
	return os.ReadFile(path)
}
