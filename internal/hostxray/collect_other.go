//go:build !linux

package hostxray

import (
	"context"
	"runtime"
	"time"
)

// runtimeCollector is the non-Linux fallback. It samples the Go runtime of the
// Sift process (goroutines, heap, GC pauses) and records explicitly that no
// kernel evidence is available on this platform. It is not a substitute for
// host metrics: it can only speak about Sift itself.
type runtimeCollector struct {
	caps Capabilities
}

func newPlatformCollector(_ Options) (Collector, error) {
	return &runtimeCollector{caps: DetectCapabilities()}, nil
}

// Capabilities reports the detection result computed once at construction.
func (c *runtimeCollector) Capabilities() Capabilities { return c.caps }

// Close releases nothing; the fallback holds no resources.
func (c *runtimeCollector) Close() error { return nil }

// Collect returns one Go runtime sample. It cannot fail except on context
// cancellation.
func (c *runtimeCollector) Collect(ctx context.Context) (Sample, error) {
	if err := ctx.Err(); err != nil {
		return Sample{}, err
	}
	return Sample{
		Timestamp: time.Now().UTC(),
		Source:    SourceRuntime,
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		Runtime:   runtimeSnapshot(),
		Notes: []string{
			"kernel evidence is unavailable on this platform: /proc and BTF are Linux-only",
			"values describe the Go runtime of the Sift process, not the host kernel",
		},
	}, nil
}
