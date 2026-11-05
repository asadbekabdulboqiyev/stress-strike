//go:build race

package engine

// buildInstrumented reports whether this test binary was compiled with the Go
// race detector. Race instrumentation stretches the real concurrency window of
// the process, which matters for the loopback burst-budget tests below.
func buildInstrumented() bool { return true }
