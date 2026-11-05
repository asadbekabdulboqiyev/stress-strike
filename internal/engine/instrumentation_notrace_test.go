//go:build !race

package engine

import "testing"

// buildInstrumented reports whether this test binary was compiled with coverage
// instrumentation (-cover / -coverpkg), which widens the window a burst has to
// fit into. Both flags stretch the effective capacity of the process, so the
// loopback burst budgets below have to know about them to stay meaningful.
func buildInstrumented() bool { return testing.CoverMode() != "" }
