//go:build !windows

package coordinator

import "syscall"

// processCPUSeconds returns the CPU time (user + system) this process has
// consumed so far, in seconds, and whether the sample is available.
//
// getrusage(2) is the POSIX way to read the per-process counters; both the
// Linux and the Darwin struct expose them as Utime/Stime with microsecond
// fields, so the same conversion works on every non-Windows platform.
func processCPUSeconds() (float64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	return float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6 +
		float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6, true
}
