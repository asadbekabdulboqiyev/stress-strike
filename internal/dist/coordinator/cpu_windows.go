//go:build windows

package coordinator

import "golang.org/x/sys/windows"

// processCPUSeconds returns the CPU time (user + kernel) this process has
// consumed so far, in seconds, and whether the sample is available.
//
// Windows has no getrusage(2). GetProcessTimes reports the same two counters,
// as FILETIME values that here hold *durations*, not timestamps: they are
// 100-nanosecond ticks since process start, so they are converted directly.
//
// Do NOT use Filetime.Nanoseconds(): that method reinterprets a FILETIME as an
// absolute time and subtracts the 1601->1970 epoch offset, which would turn a
// CPU duration into a meaningless ~369-year number.
func processCPUSeconds() (float64, bool) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		return 0, false
	}
	return filetimeDurationSeconds(kernel) + filetimeDurationSeconds(user), true
}

// filetimeDurationSeconds converts a FILETIME duration (100 ns ticks since the
// process started) into seconds.
func filetimeDurationSeconds(ft windows.Filetime) float64 {
	ticks := int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
	return float64(ticks) / 1e7
}
