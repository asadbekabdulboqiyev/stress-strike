//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"

	"stress-strike/internal/config"
)

// warnLowFileLimit warns the user when the open-file limit (ulimit -n) may be
// too low for the planned concurrency, so sockets are not silently exhausted
// mid-test. Unix-only: requires Getrlimit/RLIMIT_NOFILE.
func warnLowFileLimit(profile config.Profile) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		// Cannot read the limit; nothing useful to warn about.
		return
	}
	need := uint64(profile.Users * 4)
	if profile.SpikeUsers > profile.Users {
		need = uint64(profile.SpikeUsers * 4)
	}
	if lim.Cur < need {
		fmt.Fprintf(os.Stderr, "warning: open-file limit is %d but the test may need ~%d sockets (raise with 'ulimit -n')\n", lim.Cur, need)
	}
}
