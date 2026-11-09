//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// killedBySignal is a no-op on Windows: there is no equivalent signal status
// on a child process, so callers fall back to the plain exit code.
func killedBySignal(err *exec.ExitError) (syscall.Signal, bool) {
	return 0, false
}

func signalExitCode(sig syscall.Signal) int {
	return 1
}
