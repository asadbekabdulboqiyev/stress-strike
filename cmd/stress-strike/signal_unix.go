//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// killedBySignal reports the signal that terminated a child process, if any.
// cmd.Run() collapses a signalled child into *exec.ExitError with ExitCode()
// == -1, which loses the reason; the WaitStatus keeps it.
func killedBySignal(err *exec.ExitError) (syscall.Signal, bool) {
	if err == nil {
		return 0, false
	}
	ws, ok := err.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return 0, false
	}
	return ws.Signal(), true
}

// signalExitCode converts a terminating signal into the shell's 128+N code.
func signalExitCode(sig syscall.Signal) int {
	return 128 + int(sig)
}
