//go:build windows

package demostore

import "os/exec"

// spawnProcessGroup is a no-op on Windows (no POSIX process groups).
func spawnProcessGroup(cmd *exec.Cmd) {}

// killProcessGroup falls back to a plain kill on Windows.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
