//go:build !windows

package demostore

import (
	"os/exec"
	"syscall"
)

// spawnProcessGroup starts cmd in its own process group so a later
// killProcessGroup reaps the whole tree. This matters for the `go run`
// fallback: go run compiles the store and execs it as a child, so killing
// only the go run wrapper would orphan the compiled demo_store binary.
func spawnProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessGroup terminates every process in cmd's group — the go run
// wrapper AND the compiled demo_store child.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	// A negative PID targets the process group.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
