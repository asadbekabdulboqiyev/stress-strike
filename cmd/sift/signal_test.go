//go:build unix

package main

import (
	"os/exec"
	"syscall"
	"testing"
)

// TestKilledBySignal proves the helper recovers a signal that cmd.Run()
// flattens into ExitCode() == -1. This is the macOS "zsh: killed" path.
func TestKilledBySignal(t *testing.T) {
	cmd := exec.Command("sh", "-c", "kill -9 $$")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected the child to be killed")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError, got %T", err)
	}
	if code := exitErr.ExitCode(); code != -1 {
		t.Fatalf("precondition: ExitCode() = %d, want -1 for a signalled child", code)
	}
	sig, killed := killedBySignal(exitErr)
	if !killed {
		t.Fatal("killedBySignal reported no signal")
	}
	if sig != syscall.SIGKILL {
		t.Fatalf("signal = %v, want SIGKILL", sig)
	}
	if got, want := signalExitCode(sig), 137; got != want {
		t.Fatalf("signalExitCode = %d, want %d", got, want)
	}
	if name := sig.String(); name != "killed" {
		t.Fatalf("signal name = %q, want %q (the string the hint keys on)", name, "killed")
	}
}

// TestKilledBySignalExitCode guards the normal, non-signalled path.
func TestKilledBySignalExitCode(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 3").Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError, got %T", err)
	}
	if _, killed := killedBySignal(exitErr); killed {
		t.Fatal("exit 3 must not be reported as a signal")
	}
	if code := exitErr.ExitCode(); code != 3 {
		t.Fatalf("ExitCode = %d, want 3", code)
	}
}
