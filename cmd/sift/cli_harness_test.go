package main

// cli_harness_test.go — in-process driver for the command entry points.
//
// The historical CLI tests (cmd_verify_test.go and friends) build the real
// binary and run it as a subprocess. That proves behaviour but contributes no
// statement coverage: the test process never executes the code under test.
//
// This harness runs a command function inside the test process instead. It
// installs exitProcess / cliux.ExitProcess hooks that stop the command with a
// sentinel panic, redirects os.Args, os.Stdin, os.Stdout and os.Stderr, and
// reports the captured streams plus the would-be exit code. Tests therefore
// exercise the real dispatch, flag parsing, gate and output paths.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/cliux"
)

// exitSignal carries the exit code a command asked for.
type exitSignal int

// cliRunResult is one captured invocation.
type cliRunResult struct {
	code   int
	stdout string
	stderr string
}

// runCLIInProcess drives main() (the real dispatch) with args.
func runCLIInProcess(t *testing.T, args ...string) cliRunResult {
	t.Helper()
	return driveCommand(t, "", main, args...)
}

// runCLIInProcessStdin is runCLIInProcess with stdin fed from a string.
func runCLIInProcessStdin(t *testing.T, stdin string, args ...string) cliRunResult {
	t.Helper()
	return driveCommand(t, stdin, main, args...)
}

// runCommandFn drives one command function directly, bypassing main()'s
// dispatch. argv is what the command sees in os.Args (index 2 onward are its
// flags).
func runCommandFn(t *testing.T, fn func(), argv ...string) cliRunResult {
	t.Helper()
	return driveCommand(t, "", fn, argv...)
}

// driveCommand runs fn with the given argv, capturing streams and the exit
// code. A sentinel.panic unwinds the command; any other panic is re-raised so a
// genuine bug still fails the test loudly.
func driveCommand(t *testing.T, stdin string, fn func(), args ...string) (res cliRunResult) {
	t.Helper()

	dir := t.TempDir()
	stdoutFile, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatalf("create stdout capture: %v", err)
	}
	stderrFile, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatalf("create stderr capture: %v", err)
	}
	stdinFile, err := os.Create(filepath.Join(dir, "stdin"))
	if err != nil {
		t.Fatalf("create stdin source: %v", err)
	}
	if stdin != "" {
		if _, err := stdinFile.WriteString(stdin); err != nil {
			t.Fatalf("write stdin source: %v", err)
		}
		if _, err := stdinFile.Seek(0, 0); err != nil {
			t.Fatalf("rewind stdin source: %v", err)
		}
	}

	prevArgs := os.Args
	prevIn, prevOut, prevErr := os.Stdin, os.Stdout, os.Stderr
	prevExit, prevCLIExit := exitProcess, cliux.ExitProcess

	argv := append([]string{"Sift"}, args...)
	os.Args = argv
	os.Stdin, os.Stdout, os.Stderr = stdinFile, stdoutFile, stderrFile

	// The hooks panic so control returns here instead of killing the test
	// binary. Production keeps os.Exit.
	exitProcess = func(code int) { panic(exitSignal(code)) }
	cliux.ExitProcess = func(code int) { panic(exitSignal(code)) }

	func() {
		defer func() {
			if r := recover(); r != nil {
				if sig, ok := r.(exitSignal); ok {
					res.code = int(sig)
					return
				}
				panic(r)
			}
		}()
		fn()
	}()

	os.Args = prevArgs
	os.Stdin, os.Stdout, os.Stderr = prevIn, prevOut, prevErr
	exitProcess, cliux.ExitProcess = prevExit, prevCLIExit

	for _, f := range []*os.File{stdoutFile, stderrFile, stdinFile} {
		if err := f.Close(); err != nil {
			t.Fatalf("close capture file: %v", err)
		}
	}
	res.stdout = readCapture(t, filepath.Join(dir, "stdout"))
	res.stderr = readCapture(t, filepath.Join(dir, "stderr"))
	return res
}

// readCapture reads a capture file, tolerating an empty one.
func readCapture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read capture %s: %v", path, err)
	}
	return string(data)
}

// scanCLIHome points the CLI's authorization state (policy + audit log) at a
// throwaway directory, so a test never touches ~/.Sift.
func scanCLIHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("SIFT_HOME", home)
	return home
}
