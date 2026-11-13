package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// subBinaryName renders the on-disk name of a sibling sub-binary. Windows
// resolves executables by extension, so a bare "Sift-scan" never
// matches "Sift-scan.exe": without this the Windows build would always
// miss the shipped sibling and fall through to `go run`, which a distributed
// binary cannot do.
func subBinaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// runSubCommand locates and executes a sub-binary by name.
// It first tries the sibling binary next to the current executable,
// then falls back to `go run` from the project root.
func runSubCommand(name string, args []string) {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine executable path: %v\n", err)
		exitProcess(1)
	}
	exe = filepath.Clean(exe)
	binDir := filepath.Dir(exe)
	bin := filepath.Join(binDir, subBinaryName(name))

	if _, err := os.Stat(bin); err == nil {
		// Found standalone binary — run it directly
		cmd := exec.Command(bin, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			exitFromChild(name, bin, "", err)
		}
		return
	}

	// Fallback: run via `go run`
	goArgs := append([]string{"run", "./cmd/" + name}, args...)
	cmd := exec.Command("go", goArgs...)
	cmd.Dir = findProjectRoot()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		hint := fmt.Sprintf("Error: %s command failed. Build with: go build -o bin/%s ./cmd/%s\n", name, name, name)
		exitFromChild(name, "", hint, err)
	}
}

// exitFromChild turns a failed child process into a truthful exit status. A
// child that was killed by a signal has no exit code at all — reporting one
// (Go returns -1) hides the cause, and on macOS an invalid ad-hoc signature
// shows up exactly that way: the kernel SIGKILLs the binary at launch.
func exitFromChild(name, bin, hint string, err error) {
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		if hint != "" {
			fmt.Fprint(os.Stderr, hint)
		}
		fmt.Fprintf(os.Stderr, "Error: %s command failed: %v\n", name, err)
		exitProcess(1)
	}
	if sig, killed := killedBySignal(exitErr); killed {
		fmt.Fprintf(os.Stderr, "\nError: %s was killed by a signal (%s) before it could report anything.\n", name, sig)
		if sig.String() == "killed" {
			fmt.Fprintln(os.Stderr, "Hint: macOS kills a binary whose code signature does not match the file on disk.")
			if bin != "" {
				fmt.Fprintf(os.Stderr, "      Re-sign it:  codesign --force --sign - %q\n", bin)
			}
			fmt.Fprintln(os.Stderr, "      Or reinstall everything:  make install")
		}
		exitProcess(signalExitCode(sig))
	}
	if hint != "" {
		fmt.Fprint(os.Stderr, hint)
	}
	exitProcess(exitErr.ExitCode())
}

func cmdReplay()    { runSubCommand("Sift-replay", os.Args[2:]) }
func cmdScan()      { runSubCommand("Sift-scan", os.Args[2:]) }
func cmdDashboard() { runSubCommand("Sift-dashboard", os.Args[2:]) }
func cmdMaster()    { runSubCommand("Sift-master", os.Args[2:]) }
func cmdWorker()    { runSubCommand("Sift-worker", os.Args[2:]) }

func findProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}
