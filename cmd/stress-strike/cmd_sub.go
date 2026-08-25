package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// runSubCommand locates and executes a sub-binary by name.
// It first tries the sibling binary next to the current executable,
// then falls back to `go run` from the project root.
func runSubCommand(name string, args []string) {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine executable path: %v\n", err)
		os.Exit(1)
	}
	exe = filepath.Clean(exe)
	binDir := filepath.Dir(exe)
	bin := filepath.Join(binDir, name)

	if _, err := os.Stat(bin); err == nil {
		// Found standalone binary — run it directly
		cmd := exec.Command(bin, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			fmt.Fprintf(os.Stderr, "Error: %s command failed: %v\n", name, err)
			os.Exit(1)
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
		fmt.Fprintf(os.Stderr, "Error: %s command failed. Build with: go build -o bin/%s ./cmd/%s\n", name, name, name)
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

func cmdReplay()    { runSubCommand("stress-strike-replay", os.Args[2:]) }
func cmdScan()      { runSubCommand("stress-strike-scan", os.Args[2:]) }
func cmdDashboard() { runSubCommand("stress-strike-dashboard", os.Args[2:]) }
func cmdAI()        { runSubCommand("stress-strike-ai", os.Args[2:]) }
func cmdMaster()    { runSubCommand("stress-strike-master", os.Args[2:]) }
func cmdWorker()    { runSubCommand("stress-strike-worker", os.Args[2:]) }

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
