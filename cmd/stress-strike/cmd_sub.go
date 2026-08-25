package main

import (
	"fmt"
	"os"
	"os/exec"
)

func cmdReplay() {
	// Find the replay binary next to this binary
	binDir, _ := os.Executable()
	binDir = binDir[:len(binDir)-len("stress-strike")]
	bin := binDir + "stress-strike-replay"

	// If standalone binary not found, try to run via go run
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		// Try go run
		args := append([]string{"run", "./cmd/stress-strike-replay"}, os.Args[2:]...)
		cmd := exec.Command("go", args...)
		cmd.Dir = findProjectRoot()
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: replay command failed. Build with: go build -o bin/stress-strike-replay ./cmd/stress-strike-replay\n")
			os.Exit(1)
		}
		return
	}

	cmd := exec.Command(bin, os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func cmdScan() {
	binDir, _ := os.Executable()
	binDir = binDir[:len(binDir)-len("stress-strike")]
	bin := binDir + "stress-strike-scan"

	if _, err := os.Stat(bin); os.IsNotExist(err) {
		args := append([]string{"run", "./cmd/stress-strike-scan"}, os.Args[2:]...)
		cmd := exec.Command("go", args...)
		cmd.Dir = findProjectRoot()
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: scan command failed. Build with: go build -o bin/stress-strike-scan ./cmd/stress-strike-scan\n")
			os.Exit(1)
		}
		return
	}

	cmd := exec.Command(bin, os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func cmdDashboard() {
	binDir, _ := os.Executable()
	binDir = binDir[:len(binDir)-len("stress-strike")]
	bin := binDir + "stress-strike-dashboard"

	if _, err := os.Stat(bin); os.IsNotExist(err) {
		args := append([]string{"run", "./cmd/stress-strike-dashboard"}, os.Args[2:]...)
		cmd := exec.Command("go", args...)
		cmd.Dir = findProjectRoot()
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: dashboard command failed. Build with: go build -o bin/stress-strike-dashboard ./cmd/stress-strike-dashboard\n")
			os.Exit(1)
		}
		return
	}

	cmd := exec.Command(bin, os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func cmdAI() {
	binDir, _ := os.Executable()
	binDir = binDir[:len(binDir)-len("stress-strike")]
	bin := binDir + "stress-strike-ai"

	if _, err := os.Stat(bin); os.IsNotExist(err) {
		args := append([]string{"run", "./cmd/stress-strike-ai"}, os.Args[2:]...)
		cmd := exec.Command("go", args...)
		cmd.Dir = findProjectRoot()
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: ai command failed. Build with: go build -o bin/stress-strike-ai ./cmd/stress-strike-ai\n")
			os.Exit(1)
		}
		return
	}

	cmd := exec.Command(bin, os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func cmdMaster() {
	binDir, _ := os.Executable()
	binDir = binDir[:len(binDir)-len("stress-strike")]
	bin := binDir + "stress-strike-master"

	if _, err := os.Stat(bin); os.IsNotExist(err) {
		args := append([]string{"run", "./cmd/stress-strike-master"}, os.Args[2:]...)
		cmd := exec.Command("go", args...)
		cmd.Dir = findProjectRoot()
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: master command failed. Build with: go build -o bin/stress-strike-master ./cmd/stress-strike-master\n")
			os.Exit(1)
		}
		return
	}

	cmd := exec.Command(bin, os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func cmdWorker() {
	binDir, _ := os.Executable()
	binDir = binDir[:len(binDir)-len("stress-strike")]
	bin := binDir + "stress-strike-worker"

	if _, err := os.Stat(bin); os.IsNotExist(err) {
		args := append([]string{"run", "./cmd/stress-strike-worker"}, os.Args[2:]...)
		cmd := exec.Command("go", args...)
		cmd.Dir = findProjectRoot()
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: worker command failed. Build with: go build -o bin/stress-strike-worker ./cmd/stress-strike-worker\n")
			os.Exit(1)
		}
		return
	}

	cmd := exec.Command(bin, os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func findProjectRoot() string {
	// Try to find go.mod
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir
		}
		parent := dir[:len(dir)-1]
		for i := len(parent) - 1; i >= 0; i-- {
			if parent[i] == '/' {
				parent = parent[:i]
				break
			}
		}
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}
