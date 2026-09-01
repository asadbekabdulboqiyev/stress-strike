package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"stress-strike/internal/engine"
	"stress-strike/internal/report"
)

// isInteractiveTerminal reports whether stdin is a TTY (interactive user)
// as opposed to piped/redirected input (scripts, CI).
func isInteractiveTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// interactivePicker presents the workspace selection menu when the binary is
// run with no arguments from a terminal: choose CLI (terminal report) or
// Web Server (real-time dashboard), then gather the minimum settings and run.
func interactivePicker() {
	r := bufio.NewReader(os.Stdin)

	banner()
	fmt.Println()
	fmt.Println("Choose a workspace:")
	fmt.Println()
	fmt.Println("  1) CLI — run a load test and print a report to the terminal")
	fmt.Println("  2) Web Server — start the real-time dashboard and run from the browser")
	fmt.Println("  0) Quit")
	fmt.Println()

	choice := strings.TrimSpace(readLine(r, "Select [1/2/0]"))

	switch choice {
	case "2", "web", "server", "dashboard":
		interactiveDashboard(r)
	case "0", "q", "quit", "exit":
		fmt.Println("Bye.")
		os.Exit(0)
	default:
		interactiveCLI(r)
	}
}

// interactiveDashboard starts the real-time Web Server dashboard. It builds a
// default scenario from the answered settings, launches the dashboard server
// and the real engine; the user drives it from the browser.
func interactiveDashboard(r *bufio.Reader) {
	url := readLine(r, "Target URL (e.g. https://api.example.com)")
	if url == "" {
		fmt.Println("error: target URL is required.")
		os.Exit(1)
	}
	users := readInt(r, "Virtual users", 10)
	duration := readInt(r, "Duration (seconds)", 30)
	listen := readLine(r, "Dashboard listen address (e.g. :8888)")
	if listen == "" {
		listen = ":8888"
	}

	sc, err := quickScenario("interactive", url, "GET", "", headerFlags{},
		"steady", users, duration, 0, 0, 0, 0, 0, 0, 0, 5, true)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("\nStarting Web Server dashboard on %s — open it in a browser and press Start.\n\n", listen)
	runWithDashboard(sc, listen, "./reports")
}

// interactiveCLI gathers settings on the command line, then runs the real load
// engine and prints the terminal report.
func interactiveCLI(r *bufio.Reader) {
	fmt.Println()
	fmt.Println("Load test configuration (CLI mode):")
	fmt.Println()

	url := readLine(r, "Target URL (e.g. https://api.example.com)")
	if url == "" {
		fmt.Println("error: target URL is required.")
		os.Exit(1)
	}
	users := readInt(r, "Virtual users", 10)
	duration := readInt(r, "Duration (seconds)", 30)

	fmt.Println("\nRunning load test...")

	sc, err := quickScenario("interactive", url, "GET", "", headerFlags{},
		"steady", users, duration, 0, 0, 0, 0, 0, 0, 0, 5, true)
	if err != nil {
		fatal(err)
	}

	eng, err := engine.New(sc)
	if err != nil {
		fatal(err)
	}

	progress := engine.NewProgressTracker(
		time.Duration(sc.Profile.TotalDuration())*time.Second,
		sc.Profile.Users,
	)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tr, err := eng.Run(ctx, engine.RunOptions{Out: os.Stderr, Progress: progress})
	if err != nil {
		fatal(err)
	}
	if progress != nil {
		progress.Finish()
	}

	rpt := report.Build(tr, sc)
	rpt.Render(os.Stdout)

	jp, err := rpt.SaveJSON("./reports")
	if err == nil {
		tp, _ := rpt.SaveTXT("./reports")
		fmt.Fprintf(os.Stderr, "\nReports written:\n  %s\n", jp)
		if tp != "" {
			fmt.Fprintf(os.Stderr, "  %s\n", tp)
		}
	}
}

// readLine prompts the user and returns their trimmed input.
func readLine(r *bufio.Reader, prompt string) string {
	fmt.Printf("  %s: ", prompt)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimSpace(line)
}

func readInt(r *bufio.Reader, prompt string, def int) int {
	for {
		fmt.Printf("  %s [%d]: ", prompt, def)
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		if err == nil {
			n, e := strconv.Atoi(line)
			if e == nil {
				return n
			}
		}
		fmt.Println("    Invalid number, try again.")
	}
}

func banner() {
	fmt.Println("┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│           stress-strike — Load Testing Suite           │")
	fmt.Printf("│                     version %-10s                │\n", version)
	fmt.Println("└─────────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("WARNING: Only test systems you own or have explicit permission to test.")
	fmt.Println("         Unauthorized load testing is illegal (DDoS).")
}
