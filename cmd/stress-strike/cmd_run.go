package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/fingerprint"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
)

type headerFlags map[string]string

func (h headerFlags) String() string { return "" }
func (h headerFlags) Set(value string) error {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 || parts[0] == "" {
		return fmt.Errorf("header must be in Key=Value form, got %q", value)
	}
	h[parts[0]] = parts[1]
	return nil
}

func cmdRun() {
	var (
		configPath    string
		url           string
		method        string
		data          string
		headers       = headerFlags{}
		name          string
		profile       string
		users         int
		duration      int
		rampUp        int
		spikeUsers    int
		spikeWarmup   int
		spikeHold     int
		wavePeriod    int
		rps           int
		timeout       int
		keepAlive     bool
		quiet         bool
		reportDir     string
		showVersion   bool
		expectP99     float64
		expectAvg     float64
		expectErrRate float64
		expectMinRPS  float64
		comparePath   string
		regressPct    float64
		timelineCSV   bool
		preWarm       bool
		preWarmConns  int
		targetRPS     int
		mode          string
		dashListen    string
		tlsFP         string
	)

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // suppress raw Go flag noise; we render our own
	fs.Usage = func() {}     // usage dumps are handled explicitly below
	fs.StringVar(&configPath, "config", "", "YAML/JSON scenario file")
	fs.StringVar(&configPath, "c", "", "shorthand for --config")
	fs.StringVar(&url, "url", "", "target URL (quick mode)")
	fs.StringVar(&method, "method", "GET", "HTTP method (quick mode)")
	fs.StringVar(&data, "data", "", "request body (quick mode)")
	fs.Var(headers, "header", "request header in Key=Value form (repeatable)")
	fs.StringVar(&name, "name", "quick-test", "report/test name")
	fs.StringVar(&profile, "profile", "steady", "load profile: steady, soak, linear-ramp, spike, wave, constant-rps")
	fs.IntVar(&users, "users", 10, "concurrent virtual users")
	fs.IntVar(&duration, "duration", 30, "test duration in seconds")
	fs.IntVar(&rampUp, "ramp-up", 0, "ramp-up duration in seconds")
	fs.IntVar(&spikeUsers, "spike-users", 0, "target users for spike burst")
	fs.IntVar(&spikeWarmup, "spike-warmup", 5, "baseline warmup seconds before spike")
	fs.IntVar(&spikeHold, "spike-hold", 10, "spike burst duration in seconds")
	fs.IntVar(&wavePeriod, "wave-period", 0, "oscillation period in seconds (wave)")
	fs.IntVar(&rps, "rps", 0, "global pacing cap (requests per second)")
	fs.IntVar(&targetRPS, "target-rps", 0, "target requests per second (constant-rps mode)")
	fs.IntVar(&timeout, "timeout", 5, "per-request timeout in seconds")
	fs.BoolVar(&keepAlive, "keep-alive", true, "reuse TCP connections")
	fs.StringVar(&tlsFP, "tls-fingerprint", "", "TLS ClientHello fingerprint (chrome, firefox, safari, edge, ios, android_okhttp, randomized, golang, ...)")
	fs.Float64Var(&expectP99, "expect-p99-ms", 0, "SLA: max p99 latency (ms)")
	fs.Float64Var(&expectAvg, "expect-avg-ms", 0, "SLA: max avg latency (ms)")
	fs.Float64Var(&expectErrRate, "expect-error-rate", 0, "SLA: max error rate (%%)")
	fs.Float64Var(&expectMinRPS, "expect-min-rps", 0, "SLA: min throughput")
	fs.StringVar(&comparePath, "compare", "", "baseline report for comparison")
	fs.Float64Var(&regressPct, "regress-pct", 20, "regression threshold %%")
	fs.BoolVar(&timelineCSV, "timeline", false, "write per-second CSV timeline")
	fs.BoolVar(&preWarm, "pre-warm", false, "pre-establish TCP connections before test start")
	fs.IntVar(&preWarmConns, "pre-warm-conns", 0, "number of pre-warmed connections (default: users count)")
	fs.BoolVar(&quiet, "quiet", false, "disable live progress")
	fs.StringVar(&reportDir, "report-dir", "./reports", "report output directory")
	fs.BoolVar(&showVersion, "version", false, "print version")
	fs.StringVar(&mode, "mode", "cli", "output mode: cli (terminal report) | dashboard (real-time web dashboard)")
	fs.StringVar(&dashListen, "listen", "127.0.0.1:8888", "dashboard listen address (with --mode dashboard)")

	// Parse args: os.Args = ["run", "--url", ...] after slicing in main.go.
	// Friendly flag errors, consistent help, exit 2 on usage errors.
	cliux.Parse(fs, os.Args[1:], func() { printRunHelp(fs) }, cliux.Options{
		Command: "run",
		FlagSet: fs,
		Examples: []string{
			"stress-strike run --url https://api.example.com --users 10 --duration 10",
		},
	})

	if showVersion {
		fmt.Printf("stress-strike v%s\n", version)
		return
	}

	nameSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "name" {
			nameSet = true
		}
	})

	var scenario *config.Scenario
	if configPath != "" {
		sc, err := config.Load(configPath)
		if err != nil {
			fatal(err)
		}
		if nameSet {
			sc.Name = name
		}
		scenario = sc
	} else {
		if url == "" {
			fatal(fmt.Errorf("either --config or --url is required\n\nExample: stress-strike run --url https://api.example.com --users 10 --duration 10"))
		}
		// When --target-rps is set, automatically use constant-rps profile.
		if targetRPS > 0 && profile == "steady" {
			profile = "constant-rps"
		}
		sc, err := quickScenario(name, url, method, data, headers, profile, users, duration, rampUp, spikeUsers, spikeWarmup, spikeHold, wavePeriod, rps, targetRPS, timeout, keepAlive)
		if err != nil {
			fatal(err)
		}
		scenario = sc
	}

	if tlsFP != "" {
		if !fingerprint.Profile(tlsFP).Valid() {
			fatal(fmt.Errorf("unknown -tls-fingerprint %q (valid values: %s)", tlsFP, strings.Join(fingerprint.Names(), ", ")))
		}
		scenario.Profile.TLSFingerprint = tlsFP
	}

	sla := scenario.SLA
	if sla == nil {
		sla = &config.SLA{}
	}
	if expectP99 > 0 {
		sla.MaxP99Ms = expectP99
	}
	if expectAvg > 0 {
		sla.MaxAvgMs = expectAvg
	}
	if expectErrRate > 0 {
		sla.MaxErrorRatePct = expectErrRate
	}
	if expectMinRPS > 0 {
		sla.MinRPS = expectMinRPS
	}
	if !sla.Empty() {
		scenario.SLA = sla
	}

	// Validate mode
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "cli" && mode != "dashboard" {
		fatal(fmt.Errorf("invalid --mode %q: must be 'cli' or 'dashboard'", mode))
	}

	// Dashboard mode: open the real-time WebSocket dashboard and drive the
	// real load engine from the browser. No terminal report is printed.
	if mode == "dashboard" {
		runWithDashboard(scenario, dashListen, reportDir)
		return
	}

	if preWarm {
		scenario.PreWarm = true
		if preWarmConns > 0 {
			scenario.PreWarmConnections = preWarmConns
		}
	}

	fmt.Fprintln(os.Stderr, "WARNING: stress-strike is a load testing tool. Only run it against systems you own or")
	fmt.Fprintln(os.Stderr, "have explicit written permission to test. Unauthorized load floods are illegal (DDoS).")
	if scenario.Profile.TLSFingerprint != "" {
		fmt.Fprintf(os.Stderr, "TLS fingerprint: masking ClientHello as %q (JA3-mitigation bypass)\n", scenario.Profile.TLSFingerprint)
	}

	eng, err := engine.New(scenario)
	if err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		second := make(chan os.Signal, 1)
		signal.Notify(second, os.Interrupt, syscall.SIGTERM)
		<-second
		os.Exit(130)
	}()

	fmt.Fprintf(os.Stderr, "stress-strike v%s | target: %s | profile: %s | duration: %ds\n",
		version, targetDisplay(scenario), scenario.Profile.Type, scenario.Profile.TotalDuration())

	var progress *engine.ProgressTracker
	if !quiet {
		dur := time.Duration(scenario.Profile.TotalDuration()) * time.Second
		progress = engine.NewProgressTracker(dur, scenario.Profile.Users)
	}

	telemetry, err := eng.Run(ctx, engine.RunOptions{Out: os.Stderr, Quiet: quiet, Progress: progress})
	if err != nil {
		fatal(err)
	}
	if progress != nil {
		progress.Finish()
	}

	r := report.Build(telemetry, scenario)
	fmt.Fprintln(os.Stderr)
	r.Render(os.Stdout)

	if comparePath != "" {
		baseline, err := report.LoadReport(comparePath)
		if err != nil {
			fatal(err)
		}
		result := report.Compare(&r, baseline)
		fmt.Print(result.Render())
		if result.Regression && result.RegressionPct > regressPct {
			fmt.Fprintf(os.Stderr, "REGRESSION DETECTED vs %s (threshold %.0f%%, actual %.1f%%)\n",
				comparePath, regressPct, result.RegressionPct)
			os.Exit(2)
		}
	}

	jsonPath, err := r.SaveJSON(reportDir)
	if err != nil {
		fatal(err)
	}
	txtPath, err := r.SaveTXT(reportDir)
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "\nReports written:\n  %s\n  %s\n", jsonPath, txtPath)

	if timelineCSV {
		csvPath, err := r.SaveCSV(reportDir)
		if err != nil {
			fatal(err)
		}
		if csvPath != "" {
			fmt.Fprintf(os.Stderr, "  %s\n", csvPath)
		}
	}

	if len(r.SLA) > 0 && !report.SLAPassed(r.SLA) {
		fmt.Fprintln(os.Stderr, "SLA gate FAILED — exiting with code 2")
		os.Exit(2)
	}

	// Safety net: a run that failed on 100% of requests (e.g. dead port,
	// DNS failure, unreachable host) should not look like a success.
	if r.TotalRequests > 0 && r.TotalErrors == r.TotalRequests {
		fmt.Fprintln(os.Stderr, "FATAL: 100% of requests failed — target unreachable or refusing connections")
		fmt.Fprintln(os.Stderr, "  Check the target URL, network, and that the server is up.")
		os.Exit(1)
	}
}

func quickScenario(name, url, method, data string, headers headerFlags, profile string, users, duration, rampUp, spikeUsers, spikeWarmup, spikeHold, wavePeriod, rps, targetRPS, timeout int, keepAlive bool) (*config.Scenario, error) {
	sc := &config.Scenario{
		Name: name,
		Profile: config.Profile{
			Type:        profile,
			Users:       users,
			Duration:    duration,
			RampUp:      rampUp,
			SpikeUsers:  spikeUsers,
			SpikeWarmup: spikeWarmup,
			SpikeHold:   spikeHold,
			WavePeriod:  wavePeriod,
			RPS:         rps,
			TargetRPS:   targetRPS,
			Timeout:     timeout,
			KeepAlive:   &keepAlive,
		},
		Steps: []config.Step{
			{
				Name:    "request",
				Method:  method,
				URL:     url,
				Headers: headers,
				Body:    data,
			},
		},
	}
	if err := sc.Normalize(); err != nil {
		return nil, err
	}
	return sc, nil
}

func targetDisplay(scenario *config.Scenario) string {
	if scenario.BaseURL != "" {
		return scenario.BaseURL
	}
	if len(scenario.Steps) > 0 {
		return scenario.Steps[0].URL
	}
	return "n/a"
}

// printRunHelp renders `stress-strike run --help` in the same sectioned,
// two-dash style as the top-level help, with real examples.
func printRunHelp(fs *flag.FlagSet) {
	w := os.Stderr
	fmt.Fprintf(w, "\n stress-strike run — HTTP/gRPC/WebSocket load test\n\n")
	fmt.Fprintf(w, " USAGE\n")
	fmt.Fprintf(w, "   stress-strike run --url https://api.example.com --users 100 --duration 60\n")
	fmt.Fprintf(w, "   stress-strike run --url https://api.example.com --target-rps 1000 --duration 30\n")
	fmt.Fprintf(w, "   stress-strike run --config scenario.yaml\n\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " FLAGS\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " EXAMPLES\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Simple load test",
		"stress-strike run --url https://api.example.com --users 100 --duration 60",
		"",
		"# Constant RPS mode (1000 requests/sec)",
		"stress-strike run --url https://api.example.com --target-rps 1000 --duration 30",
		"",
		"# Compare with a baseline report (exit 2 on regression)",
		"stress-strike run --url https://api.example.com --users 50 --duration 30 --compare reports/baseline.json",
		"",
		"# SLA gate for CI/CD (exit code 2 on failure)",
		"stress-strike run --url https://api.example.com --users 50 --duration 30 --expect-p99-ms 200 --expect-error-rate 1",
		"",
		"# YAML scenario file",
		"stress-strike run --config examples/login-flow.yaml",
		"",
		"# Real-time web dashboard output",
		"stress-strike run --url https://api.example.com --users 100 --duration 60 --mode dashboard",
	} {
		fmt.Fprintf(w, "\n   %s\n", e)
	}
	fmt.Fprintf(w, "\n")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
