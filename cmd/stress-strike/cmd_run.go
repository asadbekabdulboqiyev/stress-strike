package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"stress-strike/internal/config"
	"stress-strike/internal/engine"
	"stress-strike/internal/report"
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
	)

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fs.StringVar(&configPath, "config", "", "YAML/JSON scenario file")
	fs.StringVar(&configPath, "c", "", "shorthand for --config")
	fs.StringVar(&url, "url", "", "target URL (quick mode)")
	fs.StringVar(&method, "method", "GET", "HTTP method (quick mode)")
	fs.StringVar(&data, "data", "", "request body (quick mode)")
	fs.Var(headers, "header", "request header in Key=Value form (repeatable)")
	fs.StringVar(&name, "name", "quick-test", "report/test name")
	fs.StringVar(&profile, "profile", "steady", "load profile: steady, soak, linear-ramp, spike, wave")
	fs.IntVar(&users, "users", 10, "concurrent virtual users")
	fs.IntVar(&duration, "duration", 30, "test duration in seconds")
	fs.IntVar(&rampUp, "ramp-up", 0, "ramp-up duration in seconds")
	fs.IntVar(&spikeUsers, "spike-users", 0, "target users for spike burst")
	fs.IntVar(&spikeWarmup, "spike-warmup", 5, "baseline warmup seconds before spike")
	fs.IntVar(&spikeHold, "spike-hold", 10, "spike burst duration in seconds")
	fs.IntVar(&wavePeriod, "wave-period", 0, "oscillation period in seconds (wave)")
	fs.IntVar(&rps, "rps", 0, "global pacing cap (requests per second)")
	fs.IntVar(&timeout, "timeout", 5, "per-request timeout in seconds")
	fs.BoolVar(&keepAlive, "keep-alive", true, "reuse TCP connections")
	fs.Float64Var(&expectP99, "expect-p99-ms", 0, "SLA: max p99 latency (ms)")
	fs.Float64Var(&expectAvg, "expect-avg-ms", 0, "SLA: max avg latency (ms)")
	fs.Float64Var(&expectErrRate, "expect-error-rate", 0, "SLA: max error rate (%%)")
	fs.Float64Var(&expectMinRPS, "expect-min-rps", 0, "SLA: min throughput")
	fs.StringVar(&comparePath, "compare", "", "baseline report for comparison")
	fs.Float64Var(&regressPct, "regress-pct", 20, "regression threshold %%")
	fs.BoolVar(&timelineCSV, "timeline", false, "write per-second CSV timeline")
	fs.BoolVar(&quiet, "quiet", false, "disable live progress")
	fs.StringVar(&reportDir, "report-dir", "./reports", "report output directory")
	fs.BoolVar(&showVersion, "version", false, "print version")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "stress-strike run — HTTP/gRPC/WebSocket load test\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  stress-strike run --url https://api.example.com --users 100 --duration 60\n")
		fmt.Fprintf(os.Stderr, "  stress-strike run --config scenario.yaml\n\n")
		fs.PrintDefaults()
	}

	// Parse args: os.Args = ["run", "--url", ...] after slicing in main.go
	fs.Parse(os.Args[1:])

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
			fatal(fmt.Errorf("either --config or --url is required"))
		}
		sc, err := quickScenario(name, url, method, data, headers, profile, users, duration, rampUp, spikeUsers, spikeWarmup, spikeHold, wavePeriod, rps, timeout, keepAlive)
		if err != nil {
			fatal(err)
		}
		scenario = sc
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

	fmt.Fprintln(os.Stderr, "WARNING: stress-strike is a load testing tool. Only run it against systems you own or")
	fmt.Fprintln(os.Stderr, "have explicit written permission to test. Unauthorized load floods are illegal (DDoS).")

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

	telemetry, err := eng.Run(ctx, engine.RunOptions{Out: os.Stderr, Quiet: quiet})
	if err != nil {
		fatal(err)
	}

	r := report.Build(telemetry, scenario)
	fmt.Fprintln(os.Stderr)
	r.Render(os.Stdout)

	if comparePath != "" {
		baseline, err := report.LoadReport(comparePath)
		if err != nil {
			fatal(err)
		}
		rows, regressed := report.Compare(&r, baseline, regressPct)
		renderComparison(rows)
		if regressed {
			fmt.Fprintf(os.Stderr, "REGRESSION DETECTED vs %s (threshold %.0f%%)\n", comparePath, regressPct)
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
}

func quickScenario(name, url, method, data string, headers headerFlags, profile string, users, duration, rampUp, spikeUsers, spikeWarmup, spikeHold, wavePeriod, rps, timeout int, keepAlive bool) (*config.Scenario, error) {
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

func renderComparison(rows []report.CompareRow) {
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\x1b[1m  BASELINE COMPARISON\x1b[0m")
	fmt.Fprintln(os.Stdout, "\x1b[1m  ──────────────────────────────────────────────────────────────\x1b[0m")
	for _, row := range rows {
		status := row.Status
		switch status {
		case "regressed":
			status = "✗ REGRESSED"
		case "improved":
			status = "↑ improved"
		default:
			status = "= ok"
		}
		fmt.Fprintf(os.Stdout, "    %-12s %-10s → %-10s %-9s %s\n",
			row.Metric, row.Baseline, row.Current, row.Delta, status)
	}
	fmt.Fprintln(os.Stdout)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
