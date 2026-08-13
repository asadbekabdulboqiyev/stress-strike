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

const version = "0.1.0"

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

func main() {
	var (
		configPath  string
		url         string
		method      string
		data        string
		headers     = headerFlags{}
		name        string
		profile     string
		users       int
		duration    int
		rampUp      int
		spikeUsers  int
		spikeWarmup int
		spikeHold   int
		rps         int
		timeout     int
		keepAlive   bool
		quiet       bool
		reportDir   string
		showVersion bool
	)

	flag.StringVar(&configPath, "config", "", "YAML/JSON scenario file (see examples/scenario.yaml)")
	flag.StringVar(&configPath, "c", "", "shorthand for --config")
	flag.StringVar(&url, "url", "", "target URL (quick mode, used when --config is empty)")
	flag.StringVar(&method, "method", "GET", "HTTP method (quick mode)")
	flag.StringVar(&data, "data", "", "request body (quick mode)")
	flag.Var(headers, "header", "request header in Key=Value form (repeatable)")
	flag.StringVar(&name, "name", "quick-test", "report/test name")
	flag.StringVar(&profile, "profile", "steady", "load profile: steady, linear-ramp, spike")
	flag.IntVar(&users, "users", 10, "concurrent virtual users")
	flag.IntVar(&duration, "duration", 30, "test duration in seconds")
	flag.IntVar(&rampUp, "ramp-up", 0, "ramp-up duration in seconds (linear-ramp)")
	flag.IntVar(&spikeUsers, "spike-users", 0, "target users for spike burst")
	flag.IntVar(&spikeWarmup, "spike-warmup", 5, "baseline warmup seconds before spike")
	flag.IntVar(&spikeHold, "spike-hold", 10, "spike burst duration in seconds")
	flag.IntVar(&rps, "rps", 0, "global pacing cap (requests per second, 0 = unlimited)")
	flag.IntVar(&timeout, "timeout", 5, "per-request timeout in seconds")
	flag.BoolVar(&keepAlive, "keep-alive", true, "reuse TCP connections (connection pooling)")
	flag.BoolVar(&quiet, "quiet", false, "disable live progress line")
	flag.StringVar(&reportDir, "report-dir", "./reports", "directory for generated reports")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "stress-strike v%s — load testing & network simulator\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n  stress-strike --config scenario.yaml\n  stress-strike --url https://api.example.com --users 1000 --duration 60\n\n")
		fmt.Fprintf(os.Stderr, "WARNING: Only run against systems you own or have explicit permission to test.\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	nameSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "name" {
			nameSet = true
		}
	})

	if showVersion {
		fmt.Printf("stress-strike v%s\n", version)
		return
	}

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
		sc, err := quickScenario(name, url, method, data, headers, profile, users, duration, rampUp, spikeUsers, spikeWarmup, spikeHold, rps, timeout, keepAlive)
		if err != nil {
			fatal(err)
		}
		scenario = sc
	}

	fmt.Fprintln(os.Stderr, "WARNING: stress-strike is a load testing tool. Only run it against systems you own or")
	fmt.Fprintln(os.Stderr, "have explicit written permission to test. Unauthorized load floods are illegal (DDoS).")

	warnLowFileLimit(scenario.Profile)

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

	jsonPath, err := r.SaveJSON(reportDir)
	if err != nil {
		fatal(err)
	}
	txtPath, err := r.SaveTXT(reportDir)
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "\nReports written:\n  %s\n  %s\n", jsonPath, txtPath)
}

func quickScenario(name, url, method, data string, headers headerFlags, profile string, users, duration, rampUp, spikeUsers, spikeWarmup, spikeHold, rps, timeout int, keepAlive bool) (*config.Scenario, error) {
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

func warnLowFileLimit(profile config.Profile) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return
	}
	need := uint64(profile.Users * 4)
	if profile.SpikeUsers > profile.Users {
		need = uint64(profile.SpikeUsers * 4)
	}
	if lim.Cur < need {
		fmt.Fprintf(os.Stderr, "warning: open-file limit is %d but the test may need ~%d sockets (raise with 'ulimit -n')\n", lim.Cur, need)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
