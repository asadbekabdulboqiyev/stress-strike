package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"stress-strike/internal/config"
	"stress-strike/internal/engine"
	"stress-strike/internal/report"
)

const version = "0.7.0"

const maxCaptureEntries = 100

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
		wavePeriod  int
		rps         int
		timeout     int
		keepAlive   bool
		quiet       bool
		reportDir   string
		showVersion bool
		forceWizard bool
		captureN    int
		warmup      int
		jsonOut     bool
	)

	flag.StringVar(&configPath, "config", "", "YAML/JSON scenario file (see examples/scenario.yaml)")
	flag.StringVar(&configPath, "c", "", "shorthand for --config")
	flag.StringVar(&url, "url", "", "target URL (quick mode, used when --config is empty)")
	flag.StringVar(&method, "method", "GET", "HTTP method (quick mode)")
	flag.StringVar(&data, "data", "", "request body (quick mode)")
	flag.Var(headers, "header", "request header in Key=Value form (repeatable)")
	flag.StringVar(&name, "name", "quick-test", "report/test name")
	flag.StringVar(&profile, "profile", "steady", "load profile: steady, soak, linear-ramp, spike, wave")
	flag.IntVar(&users, "users", 10, "concurrent virtual users")
	flag.IntVar(&duration, "duration", 30, "test duration in seconds")
	flag.IntVar(&rampUp, "ramp-up", 0, "ramp-up duration in seconds (linear-ramp)")
	flag.IntVar(&spikeUsers, "spike-users", 0, "target users for spike burst")
	flag.IntVar(&spikeWarmup, "spike-warmup", 5, "baseline warmup seconds before spike")
	flag.IntVar(&spikeHold, "spike-hold", 10, "spike burst duration in seconds")
	flag.IntVar(&wavePeriod, "wave-period", 0, "oscillation period in seconds (wave)")
	flag.IntVar(&rps, "rps", 0, "global pacing cap (requests per second, 0 = unlimited)")
	flag.IntVar(&timeout, "timeout", 5, "per-request timeout in seconds")
	flag.BoolVar(&keepAlive, "keep-alive", true, "reuse TCP connections (connection pooling)")
	flag.BoolVar(&quiet, "quiet", false, "disable live progress line")
	flag.StringVar(&reportDir, "report-dir", "./reports", "directory for generated reports")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&forceWizard, "interactive", false, "guided setup wizard (auto-starts when --url/--config are omitted in a terminal)")
	flag.BoolVar(&forceWizard, "i", false, "shorthand for --interactive")
	flag.IntVar(&captureN, "capture", 0, "save first N raw responses to <report-dir>/ for debugging (max 100; request credentials are never stored)")
	flag.IntVar(&warmup, "warmup", 0, "exclude the first S seconds from metrics while still sending load (stabilizes percentiles)")
	flag.BoolVar(&jsonOut, "json", false, "print the full machine-readable JSON report to stdout")
	gateMode := flag.Bool("gate", false, "race-condition strike: all users fire ONE simultaneous request when the gate opens (authorized targets only)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "stress-strike v%s — load testing & network simulator\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n  stress-strike --config scenario.yaml\n  stress-strike --url https://api.example.com --users 1000 --duration 60\n  stress-strike            (interactive setup in a terminal)\n\n")
		fmt.Fprintf(os.Stderr, "WARNING: Only run against systems you own or have explicit permission to test.\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	nameSet := false
	warmupSet := false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "name":
			nameSet = true
		case "warmup":
			warmupSet = true
		}
	})

	if showVersion {
		fmt.Printf("stress-strike v%s\n", version)
		return
	}

	if configPath == "" && url == "" {
		if !forceWizard && !stdinIsTerminal() {
			fatal(fmt.Errorf("either --config or --url is required (run inside a terminal or pass --interactive for guided setup)"))
		}
		ans, err := runWizard(os.Stdin, os.Stderr, stdoutIsColorable())
		if err != nil {
			if errors.Is(err, errCanceled) {
				fmt.Fprintln(os.Stderr, "Setup canceled.")
				return
			}
			fatal(err)
		}
		if !nameSet {
			name = ans.name
		}
		url = ans.url
		method = ans.method
		data = ans.data
		headers = ans.headers
		profile = ans.profile
		users = ans.users
		duration = ans.duration
		rampUp = ans.rampUp
		spikeUsers = ans.spikeUsers
		spikeWarmup = ans.spikeWarmup
		spikeHold = ans.spikeHold
		wavePeriod = ans.wavePeriod
		rps = ans.rps
		timeout = ans.timeout
		keepAlive = ans.keepAlive
		captureN = ans.capture
	} else if configPath != "" && url != "" {
		fmt.Fprintln(os.Stderr, "note: both --config and --url given; --config takes precedence")
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
		sc, err := quickScenario(name, url, method, data, headers, profile, users, duration, rampUp, spikeUsers, spikeWarmup, spikeHold, wavePeriod, rps, timeout, keepAlive)
		if err != nil {
			fatal(err)
		}
		scenario = sc
	}

	if warmupSet {
		scenario.Profile.Warmup = warmup
	}
	if *gateMode {
		scenario.Profile.Gate = true
	}
	if warmupSet || *gateMode {
		if err := scenario.Profile.Normalize(); err != nil {
			fatal(err)
		}
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

	var capSink *engine.BufferCapture
	if captureN > 0 {
		if captureN > maxCaptureEntries {
			captureN = maxCaptureEntries
		}
		capSink = engine.NewBufferCapture(captureN, engine.DefaultCaptureBodyBytes)
	}

	opts := engine.RunOptions{Out: os.Stderr, Quiet: quiet}
	if capSink != nil {
		opts.Capture = capSink
	}
	telemetry, err := eng.Run(ctx, opts)
	if err != nil {
		fatal(err)
	}

	r := report.Build(telemetry, scenario)
	fmt.Fprintln(os.Stderr)
	r.Render(os.Stdout)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fatal(err)
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

	if capSink != nil {
		if kept, _ := capSink.Count(); kept > 0 {
			capPath := filepath.Join(reportDir, fmt.Sprintf("%s_%s-capture.txt",
				sanitizeCaptureName(scenario.Name), time.Now().Format("20060102-150405")))
			var buf bytes.Buffer
			if err := capSink.Render(&buf); err == nil {
				if err := os.WriteFile(capPath, buf.Bytes(), 0o600); err == nil {
					fmt.Fprintf(os.Stderr, "  %s (debug capture)\n", capPath)
				}
			}
		}
	}
}

func sanitizeCaptureName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
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

// warnLowFileLimit is platform-specific (Unix: rlimit check; Windows: no-op),
// implemented in limit_unix.go / limit_windows.go.

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
