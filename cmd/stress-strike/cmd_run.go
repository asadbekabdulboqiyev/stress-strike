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

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/dashboard"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/evidence"
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

// stringListFlags collects a repeatable string flag (e.g. -auth-token a -auth-token b).
type stringListFlags []string

func (s *stringListFlags) String() string { return strings.Join(*s, ",") }
func (s *stringListFlags) Set(v string) error {
	*s = append(*s, v)
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
		noHTTP2       bool
		coordOmission bool
		emitBundle    string
		bundleKey     string
		bundleWorker  string
		authzOpts     gateOptions

		dashAuthTokens    stringListFlags
		dashAuthAPIKeys   stringListFlags
		dashAuthOrigins   stringListFlags
		dashAuthRateLimit float64
		dashAuthBurst     int
		dashAuthProxy     bool
		dashAuthInsecure  bool
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
	fs.StringVar(&profile, "profile", "steady", "load profile: steady, soak, linear-ramp, spike, wave, constant-rps, burst")
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
	fs.BoolVar(&noHTTP2, "no-http2", false, "disable HTTP/2 negotiation (force HTTP/1.1)")
	fs.BoolVar(&coordOmission, "coordinated-omission", false, "apply coordinated-omission correction to paced runs (constant-rps / --rps)")
	fs.StringVar(&emitBundle, "emit-bundle", "", "write a verifiable vpmp/v1 evidence bundle (plus its .samples.jsonl sidecar) to this path")
	fs.StringVar(&bundleKey, "bundle-key", "", "Ed25519 keypair PEM that seals the bundle (generated ephemerally when omitted)")
	fs.StringVar(&bundleWorker, "bundle-worker", "", "worker identity recorded in the bundle (default: hostname, sanitised)")
	fs.StringVar(&authzOpts.authorized, "authorized", "", "authorization ticket id recorded by an approver")
	fs.BoolVar(&authzOpts.allowPrivate, "allow-private", false, "allow private/link-local targets explicitly")
	fs.StringVar(&authzOpts.policyPath, "policy", "", "authorization policy file (default ~/.stress-strike/authz.json)")
	fs.StringVar(&authzOpts.auditPath, "audit-log", "", "audit log file (default ~/.stress-strike/audit.jsonl)")
	fs.StringVar(&authzOpts.webhook, "notify-webhook", "", "webhook URL for audit notifications")
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
	fs.Var(&dashAuthTokens, "dashboard-auth-token", "bearer token required for the dashboard control API (repeatable)")
	fs.Var(&dashAuthAPIKeys, "dashboard-auth-api-key", "SHA-256 hex of an accepted dashboard API key (repeatable)")
	fs.Var(&dashAuthOrigins, "dashboard-auth-origin", "allowed origin for state-changing requests (repeatable; CSRF)")
	fs.Float64Var(&dashAuthRateLimit, "dashboard-auth-rate-limit", 0, "per-client-IP request rate limit (0 = disabled)")
	fs.IntVar(&dashAuthBurst, "dashboard-auth-rate-burst", 0, "rate limiter bucket capacity (default 1)")
	fs.BoolVar(&dashAuthProxy, "dashboard-auth-trust-proxy", false, "honor X-Forwarded-For / X-Real-IP for the limiter (only behind a trusted proxy)")
	fs.BoolVar(&dashAuthInsecure, "dashboard-insecure", false, "acknowledge running the unauthenticated dashboard control API on a non-loopback address (demo only)")

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

	durationSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "duration" {
			durationSet = true
		}
	})
	// burst: a short, maximum-speed volley — every user from t=0, no RPS cap.
	// Defaults to a 3-second window unless --duration is given explicitly.
	if profile == "burst" && !durationSet {
		duration = 3
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

	// Coordinated-omission correction is only meaningful for paced runs: with
	// no arrival schedule (no limiter) there is nothing to fall behind.
	if coordOmission {
		scenario.Profile.CoordinatedOmission = true
		if scenario.Profile.RPS <= 0 && !scenario.Profile.IsConstantRPS() {
			fmt.Fprintln(os.Stderr, "WARNING: --coordinated-omission has no effect without pacing; add --target-rps or --rps")
		}
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

	// Authorization gate: nothing is sent until every target passes the policy
	// and the decision is appended to the audit trail.
	enforceAuthz(authz.OpLoadTest, scenarioTargets(scenario), os.Args, authzOpts)

	// Dashboard mode: open the real-time WebSocket dashboard and drive the
	// real load engine from the browser. No terminal report is printed.
	if mode == "dashboard" {
		dashAuth := dashboard.AuthOptions{
			Tokens:         dashAuthTokens,
			APIKeyHashes:   dashAuthAPIKeys,
			AllowedOrigins: dashAuthOrigins,
			RateLimitRPS:   dashAuthRateLimit,
			RateLimitBurst: dashAuthBurst,
			TrustProxy:     dashAuthProxy,
			AllowAnonymous: dashAuthInsecure,
		}
		runWithDashboard(scenario, dashListen, reportDir, dashAuth)
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

	// --no-http2 maps onto the profile (nil = enabled, true by default).
	// The transport wiring itself lives in internal/engine/client.go.
	if noHTTP2 {
		off := false
		scenario.Profile.Http2 = &off
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

	// VeriBench: when a bundle is requested, every measured request is fed to a
	// collector as well, so the evidence pack is built from the same
	// measurements the report is — not from a summary of them.
	var collector *evidence.Collector
	runOpts := engine.RunOptions{Out: os.Stderr, Quiet: quiet, Progress: progress}
	if strings.TrimSpace(emitBundle) != "" {
		worker := strings.TrimSpace(bundleWorker)
		if worker == "" {
			worker = defaultWorkerID()
		}
		collector, err = evidence.NewCollector(worker)
		if err != nil {
			fatal(err)
		}
		runOpts.Samples = collector
	}

	telemetry, err := eng.Run(ctx, runOpts)
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

	// The evidence is written even when the SLA gate fails: a bundle that
	// proves the target missed its budget is exactly the bundle you want.
	if collector != nil {
		if err := emitEvidenceBundle(emitBundle, bundleKey, collector, scenario); err != nil {
			fatal(err)
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
	fmt.Fprintf(w, "   stress-strike run --url https://api.example.com --profile burst --users 500\n")
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
		"# Constant RPS with coordinated-omission correction (trustworthy p99 under saturation)",
		"stress-strike run --url https://api.example.com --target-rps 1000 --duration 30 --coordinated-omission",
		"",
		"# SEAL THE RESULT: emit verifiable evidence a third party can check offline",
		"stress-strike keygen --out operator.key",
		"stress-strike run --url https://api.example.com --target-rps 1000 --duration 30 --coordinated-omission \\",
		"    --emit-bundle bundle.json --bundle-key operator.key",
		"stress-strike verify --bundle bundle.json --samples bundle.samples.jsonl   # 0 = valid, 1 = tampered",
		"",
		"# Burst: 3s maximum-speed volley, all users at once, no RPS cap",
		"stress-strike run --url https://api.example.com --profile burst --users 500",
		"",
		"# Advanced scenario: branching, retries, think time",
		"stress-strike run --config examples/branching-flow.yaml",
		"",
		"# Client-streaming gRPC load test",
		"stress-strike run --config examples/streaming.yaml",
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

// defaultWorkerID names this process as a worker in an evidence bundle. A
// bundle records who measured what, so the identity has to be stable enough for
// an auditor to pin it later: hostname plus pid does that without any
// configuration.
func defaultWorkerID() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		host = "local"
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}

// coCorrectionGate reports why the coordinated-omission correction may not be
// claimed for a run, or "" when it may.
//
// The correction answers one question: a request was served late after waiting
// for its slot; how long did the user actually wait? That question only has an
// answer when the client kept a *fixed arrival schedule*. A steady (or soak)
// profile with a fixed --rps cap is the one shape where that holds: the profile
// maps to a fixed number of workers for the whole run, and the rate cap applies
// from the first millisecond. Every other shape moves its own target —
// constant-rps ramps over half the run by default, and linear-ramp, spike and
// wave vary it by construction — so arrivals are late *by design* and the same
// arithmetic would manufacture queue time nobody waited for. Observed on a
// ramped run: a raw p99 of 0.8 ms became a "corrected" p99 of 1.35 s, entirely
// generator lag.
//
// Note what the gate deliberately does NOT require: that the client kept up.
// Falling behind is the very situation the correction exists to measure, so a
// saturated run still gets a corrected tail. The shortfall stays visible instead
// of being hidden: the integrity block seals the planned and achieved rates and
// the dropped-sample count either way.
//
// The check keys off the profile, not off Profile.RampUp: Normalize fills
// RampUp with Duration/2 for *every* scenario, including steady ones, and the
// steady profile never reads it (it holds a fixed worker count for the whole
// run). Testing the ramp field would therefore reject exactly the runs whose
// schedule is provably constant.
func coCorrectionGate(scenario *config.Scenario, plannedMilli int64) string {
	switch {
	case plannedMilli <= 0:
		return "the run had no pacing rate (no --rps / --target-rps)"
	case scenario.Profile.Type != config.ProfileSteady && scenario.Profile.Type != config.ProfileSoak:
		return fmt.Sprintf("the %q profile moves its own arrival target over the run, so its schedule is not constant", scenario.Profile.Type)
	}
	return ""
}

// bundleKeypair loads the operator's signing keypair, or mints a throwaway one
// so that even a one-off run can produce a sealed bundle. The second return
// value reports whether the key is ephemeral: an ephemeral seal still proves
// the evidence was fixed before it was published, but nobody can attribute it
// to a key they already trust, so a real workflow uses --bundle-key with a key
// from `stress-strike keygen`.
func bundleKeypair(path string) (*attest.Keypair, bool, error) {
	if p := strings.TrimSpace(path); p != "" {
		kp, err := attest.LoadKeypairPEM(p)
		if err != nil {
			return nil, false, fmt.Errorf("emit-bundle: %w", err)
		}
		return kp, false, nil
	}
	kp, err := attest.GenerateKeypair()
	if err != nil {
		return nil, false, fmt.Errorf("emit-bundle: %w", err)
	}
	return kp, true, nil
}

// emitEvidenceBundle seals the collected measurements into a signed vpmp/v1
// bundle and writes it beside its sample sidecar.
//
// Nothing here is copied out of the terminal report. Every sealed number is
// recomputed from the raw records, so the bundle is an independent statement
// about the same run: if the report and the bundle ever disagree, the report is
// wrong — not the bundle.
func emitEvidenceBundle(path, keyPath string, collector *evidence.Collector, scenario *config.Scenario) error {
	plannedMilli := evidence.PlannedRPSMilli(scenario)
	planned, err := attest.DecimalFromMilli(plannedMilli)
	if err != nil {
		return fmt.Errorf("emit-bundle: planned rate %d: %w", plannedMilli, err)
	}

	kp, ephemeral, err := bundleKeypair(keyPath)
	if err != nil {
		return err
	}

	// The coordinated-omission correction is defined against a pacing schedule,
	// so it may only be claimed when the run actually had one and kept it (see
	// coCorrectionGate). Otherwise the bundle says plainly that it carries raw
	// percentiles instead of inventing a schedule to correct against.
	co := scenario.Profile.CoordinatedOmission
	durationNS := int64(scenario.Profile.TotalDuration()) * int64(time.Second)
	// The correction may only be claimed when the run had a pacing schedule and
	// kept it. When it did not — no pacing rate, a ramped run, or a client that
	// fell behind — the same arithmetic adds queue time nobody waited for, so the
	// claim is withheld with the reason stated. The gate reads the same raw count
	// and rate the integrity block seals, so the claim and the sealed numbers
	// always agree.
	if co {
		if reason := coCorrectionGate(scenario, plannedMilli); reason != "" {
			fmt.Fprintln(os.Stderr, "emit-bundle: coordinated-omission correction withheld —", reason)
			fmt.Fprintln(os.Stderr, "  The bundle records raw percentiles, co_corrected=false: honest, but uncorrected.")
			co = false
		}
	}

	bundle, err := evidence.BuildBundle(evidence.BundleInput{
		Collector:      collector,
		WorkerKey:      kp,
		CoordinatorKey: kp,
		Tool:           attest.Tool{Name: "stress-strike", Version: version},
		Run: attest.Run{
			Target:     targetDisplay(scenario),
			Profile:    scenario.Profile.Type,
			DurationNS: durationNS,
			PlannedRPS: planned,
		},
		// In a local run one operator both measures and claims, so the worker
		// commitment and the coordinator seal share an identity. Distributed
		// runs give each worker its own key (internal/dist/coordinator).
		COCorrected: co,
	})
	if err != nil {
		return err
	}

	sidecar, err := evidence.WriteBundle(bundle, collector.Records(), path)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nVerifiable evidence written:\n  %s\n  %s\n", path, sidecar)
	fmt.Fprintf(os.Stderr, "  format:        %s — %d samples, worker %q\n", bundle.Format, bundle.Aggregate.Count, bundle.Workers[0].ID)
	fmt.Fprintf(os.Stderr, "  coordinator:   %s\n", bundle.Signature.Key)
	if ephemeral {
		fmt.Fprintln(os.Stderr, "  note:          the seal key was generated for this run; pin it with --bundle-key to make the claim attributable")
	}
	if bundle.Aggregate.COCorrected {
		fmt.Fprintf(os.Stderr, "  p99:           %s (coordinated-omission corrected, 95%% CI %s)\n",
			asMillis(bundle.Aggregate.P99NS), millisInterval(bundle.Aggregate.COCI95NS.LowNS, bundle.Aggregate.COCI95NS.HighNS))
	} else {
		fmt.Fprintf(os.Stderr, "  p99:           %s (raw, uncorrected)\n", asMillis(bundle.Aggregate.P99NS))
	}
	fmt.Fprintf(os.Stderr, "  verify it yourself (exit 0 = valid, 1 = tampered):\n    stress-strike verify --bundle %s --samples %s\n", path, sidecar)
	return nil
}

// asMillis renders a nanosecond duration for humans only. The bundle itself is
// integer nanoseconds throughout; this is display formatting, not a
// measurement.
func asMillis(ns int64) string { return fmt.Sprintf("%.3fms", float64(ns)/1e6) }

func millisInterval(lowNS, highNS int64) string {
	return fmt.Sprintf("[%s, %s]", asMillis(lowNS), asMillis(highNS))
}
