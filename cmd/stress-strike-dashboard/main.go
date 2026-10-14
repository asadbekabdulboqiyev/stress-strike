package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/dashboard"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/health"
	prom "github.com/asadbekabdulboqiyev/stress-strike/internal/metrics/exporter"
)

// flagStrings collects a repeatable string flag (e.g. -auth-token a -auth-token b).
type flagStrings []string

func (s *flagStrings) String() string { return strings.Join(*s, ",") }
func (s *flagStrings) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	// Friendly flag errors + consistent help (exit 2 on usage errors).
	flag.CommandLine.Init("stress-strike-dashboard", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	listen := flag.String("listen", "127.0.0.1:8888", "Dashboard listen address")
	var (
		authTokens  flagStrings
		authAPIKeys flagStrings
		authOrigins flagStrings
	)
	flag.Var(&authTokens, "auth-token", "Bearer token required for the control API (repeatable)")
	flag.Var(&authAPIKeys, "auth-api-key", "SHA-256 hex of an accepted API key (repeatable)")
	flag.Var(&authOrigins, "auth-origin", "Allowed origin for state-changing requests (repeatable; CSRF)")
	authRateLimit := flag.Float64("auth-rate-limit", 0, "Per-client-IP request rate limit (0 = disabled)")
	authRateBurst := flag.Int("auth-rate-burst", 0, "Rate limiter bucket capacity (default 1)")
	authTrustProxy := flag.Bool("auth-trust-proxy", false, "Honor X-Forwarded-For / X-Real-IP for the limiter (only behind a trusted proxy)")
	insecure := flag.Bool("insecure", false, "Acknowledge running the unauthenticated control API on a non-loopback address (demo only)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
╔═══════════════════════════════════════════════════════════════╗
║  stress-strike dashboard — Real-time Web Dashboard            ║
║                                                               ║
║  • Live RPS sparkline graph                                   ║
║  • Latency percentiles (p50/p95/p99)                         ║
║  • Error rate tracking                                        ║
║  • Worker node monitoring                                     ║
║  • Run history + time-travel replay                           ║
║  • Start/stop runs directly from browser                     ║
║  • One-click VoltStore demo launcher (VeriGate, /admin)      ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
  stress-strike-dashboard [flags]

Flags:
`)
		cliux.PrintFlagList(os.Stderr, flag.CommandLine)
		fmt.Fprintf(os.Stderr, `
Examples:
  # Start dashboard on default port
  stress-strike-dashboard

  # Custom port
  stress-strike-dashboard -listen :9090

  # Locked down with a bearer token (required beyond loopback)
  stress-strike-dashboard -listen 0.0.0.0:8888 -auth-token 'change-me' -auth-origin https://team.example.com
`)
	}
	cliux.Parse(flag.CommandLine, os.Args[1:], flag.Usage, cliux.Options{
		Command: "dashboard",
		FlagSet: flag.CommandLine,
		Examples: []string{
			"stress-strike dashboard",
		},
	})

	srv := dashboard.NewServer()
	bridge := dashboard.NewEngineBridge(srv)

	// Lifecycle of the currently running engine run (guarded by runMu).
	var (
		runMu     sync.Mutex
		runCancel context.CancelFunc
		runActive bool
	)

	// /metrics mirrors the active run; declared here so the command handler can
	// feed it without waiting for the first run.
	selfMetrics := prom.NewMetrics()

	// Handle commands from browser
	srv.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		switch cmd {
		case "start":
			startRun(bridge, srv, selfMetrics, &runMu, &runActive, &runCancel, args)
		case "stop":
			stopRun(bridge, &runMu, &runCancel)
		}
	})

	authOpts := dashboard.AuthOptions{
		Tokens:         authTokens,
		APIKeyHashes:   authAPIKeys,
		AllowedOrigins: authOrigins,
		RateLimitRPS:   *authRateLimit,
		RateLimitBurst: *authRateBurst,
		TrustProxy:     *authTrustProxy,
		AllowAnonymous: *insecure,
	}
	var auth *dashboard.Auth
	switch {
	case authOpts.HasCredentials():
		auth = srv.ApplyAuth(authOpts)
		defer auth.Close()
		fmt.Printf("  🔒 Control API protected (tokens=%d api-keys=%d origins=%d)\n",
			len(authTokens), len(authAPIKeys), len(authOrigins))
	case !dashboard.IsLoopbackAddr(*listen) && !authOpts.AllowAnonymous:
		fmt.Fprintln(os.Stderr, "FATAL: dashboard is listening on a non-loopback interface with NO authentication.")
		fmt.Fprintln(os.Stderr, "The control API can start/stop real load runs, so it must be locked down.")
		fmt.Fprintln(os.Stderr, "Pass -auth-token (or -auth-api-key), bind a loopback address (127.0.0.1:8888),")
		fmt.Fprintln(os.Stderr, "or pass -insecure to acknowledge the risk (publish the port on loopback only).")
		// os.Exit here and the deferred auth.Close() above are in mutually
		// exclusive switch branches; nothing survives to leak when we exit.
		os.Exit(1) //nolint:gocritic // see note above
	case !dashboard.IsLoopbackAddr(*listen):
		fmt.Fprintln(os.Stderr, "WARNING: dashboard is listening on a non-loopback interface with NO authentication (-insecure).")
		fmt.Fprintln(os.Stderr, "Anyone who can reach this address can start/stop load runs. Publish the port on loopback only.")
	}

	// Operations endpoints for orchestrators and Prometheus.
	checker := health.NewChecker()
	checker.Register("dashboard", func(context.Context) error { return nil })
	srv.SetHealthHandlers(checker.LivenessHandler(), checker.ReadinessHandler())
	srv.SetMetricsHandler(selfMetrics.Handler())

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  stress-strike dashboard — real-time load telemetry             ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Dashboard: http://%s\n", *listen)
	fmt.Println()

	// Graceful shutdown: cancel any in-flight run on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		runMu.Lock()
		if runCancel != nil {
			runCancel()
		}
		runMu.Unlock()
		fmt.Println("\n  Dashboard shutting down...")
		os.Exit(0)
	}()

	dashSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if err := dashSrv.ListenAndServe(); err != nil {
		log.Fatalf("Dashboard server failed: %v", err)
	}
}

// startRun builds a real config.Scenario from the browser's RunConfig and runs
// it on the actual load engine, streaming live telemetry to the dashboard.
func startRun(bridge *dashboard.EngineBridge, srv *dashboard.Server, selfMetrics *prom.Metrics, runMu *sync.Mutex, runActive *bool, runCancel *context.CancelFunc, args map[string]interface{}) {
	runMu.Lock()
	if *runActive {
		runMu.Unlock()
		fmt.Println("  ⚠ Run already in progress — ignoring duplicate start")
		return
	}
	*runActive = true
	runMu.Unlock()

	config := &dashboard.RunConfig{}
	// The browser posts a RunConfig which the server decodes into the config
	// arg; tolerate a raw map too for robustness.
	if raw, ok := args["config"]; ok {
		if rc, ok := raw.(dashboard.RunConfig); ok {
			config = &rc
		} else if m, ok := raw.(map[string]interface{}); ok {
			config.TargetURL = getString(m, "target_url", "http://localhost:8080/health")
			config.Users = getInt(m, "users", 10)
			config.DurationSeconds = getInt(m, "duration_seconds", 10)
			config.Method = getString(m, "method", "GET")
			config.RateLimit = getInt(m, "rate_limit", 0)
			config.Profile = getString(m, "profile", "")
			config.TLSFingerprint = getString(m, "tls_fingerprint", "")
			config.Body = getString(m, "body", "")
			config.Headers = getStringMap(m, "headers")
		}
	}

	bridge.StartRun(config)

	sc, err := scenarioFromConfig(config)
	if err != nil {
		fmt.Printf("  ✗ Invalid run config: %v\n", err)
		bridge.RunFailed(err)
		markInactive(runMu, runActive)
		return
	}

	eng, err := engine.New(sc)
	if err != nil {
		fmt.Printf("  ✗ Engine setup failed: %v\n", err)
		bridge.RunFailed(err)
		markInactive(runMu, runActive)
		return
	}

	runCtx, cancel := context.WithCancel(context.Background())
	runMu.Lock()
	*runCancel = cancel
	runMu.Unlock()

	fmt.Printf("  ▶ Run started: %s (%d users, %ds, profile=%s, rps=%d)\n",
		config.TargetURL, config.Users, config.DurationSeconds, sc.Profile.Type, sc.Profile.RPS)

	// Poll the engine's live telemetry and push snapshots to the bridge.
	stopStream := make(chan struct{})
	streamDone := make(chan struct{})
	go streamTelemetry(bridge, eng, selfMetrics, stopStream, streamDone)

	// Drive the real engine in the background.
	go func() {
		opts := engine.RunOptions{Quiet: true, Out: io.Discard}
		if coll := bridge.AttachEngineSink(); coll != nil {
			opts.Samples = coll
		}
		tel, runErr := eng.Run(runCtx, opts)
		close(stopStream)
		<-streamDone

		runMu.Lock()
		*runCancel = nil
		*runActive = false
		runMu.Unlock()

		if runErr != nil {
			fmt.Printf("  ✗ Run failed: %v\n", runErr)
			bridge.RunFailed(runErr)
			return
		}

		// Final snapshot with the completed telemetry, then finish the run.
		bridge.PushSnapshot(bridge.SnapshotFromTelemetry(tel))
		if bridge.IsStopped() {
			fmt.Printf("  ⏹ Run stopped — %d requests\n", tel.TotalRequests())
		} else {
			fmt.Printf("  ✅ Run completed — %d requests\n", tel.TotalRequests())
		}
		bridge.RunComplete()
	}()
}

func stopRun(bridge *dashboard.EngineBridge, runMu *sync.Mutex, runCancel *context.CancelFunc) {
	runMu.Lock()
	c := *runCancel
	runMu.Unlock()
	if c != nil {
		c()
	}
	bridge.StopRun()
	fmt.Println("  ⏹ Stop requested")
}

func markInactive(runMu *sync.Mutex, runActive *bool) {
	runMu.Lock()
	*runActive = false
	runMu.Unlock()
}

// streamTelemetry polls the engine's live Telemetry and pushes snapshots to the
// bridge until stop is closed. It also mirrors the run totals into selfMetrics
// so the dashboard's own /metrics endpoint reflects the active run without
// paying one atomic add per request: whole deltas are added per tick, and the
// tick's average latency is recorded once (the resulting histogram stays
// truthful for the distribution's average and total, while its sample count is
// per-tick rather than per-request).
func streamTelemetry(bridge *dashboard.EngineBridge, eng *engine.Engine, selfMetrics *prom.Metrics, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var lastCount, lastErr uint64
	var lastSum uint64 // nanosecond cumulative latency
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if tel := eng.Telemetry(); tel != nil {
				bridge.PushSnapshot(bridge.SnapshotFromTelemetry(tel))
				if selfMetrics != nil {
					snap := tel.Overall.Latency.Snapshot()
					if d := snap.Count - lastCount; d > 0 {
						// d > 0 is guaranteed by the branch condition, so the
						// division below is safe.
						selfMetrics.IncRequestsN(d)
						selfMetrics.ObserveLatency(time.Duration((snap.Sum - lastSum) / d)) //nolint:gosec // latency in ns fits int64 for any realistic run
					}
					if d := tel.TotalErrors() - lastErr; d > 0 {
						selfMetrics.IncErrorsN(d)
					}
					lastCount, lastErr, lastSum = snap.Count, tel.TotalErrors(), snap.Sum
				}
			}
		}
	}
}

// scenarioFromConfig builds a validated config.Scenario from the dashboard's
// RunConfig (target, method, users, duration, rate limit, profile, headers,
// body, and TLS fingerprint when present).
func scenarioFromConfig(cfg *dashboard.RunConfig) (*config.Scenario, error) {
	if cfg.TargetURL == "" {
		return nil, fmt.Errorf("target_url is required")
	}
	profileType := cfg.Profile
	if profileType == "" {
		profileType = config.ProfileSteady
	}
	users := cfg.Users
	if users <= 0 {
		users = 10
	}
	duration := cfg.DurationSeconds
	if duration <= 0 {
		duration = 30
	}
	method := cfg.Method
	if method == "" {
		method = "GET"
	}
	keepAlive := true

	profile := config.Profile{
		Type:           profileType,
		Users:          users,
		Duration:       duration,
		RPS:            cfg.RateLimit,
		KeepAlive:      &keepAlive,
		TLSFingerprint: cfg.TLSFingerprint,
	}
	// For constant-rps the rate limit acts as the target; Normalize requires
	// target_rps > 0 for that profile.
	if profileType == config.ProfileConstantRPS && cfg.RateLimit > 0 {
		profile.TargetRPS = cfg.RateLimit
	}

	sc := &config.Scenario{
		Name:    "dashboard-run",
		Profile: profile,
		Steps: []config.Step{
			{
				Name:    "request",
				Method:  method,
				URL:     cfg.TargetURL,
				Headers: cfg.Headers,
				Body:    cfg.Body,
			},
		},
	}
	if err := sc.Normalize(); err != nil {
		return nil, err
	}
	return sc, nil
}

func getString(m map[string]interface{}, key, def string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func getInt(m map[string]interface{}, key string, def int) int {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return def
}

func getStringMap(m map[string]interface{}, key string) map[string]string {
	if v, ok := m[key].(map[string]interface{}); ok {
		out := make(map[string]string, len(v))
		for k, val := range v {
			switch t := val.(type) {
			case string:
				out[k] = t
			case float64:
				out[k] = strconv.FormatFloat(t, 'f', -1, 64)
			case bool:
				out[k] = strconv.FormatBool(t)
			default:
				out[k] = fmt.Sprintf("%v", val)
			}
		}
		return out
	}
	return nil
}
