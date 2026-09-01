package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"stress-strike/internal/config"
	"stress-strike/internal/dashboard"
	"stress-strike/internal/engine"
	"stress-strike/internal/metrics"
	"stress-strike/internal/report"
)

// runWithDashboard starts the real-time web dashboard and serves live JSON
// telemetry built from the actual load engine (no simulation). The run is
// started from the browser's Start button using the CLI-provided scenario as
// the default configuration.
func runWithDashboard(scenario *config.Scenario, dashListen, reportDir string) {
	srv := dashboard.NewServer()
	bridge := dashboard.NewEngineBridge(srv)

	var (
		mu      sync.Mutex
		cancel  context.CancelFunc
		running bool
		sla     = scenario.SLA
	)

	// Command handler — start/stop from the browser.
	srv.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		switch cmd {
		case "start":
			mu.Lock()
			if running {
				mu.Unlock()
				return
			}
			running = true
			mu.Unlock()

			// Build run config from CLI flags, merged with browser overrides.
			cfg := &dashboard.RunConfig{
				TargetURL:       targetDisplay(scenario),
				Users:           scenario.Profile.Users,
				DurationSeconds: scenario.Profile.TotalDuration(),
				Method: func() string {
					if len(scenario.Steps) > 0 {
						return scenario.Steps[0].Method
					}
					return "GET"
				}(),
			}
			if argv, ok := args["config"].(map[string]interface{}); ok {
				if v := getS(argv, "target_url"); v != "" {
					cfg.TargetURL = v
				}
				if v := getI(argv, "users"); v > 0 {
					cfg.Users = v
				}
				if v := getI(argv, "duration_seconds"); v > 0 {
					cfg.DurationSeconds = v
				}
				if v := getS(argv, "method"); v != "" {
					cfg.Method = v
				}
			}

			bridge.StartRun(cfg)

			// Build a fresh scenario from the (possibly overridden) config.
			sc, err := quickScenario(
				scenario.Name, cfg.TargetURL, cfg.Method, "", headerFlags{},
				"steady", cfg.Users, cfg.DurationSeconds,
				0, 0, 0, 0, 0, 0, 0, scenario.Profile.Timeout, true,
			)
			if err != nil {
				bridge.RunFailed(err)
				mu.Lock()
				running = false
				mu.Unlock()
				return
			}
			sc.SLA = sla

			runCtx, runCancel := context.WithCancel(context.Background())
			mu.Lock()
			cancel = runCancel
			mu.Unlock()

			e, err := engine.New(sc)
			if err != nil {
				bridge.RunFailed(err)
				runCancel()
				mu.Lock()
				running = false
				mu.Unlock()
				return
			}

			fmt.Printf("  ▶ Run started: %s (%d users, %ds)\n", cfg.TargetURL, cfg.Users, cfg.DurationSeconds)

			// Stream telemetry live WHILE the engine runs (~ real-time).
			streamStop := make(chan struct{})
			go streamTelemetry(srv, e, sc, streamStop)

			// Run the engine in the background.
			go func() {
				telemetry, runErr := e.Run(runCtx, engine.RunOptions{Out: io.Discard, Quiet: true})
				close(streamStop) // stop the live streamer
				mu.Lock()
				running = false
				mu.Unlock()
				if runErr != nil {
					bridge.RunFailed(runErr)
					return
				}
				// Final snapshot + complete
				srv.UpdateSnapshot(snapshotFromTelemetry(e, sc))
				bridge.RunComplete()

				// Persist a report so it is not lost.
				r := report.Build(telemetry, sc)
				if _, err := r.SaveJSON(reportDir); err == nil {
					_, _ = r.SaveTXT(reportDir)
				}
			}()
		case "stop":
			mu.Lock()
			c := cancel
			mu.Unlock()
			if c != nil {
				c()
			}
			bridge.StopRun()
			fmt.Println("  ⏹ Run stopped")
		}
	})

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  stress-strike dashboard — real-time load telemetry             ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Dashboard : http://localhost%s\n", dashListen)
	fmt.Printf("  Default   : %s (%d users, %ds)\n", targetDisplay(scenario), scenario.Profile.Users, scenario.Profile.TotalDuration())
	fmt.Println("  Open the URL in a browser and press Start.")
	fmt.Println()

	srv.SetRunState(&dashboard.RunState{
		Status: "idle",
		Config: &dashboard.RunConfig{
			TargetURL:       targetDisplay(scenario),
			Users:           scenario.Profile.Users,
			DurationSeconds: scenario.Profile.TotalDuration(),
			Method: func() string {
				if len(scenario.Steps) > 0 {
					return scenario.Steps[0].Method
				}
				return "GET"
			}(),
		},
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		mu.Lock()
		if cancel != nil {
			cancel()
		}
		mu.Unlock()
		os.Exit(0)
	}()

	if err := http.ListenAndServe(dashListen, srv); err != nil {
		fmt.Fprintf(os.Stderr, "dashboard server failed: %v\n", err)
		os.Exit(1)
	}
}

// streamTelemetry samples the engine's live Telemetry and pushes snapshots to
// the WebSocket server at a fixed interval until streamStop is closed.
func streamTelemetry(srv *dashboard.Server, e *engine.Engine, sc *config.Scenario, stop <-chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			srv.UpdateSnapshot(snapshotFromTelemetry(e, sc))
		}
	}
}

// snapshotFromTelemetry converts the engine's live Telemetry into a dashboard
// LiveSnapshot for WebSocket broadcast.
func snapshotFromTelemetry(e *engine.Engine, sc *config.Scenario) *dashboard.LiveSnapshot {
	t, ok := engineTelemetry(e)
	if !ok {
		return &dashboard.LiveSnapshot{
			Timestamp:   time.Now(),
			ActiveUsers: sc.Profile.Users,
			StatusCodes: map[int]uint64{},
		}
	}

	elapsed := t.Elapsed()
	elapsedSec := elapsed.Seconds()
	if elapsedSec <= 0 {
		elapsedSec = 0.001
	}

	reqs := t.TotalRequests()
	errs := t.TotalErrors()
	var errRate float64
	if reqs > 0 {
		errRate = float64(errs) / float64(reqs) * 100
	}

	// Percentiles from overall histogram
	snap := t.Overall.Latency.Snapshot()
	p50 := snap.Percentile(0.50)
	p95 := snap.Percentile(0.95)
	p99 := snap.Percentile(0.99)

	totalDur := sc.Profile.TotalDuration()
	progress := 0.0
	if totalDur > 0 {
		progress = elapsedSec / float64(totalDur) * 100
		if progress > 100 {
			progress = 100
		}
	}

	return &dashboard.LiveSnapshot{
		Timestamp:   time.Now(),
		RPS:         float64(reqs) / elapsedSec,
		TotalReq:    reqs,
		TotalErrors: errs,
		ErrorRate:   errRate,
		P50Latency:  p50.Seconds() * 1000,
		P95Latency:  p95.Seconds() * 1000,
		P99Latency:  p99.Seconds() * 1000,
		AvgLatency:  snap.Average.Seconds() * 1000,
		MaxLatency:  snap.Max.Seconds() * 1000,
		ActiveUsers: int(t.ActiveUsers.Load()),
		StatusCodes: t.StatusCodes(),
	}
}

// engineTelemetry safely returns the engine's live telemetry if available.
func engineTelemetry(e *engine.Engine) (*metrics.Telemetry, bool) {
	// Engine exposes its telemetry via concurrent-safe accessor methods;
	// telemetry is set at the start of Run.
	t := e.Telemetry()
	if t == nil {
		return nil, false
	}
	return t, true
}

func getS(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getI(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return 0
}
