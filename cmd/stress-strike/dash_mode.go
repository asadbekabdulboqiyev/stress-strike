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

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/dashboard"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
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
				Profile:         scenario.Profile.Type,
				Warmup:          scenario.Profile.Warmup,
				RampUp:          scenario.Profile.RampUp,
				SpikeUsers:      scenario.Profile.SpikeUsers,
				SpikeWarmup:     scenario.Profile.SpikeWarmup,
				SpikeHold:       scenario.Profile.SpikeHold,
				WavePeriod:      scenario.Profile.WavePeriod,
				Timeout:         scenario.Profile.Timeout,
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
				if v := getS(argv, "profile"); v != "" {
					cfg.Profile = v
				}
				if v := getI(argv, "rate_limit"); v > 0 {
					cfg.RateLimit = v
				}
				if v := getI(argv, "warmup"); v > 0 {
					cfg.Warmup = v
				}
				if v := getI(argv, "ramp_up"); v > 0 {
					cfg.RampUp = v
				}
				if v := getI(argv, "spike_users"); v > 0 {
					cfg.SpikeUsers = v
				}
				if v := getI(argv, "spike_warmup"); v > 0 {
					cfg.SpikeWarmup = v
				}
				if v := getI(argv, "spike_hold"); v > 0 {
					cfg.SpikeHold = v
				}
				if v := getI(argv, "wave_period"); v > 0 {
					cfg.WavePeriod = v
				}
			}

			bridge.StartRun(cfg)

			// Build a fresh scenario from the (possibly overridden) config.
			sc, err := quickScenario(
				scenario.Name, cfg.TargetURL, cfg.Method, "", headerFlags{},
				cfg.Profile, cfg.Users, cfg.DurationSeconds,
				cfg.RampUp, cfg.SpikeUsers, cfg.SpikeWarmup, cfg.SpikeHold,
				cfg.WavePeriod, cfg.RateLimit, cfg.RateLimit, cfg.Timeout, true,
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

			fmt.Printf("  ▶ Run started: %s (%d users, %ds, %s)\n", cfg.TargetURL, cfg.Users, cfg.DurationSeconds, cfg.Profile)

			// Stream telemetry live WHILE the engine runs (~ real-time).
			streamStop := make(chan struct{})
			go dashboard.StreamTelemetry(srv, e, sc, streamStop)

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
				final := dashboard.SnapshotFromTelemetry(e, sc)
				srv.UpdateSnapshot(final)
				bridge.RunCompleteFromSnapshot(final)

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

// streamTelemetry is provided by the dashboard package (live.go).
// getS and getI coerce browser-sent JSON values into Go types.
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
