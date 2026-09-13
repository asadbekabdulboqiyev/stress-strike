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
	"sync"
	"syscall"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/dashboard"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
)

func main() {
	listen := flag.String("listen", ":8888", "Dashboard listen address")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
╔═══════════════════════════════════════════════════════════════╗
║  stress-strike dashboard — Real-time Web Dashboard            ║
║                                                               ║
║  • Live RPS sparkline graph                                   ║
║  • Latency percentiles (p50/p95/p99)                         ║
║  • Load profiles (steady, soak, ramp, spike, wave)           ║
║  • Per-step breakdown with protocol badges                   ║
║  • Error reason breakdown                                    ║
║  • Error rate tracking                                        ║
║  • Worker node monitoring                                     ║
║  • Run history + time-travel replay                           ║
║  • Start/stop runs directly from browser                     ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
  stress-strike-dashboard [flags]

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  # Start dashboard on default port
  stress-strike-dashboard

  # Custom port
  stress-strike-dashboard -listen :9090
`)
	}
	flag.Parse()

	srv := dashboard.NewServer()
	bridge := dashboard.NewEngineBridge(srv)

	var (
		mu      sync.Mutex
		cancel  context.CancelFunc
		running bool
	)

	// Handle commands from browser. Runs the real load engine — live
	// telemetry is streamed over WebSocket while the run executes.
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

			var cfg dashboard.RunConfig
			switch c := args["config"].(type) {
			case dashboard.RunConfig:
				// Typed config (HTTP /api/run/start path).
				cfg = c
			case map[string]interface{}:
				// Raw JSON object (WebSocket command path).
				cfg = dashboard.RunConfig{
					TargetURL:       getString(c, "target_url", "http://localhost:8080/health"),
					Users:           getInt(c, "users", 10),
					DurationSeconds: getInt(c, "duration_seconds", 30),
					RateLimit:       getInt(c, "rate_limit", 0),
					Method:          getString(c, "method", "GET"),
					Profile:         getString(c, "profile", "steady"),
					Warmup:          getInt(c, "warmup", 0),
					RampUp:          getInt(c, "ramp_up", 0),
					SpikeUsers:      getInt(c, "spike_users", 0),
					SpikeWarmup:     getInt(c, "spike_warmup", 0),
					SpikeHold:       getInt(c, "spike_hold", 0),
					WavePeriod:      getInt(c, "wave_period", 0),
					Timeout:         getInt(c, "timeout", 5),
				}
			default:
				// No config supplied — sane in-browser defaults.
				cfg = dashboard.RunConfig{
					TargetURL:       "http://localhost:8080/health",
					Users:           10,
					DurationSeconds: 30,
					Method:          "GET",
					Profile:         "steady",
					Timeout:         5,
				}
			}

			bridge.StartRun(&cfg)

			// Build a real scenario from the browser config and run it.
			sc, err := dashboard.ScenarioFromRunConfig("dashboard", &cfg)
			if err != nil {
				bridge.RunFailed(err)
				mu.Lock()
				running = false
				mu.Unlock()
				return
			}

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

			fmt.Printf("  ▶ Run started: %s (%d users, %ds, profile=%s)\n",
				cfg.TargetURL, cfg.Users, cfg.DurationSeconds, cfg.Profile)

			streamStop := make(chan struct{})
			go dashboard.StreamTelemetry(srv, e, sc, streamStop)

			go func() {
				_, runErr := e.Run(runCtx, engine.RunOptions{Out: io.Discard, Quiet: true})
				close(streamStop)
				mu.Lock()
				running = false
				mu.Unlock()
				if runErr != nil {
					bridge.RunFailed(runErr)
					fmt.Printf("  ✖ Run failed: %v\n", runErr)
					return
				}
				final := dashboard.SnapshotFromTelemetry(e, sc)
				srv.UpdateSnapshot(final)
				bridge.RunCompleteFromSnapshot(final)
				fmt.Println("  ✅ Run completed")
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
	fmt.Println("║  stress-strike dashboard — real load engine                    ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Dashboard: http://localhost%s\n", *listen)
	fmt.Println()

	// Graceful shutdown
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

	if err := http.ListenAndServe(*listen, srv); err != nil {
		log.Fatalf("Dashboard server failed: %v", err)
	}
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
