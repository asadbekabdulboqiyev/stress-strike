package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"stress-strike/internal/dashboard"
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

	// Handle commands from browser
	srv.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		switch cmd {
		case "start":
			if cfg, ok := args["config"].(map[string]interface{}); ok {
				config := &dashboard.RunConfig{
					TargetURL:       getString(cfg, "target_url", "http://localhost:8080/health"),
					Users:           getInt(cfg, "users", 10),
					DurationSeconds: getInt(cfg, "duration_seconds", 10),
					Method:          getString(cfg, "method", "GET"),
				}
				bridge.StartRun(config)
				fmt.Printf("  ▶ Run started: %s (%d users, %ds)\n", config.TargetURL, config.Users, config.DurationSeconds)

				// Simulate run (in real usage, this would start the engine)
				go func() {
					for i := 0; i < config.DurationSeconds; i++ {
						time.Sleep(1 * time.Second)

						// Simulate requests
						for j := 0; j < config.Users*10; j++ {
							latency := time.Duration(100+time.Now().UnixNano()%500) * time.Microsecond
							isError := time.Now().UnixNano()%100 < 3
							status := 200
							if isError {
								status = 500
							}
							bridge.RecordRequest(status, latency, isError)
						}
					}
					bridge.RunComplete()
					fmt.Println("  ✅ Run completed")
				}()
			}
		case "stop":
			bridge.StopRun()
			fmt.Println("  ⏹ Run stopped")
		}
	})

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  stress-strike dashboard — Starting...                       ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Dashboard: http://localhost%s\n", *listen)
	fmt.Println()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := http.ListenAndServe(*listen, srv); err != nil {
			log.Fatalf("Dashboard server failed: %v", err)
		}
	}()

	<-sigCh
	fmt.Println("\n  Dashboard shutting down...")
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
