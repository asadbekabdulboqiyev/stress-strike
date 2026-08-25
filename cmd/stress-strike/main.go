package main

import (
	"fmt"
	"os"
)

const version = "0.3.0"

func main() {
	// Check for subcommands
	if len(os.Args) > 1 {
		cmd := os.Args[1]
		switch cmd {
		case "run":
			os.Args = os.Args[1:] // keep "run" as [0] for flagset
			cmdRun()
			return
		case "replay":
			cmdReplay()
			return
		case "scan":
			cmdScan()
			return
		case "dashboard":
			cmdDashboard()
			return
		case "ai":
			cmdAI()
			return
		case "master":
			cmdMaster()
			return
		case "worker":
			cmdWorker()
			return
		case "help", "--help", "-h":
			printFullHelp()
			return
		case "version", "--version", "-v":
			fmt.Printf("stress-strike v%s\n", version)
			return
		}
	}

	// Default: run (backwards compatible with old flag syntax)
	cmdRun()
}

func printFullHelp() {
	fmt.Fprintf(os.Stderr, `
stress-strike v%s — Professional Load Testing & Security Suite

 USAGE
   stress-strike <command> [flags]

 COMMANDS
   run         HTTP/gRPC/WebSocket load test (default if no command)
   replay      Replay real traffic from PCAP/HAR captures
   scan        TLS/WAF deep scanner + fingerprinting
   dashboard   Real-time web dashboard with WebSocket
   ai          AI anomaly detector (Gemini/Ollama/OpenAI)
   master      Distributed mode — master coordinator
   worker      Distributed mode — worker node
   help        Show this help
   version     Show version

 QUICK EXAMPLES

   # Simple load test
   stress-strike run --url https://api.example.com --users 100 --duration 60

   # Load test with SLA gate
   stress-strike run --url https://api.example.com --users 50 --duration 30 \
     --expect-p99-ms 200 --expect-error-rate 1

   # Replay production traffic at 10x speed
   stress-strike replay -input traffic.har -rate 10x -concurrency 20

   # Scan a server for security issues
   stress-strike scan -target example.com -all

   # Start web dashboard
   stress-strike dashboard -listen :8888

   # AI anomaly analysis
   stress-strike ai -input report.json

   # Distributed load test
   stress-strike master --workers host1:50052,host2:50052 --url URL --users 1000
   stress-strike worker --listen :50052

   # Use a YAML scenario file
   stress-strike run --config scenario.yaml

 WARNING: Only run against systems you own or have explicit permission to test.
`, version)
}
