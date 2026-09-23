package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
)

// version is overridden at build time via:
//
//	go build -ldflags "-X main.version=0.14.2"
//
// The default mirrors the latest release tag.
var version = "0.14.2"

// knownCommands is the source of truth for command suggestions and the
// "unknown command" listing. Keep in sync with the switch in main().
var knownCommands = []string{
	"run", "replay", "scan", "dashboard", "master", "worker",
	"demo-store", "pentest", "help", "version",
}

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
		case "master":
			cmdMaster()
			return
		case "worker":
			cmdWorker()
			return
		case "pentest":
			cmdPentest()
			return
		case "demo-store":
			cmdDemoStore()
			return
		case "help", "--help", "-h":
			printFullHelp()
			return
		case "version", "--version", "-v":
			fmt.Printf("stress-strike v%s\n", version)
			return
		default:
			unknownCommand(cmd)
			os.Exit(2)
		}
	}

	// No subcommand: if a TTY is attached, show the interactive mode picker
	// (CLI vs Web Server). Otherwise fall back to run for script/CI usage.
	if isInteractiveTerminal() {
		interactivePicker()
		return
	}
	cmdRun()
}

// unknownCommand reports an unrecognized subcommand with a "did you mean"
// suggestion, the command list, and a pointer to --help. Exit code 2 matches
// the usage-error convention used across the CLI.
func unknownCommand(cmd string) {
	w := os.Stderr
	if cliux.IsColorable(w) {
		fmt.Fprintf(w, "\x1b[1;31mError:\x1b[0m unknown command %q.\n\n", cmd)
	} else {
		fmt.Fprintf(w, "Error: unknown command %q.\n\n", cmd)
	}
	if suggs := cliux.Suggestions(cmd, knownCommands, 3); len(suggs) > 0 {
		fmt.Fprintf(w, "Did you mean: %s?\n\n", strings.Join(suggs, " | "))
	}
	fmt.Fprintf(w, "Run '%s' with one of these commands:\n", filepath.Base(os.Args[0]))
	for _, c := range knownCommands {
		fmt.Fprintf(w, "   %s\n", c)
	}
	fmt.Fprintf(w, "\nRun 'stress-strike --help' to see all commands, flags and examples.\n")
}

// shouldFailGate reports whether the measured error rate should trip the SLA
// gate. A threshold of 0 (or negative) disables the gate. The gate fails only
// when the rate is strictly greater than the threshold.
func shouldFailGate(ratePct, threshold float64) bool {
	return threshold > 0 && ratePct > threshold
}

func printFullHelp() {
	fmt.Fprintf(os.Stderr, `
stress-strike v%s — Ultra-Fast Load Testing & Security Suite

 USAGE
   stress-strike <command> [flags]

═══════════════════════════════════════════════════════════════════════
 COMMANDS
═══════════════════════════════════════════════════════════════════════
   run         HTTP/gRPC/WebSocket load test (default)
   replay      Replay real traffic from PCAP/HAR captures
   scan        TLS/WAF deep scanner + fingerprinting
   dashboard   Real-time web dashboard with WebSocket
   master      Distributed mode — master coordinator
   worker      Distributed mode — worker node
   demo-store  Launch bundled VoltStore demo (VeriGate ON)
   pentest     1-click professional security assessment
   help        Show this help
   version     Show version

═══════════════════════════════════════════════════════════════════════
 RUN FLAGS — Load Test
═══════════════════════════════════════════════════════════════════════
   --url string             Target URL (required if no --config)
   --config string          YAML scenario file (alternative to --url)
   --users int              Virtual users (default: 10)
   --duration int           Test duration in seconds (default: 10)
   --ramp-up int            Ramp-up time in seconds (default: 0)
   --method string          HTTP method: GET, POST, PUT, DELETE, PATCH
   --data string            Request body (JSON)
   --header string          Header: -header "Key: Value" (repeatable)
   --timeout int            Request timeout in seconds (default: 10)
   --keep-alive             Reuse TCP connections (default: true)
   --name string            Report name (default: "stress-test")

   Load Profiles:
   --profile string         steady|soak|linear-ramp|spike|wave|constant-rps
   --target-rps int         Target RPS for constant-rps mode
   --spike-users int        Spike peak users
   --spike-warmup int       Spike warmup seconds
   --spike-hold int         Spike hold seconds
   --wave-period int        Wave period seconds

   Performance:
   --pre-warm               Pre-establish TCP connections before test
   --pre-warm-conns int     Number of pre-warmed connections (default: users)
   --quiet                  Suppress live progress bar

   SLA Gate (CI/CD):
   --expect-p99-ms float    Max P99 latency in ms (exit 2 if exceeded)
   --expect-error-rate float Max error rate %% (exit 2 if exceeded)
   --expect-min-rps float   Min RPS threshold (exit 2 if below)

   Comparison:
   --compare string         Baseline report JSON for comparison
   --regress-pct float      Max regression %% before exit 2 (default: 20)

   Output:
   --timeline               Save per-second CSV timeline
   --report-dir string      Report output directory (default: "reports")

   Mode:
   --mode string            cli (terminal report, default) | dashboard (real-time web)
   --listen string          Dashboard listen address (default: 127.0.0.1:8888, with --mode dashboard)

═══════════════════════════════════════════════════════════════════════
 REPLAY FLAGS — Traffic Replay
═══════════════════════════════════════════════════════════════════════
   -input string            PCAP or HAR capture file (required)
   -rate float              Speed multiplier: 1.0=realtime, 10.0=10x (default: 1.0)
   -concurrency int         Parallel workers (default: 5)
   -tls-key string          TLS private key for HTTPS decryption
   -base-url string         Override target URL
   -validate                Enable response assertions
   -assert-status int       Expected HTTP status code
   -assert-regex string     Expected response body regex
   -output-json string      Save results to JSON file
   -report-dir string       Report output directory

   Filters:
   -filter-methods string   Comma-separated HTTP methods to include
   -filter-urls string      URL pattern (regex)
   -filter-min-status int   Min status code
   -filter-max-status int   Max status code

═══════════════════════════════════════════════════════════════════════
 SCAN FLAGS — Security Scanner
═══════════════════════════════════════════════════════════════════════
   -target string           Target host:port (required)
   -tls                     Run TLS scanner
   -waf                     Run WAF detection
   -http                    Run HTTP fingerprinting
   -all                     Run all scanners
   -json string             Save results to JSON file

═══════════════════════════════════════════════════════════════════════
 DASHBOARD FLAGS — Web Dashboard
═══════════════════════════════════════════════════════════════════════
   -listen string           Address to listen on (default: "127.0.0.1:8888")

═══════════════════════════════════════════════════════════════════════
 MASTER FLAGS — Distributed Coordinator
═══════════════════════════════════════════════════════════════════════
   --workers string         Comma-separated worker addresses (required)
   --url string             Target URL (required)
   --users int              Total virtual users (default: 10)
   --duration int           Test duration in seconds (default: 10)
   --listen string          Master gRPC address (default: ":50051")
   --compare string         Baseline report for comparison
   --regress-pct float      Max regression %% (default: 20)

═══════════════════════════════════════════════════════════════════════
 WORKER FLAGS — Distributed Worker
═══════════════════════════════════════════════════════════════════════
   --listen string          Worker gRPC address (default: ":50052")

═══════════════════════════════════════════════════════════════════════
 PENTEST FLAGS — 1-Click Security Assessment (14 phases)
═══════════════════════════════════════════════════════════════════════
   --target string        Target URL or domain (required)
   --depth int            Scan depth: 1=quick, 2=standard, 3=deep (default: 2)
   --output string        Output directory (default: reports/pentest-{target}-{ts})
   --format string        Report format: html,json,markdown,pdf,professional,all
                          (pdf=client-ready PDF, professional=PDF+HTML+MD) (default: all)
   --scope string         Scope: full,web,network (default: full)
   --threads int          Parallel threads (default: 10)
   --timeout int          Request timeout in seconds (default: 10)
   --skip-load-test       Skip load testing phase
   --verbose              Show detailed progress

 AUTHENTICATED SCANNING — test behind login (where most bugs live)
   --auth-form URL        Form login URL, e.g. https://site.com/login
   --auth-user string     Login username
   --auth-pass string     Login password
   --auth-user-field      Username field name (default: username)
   --auth-pass-field      Password field name (default: password)
   --auth-cookie string   Raw cookie header instead of form login
   --auth-header string   Static header 'Name: Value' (e.g. Authorization: Bearer x)

 ATTACK SURFACE & INTEL
   --crawl                Crawl target to discover endpoints/forms (default: true)
   --max-pages int        Max pages to crawl (default: 50)
   --nvd                  Query live NVD database, 240K+ CVEs (default: true)
   --compliance string    Frameworks: pci-dss,soc2,iso27001,none (default: all three)

═══════════════════════════════════════════════════════════════════════
 QUICK EXAMPLES
═══════════════════════════════════════════════════════════════════════

  # Simple load test
  stress-strike run --url https://api.example.com --users 100 --duration 60

  # Constant RPS mode (1000 requests/sec)
  stress-strike run --url https://api.example.com --target-rps 1000 --duration 30

  # Pre-warm connections (zero handshake overhead)
  stress-strike run --url https://api.example.com --users 100 --pre-warm

  # SLA gate for CI/CD (exit code 2 on failure)
  stress-strike run --url https://api.example.com --users 50 --duration 30 \
    --expect-p99-ms 200 --expect-error-rate 1

  # Compare with baseline (detect regressions)
  stress-strike run --url https://api.example.com --users 50 --duration 30 \
    --compare reports/baseline.json --regress-pct 20

  # Replay production traffic at 10x speed
  stress-strike replay -input traffic.har -rate 10x -concurrency 20

  # Scan server security
  stress-strike scan -target example.com -all

  # Start web dashboard (loopback only by default)
  stress-strike dashboard

  # Expose on all interfaces (warns: no auth)
  stress-strike dashboard -listen :8888

  # Distributed load test
  stress-strike master --workers host1:50052,host2:50052 --url URL --users 1000
  stress-strike worker --listen :50052

  # YAML scenario file
  stress-strike run --config examples/login-flow.yaml

  # Spike test
  stress-strike run --url https://api.example.com --users 100 --duration 60 \
    --profile spike --spike-users 500 --spike-warmup 10 --spike-hold 20

  # 1-click security assessment
  stress-strike pentest --target https://example.com --depth 2 --verbose

  # Quiet mode (no progress bar, for scripts)
  stress-strike run --url https://api.example.com --users 100 --duration 60 --quiet

  # Real-time web dashboard output (open browser, press Start)
  stress-strike run --url https://api.example.com --users 100 --duration 60 --mode dashboard

═══════════════════════════════════════════════════════════════════════
 WARNING: Only test systems you own or have explicit permission to test.
          Unauthorized load testing is illegal.
═══════════════════════════════════════════════════════════════════════
`, version)
}
