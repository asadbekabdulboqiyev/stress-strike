package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/replay"
)

func main() {
	// Friendly flag errors + consistent help (exit 2 on usage errors).
	flag.CommandLine.Init("stress-strike-replay", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	// Flags
	inputFile := flag.String("input", "", "PCAP or HAR file to replay")
	rate := flag.String("rate", "1x", "Replay rate multiplier (e.g. 1x, 5x, 10x, 100x)")
	concurrency := flag.Int("concurrency", 10, "Number of concurrent replay workers")
	duration := flag.String("duration", "", "Max replay duration (e.g. 30s, 5m)")
	baseURL := flag.String("base-url", "", "Override target base URL")
	skipTLS := flag.Bool("skip-tls-verify", false, "Skip TLS certificate verification")
	pace := flag.String("pace", "timing", "Pacing mode: timing (capture-accurate, default), rps (fixed requests/sec), legacy (1s/rate)")
	rpsFlag := flag.Float64("rps", 0, "Target requests per second (used with --pace rps)")
	followRedirects := flag.Bool("follow-redirects", false, "Follow HTTP redirects (up to 10)")
	methods := flag.String("methods", "", "Filter by HTTP methods (e.g. GET,POST)")
	urlPattern := flag.String("url-pattern", "", "Filter by URL pattern (glob)")
	statusCodes := flag.String("status", "", "Filter by response status codes (e.g. 200,404)")
	validate := flag.Bool("validate", false, "Run response assertions")
	assertStatus := flag.String("assert-status", "", "Assert response status code")
	assertRegex := flag.String("assert-regex", "", "Assert response body matches regex")
	outputJSON := flag.String("output-json", "", "Export results to JSON file")
	outputCSV := flag.String("output-csv", "", "Export latency data to CSV file")
	reportDir := flag.String("report-dir", "reports", "Directory for reports")
	tlsKey := flag.String("tls-key", "", "TLS private key file for decryption")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file for decryption")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
╔═══════════════════════════════════════════════════════════════╗
║  stress-strike replay — Real Traffic Replay Engine            ║
║                                                               ║
║  Replay captured production traffic at configurable speed.    ║
║  Supports PCAP (gopacket) and HAR (browser export).          ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
  stress-strike-replay [flags]

Flags:
`)
		cliux.PrintFlagList(os.Stderr, flag.CommandLine)
		fmt.Fprintf(os.Stderr, `
Examples:
  # Replay HAR at 10x speed
  stress-strike-replay -input traffic.har -rate 10x

  # Replay HAR at real-time capture pace (timing-accurate, the default)
  stress-strike-replay -input traffic.har -pace timing

  # Constant-rate replay
  stress-strike-replay -input traffic.har -pace rps -rps 50

  # Legacy fixed pacing (1s per rate unit)
  stress-strike-replay -input traffic.har -rate 10x -pace legacy

  # Replay PCAP at 50x with 50 workers, filter GET requests
  stress-strike-replay -input capture.pcap -rate 50x -concurrency 50 -methods GET

  # Replay with response validation
  stress-strike-replay -input traffic.har -rate 5x -validate -assert-status 200

  # Replay with custom TLS keys
  stress-strike-replay -input capture.pcap -tls-key client.key -tls-cert client.crt -rate 10x

  # Replay with base URL override (redirect to staging)
  stress-strike-replay -input traffic.har -base-url https://staging.example.com -rate 5x
`)
	}

	cliux.Parse(flag.CommandLine, os.Args[1:], flag.Usage, cliux.Options{
		Command: "replay",
		FlagSet: flag.CommandLine,
		Examples: []string{
			"stress-strike replay -input traffic.har -rate 10x",
		},
	})

	if *inputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --input is required.")
		fmt.Fprintln(os.Stderr, "Example: stress-strike replay -input traffic.har -rate 10x")
		fmt.Fprintln(os.Stderr, "")
		flag.Usage()
		os.Exit(1)
	}

	// Parse rate multiplier
	rateMultiplier, err := parseRate(*rate)
	if err != nil {
		log.Fatalf("Invalid rate: %v", err)
	}

	// Resolve pacing mode
	var pacing replay.ReplayPacing
	switch *pace {
	case "timing":
		pacing = replay.PacingTiming
	case "rps":
		pacing = replay.PacingRPS
	case "legacy":
		pacing = replay.PacingLegacy
	default:
		log.Fatalf("Invalid pacing mode %q (use timing, rps, or legacy)", *pace)
	}
	if pacing == replay.PacingRPS && *rpsFlag <= 0 {
		log.Fatalf("--rps must be a positive value when --pace rps is used")
	}

	// Parse duration
	var dur time.Duration
	if *duration != "" {
		dur, err = time.ParseDuration(*duration)
		if err != nil {
			log.Fatalf("Invalid duration: %v", err)
		}
	}

	// Load TLS keys
	var tlsKeys []*replay.TLSKey
	if *tlsKey != "" && *tlsCert != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("Load TLS key: %v", err)
		}
		tlsKeys = append(tlsKeys, &replay.TLSKey{Key: &cert})
	}

	// Parse filter flags
	filter := &replay.PacketFilter{}
	if *methods != "" {
		filter.Methods = strings.Split(strings.ToUpper(*methods), ",")
	}
	if *urlPattern != "" {
		filter.URLPatterns = strings.Split(*urlPattern, ",")
	}
	if *statusCodes != "" {
		for _, s := range strings.Split(*statusCodes, ",") {
			code, _ := strconv.Atoi(strings.TrimSpace(s))
			if code > 0 {
				filter.StatusCodes = append(filter.StatusCodes, code)
			}
		}
	}

	// Parse assertions
	var assertions []replay.Assertion
	if *assertStatus != "" {
		assertions = append(assertions, replay.Assertion{Type: "status", Value: *assertStatus})
	}
	if *assertRegex != "" {
		assertions = append(assertions, replay.Assertion{Type: "regex", Value: *assertRegex})
	}

	// Build config
	config := &replay.ReplayConfig{
		RateMultiplier:   rateMultiplier,
		MaxConcurrency:   *concurrency,
		Duration:         dur,
		Pacing:           pacing,
		RPS:              *rpsFlag,
		BaseURL:          *baseURL,
		SkipTLSVerify:    *skipTLS,
		TLSKeys:          tlsKeys,
		FollowRedirects:  *followRedirects,
		ValidateResponse: *validate,
		Assertions:       assertions,
		OutputReport:     *outputJSON != "" || *outputCSV != "",
		ReportDir:        *reportDir,
		Filter:           filter,
	}

	// Load capture
	ext := strings.ToLower(filepath.Ext(*inputFile))
	var capture *replay.Capture

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  stress-strike replay — Loading capture...                   ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")

	// Security notice: warn loudly when certificate verification is disabled.
	if *skipTLS {
		fmt.Println()
		fmt.Println("  ⚠  TLS certificate verification DISABLED (--skip-tls-verify).")
		fmt.Println("     Connection is vulnerable to MITM attacks — only use this")
		fmt.Println("     when replaying captures through a trusted MITM proxy or")
		fmt.Println("     against hosts with self-signed certificates you control.")
		fmt.Println()
	}

	switch ext {
	case ".har":
		fmt.Printf("  Loading HAR: %s\n", *inputFile)
		capture, err = replay.ParseHAR(*inputFile)
	case ".pcap", ".pcapng":
		fmt.Printf("  Loading PCAP: %s\n", *inputFile)
		parser := replay.NewPCAPParser(tlsKeys)
		capture, err = parser.ParseFile(*inputFile)
	default:
		log.Fatalf("Unsupported file format: %s (use .har, .pcap, or .pcapng)", ext)
	}

	if err != nil {
		log.Fatalf("Failed to load capture: %v", err)
	}

	fmt.Printf("  Loaded %d packets\n", len(capture.Packets))
	fmt.Printf("  Time span: %s → %s\n", capture.StartTime.Format("15:04:05"), capture.EndTime.Format("15:04:05"))
	if len(capture.Metadata) > 0 {
		for k, v := range capture.Metadata {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}
	fmt.Println()

	// Apply filter
	packets := capture.Packets
	if len(filter.Methods) > 0 || len(filter.URLPatterns) > 0 || len(filter.StatusCodes) > 0 {
		packets = capture.Filter(filter)
		fmt.Printf("  Filtered: %d → %d packets\n", len(capture.Packets), len(packets))
		// Override capture packets for engine
		capture.Packets = packets
	}

	// Create engine
	numWorkers := *concurrency
	if numWorkers > len(packets) {
		numWorkers = len(packets)
	}
	if numWorkers < 1 {
		numWorkers = 1
	}

	engine := replay.NewReplayEngine(config, capture, numWorkers)

	// Run
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Printf("║  REPLAYING at %.1fx speed with %d workers                    \n", rateMultiplier, numWorkers)
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Pacing: %s\n", pacing)
	fmt.Println()

	startTime := time.Now()
	result, err := engine.Run()
	if err != nil {
		log.Fatalf("Replay failed: %v", err)
	}
	totalTime := time.Since(startTime)

	// Print results
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  REPLAY COMPLETE")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Total: %d | Succeeded: %d | Failed: %d\n", result.Replayed, result.Succeeded, result.Failed)
	fmt.Printf("  Time: %s | Packets: %d\n", totalTime.Round(time.Millisecond), result.TotalPackets)
	if result.Replayed > 0 {
		fmt.Printf("  Throughput: %.1f req/s\n", float64(result.Replayed)/totalTime.Seconds())
	}
	if len(result.Latencies) > 0 {
		fmt.Printf("  Latency: avg=%s p50=%s p95=%s p99=%s\n",
			result.AvgLatency.Round(time.Microsecond),
			result.P50Latency.Round(time.Microsecond),
			result.P95Latency.Round(time.Microsecond),
			result.P99Latency.Round(time.Microsecond),
		)
	}
	if len(result.Errors) > 0 {
		fmt.Println("  Errors:")
		for err, count := range result.Errors {
			fmt.Printf("    - %s (%d times)\n", err, count)
		}
	}
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// Export JSON
	if *outputJSON != "" {
		if err := os.MkdirAll(*reportDir, 0755); err != nil {
			log.Printf("Failed to create report directory: %v", err)
		}
		jsonPath := *outputJSON
		if !strings.Contains(jsonPath, "/") {
			jsonPath = filepath.Join(*reportDir, jsonPath)
		}
		if err := result.ExportJSONToFile(jsonPath); err != nil {
			log.Printf("Failed to export JSON: %v", err)
		} else {
			fmt.Printf("\n  JSON report: %s\n", jsonPath)
		}
	}

	// Export CSV
	if *outputCSV != "" {
		if err := os.MkdirAll(*reportDir, 0755); err != nil {
			log.Printf("Failed to create report directory: %v", err)
		}
		csvPath := *outputCSV
		if !strings.Contains(csvPath, "/") {
			csvPath = filepath.Join(*reportDir, csvPath)
		}
		f, err := os.Create(csvPath)
		if err != nil {
			log.Printf("Failed to create CSV: %v", err)
		} else {
			defer f.Close()
			f.WriteString("index,latency_ms,status\n")
			for i, lat := range result.Latencies {
				f.WriteString(fmt.Sprintf("%d,%.2f,ok\n", i+1, float64(lat.Microseconds())/1000.0))
			}
			fmt.Printf("  CSV report: %s\n", csvPath)
		}
	}
}

func parseRate(s string) (float64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "x")
	s = strings.TrimSuffix(s, "X")
	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("parse rate %q: %w", s, err)
	}
	if val <= 0 {
		return 0, fmt.Errorf("rate must be positive")
	}
	return val, nil
}
