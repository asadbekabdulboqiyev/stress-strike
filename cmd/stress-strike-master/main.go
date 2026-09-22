package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/dist/coordinator"
	distproto "github.com/asadbekabdulboqiyev/stress-strike/internal/dist/proto"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/fingerprint"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
)

var version = "0.11.0"

var (
	listenAddr  = flag.String("listen", ":50051", "Master listen address (for worker registration)")
	workerAddrs = flag.String("workers", "", "Comma-separated worker addresses (static fleet)")
	waitWorkers = flag.Int("wait-workers", 0, "Auto-discovery: wait for N self-registering workers")
	waitTimeout = flag.Int("wait-timeout", 30, "Auto-discovery registration timeout (seconds)")
	configPath  = flag.String("config", "", "Scenario file")
	url         = flag.String("url", "", "Target URL (quick mode)")
	users       = flag.Int("users", 100, "Virtual users")
	duration    = flag.Int("duration", 30, "Duration seconds")
	profile     = flag.String("profile", "steady", "Load profile")
	name        = flag.String("name", "distributed-run", "Run name")
	regressPct  = flag.Float64("regress-pct", 20, "Regression threshold %")
	comparePath = flag.String("compare", "", "Baseline report for comparison")
	timeline    = flag.Bool("timeline", false, "Export CSV timeline")
	expectP99   = flag.Float64("expect-p99-ms", 0, "SLA: max p99 latency")
	expectErr   = flag.Float64("expect-error-rate", 0, "SLA: max error rate %")
	expectRPS   = flag.Float64("expect-min-rps", 0, "SLA: min throughput")
	token       = flag.String("token", "", "Shared control-plane token (empty = disabled)")
	runTimeout  = flag.Int("run-timeout", 0, "Overall run deadline in seconds (0 = duration + 60s)")
	quiet       = flag.Bool("quiet", false, "Suppress live progress output")
	tlsFP       = flag.String("tls-fingerprint", "", "TLS ClientHello fingerprint workers should present (chrome, firefox, ...)")
)

func main() {
	flag.Parse()
	coordinator.Version = version

	if *configPath == "" && *url == "" {
		log.Fatal("Either -config or -url is required")
	}

	var workerList []string
	if *workerAddrs != "" {
		for _, w := range splitAndTrim(*workerAddrs) {
			if w != "" {
				workerList = append(workerList, w)
			}
		}
	}
	if len(workerList) == 0 && *waitWorkers <= 0 {
		log.Fatal("Pass -workers (static) or -wait-workers N (auto-discovery)")
	}

	var scenario *config.Scenario
	if *configPath != "" {
		sc, err := config.Load(*configPath)
		if err != nil {
			log.Fatal(err)
		}
		scenario = sc
	} else {
		sc, err := quickScenario(*name, *url, *users, *duration, *profile)
		if err != nil {
			log.Fatal(err)
		}
		scenario = sc
	}
	if *tlsFP != "" {
		if !fingerprint.Profile(*tlsFP).Valid() {
			log.Fatalf("unknown -tls-fingerprint %q (valid values: %s)", *tlsFP, strings.Join(fingerprint.Names(), ", "))
		}
		scenario.Profile.TLSFingerprint = *tlsFP
	}

	sla := scenario.SLA
	if sla == nil {
		sla = &config.SLA{}
	}
	if *expectP99 > 0 {
		sla.MaxP99Ms = *expectP99
	}
	if *expectErr > 0 {
		sla.MaxErrorRatePct = *expectErr
	}
	if *expectRPS > 0 {
		sla.MinRPS = *expectRPS
	}
	if !slaEmpty(sla) {
		scenario.SLA = sla
	}

	timeout := time.Duration(*runTimeout) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(scenario.Profile.Duration)*time.Second + 60*time.Second
	}

	master := coordinator.NewMaster(coordinator.MasterConfig{
		Scenario:        scenario,
		Workers:         workerList,
		ListenAddr:      *listenAddr,
		Token:           *token,
		RunTimeout:      timeout,
		AutoWorkers:     *waitWorkers,
		RegisterTimeout: time.Duration(*waitTimeout) * time.Second,
	})
	defer master.Close()

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer(coordinator.ServerOptions(*token)...)
	distproto.RegisterMasterWorkerServer(grpcServer, master)
	go func() {
		log.Printf("Master gRPC listening on %s", lis.Addr())
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("Master server error: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrs := workerList
	if len(addrs) == 0 {
		log.Printf("Waiting for %d self-registering workers (timeout %ds)...", *waitWorkers, *waitTimeout)
		addrs, err = master.ResolveWorkers(ctx)
		if err != nil {
			log.Fatalf("Worker discovery failed: %v", err)
		}
	}

	connected, err := master.Connect(ctx, addrs)
	if err != nil {
		log.Fatalf("Failed to connect to workers: %v", err)
	}

	runID := fmt.Sprintf("run-%d", time.Now().UnixMilli())
	log.Printf("Starting distributed run %s on %d workers", runID, len(connected))

	if err := master.StartRun(ctx, runID); err != nil {
		log.Fatalf("Run failed: %v", err)
	}

	stopProgress := make(chan struct{})
	var progressWG sync.WaitGroup
	if !*quiet {
		progressWG.Add(1)
		go func() {
			defer progressWG.Done()
			printLiveProgress(master, stopProgress)
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case <-master.Done():
		log.Println("Run completed")
	case sig := <-sigCh:
		log.Printf("Received signal %v, stopping gracefully...", sig)
		master.StopRun(runID, true)
		select {
		case <-master.Done():
		case <-time.After(15 * time.Second):
			log.Println("Timeout waiting for graceful stop; finalizing partial results")
		}
	}

	close(stopProgress)
	progressWG.Wait()

	if failed := master.FailedWorkers(); len(failed) > 0 {
		log.Printf("WARNING: %d worker(s) failed or disconnected: %v", len(failed), failed)
	}

	finalReport := master.FinalReport()
	if finalReport != nil {
		printSummary(finalReport)
		saveReports(finalReport, *name)

		if *comparePath != "" {
			compareReports(finalReport, *comparePath, *regressPct)
		}

		if scenario.SLA != nil && !slaEmpty(scenario.SLA) {
			passed := evaluateSLA(finalReport, scenario.SLA)
			if !passed {
				grpcServer.GracefulStop()
				log.Fatal("SLA GATE FAILED")
			}
			log.Println("SLA GATE PASSED")
		}
	} else {
		log.Println("No final report produced (no worker reported results)")
	}

	grpcServer.GracefulStop()
	log.Println("Master shutdown complete")
}

// printLiveProgress renders a single updating status line from the aggregate
// live telemetry until stop is closed.
func printLiveProgress(master *coordinator.Master, stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			fmt.Print("\r\x1b[K")
			return
		case <-ticker.C:
			agg := master.Aggregator().Snapshot()
			if agg.Workers == 0 {
				continue
			}
			fmt.Printf("\r\x1b[K  workers=%d req=%s err=%s (%.2f%%) rps=%s p95=%s",
				agg.Workers,
				formatCount(uint64(max64(agg.TotalRequests, 0))),
				formatCount(uint64(max64(agg.TotalErrors, 0))),
				errorRate(agg.TotalRequests, agg.TotalErrors),
				formatRPS(agg.RPS),
				agg.P95,
			)
		}
	}
}

func errorRate(total, errors int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(errors) / float64(total) * 100
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func splitAndTrim(s string) []string {
	var out []string
	for _, part := range splitComma(s) {
		if trimmed := trimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func splitComma(s string) []string {
	out := []string{}
	current := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, current)
			current = ""
		} else {
			current += string(r)
		}
	}
	out = append(out, current)
	return out
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	if start >= end {
		return ""
	}
	return s[start:end]
}

func quickScenario(name, url string, users, duration int, profile string) (*config.Scenario, error) {
	sc := &config.Scenario{
		Name: name,
		Profile: config.Profile{
			Type:     profile,
			Users:    users,
			Duration: duration,
			Timeout:  5,
		},
		Steps: []config.Step{
			{Name: "request", Method: "GET", URL: url},
		},
	}
	return sc, sc.Normalize()
}

func printSummary(r *report.Report) {
	fmt.Printf("\n%s\n", "═══════════════════════════════════════════════════════════════")
	fmt.Printf("  DISTRIBUTED RUN COMPLETE: %s\n", r.Name)
	fmt.Printf("%s\n", "═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Requests: %s | Errors: %s (%.2f%%) | RPS: %s\n",
		formatCount(r.TotalRequests), formatCount(r.TotalErrors), r.ErrorRatePct, formatRPS(r.RPS))
	fmt.Printf("  Latency: avg=%s p50=%s p95=%s p99=%s max=%s\n",
		r.Overall.Avg, r.Overall.P50, r.Overall.P95, r.Overall.P99, r.Overall.Max)
	fmt.Printf("%s\n", "═══════════════════════════════════════════════════════════════")
}

func formatCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func formatRPS(rps float64) string {
	if rps >= 1_000 {
		return fmt.Sprintf("%.1fK", rps/1_000)
	}
	return fmt.Sprintf("%.0f", rps)
}

func saveReports(r *report.Report, name string) {
	dir := "./reports"
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("Failed to create reports dir: %v", err)
		return
	}
	jsonPath, _ := r.SaveJSON(dir)
	txtPath, _ := r.SaveTXT(dir)
	fmt.Printf("\nReports written:\n  %s\n  %s\n", jsonPath, txtPath)
}

func compareReports(current *report.Report, baselinePath string, regressPct float64) {
	baseline, err := report.LoadReport(baselinePath)
	if err != nil {
		log.Printf("Failed to load baseline: %v", err)
		return
	}
	result := report.Compare(current, baseline)
	fmt.Print(result.Render())
	if result.Regression && result.RegressionPct > regressPct {
		fmt.Printf("  REGRESSION DETECTED (threshold %.0f%%)\n", regressPct)
	}
}

func evaluateSLA(r *report.Report, sla *config.SLA) bool {
	if sla == nil || slaEmpty(sla) {
		return true
	}
	results := report.EvaluateSLA(r, sla)
	passed := true
	for _, res := range results {
		status := "PASS"
		if !res.Pass {
			status = "FAIL"
			passed = false
		}
		fmt.Printf("  %s  %-14s target %-12s actual %s\n", status, res.Metric, res.Target, res.Actual)
	}
	return passed
}

func slaEmpty(sla *config.SLA) bool {
	return sla == nil || (sla.MaxP99Ms <= 0 && sla.MaxAvgMs <= 0 && sla.MaxErrorRatePct <= 0 && sla.MinRPS <= 0)
}
