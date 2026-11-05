package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// cmd_crawl.go implements `stress-strike crawl`: the CLI face of the dashboard's
// POST /api/crawl/scan. It is a breadth-first site spider that discovers links
// and forms, and reports every endpoint it finds.
//
// Crawl is information gathering (OpScan): a named ticket is not required, but
// the gate still refuses anything off the scope allowlist (default: the named
// host). Offsite links are never followed unless --offsite is given, and every
// hop is routed through the Guard via guardRoundTripper — redirect hops stay on
// the original host (crawlerRedirectGuard).
func cmdCrawl() {
	var (
		target      string
		depth       int
		pages       int
		concurrency int
		offsite     bool
		timeout     int
	)
	sf := &scanFlags{}

	fs := flag.NewFlagSet("crawl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&target, "target", "", "target URL (required), e.g. https://example.com")
	fs.IntVar(&depth, "depth", 3, "maximum link depth to follow")
	fs.IntVar(&pages, "pages", 100, "maximum pages to fetch")
	fs.IntVar(&concurrency, "concurrency", 5, "parallel fetches")
	fs.BoolVar(&offsite, "offsite", false, "follow links off the target host (may leave scope)")
	fs.IntVar(&timeout, "timeout", 10, "per-request timeout in seconds")
	addScanGateFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printCrawlHelp(fs) }, cliux.Options{
		Command: "crawl",
		FlagSet: fs,
		Examples: []string{
			"stress-strike crawl --target https://example.com --depth 3",
		},
	})

	if strings.TrimSpace(target) == "" {
		usageFatal(fmt.Errorf("--target is required\n\nExample: stress-strike crawl --target https://example.com"))
	}
	parsed, err := validateScanTarget(target)
	if err != nil {
		usageFatal(err)
	}

	// Zero or negative means "use the default", matching the dashboard's
	// convention. The CLI does NOT apply the web-only upper caps (depth 10,
	// pages 1000, concurrency 20): an operator is not a browser click.
	if depth < 1 {
		depth = 3
	}
	if pages < 1 {
		pages = 100
	}
	if concurrency < 1 {
		concurrency = 5
	}
	if timeout < 1 {
		timeout = 10
	}

	// Authorization gate: crawl is an OpScan operation. The decision is
	// recorded before the first page is fetched.
	enforceAuthz(authz.OpScan, []string{parsed.String()}, os.Args, sf.gate)

	scanWarning("crawl")
	announceScanScope("crawl", parsed, sf)

	timeoutDur := time.Duration(timeout) * time.Second
	gate, err := buildScanGuard(parsed, sf, false, timeoutDur)
	if err != nil {
		usageFatal(err)
	}

	crawler := scanner.NewCrawler(parsed.String(), scanner.CrawlOptions{
		MaxDepth:     depth,
		MaxPages:     pages,
		Timeout:      timeoutDur,
		AllowOffsite: offsite,
		UserAgent:    "stress-strike-crawler/1.0",
		Concurrency:  concurrency,
	})
	crawler.Client = &http.Client{
		Timeout:   timeoutDur,
		Transport: &guardRoundTripper{g: gate}, // every hop passes through the safety gate
	}
	result := crawler.Crawl()
	st := gate.Stats()
	printScanGateStats(st)

	if err := emitScanJSON(result, sf); err != nil {
		fatal(err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Printf("crawl: %s\n", parsed.String())
	fmt.Printf("  pages:     %d\n", result.Pages)
	fmt.Printf("  endpoints: %d\n", len(result.Endpoints))
	fmt.Printf("  offsite:   %v\n", offsite)
	fmt.Printf("  scope:     %s\n", scanScopeLabel(parsed, sf))
	if note := scanGateNote(st); note != "" {
		fmt.Printf("  note:      %s\n", note)
	}
	for _, ep := range result.Endpoints {
		fmt.Printf("  - %s %s", ep.Method, ep.URL)
		if len(ep.Params) > 0 {
			fmt.Printf(" (%s)", strings.Join(ep.Params, ", "))
		}
		fmt.Println()
	}
	if len(result.Endpoints) == 0 {
		fmt.Println("  no endpoints discovered")
	}
}

// printCrawlHelp renders `stress-strike crawl --help`.
func printCrawlHelp(fs *flag.FlagSet) {
	w := os.Stderr
	fmt.Fprintf(w, "\n stress-strike crawl — site spider (endpoint discovery)\n\n")
	fmt.Fprintf(w, " USAGE\n")
	fmt.Fprintf(w, "   stress-strike crawl --target https://example.com [flags]\n\n")
	fmt.Fprintf(w, " Breadth-first crawl that discovers links and forms and reports every\n")
	fmt.Fprintf(w, " endpoint found. Information gathering (scope-enforced, not intrusive):\n")
	fmt.Fprintf(w, " offsite links are never followed unless --offsite is given, and every\n")
	fmt.Fprintf(w, " request passes through the probe gate.\n\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " FLAGS\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " EXAMPLES\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Crawl a site three levels deep",
		"stress-strike crawl --target https://example.com --depth 3 --pages 200",
		"",
		"# Never leave the target host (the default)",
		"stress-strike crawl --target https://example.com",
		"",
		"# Machine-readable output (the endpoint list)",
		"stress-strike crawl --target https://example.com --json --output-json crawl.json",
	} {
		fmt.Fprintf(w, "\n   %s\n", e)
	}
	fmt.Fprintf(w, "\n")
}
