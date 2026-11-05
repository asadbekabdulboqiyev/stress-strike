package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// cmd_fuzz.go implements `stress-strike fuzz`: the CLI face of the dashboard's
// POST /api/fuzz/scan. Same engine, same gate, same authorization semantics —
// only the transport differs.
//
// The fuzzer mutates request inputs (path, query, body, header) and reports the
// responses that differ from the baseline. Intrusive mutations (write methods,
// traversal, injection payloads) are OFF unless --intrusive is given: they can
// change server state, so they require the operator's explicit opt-in and the
// Guard records the refusal when they are off.
func cmdFuzz() {
	var (
		target      string
		paths       stringListFlags
		methods     stringListFlags
		mutations   int
		concurrency int
		intrusive   bool
		timeout     int
	)
	sf := &scanFlags{}

	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&target, "target", "", "target URL (required), e.g. https://example.com/api")
	fs.Var(&paths, "path", "endpoint path to fuzz (repeatable, required), e.g. /item/{id}")
	fs.Var(&methods, "method", "HTTP method to try (repeatable; default GET,POST)")
	fs.IntVar(&mutations, "mutations", 100, "mutated requests to send per path/method")
	fs.IntVar(&concurrency, "concurrency", 10, "parallel requests")
	fs.BoolVar(&intrusive, "intrusive", false, "enable intrusive mutations (write methods, traversal, injection payloads)")
	fs.IntVar(&timeout, "timeout", 10, "per-request timeout in seconds")
	addScanGateFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printFuzzHelp(fs) }, cliux.Options{
		Command: "fuzz",
		FlagSet: fs,
		Examples: []string{
			"stress-strike fuzz --target https://example.com --path /item/{id} --mutations 200",
		},
	})

	if strings.TrimSpace(target) == "" {
		usageFatal(fmt.Errorf("--target is required\n\nExample: stress-strike fuzz --target https://example.com --path /item/{id}"))
	}
	parsed, err := validateScanTarget(target)
	if err != nil {
		usageFatal(err)
	}
	normPaths := fuzzNormalizePaths(paths)
	if len(normPaths) == 0 {
		usageFatal(fmt.Errorf("--path is required (at least one endpoint path)\n\nExample: stress-strike fuzz --target https://example.com --path /item/{id}"))
	}
	tryMethods := []string(methods)
	if len(tryMethods) == 0 {
		tryMethods = []string{"GET", "POST"}
	}
	if mutations <= 0 {
		usageFatal(fmt.Errorf("--mutations must be positive, got %d", mutations))
	}
	if concurrency <= 0 {
		usageFatal(fmt.Errorf("--concurrency must be positive, got %d", concurrency))
	}
	if timeout <= 0 {
		usageFatal(fmt.Errorf("--timeout must be positive, got %d", timeout))
	}

	// Authorization gate: fuzz is an OpScan operation in the dashboard
	// (/api/fuzz/scan), so a named ticket is optional but the policy is still
	// enforced and the decision is recorded before a single byte is sent.
	enforceAuthz(authz.OpScan, []string{parsed.String()}, os.Args, sf.gate)

	scanWarning("fuzz")
	announceScanScope("fuzz", parsed, sf)
	timeoutDur := time.Duration(timeout) * time.Second
	gate, err := buildScanGuard(parsed, sf, intrusive, timeoutDur)
	if err != nil {
		usageFatal(err)
	}

	fuzzer, err := scanner.NewFuzzer(scanner.FuzzConfig{
		BaseURL:     parsed.String(),
		Paths:       normPaths,
		Methods:     tryMethods,
		Seed:        time.Now().UnixNano(),
		Mutations:   mutations,
		Concurrency: concurrency,
		Timeout:     timeoutDur,
		Intrusive:   intrusive,
	}, gate)
	if err != nil {
		fatal(err)
	}

	result := fuzzer.Run(context.Background())
	st := gate.Stats()
	printScanGateStats(st)

	if err := emitScanJSON(result, sf); err != nil {
		fatal(err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Printf("fuzz: %s\n", result.BaseURL)
	fmt.Printf("  paths:       %d\n", len(normPaths))
	fmt.Printf("  methods:     %s\n", strings.Join(tryMethods, ", "))
	fmt.Printf("  sent:        %d\n", result.Sent)
	fmt.Printf("  refused:     %d\n", result.Refused)
	fmt.Printf("  interesting: %d\n", result.Interesting)
	fmt.Printf("  seed:        %d\n", result.Seed)
	fmt.Printf("  scope:       %s\n", scanScopeLabel(parsed, sf))
	if note := scanGateNote(st); note != "" {
		fmt.Printf("  note:        %s\n", note)
	}
	for _, f := range result.Findings {
		fmt.Printf("  - [%s] %s %s -> %d (%s; %d bytes)\n",
			f.Mutation, f.Method, f.URL, f.StatusCode, f.Reason, f.BodyLen)
	}
	if len(result.Findings) == 0 {
		fmt.Println("  no interesting responses found")
	}
}

// fuzzNormalizePaths normalizes --path entries exactly like the dashboard's
// fuzzValidatePaths — root-relative, no scheme/host of its own, deduplicated —
// but WITHOUT the web control plane's 25-path cap: a CLI operator is not a
// browser click that must not pin a server goroutine.
func fuzzNormalizePaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || strings.Contains(p, "://") {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// printFuzzHelp renders `stress-strike fuzz --help`.
func printFuzzHelp(fs *flag.FlagSet) {
	w := os.Stderr
	fmt.Fprintf(w, "\n stress-strike fuzz — coverage-aware HTTP fuzzer\n\n")
	fmt.Fprintf(w, " USAGE\n")
	fmt.Fprintf(w, "   stress-strike fuzz --target https://example.com --path /item/{id} [flags]\n\n")
	fmt.Fprintf(w, " Honestly report what a fuzzing campaign touches: every request goes\n")
	fmt.Fprintf(w, " through the probe gate (scope, rate, budget, dry-run) and the\n")
	fmt.Fprintf(w, " authorization decision is recorded in the audit log.\n\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " FLAGS\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " EXAMPLES\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Fuzz two endpoints, 200 mutations each",
		"stress-strike fuzz --target https://example.com --path /search --path /item/{id} --mutations 200",
		"",
		"# Enable intrusive mutations (write methods, traversal, injection)",
		"stress-strike fuzz --target https://example.com --path /api/item --intrusive",
		"",
		"# Preview the policy without sending anything",
		"stress-strike fuzz --target example.com --path / --dry-run",
		"",
		"# Machine-readable output",
		"stress-strike fuzz --target https://example.com --path / --json --output-json fuzz.json",
	} {
		fmt.Fprintf(w, "\n   %s\n", e)
	}
	fmt.Fprintf(w, "\n")
}
