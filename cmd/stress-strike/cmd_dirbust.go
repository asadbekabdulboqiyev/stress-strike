package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// cmd_dirbust.go implements `stress-strike dirbust`: the CLI face of the
// dashboard's POST /api/dirbust. It guesses common/sensitive paths on a web
// server and reports the ones that do not answer 404.
//
// The dashboard endpoint hardcodes the scope to the target host and offers no
// Allow/AllowAll/dry-run knobs. The CLI honors the full uniform gate (--allow,
// --allow-all, --dry-run, --rate, --budget) because an operator who learned
// those flags on `pentest` expects them everywhere.
func cmdDirBust() {
	var (
		target string
		paths  stringListFlags
	)
	sf := &scanFlags{}

	fs := flag.NewFlagSet("dirbust", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&target, "target", "", "target URL (required), e.g. https://example.com")
	fs.Var(&paths, "path", "path to probe (repeatable; default: built-in wordlist)")
	addScanGateFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printDirBustHelp(fs) }, cliux.Options{
		Command: "dirbust",
		FlagSet: fs,
		Examples: []string{
			"stress-strike dirbust --target https://example.com",
		},
	})

	if target == "" {
		usageFatal(fmt.Errorf("--target is required\n\nExample: stress-strike dirbust --target https://example.com"))
	}
	parsed, err := validateScanTarget(target)
	if err != nil {
		usageFatal(err)
	}

	// Authorization gate: dirbust is an OpScan operation, like the dashboard's
	// /api/dirbust. The refusal is recorded before any probe is sent.
	enforceAuthz(authz.OpScan, []string{parsed.String()}, os.Args, sf.gate)

	scanWarning("dirbust")
	announceScanScope("dirbust", parsed, sf)

	gate, err := buildScanGuard(parsed, sf, false, scanner.DefaultTimeout)
	if err != nil {
		usageFatal(err)
	}

	result := scanner.DirBust(context.Background(), parsed.String(), []string(paths), gate)
	st := gate.Stats()
	printScanGateStats(st)

	if err := emitScanJSON(result, sf); err != nil {
		fatal(err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Printf("dirbust: %s\n", result.Target)
	fmt.Printf("  found:  %d\n", result.Found)
	fmt.Printf("  scope:  %s\n", scanScopeLabel(parsed, sf))
	if note := scanGateNote(st); note != "" {
		fmt.Printf("  note:   %s\n", note)
	}
	for _, e := range result.Entries {
		title := ""
		if e.Title != "" {
			title = " — " + e.Title
		}
		fmt.Printf("  - %d %s (%d bytes)%s\n", e.StatusCode, e.URL, e.Size, title)
	}
	if result.Found == 0 {
		fmt.Println("  no paths discovered")
	}
}

// printDirBustHelp renders `stress-strike dirbust --help`.
func printDirBustHelp(fs *flag.FlagSet) {
	w := os.Stderr
	fmt.Fprintf(w, "\n stress-strike dirbust — directory/file brute-forcer\n\n")
	fmt.Fprintf(w, " USAGE\n")
	fmt.Fprintf(w, "   stress-strike dirbust --target https://example.com [flags]\n\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " FLAGS\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " EXAMPLES\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Brute-force the built-in wordlist",
		"stress-strike dirbust --target https://example.com",
		"",
		"# Probe specific paths only",
		"stress-strike dirbust --target https://example.com --path /admin --path /.env",
		"",
		"# Machine-readable output",
		"stress-strike dirbust --target https://example.com --json --output-json dirbust.json",
	} {
		fmt.Fprintf(w, "\n   %s\n", e)
	}
	fmt.Fprintf(w, "\n")
}
