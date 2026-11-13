package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/cliux"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
)

// cmd_subdomain.go implements `Sift subdomain`: the CLI face of the
// dashboard's POST /api/subdomain/scan. It passively discovers subdomains from
// certificate transparency logs (crt.sh) and DNS records — no active probing of
// the discovered hostnames.
//
// The enumeration dials DNS and crt.sh directly, so it cannot route through the
// Guard. The Guard is still built to validate the policy knobs, and --dry-run
// skips the enumeration entirely. Unlike the dashboard, the CLI passes the bare
// hostname (not the full URL) to the scanner: EnumerateSubdomains matches
// `name == target || strings.HasSuffix(name, "."+target)`, which never matches a
// target that still carries a scheme, so the dashboard always reports zero
// subdomains.
func cmdSubdomain() {
	var target string
	sf := &scanFlags{}

	fs := flag.NewFlagSet("subdomain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&target, "target", "", "target domain or URL (required), e.g. https://example.com")
	addScanGateFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printSubdomainHelp(fs) }, cliux.Options{
		Command: "subdomain",
		FlagSet: fs,
		Examples: []string{
			"Sift subdomain --target https://example.com",
		},
	})

	if strings.TrimSpace(target) == "" {
		usageFatal(fmt.Errorf("--target is required\n\nExample: Sift subdomain --target https://example.com"))
	}
	parsed, err := validateScanTarget(target)
	if err != nil {
		usageFatal(err)
	}

	// Authorization gate: subdomain enumeration is an OpScan operation.
	enforceAuthz(authz.OpScan, []string{parsed.String()}, os.Args, sf.gate)

	scanWarning("subdomain")
	announceScanScope("subdomain", parsed, sf)

	// Built only to validate --allow/--rate/--budget; the DNS/crt.sh dials
	// bypass it.
	if _, err := buildScanGuard(parsed, sf, false, scanner.DefaultTimeout); err != nil {
		usageFatal(err)
	}
	hostname := parsed.Hostname()
	scanDirectDialNote("subdomain", hostname)

	if skip, err := scanDryRunSkip("subdomain", hostname, sf); err != nil {
		fatal(err)
	} else if skip {
		return
	}

	result := scanner.EnumerateSubdomains(context.Background(), hostname, nil)

	if err := emitScanDirectDialJSON("subdomain", hostname, result, sf); err != nil {
		fatal(err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Printf("subdomain: %s\n", result.Target)
	fmt.Printf("  found:    %d\n", result.Found)
	fmt.Printf("  resolved: %d\n", result.Resolved)
	fmt.Printf("  scope:    %s\n", scanScopeLabel(parsed, sf))
	for _, s := range result.Subdomains {
		ips := ""
		if len(s.IPs) > 0 {
			ips = " -> " + strings.Join(s.IPs, ", ")
		}
		fmt.Printf("  - %s [%s]%s\n", s.Name, s.Source, ips)
	}
	if result.Found == 0 {
		fmt.Println("  no subdomains discovered")
	}
}

// printSubdomainHelp renders `Sift subdomain --help`.
func printSubdomainHelp(fs *flag.FlagSet) {
	w := os.Stderr
	fmt.Fprintf(w, "\n Sift subdomain — passive subdomain enumeration\n\n")
	fmt.Fprintf(w, " USAGE\n")
	fmt.Fprintf(w, "   Sift subdomain --target https://example.com [flags]\n\n")
	fmt.Fprintf(w, " Passive discovery from certificate transparency logs (crt.sh) and DNS\n")
	fmt.Fprintf(w, " records, then local resolution of what it finds. No active probing of\n")
	fmt.Fprintf(w, " the discovered hostnames is performed.\n\n")
	fmt.Fprintf(w, " The enumeration dials DNS/crt.sh directly and bypasses the probe gate:\n")
	fmt.Fprintf(w, " scope/rate/budget are validated but not enforced on those lookups.\n")
	fmt.Fprintf(w, " Use --dry-run to see the intent without querying anything.\n\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " FLAGS\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " EXAMPLES\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Enumerate subdomains of a domain",
		"Sift subdomain --target https://example.com",
		"",
		"# Preview the policy without querying",
		"Sift subdomain --target example.com --dry-run",
		"",
		"# Machine-readable output",
		"Sift subdomain --target https://example.com --json --output-json subdomains.json",
	} {
		fmt.Fprintf(w, "\n   %s\n", e)
	}
	fmt.Fprintf(w, "\n")
}
