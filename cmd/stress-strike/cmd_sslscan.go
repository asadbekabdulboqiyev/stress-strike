package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// cmd_sslscan.go implements `stress-strike sslscan`: the CLI face of the
// dashboard's POST /api/sslscan. It performs a TLS handshake and reports the
// certificate (issuer, subject, validity window, SANs) plus protocol/cipher
// weaknesses.
//
// The handshake dials TLS directly, so it cannot route through the Guard. The
// Guard is still built to validate the policy knobs, and --dry-run skips the
// handshake so it never opens a socket.
func cmdSSLScan() {
	var target string
	sf := &scanFlags{}

	fs := flag.NewFlagSet("sslscan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&target, "target", "", "target host or URL (required), e.g. https://example.com")
	addScanGateFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printSSLScanHelp(fs) }, cliux.Options{
		Command: "sslscan",
		FlagSet: fs,
		Examples: []string{
			"stress-strike sslscan --target https://example.com",
		},
	})

	if strings.TrimSpace(target) == "" {
		usageFatal(fmt.Errorf("--target is required\n\nExample: stress-strike sslscan --target https://example.com"))
	}
	parsed, err := validateScanTarget(target)
	if err != nil {
		usageFatal(err)
	}

	// Authorization gate: a TLS inspection is an OpScan operation.
	enforceAuthz(authz.OpScan, []string{parsed.String()}, os.Args, sf.gate)

	scanWarning("sslscan")
	announceScanScope("sslscan", parsed, sf)

	// Built only to validate --allow/--rate/--budget; the TLS dial bypasses it.
	if _, err := buildScanGuard(parsed, sf, false, scanner.DefaultTimeout); err != nil {
		usageFatal(err)
	}

	// ScanSSL needs host:port; parsed.String() carries the scheme, which breaks
	// dialing. Use the explicit port when present, else 443 for https and 80 for
	// http — exactly like the dashboard.
	var scanTarget string
	if p := parsed.Port(); p != "" {
		scanTarget = net.JoinHostPort(parsed.Hostname(), p)
	} else if parsed.Scheme == "https" {
		scanTarget = net.JoinHostPort(parsed.Hostname(), "443")
	} else {
		scanTarget = net.JoinHostPort(parsed.Hostname(), "80")
	}
	scanDirectDialNote("sslscan", scanTarget)

	if skip, err := scanDryRunSkip("sslscan", scanTarget, sf); err != nil {
		fatal(err)
	} else if skip {
		return
	}

	result := scanner.ScanSSL(context.Background(), scanTarget)

	if err := emitScanDirectDialJSON("sslscan", scanTarget, result, sf); err != nil {
		fatal(err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Printf("sslscan: %s\n", result.Target)
	fmt.Printf("  valid:     %v\n", result.Valid)
	fmt.Printf("  expired:   %v\n", result.Expired)
	if result.Version != "" {
		fmt.Printf("  version:   %s\n", result.Version)
	}
	if result.Cipher != "" {
		fmt.Printf("  cipher:    %s\n", result.Cipher)
	}
	if result.Issuer != "" {
		fmt.Printf("  issuer:    %s\n", result.Issuer)
	}
	if result.Subject != "" {
		fmt.Printf("  subject:   %s\n", result.Subject)
	}
	if result.NotBefore != "" {
		fmt.Printf("  notBefore: %s\n", result.NotBefore)
	}
	if result.NotAfter != "" {
		fmt.Printf("  notAfter:  %s\n", result.NotAfter)
	}
	if len(result.SANs) > 0 {
		fmt.Printf("  sans:      %s\n", strings.Join(result.SANs, ", "))
	}
	fmt.Printf("  scope:     %s\n", scanScopeLabel(parsed, sf))
	for _, issue := range result.Issues {
		fmt.Printf("  - %s\n", issue)
	}
}

// printSSLScanHelp renders `stress-strike sslscan --help`.
func printSSLScanHelp(fs *flag.FlagSet) {
	w := os.Stderr
	fmt.Fprintf(w, "\n stress-strike sslscan — TLS certificate & configuration analyzer\n\n")
	fmt.Fprintf(w, " USAGE\n")
	fmt.Fprintf(w, "   stress-strike sslscan --target https://example.com [flags]\n\n")
	fmt.Fprintf(w, " Performs a TLS handshake and reports the certificate (issuer, subject,\n")
	fmt.Fprintf(w, " validity window, SANs) plus protocol and cipher weaknesses.\n\n")
	fmt.Fprintf(w, " The handshake dials TLS directly and bypasses the probe gate: scope/\n")
	fmt.Fprintf(w, " rate/budget are validated but not enforced on that connection. Use\n")
	fmt.Fprintf(w, " --dry-run to see the intent without connecting.\n\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " FLAGS\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " EXAMPLES\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Inspect a TLS endpoint",
		"stress-strike sslscan --target https://example.com",
		"",
		"# Use an explicit port",
		"stress-strike sslscan --target https://example.com:8443",
		"",
		"# Machine-readable output",
		"stress-strike sslscan --target https://example.com --json --output-json tls.json",
	} {
		fmt.Fprintf(w, "\n   %s\n", e)
	}
	fmt.Fprintf(w, "\n")
}
