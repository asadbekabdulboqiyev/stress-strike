package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// cmd_portscan.go implements `stress-strike portscan`: the CLI face of the
// dashboard's POST /api/portscan. It performs a TCP connect scan (with light
// banner grabbing) of a curated common-port list, or of an explicit --ports set.
//
// The scanner dials TCP directly. The dashboard still wires the Guard into
// ScanPorts (which ignores it internally); the CLI does the same so the policy
// is validated and the result shape matches. --dry-run skips the scan so it
// never opens a socket.
func cmdPortScan() {
	var (
		target   string
		portsCSV string
	)
	sf := &scanFlags{}

	fs := flag.NewFlagSet("portscan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&target, "target", "", "target host or URL (required), e.g. https://example.com")
	fs.StringVar(&portsCSV, "ports", "", "comma-separated ports to scan (default: built-in common list)")
	addScanGateFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printPortScanHelp(fs) }, cliux.Options{
		Command: "portscan",
		FlagSet: fs,
		Examples: []string{
			"stress-strike portscan --target https://example.com --ports 80,443,8080",
		},
	})

	if strings.TrimSpace(target) == "" {
		usageFatal(fmt.Errorf("--target is required\n\nExample: stress-strike portscan --target https://example.com"))
	}
	parsed, err := validateScanTarget(target)
	if err != nil {
		usageFatal(err)
	}
	ports, err := parsePortList(portsCSV)
	if err != nil {
		usageFatal(err)
	}

	// Authorization gate: port scanning is an OpScan operation.
	enforceAuthz(authz.OpScan, []string{parsed.String()}, os.Args, sf.gate)

	scanWarning("portscan")
	announceScanScope("portscan", parsed, sf)

	gate, err := buildScanGuard(parsed, sf, false, scanner.DefaultTimeout)
	if err != nil {
		usageFatal(err)
	}
	hostname := parsed.Hostname()
	scanDirectDialNote("portscan", hostname)

	if skip, err := scanDryRunSkip("portscan", hostname, sf); err != nil {
		fatal(err)
	} else if skip {
		return
	}

	result := scanner.ScanPorts(context.Background(), hostname, ports, gate)

	if err := emitScanDirectDialJSON("portscan", hostname, result, sf); err != nil {
		fatal(err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Printf("portscan: %s\n", result.Target)
	fmt.Printf("  open:    %d\n", result.Opened)
	fmt.Printf("  closed:  %d\n", result.Closed)
	fmt.Printf("  scope:   %s\n", scanScopeLabel(parsed, sf))
	for _, p := range result.Ports {
		svc := ""
		if p.Service != "" {
			svc = " (" + p.Service + ")"
		}
		banner := ""
		if p.Banner != "" {
			banner = " — " + oneLine(p.Banner, 80)
		}
		fmt.Printf("  - %d/tcp %s%s%s\n", p.Port, p.State, svc, banner)
	}
	if result.Opened == 0 {
		fmt.Println("  no open ports found")
	}
}

// parsePortList parses a comma-separated port list, rejecting out-of-range and
// non-numeric values and dropping duplicates while preserving order. An empty
// string returns nil, which makes the scanner use its built-in common list.
func parsePortList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	seen := make(map[int]bool)
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: must be a number 1-65535", part)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range 1-65535", p)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// oneLine collapses a banner to a single truncated line so a multi-line server
// response cannot wreck the summary layout.
func oneLine(s string, max int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if max > 0 && len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// printPortScanHelp renders `stress-strike portscan --help`.
func printPortScanHelp(fs *flag.FlagSet) {
	w := os.Stderr
	fmt.Fprintf(w, "\n stress-strike portscan — TCP port & service scanner\n\n")
	fmt.Fprintf(w, " USAGE\n")
	fmt.Fprintf(w, "   stress-strike portscan --target https://example.com [--ports 80,443]\n\n")
	fmt.Fprintf(w, " TCP connect scan with light banner grabbing over a curated common-port\n")
	fmt.Fprintf(w, " list, or an explicit --ports set.\n\n")
	fmt.Fprintf(w, " The scanner dials TCP directly and bypasses the probe gate: scope/rate/\n")
	fmt.Fprintf(w, " budget are validated but not enforced on those sockets. Use --dry-run to\n")
	fmt.Fprintf(w, " see the intent without opening a connection.\n\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " FLAGS\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " EXAMPLES\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Scan the built-in common ports",
		"stress-strike portscan --target https://example.com",
		"",
		"# Scan a specific set of ports",
		"stress-strike portscan --target example.com --ports 22,80,443,3306",
		"",
		"# Machine-readable output",
		"stress-strike portscan --target example.com --ports 80,443 --json",
	} {
		fmt.Fprintf(w, "\n   %s\n", e)
	}
	fmt.Fprintf(w, "\n")
}
