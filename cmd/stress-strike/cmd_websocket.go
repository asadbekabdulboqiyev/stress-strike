package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// cmd_websocket.go implements `stress-strike websocket`: the CLI face of the
// dashboard's POST /api/websocket/scan. It connects to a WebSocket endpoint
// (ws:// or wss://) and reports structural weaknesses — missing origin
// validation, absent subprotocol negotiation, whether the server answers an
// unsolicited probe.
//
// Unlike the other scanners, the connect is performed by the gorilla/websocket
// dialer, which does its own TLS/TCP and cannot be routed through the probe
// gate. The guard's scope check also only accepts http/https and would refuse a
// ws:// upgrade, so a nil Requester is passed (mirroring the dashboard). The
// Guard is still constructed to validate the policy knobs, and --dry-run skips
// the dial entirely so a dry run never opens a socket.
func cmdWebSocket() {
	var wsURL string
	sf := &scanFlags{}

	fs := flag.NewFlagSet("websocket", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&wsURL, "url", "", "WebSocket endpoint URL (required), e.g. wss://example.com/socket")
	addScanGateFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printWebSocketHelp(fs) }, cliux.Options{
		Command: "websocket",
		FlagSet: fs,
		Examples: []string{
			"stress-strike websocket --url wss://example.com/socket",
		},
	})

	raw := strings.TrimSpace(wsURL)
	if raw == "" {
		usageFatal(fmt.Errorf("--url is required\n\nExample: stress-strike websocket --url wss://example.com/socket"))
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		usageFatal(fmt.Errorf("invalid WebSocket URL %q (expected ws:// or wss://host/path)", raw))
	}
	if parsed.Scheme != "ws" && parsed.Scheme != "wss" {
		usageFatal(fmt.Errorf("WebSocket URL must use ws:// or wss://, got %q", parsed.Scheme))
	}

	// Authorization gate: websocket is an OpScan operation, like the dashboard's
	// /api/websocket/scan. A ws:// URL classifies fine (authz parses the host).
	enforceAuthz(authz.OpScan, []string{raw}, os.Args, sf.gate)

	scanWarning("websocket")
	announceScanScope("websocket", parsed, sf)

	// Built only to validate --allow/--rate/--budget; the dial bypasses it.
	if _, err := buildScanGuard(parsed, sf, false, scanner.DefaultTimeout); err != nil {
		usageFatal(err)
	}
	scanDirectDialNote("websocket", raw)

	if skip, err := scanDryRunSkip("websocket", raw, sf); err != nil {
		fatal(err)
	} else if skip {
		return
	}

	result := scanner.TestWebSocket(context.Background(), raw, nil)

	if err := emitScanDirectDialJSON("websocket", raw, result, sf); err != nil {
		fatal(err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Printf("websocket: %s\n", result.URL)
	fmt.Printf("  connected:   %v\n", result.Connected)
	if result.Subprotocol != "" {
		fmt.Printf("  subprotocol: %s\n", result.Subprotocol)
	}
	fmt.Printf("  messages:    %d\n", result.Messages)
	fmt.Printf("  scope:       %s\n", scanScopeLabel(parsed, sf))
	for _, issue := range result.Issues {
		fmt.Printf("  - %s\n", issue)
	}
}

// printWebSocketHelp renders `stress-strike websocket --help`.
func printWebSocketHelp(fs *flag.FlagSet) {
	w := os.Stderr
	fmt.Fprintf(w, "\n stress-strike websocket — WebSocket security tester\n\n")
	fmt.Fprintf(w, " USAGE\n")
	fmt.Fprintf(w, "   stress-strike websocket --url wss://example.com/socket [flags]\n\n")
	fmt.Fprintf(w, " Connects without an Origin header and reports structural weaknesses:\n")
	fmt.Fprintf(w, " missing origin validation, absent subprotocol negotiation, and whether\n")
	fmt.Fprintf(w, " the server answers an unsolicited probe.\n\n")
	fmt.Fprintf(w, " The dial is performed by the WebSocket client and bypasses the probe\n")
	fmt.Fprintf(w, " gate: scope/rate/budget are validated but not enforced on the socket.\n")
	fmt.Fprintf(w, " Use --dry-run to see the intent without opening a connection.\n\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " FLAGS\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " EXAMPLES\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Test a WebSocket endpoint",
		"stress-strike websocket --url wss://example.com/socket",
		"",
		"# Preview the policy without connecting",
		"stress-strike websocket --url wss://example.com/socket --dry-run",
		"",
		"# Machine-readable output",
		"stress-strike websocket --url wss://example.com/socket --json",
	} {
		fmt.Fprintf(w, "\n   %s\n", e)
	}
	fmt.Fprintf(w, "\n")
}
