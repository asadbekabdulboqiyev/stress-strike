package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/demostore"
)

// cmdDemoStore launches the bundled VoltStore demo target straight from the
// stress-strike CLI. VeriGate protection is ON by default — the whole point
// of the demo — and can be disabled with -protect=false. The store runs in
// the foreground, like any server command, until Ctrl+C (SIGINT/SIGTERM).
//
// It reuses the same launcher as the web dashboard (internal/demostore), so
// the CLI and the dashboard agree on where the binary lives and how the
// process is supervised.
func cmdDemoStore() {
	fs := flag.NewFlagSet("demo-store", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // suppress raw Go flag noise; we render our own
	fs.Usage = func() {}     // usage dumps are handled explicitly below

	addr := fs.String("addr", "", `listen address (default "127.0.0.1:8090")`)
	protect := fs.Bool("protect", true, "enable VeriGate protection at startup (rate limit + proof-of-work + IP blocking)")

	// Friendly flag errors, consistent help, exit 2 on usage errors.
	cliux.Parse(fs, os.Args[2:], func() { printDemoStoreHelp(fs) }, cliux.Options{
		Command: "demo-store",
		FlagSet: fs,
		Examples: []string{
			"stress-strike demo-store",
			"stress-strike demo-store -protect=false",
		},
	})

	// Normalize the listen address into the probe/report URL. A bare port
	// (":9090") binds all interfaces; the readiness probe and the reported
	// URL then use loopback, which is always reachable.
	listen := *addr
	if listen == "" {
		listen = "127.0.0.1:8090"
	}
	url := "http://" + listen
	if strings.HasPrefix(listen, ":") {
		url = "http://127.0.0.1" + listen
	}

	extra := []string{"-addr=" + strings.TrimPrefix(url, "http://")}
	if *protect {
		extra = append(extra, "-protect")
	}

	store := demostore.New(demostore.Options{URL: url, ExtraArgs: extra})

	startedURL, already, err := store.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  VoltStore demo — launched from stress-strike                  ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Store:      %s\n", startedURL)
	fmt.Printf("  VeriGate:   %s\n", protectLabel(*protect))
	fmt.Printf("  Admin:      GET/POST %s/admin/protect  (live toggle)\n", startedURL)
	if *protect {
		fmt.Println()
		fmt.Println("  Attack it from another terminal:")
		fmt.Printf("    stress-strike run --url %s --users 300 --duration 10 --expect-error-rate 5\n", startedURL)
	}
	if already {
		fmt.Println()
		fmt.Println("  The store was already running — it was NOT restarted.")
		fmt.Println("  Press Ctrl+C to stop this command (the store stays up).")
	} else {
		fmt.Println()
		fmt.Println("  Press Ctrl+C to stop the demo store.")
	}

	// Run in the foreground until Ctrl+C or the store exits on its own.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
		fmt.Println("\n  Stopping demo store...")
		_ = store.Stop()
		if !already {
			fmt.Println("  Done.")
		}
	case <-store.Done():
		fmt.Println("\n  [demo-store] process exited on its own.")
	}
}

// protectLabel renders the VeriGate banner state.
func protectLabel(on bool) string {
	if on {
		return "ON  (rate limit + proof-of-work challenge + IP blocking)"
	}
	return "OFF (open target — enable with -protect)"
}

// printDemoStoreHelp renders the demo-store command's flag help.
func printDemoStoreHelp(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `
stress-strike demo-store — launch the bundled VoltStore demo target

 Launches the realistic e-commerce demo site (VoltStore) with VeriGate
 protection, exactly like the one-click button in the web dashboard.
 The store runs in the foreground until Ctrl+C.

 Examples:
   # Protected demo (default)
   stress-strike demo-store

   # Open target, custom port, attackable immediately
   stress-strike demo-store -protect=false -addr 127.0.0.1:9090

 Flags:
`)
	cliux.PrintFlagList(os.Stderr, fs)
	fmt.Fprintf(os.Stderr, `
 The VeriGate admin plane lives at <store-url>/admin — toggle protection
 live, watch rate-limit/challenge counters, or reset blocks.

 Build the store binary with:  make build   (bin/demo-store)
`)
}
