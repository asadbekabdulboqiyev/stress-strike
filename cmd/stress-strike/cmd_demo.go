package main

import (
	"flag"
	"fmt"
	"io"
	"net"
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

	listen := *addr
	if listen == "" {
		listen = "127.0.0.1:8090"
	}
	url := demoListenURL(listen)

	extra := []string{"-addr=" + strings.TrimPrefix(url, "http://")}
	if *protect {
		extra = append(extra, "-protect")
	}

	store := demostore.New(demostore.Options{URL: url, ExtraArgs: extra})

	// Signals are registered BEFORE Start: an early Ctrl+C (during the go
	// run compile window — up to 15s) must still tear the store down, or the
	// spawned process group would be orphaned when the CLI dies.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)

	type startResult struct {
		url     string
		already bool
		err     error
	}
	startCh := make(chan startResult, 1)
	go func() {
		u, already, err := store.Start()
		startCh <- startResult{url: u, already: already, err: err}
	}()

	var (
		startedURL string
		already    bool
	)
	select {
	case <-sig:
		fmt.Println("\n  Interrupted during startup — stopping demo store...")
		// Blocks until Start hands the mutex over (finishes or gives up),
		// then kills the spawned process group. Never leaves an orphan.
		_ = store.Stop()
		os.Exit(130)
	case res := <-startCh:
		if res.err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", res.err)
			os.Exit(1)
		}
		startedURL, already = res.url, res.already
	}

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  VoltStore demo — launched from stress-strike                  ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Store:      %s\n", startedURL)
	if already {
		fmt.Println("  Status:     already running (adopted — it was NOT restarted)")
		fmt.Printf("  Admin:      GET/POST %s/admin/protect  (live toggle — check real state here)\n", startedURL)
		fmt.Println()
		fmt.Println("  Press Ctrl+C to stop this command (the store stays up).")
	} else {
		fmt.Printf("  VeriGate:   %s\n", protectLabel(*protect))
		fmt.Printf("  Admin:      GET/POST %s/admin/protect  (live toggle)\n", startedURL)
		if *protect {
			fmt.Println()
			fmt.Println("  Attack it from another terminal:")
			fmt.Printf("    stress-strike run --url %s --users 300 --duration 10 --expect-error-rate 5\n", startedURL)
		}
		fmt.Println()
		fmt.Println("  Press Ctrl+C to stop the demo store.")
	}

	// Run in the foreground until Ctrl+C or the store exits on its own.
	// (For an adopted store, Done() never closes — only the signal fires.)
	select {
	case <-sig:
		if already {
			fmt.Println("\n  Store was already running — leaving it untouched.")
			return
		}
		fmt.Println("\n  Stopping demo store...")
		_ = store.Stop()
		fmt.Println("  Done.")
	case <-store.Done():
		fmt.Println("\n  [demo-store] process exited on its own.")
		os.Exit(1) // crash != clean shutdown; scripts must notice
	}
}

// demoListenURL normalizes the -addr flag into the URL used by the readiness
// probe and the banner. A bare port (":9090") or a wildcard host binds all
// interfaces, but the URL must point at loopback so both the probe and a
// browser actually work.
func demoListenURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://" + listen // not host:port — pass through (spawn fails later)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
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
