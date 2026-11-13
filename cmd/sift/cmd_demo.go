package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/asadbekabdulboqiyev/sift/internal/cliux"
	"github.com/asadbekabdulboqiyev/sift/internal/demostore"
)

// cmdDemoStore launches the bundled VoltStore demo target straight from the
// Sift CLI. VeriGate protection is ON by default — the whole point
// of the demo — and can be disabled with -protect=false. The store runs in
// the foreground, like any server command, until Ctrl+C (SIGINT/SIGTERM).
//
// It reuses the same launcher as the web dashboard (internal/demostore), so
// the CLI and the dashboard agree on where the binary lives and how the
// process is supervised.
//
// Two subcommands mirror the dashboard's thin control-plane wrappers:
//
//	demo-store status   GET  /api/demo-store/status
//	demo-store stop     POST /api/demo-store/stop
func cmdDemoStore() {
	// Intercept the subcommands before the flag parse: otherwise "status" /
	// "stop" would be ignored positionals and the store would launch in the
	// foreground. The no-subcommand path is unchanged.
	if len(os.Args) > 2 {
		switch os.Args[2] {
		case "status":
			cmdDemoStoreStatus()
			return
		case "stop":
			cmdDemoStoreStop()
			return
		}
	}

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
			"Sift demo-store",
			"Sift demo-store -protect=false",
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
		exitProcess(130)
	case res := <-startCh:
		if res.err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", res.err)
			exitProcess(1)
		}
		startedURL, already = res.url, res.already
	}

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  VoltStore demo — launched from Sift                  ║")
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
			fmt.Printf("    Sift run --url %s --users 300 --duration 10 --expect-error-rate 5\n", startedURL)
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
		exitProcess(1) // crash != clean shutdown; scripts must notice
	}
}

// cmdDemoStoreStatus reports whether the bundled VoltStore demo is listening —
// the CLI twin of the dashboard's GET /api/demo-store/status. It creates a
// fresh supervisor, so `managed` is always false here: only the process that
// spawned the store can claim to manage it. That is reported honestly rather
// than guessed from the port being open.
func cmdDemoStoreStatus() {
	var (
		urlStr string
		asJSON bool
	)
	fs := flag.NewFlagSet("demo-store status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&urlStr, "url", demostore.DefaultURL, "demo store URL to probe")
	fs.BoolVar(&asJSON, "json", false, "print the status as JSON")

	cliux.Parse(fs, os.Args[3:], func() { printDemoStoreStatusHelp(fs) }, cliux.Options{
		Command: "demo-store status",
		FlagSet: fs,
		Examples: []string{
			"Sift demo-store status",
		},
	})

	status := demostore.New(demostore.Options{URL: urlStr}).Status()

	if asJSON {
		data, err := json.MarshalIndent(status, "", "  ")
		if err != nil {
			fatal(err)
		}
		fmt.Println(string(data))
		return
	}

	fmt.Printf("demo-store: %s\n", status["url"])
	fmt.Printf("  running:    %v\n", status["running"])
	fmt.Printf("  managed:    %v\n", status["managed"])
	fmt.Printf("  protection: %v\n", status["protection"])
	if running, _ := status["running"].(bool); running {
		if managed, _ := status["managed"].(bool); !managed {
			fmt.Println("  note:       running, but not spawned by this process — a store is")
			fmt.Println("              only 'managed' by the process that launched it.")
		}
	}
}

// cmdDemoStoreStop stops the bundled VoltStore demo — the CLI twin of the
// dashboard's POST /api/demo-store/stop. demostore only kills a process its own
// supervisor spawned, and a fresh CLI process has spawned nothing, so from a
// standalone invocation this is an honest no-op: it reports the state and never
// kills a store it did not launch (mirrors TestDemoStoreStopNoopWhenNotManaged).
func cmdDemoStoreStop() {
	var urlStr string
	fs := flag.NewFlagSet("demo-store stop", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&urlStr, "url", demostore.DefaultURL, "demo store URL to stop")

	cliux.Parse(fs, os.Args[3:], func() { printDemoStoreStopHelp(fs) }, cliux.Options{
		Command: "demo-store stop",
		FlagSet: fs,
		Examples: []string{
			"Sift demo-store stop",
		},
	})

	store := demostore.New(demostore.Options{URL: urlStr})
	status := store.Status()
	if err := store.Stop(); err != nil {
		fatal(err)
	}

	if running, _ := status["running"].(bool); running {
		fmt.Printf("demo-store: nothing to stop — a store is listening at %s but this\n", status["url"])
		fmt.Println("            process did not launch it, so it is left running.")
		fmt.Println("            Stop it where it was started: Ctrl+C in that terminal, or")
		fmt.Println("            POST /api/demo-store/stop from the dashboard that launched it.")
		return
	}
	fmt.Printf("demo-store: nothing to stop — no store is listening at %s\n", status["url"])
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
Sift demo-store — launch the bundled VoltStore demo target

 Launches the realistic e-commerce demo site (VoltStore) with VeriGate
 protection, exactly like the one-click button in the web dashboard.
 The store runs in the foreground until Ctrl+C.

 Examples:
   # Protected demo (default)
   Sift demo-store

   # Open target, custom port, attackable immediately
   Sift demo-store -protect=false -addr 127.0.0.1:9090

 Flags:
`)
	cliux.PrintFlagList(os.Stderr, fs)
	fmt.Fprintf(os.Stderr, `
 The VeriGate admin plane lives at <store-url>/admin — toggle protection
 live, watch rate-limit/challenge counters, or reset blocks.

 Build the store binary with:  make build   (bin/demo-store)
`)
}

// printDemoStoreStatusHelp renders `Sift demo-store status --help`.
func printDemoStoreStatusHelp(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `
Sift demo-store status — report whether the VoltStore demo is up

 Probes the demo store address and reports running / managed / protection,
 like the dashboard's status endpoint. "managed" is false from a fresh CLI
 process: only the process that spawned the store manages it.

 Flags:
`)
	cliux.PrintFlagList(os.Stderr, fs)
	fmt.Fprintf(os.Stderr, `
 Examples:
   Sift demo-store status
   Sift demo-store status --json
`)
}

// printDemoStoreStopHelp renders `Sift demo-store stop --help`.
func printDemoStoreStopHelp(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `
Sift demo-store stop — stop the VoltStore demo this process launched

 The supervisor only terminates a store it spawned itself. From a standalone
 CLI invocation nothing is managed, so this reports the state and leaves any
 running store untouched (stop it where it was started).

 Flags:
`)
	cliux.PrintFlagList(os.Stderr, fs)
	fmt.Fprintf(os.Stderr, `
 Examples:
   Sift demo-store stop
`)
}
