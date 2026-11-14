package main

// cmd_xray.go — opt-in host observability (Kernel-Level X-Ray MVP).
//
// "xray collect" samples aggregate host counters (Linux /proc) or Go runtime
// metrics (other platforms) into a JSONL artifact. "xray report" correlates
// those samples with external Sift signals and writes an explainable Markdown
// report. "xray capabilities" reports which evidence sources are available.
//
// Safety model: collection is refused unless the operator passes --allow, no
// eBPF program is ever loaded, no cgo is used, and no privileges are requested.
// The agent reads fixed /proc paths and aggregate counters only; it never reads
// per-process, per-connection, packet payload, or credential data.
//
// Exit status: 0 on success, 1 on invalid input or runtime failure.
//
// This command is not wired into main.go's dispatch yet; it is kept here with
// the exact name cmdXray so wiring is a small, separate change.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/hostxray"
)

func cmdXray() {
	if len(os.Args) < 3 {
		xrayUsage()
		exitProcess(1)
		return
	}
	switch os.Args[2] {
	case "collect":
		cmdXrayCollect()
	case "report":
		cmdXrayReport()
	case "capabilities":
		cmdXrayCapabilities()
	case "help", "-h", "--help":
		xrayUsage()
	default:
		fmt.Fprintf(os.Stderr, "error: unknown xray subcommand %q\n\n", os.Args[2])
		xrayUsage()
		exitProcess(1)
	}
}

func cmdXrayCollect() {
	fs := flag.NewFlagSet("xray collect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	interval := fs.Duration("interval", hostxray.DefaultInterval, "sampling interval (100ms..60s)")
	duration := fs.Duration("duration", hostxray.DefaultDuration, "collection duration")
	maxSamples := fs.Int("max-samples", 0, "stop after N samples (0 derives from --duration)")
	out := fs.String("out", "reports/xray.jsonl", "path to write JSONL samples")
	allow := fs.Bool("allow", false, "confirm opt-in, authorized host observation (required)")
	redact := fs.Bool("redact", true, "replace interface names with stable aliases in samples")

	if err := fs.Parse(os.Args[3:]); err != nil {
		xrayUsage()
		exitProcess(1)
		return
	}
	if fs.NArg() > 0 || strings.TrimSpace(*out) == "" {
		xrayUsage()
		exitProcess(1)
		return
	}
	if !*allow {
		fmt.Fprintln(os.Stderr, "error: xray collect is opt-in and requires explicit authorization: pass --allow")
		fmt.Fprintln(os.Stderr, "       the agent reads aggregate host counters only (no eBPF, no privileges, no process/packet/secret data)")
		exitProcess(1)
		return
	}

	opts := hostxray.Options{
		Interval:   *interval,
		Duration:   *duration,
		MaxSamples: *maxSamples,
		Redact:     *redact,
		OptIn:      *allow,
	}

	agent, err := hostxray.New(opts)
	if err != nil {
		fatal(err)
		return
	}
	defer func() { _ = agent.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	samples, err := agent.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		fatal(err)
		return
	}

	cleanOut := filepathClean(*out)
	if werr := hostxray.WriteJSONL(cleanOut, samples); werr != nil {
		fatal(werr)
		return
	}

	caps := agent.Capabilities()
	fmt.Printf("samples:   %d\n", len(samples))
	fmt.Printf("output:    %s\n", cleanOut)
	fmt.Printf("source:    %s\n", caps.Source)
	fmt.Printf("platform:  %s/%s\n", caps.OS, caps.Arch)
	if !caps.ProcAvailable && caps.OS == "linux" {
		fmt.Println("note:      /proc unavailable; kernel counters could not be read")
	}
	if caps.OS != "linux" {
		fmt.Println("note:      non-Linux host; samples contain Go runtime metrics of the Sift process, not kernel evidence")
	}
	fmt.Println("note:      aggregate-only, opt-in collection; no eBPF program loaded and no privileges requested")
}

func cmdXrayReport() {
	fs := flag.NewFlagSet("xray report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	input := fs.String("input", "", "path to JSONL samples from 'xray collect' (required)")
	signals := fs.String("signals", "", "path to a Sift-like signal file (JSON/JSONL) for correlation (required)")
	out := fs.String("out", "reports/xray-report.md", "path to write the Markdown report")
	window := fs.Duration("window", hostxray.DefaultCorrelateWindow, "correlation lookback window (1s..5m)")
	title := fs.String("title", "Sift Host X-Ray Report", "report title")

	if err := fs.Parse(os.Args[3:]); err != nil {
		xrayUsage()
		exitProcess(1)
		return
	}
	if fs.NArg() > 0 || strings.TrimSpace(*input) == "" || strings.TrimSpace(*signals) == "" {
		xrayUsage()
		exitProcess(1)
		return
	}

	samples, err := hostxray.LoadJSONL(filepathClean(*input))
	if err != nil {
		fatal(err)
		return
	}
	sigs, err := hostxray.LoadSignals(filepathClean(*signals))
	if err != nil {
		fatal(err)
		return
	}

	indicators := hostxray.Correlate(samples, sigs, hostxray.CorrelateOptions{Window: *window})
	caps := hostxray.DetectCapabilities()
	report := hostxray.Report{
		Title:        strings.TrimSpace(*title),
		GeneratedAt:  time.Now().UTC(),
		Capabilities: caps,
		Window:       *window,
		Samples:      samples,
		Signals:      sigs,
		Indicators:   indicators,
	}

	cleanOut := filepathClean(*out)
	if err := hostxray.WriteMarkdown(cleanOut, report); err != nil {
		fatal(err)
		return
	}

	fmt.Printf("report:     %s\n", cleanOut)
	fmt.Printf("samples:    %d\n", len(samples))
	fmt.Printf("signals:    %d\n", len(sigs))
	fmt.Printf("indicators: %d\n", len(indicators))
	fmt.Println("note:       indicators are correlated evidence, not causal findings")
}

func cmdXrayCapabilities() {
	fs := flag.NewFlagSet("xray capabilities", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	if err := fs.Parse(os.Args[3:]); err != nil {
		xrayUsage()
		exitProcess(1)
		return
	}
	if fs.NArg() > 0 {
		xrayUsage()
		exitProcess(1)
		return
	}

	caps := hostxray.DetectCapabilities()
	fmt.Println("Sift host x-ray capabilities")
	fmt.Println()
	fmt.Printf("platform:        %s/%s\n", caps.OS, caps.Arch)
	fmt.Printf("evidence source: %s\n", caps.Source)
	fmt.Printf("/proc mounted:   %t\n", caps.ProcAvailable)
	fmt.Printf("/proc/loadavg:   %t\n", caps.ProcLoadAvg)
	fmt.Printf("/proc/meminfo:   %t\n", caps.ProcMemInfo)
	fmt.Printf("/proc/net/dev:   %t\n", caps.ProcNetDev)
	fmt.Printf("/proc/stat:      %t\n", caps.ProcStat)
	fmt.Printf("/proc/pressure:  %t\n", caps.ProcPressure)
	fmt.Printf("BTF vmlinux:     %t\n", caps.BTFVMLinux)
	fmt.Printf("deep eBPF ready: %t (informational only; this build never loads eBPF programs)\n", caps.DeepTracingPossible)
	if len(caps.Notes) > 0 {
		fmt.Println()
		for _, note := range caps.Notes {
			fmt.Printf("- %s\n", note)
		}
	}
}

// filepathClean normalizes a user-supplied path for artifact I/O. The actual
// open is gated and justified in hostxray's writers/loaders as well.
func filepathClean(p string) string {
	return filepath.Clean(strings.TrimSpace(p))
}

func xrayUsage() {
	fmt.Fprint(os.Stderr, `Usage: Sift xray <subcommand> [flags]

Opt-in, aggregate-only host observability for correlating external Sift
signals with in-host evidence. No eBPF program is loaded, no cgo is used, and
no privileges are requested. On Linux the agent reads fixed /proc counters; on
other platforms it samples Go runtime metrics of the Sift process.

Subcommands:
  collect       Sample host/runtime metrics into JSONL (requires --allow)
  report        Correlate samples with Sift-like signals and write Markdown
  capabilities  Show available evidence sources and kernel capability facts

collect:
  Sift xray collect --allow --interval 2s --duration 30s --out reports/xray.jsonl

  --allow is required. Collection is refused without explicit opt-in.

report:
  Sift xray report --input reports/xray.jsonl --signals signals.json \
      --out reports/xray-report.md --window 5s

capabilities:
  Sift xray capabilities

Exit status: 0 success, 1 invalid input or runtime failure.
`)
}
