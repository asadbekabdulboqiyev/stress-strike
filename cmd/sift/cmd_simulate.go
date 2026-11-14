package main

// cmd_simulate.go — digital twin / capacity simulation.
//
// `simulate fit` turns a completed Sift report into a versioned capacity model
// (twin-model.json). `simulate run` answers one what-if question against that
// model. `simulate compare` runs the three built-in scenarios (best, likely,
// worst) and prints a comparison table. Every command writes JSON artifacts plus
// a Markdown report that restates the estimate-not-guarantee caveat.
//
//	exit status
//	  0   the command succeeded
//	  1   invalid input, an unreadable artifact, or the simulation failed
//	  3   the estimated SLA breach probability exceeded --fail-on-breach-prob
//	      (the gate is disabled when the flag is 0)
//
// The exit-3 gate writes the artifacts before exiting, so CI keeps the evidence
// that justified the failure.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/asadbekabdulboqiyev/sift/internal/report"
	"github.com/asadbekabdulboqiyev/sift/internal/twin"
)

const defaultTwinOutDir = "reports/twin"

// cmdSimulate dispatches: Sift simulate <fit|run|compare> [flags].
func cmdSimulate() {
	if len(os.Args) < 3 {
		simulateUsage()
		exitProcess(1)
	}
	switch os.Args[2] {
	case "fit":
		simulateFit(os.Args[3:])
	case "run":
		simulateRun(os.Args[3:])
	case "compare":
		simulateCompare(os.Args[3:])
	default:
		simulateUsage()
		exitProcess(1)
	}
}

// simulateFit implements: Sift simulate fit --report <path> --out <dir>.
func simulateFit(args []string) {
	fs := flag.NewFlagSet("simulate fit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reportPath := fs.String("report", "", "path to a Sift report JSON (required)")
	outDir := fs.String("out", defaultTwinOutDir, "directory for twin-model.json")
	targetP99 := fs.Float64("target-p99-ms", 0, "latency objective used for capacity headroom (0 = documented default)")

	if err := fs.Parse(args); err != nil {
		simulateUsage()
		exitProcess(1)
	}
	if strings.TrimSpace(*reportPath) == "" || fs.NArg() > 0 {
		simulateUsage()
		exitProcess(1)
	}
	if *targetP99 < 0 {
		fatal(fmt.Errorf("simulate fit: --target-p99-ms must not be negative, got %v", *targetP99))
	}

	rep, err := report.LoadReport(*reportPath)
	if err != nil {
		fatal(fmt.Errorf("simulate fit: load report: %w", err))
	}
	model, err := twin.Fit(*rep, twin.FitOptions{TargetP99MS: *targetP99})
	if err != nil {
		fatal(fmt.Errorf("simulate fit: %w", err))
	}
	path, err := twin.WriteModel(*outDir, model)
	if err != nil {
		fatal(fmt.Errorf("simulate fit: %w", err))
	}

	fmt.Printf("model written: %s\n", path)
	fmt.Printf("  source report:     %s (%s, %s)\n",
		fallback(model.Source.ReportName, "unnamed"),
		fallback(model.Source.LoadProfile, "profile n/a"),
		formatSeconds(model.Source.DurationSeconds))
	fmt.Printf("  observed workload: %.2f rps, %.2f concurrent, %.3f%% errors\n",
		model.Workload.RPS, model.Workload.Concurrency, model.Workload.ErrorRatePct)
	fmt.Printf("  baseline latency:  p50 %.2f ms, p95 %.2f ms, p99 %.2f ms\n",
		model.Curve.Baseline.P50MS, model.Curve.Baseline.P95MS, model.Curve.Baseline.P99MS)
	fmt.Printf("  capacity estimate: %.2f rps (range %.2f - %.2f, +/-%.1f%%)\n",
		model.Curve.CapacityRPS, model.Curve.CapacityLowRPS, model.Curve.CapacityHighRPS,
		model.Curve.CapacityRelativeUncertainty*100)
	fmt.Printf("  confidence:        %s\n", model.Confidence)
	for _, note := range model.Calibration.Notes {
		fmt.Printf("  note: %s\n", note)
	}
}

// simulateRun implements: Sift simulate run --model <path> --scenario
// best|likely|worst [--rps N | --users N] [flags].
func simulateRun(args []string) {
	fs := flag.NewFlagSet("simulate run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	modelPath := fs.String("model", "", "path to twin-model.json (required)")
	preset := fs.String("scenario", "", "scenario preset: best|likely|worst (required)")
	rps := fs.Float64("rps", 0, "open-loop target rps (overrides the preset)")
	users := fs.Float64("users", 0, "closed-loop target users (overrides the preset)")
	duration := fs.Float64("duration", 0, "scenario duration in seconds (0 = preset)")
	slaP99 := fs.Float64("sla-p99-ms", 0, "p99 latency objective in ms (0 = preset)")
	maxErr := fs.Float64("max-error-rate", 0, "error-rate objective in percent (0 = disabled)")
	iterations := fs.Int("iterations", 0, "Monte Carlo iterations (0 = preset)")
	seed := fs.Int64("seed", 42, "PRNG seed; the same seed reproduces the result exactly")
	ramp := fs.Float64("ramp", -1, "ramp to target in seconds (-1 = preset, 0 = immediate step)")
	outDir := fs.String("out", defaultTwinOutDir, "directory for artifacts")
	failOn := fs.Float64("fail-on-breach-prob", 0, "exit 3 when the breach probability exceeds this fraction (0 = disabled)")

	if err := fs.Parse(args); err != nil {
		simulateUsage()
		exitProcess(1)
	}
	if strings.TrimSpace(*modelPath) == "" || strings.TrimSpace(*preset) == "" || fs.NArg() > 0 {
		simulateUsage()
		exitProcess(1)
	}
	if *rps > 0 && *users > 0 {
		fatal(fmt.Errorf("simulate run: --rps and --users are mutually exclusive"))
	}
	if *rps < 0 || *users < 0 || *duration < 0 || *slaP99 < 0 || *maxErr < 0 || *iterations < 0 {
		fatal(fmt.Errorf("simulate run: numeric flags must not be negative"))
	}
	if *failOn < 0 || *failOn > 1 {
		fatal(fmt.Errorf("simulate run: --fail-on-breach-prob must be in [0,1], got %v", *failOn))
	}

	model, err := twin.LoadModel(*modelPath)
	if err != nil {
		fatal(fmt.Errorf("simulate run: %w", err))
	}
	sc, err := twin.Preset(*preset, model)
	if err != nil {
		fatal(fmt.Errorf("simulate run: %w", err))
	}
	switch {
	case *rps > 0:
		sc.Mode = twin.LoopOpen
		sc.TargetRPS = *rps
		sc.TargetUsers = 0
	case *users > 0:
		sc.Mode = twin.LoopClosed
		sc.TargetUsers = *users
		sc.TargetRPS = 0
	}
	if *duration > 0 {
		sc.DurationSeconds = *duration
	}
	if *slaP99 > 0 {
		sc.SLAP99MS = *slaP99
	}
	if *maxErr > 0 {
		sc.MaxErrorRatePct = *maxErr
	}
	if *iterations > 0 {
		sc.Iterations = *iterations
	}
	applyRamp(&sc, *ramp)

	res, err := twin.Simulate(model, sc, *seed)
	if err != nil {
		fatal(fmt.Errorf("simulate run: %w", err))
	}
	results := map[string]twin.Result{res.Scenario.Name: res}
	paths, err := twin.WriteArtifacts(*outDir, model, results)
	if err != nil {
		fatal(fmt.Errorf("simulate run: %w", err))
	}

	printSimulation(res)
	fmt.Printf("  model:             %s\n", paths.ModelPath)
	for _, art := range paths.SimulationPaths {
		fmt.Printf("  result:            %s\n", art.Path)
	}
	fmt.Printf("  report:            %s\n", paths.ReportPath)
	fmt.Printf("\nNote: these are model-based estimates, not guarantees.\n")

	if *failOn > 0 && res.Summary.SLAProbabilityBreach > *failOn {
		fmt.Fprintf(os.Stderr, "simulate run: breach probability %.1f%% exceeds --fail-on-breach-prob %.1f%%\n",
			res.Summary.SLAProbabilityBreach*100, *failOn*100)
		exitProcess(3)
	}
}

// simulateCompare implements: Sift simulate compare --model <path> --out <dir>.
func simulateCompare(args []string) {
	fs := flag.NewFlagSet("simulate compare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	modelPath := fs.String("model", "", "path to twin-model.json (required)")
	duration := fs.Float64("duration", 0, "scenario duration in seconds (0 = preset)")
	slaP99 := fs.Float64("sla-p99-ms", 0, "p99 latency objective in ms (0 = preset)")
	maxErr := fs.Float64("max-error-rate", 0, "error-rate objective in percent (0 = disabled)")
	iterations := fs.Int("iterations", 0, "Monte Carlo iterations (0 = preset)")
	seed := fs.Int64("seed", 42, "PRNG seed shared by all three scenarios")
	ramp := fs.Float64("ramp", -1, "ramp to target in seconds (-1 = preset, 0 = immediate step)")
	outDir := fs.String("out", defaultTwinOutDir, "directory for artifacts")
	failOn := fs.Float64("fail-on-breach-prob", 0, "exit 3 when any breach probability exceeds this fraction (0 = disabled)")

	if err := fs.Parse(args); err != nil {
		simulateUsage()
		exitProcess(1)
	}
	if strings.TrimSpace(*modelPath) == "" || fs.NArg() > 0 {
		simulateUsage()
		exitProcess(1)
	}
	if *duration < 0 || *slaP99 < 0 || *maxErr < 0 || *iterations < 0 {
		fatal(fmt.Errorf("simulate compare: numeric flags must not be negative"))
	}
	if *failOn < 0 || *failOn > 1 {
		fatal(fmt.Errorf("simulate compare: --fail-on-breach-prob must be in [0,1], got %v", *failOn))
	}

	model, err := twin.LoadModel(*modelPath)
	if err != nil {
		fatal(fmt.Errorf("simulate compare: %w", err))
	}

	results := make(map[string]twin.Result, len(twin.PresetNames()))
	// Every scenario shares one seed: common random numbers keep capacity and
	// noise draws aligned, so the comparison isolates the load change.
	for _, name := range twin.PresetNames() {
		sc, presetErr := twin.Preset(name, model)
		if presetErr != nil {
			fatal(fmt.Errorf("simulate compare: %w", presetErr))
		}
		if *duration > 0 {
			sc.DurationSeconds = *duration
		}
		if *slaP99 > 0 {
			sc.SLAP99MS = *slaP99
		}
		if *maxErr > 0 {
			sc.MaxErrorRatePct = *maxErr
		}
		if *iterations > 0 {
			sc.Iterations = *iterations
		}
		applyRamp(&sc, *ramp)
		res, simErr := twin.Simulate(model, sc, *seed)
		if simErr != nil {
			fatal(fmt.Errorf("simulate compare (%s): %w", name, simErr))
		}
		results[name] = res
	}

	paths, err := twin.WriteArtifacts(*outDir, model, results)
	if err != nil {
		fatal(fmt.Errorf("simulate compare: %w", err))
	}

	fmt.Printf("capacity model: %.2f rps (%.2f - %.2f, confidence %s)\n\n",
		model.Curve.CapacityRPS, model.Curve.CapacityLowRPS, model.Curve.CapacityHighRPS, model.Confidence)

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SCENARIO\tLOOP\tTARGET\tP99 P50\tP99 P95\tBREACH\tSATURATION\tRISK")
	for _, name := range twin.PresetNames() {
		res := results[name]
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.2f ms\t%.2f ms\t%.1f%%\t%s\t%s\n",
			name, res.Scenario.Mode, scenarioTarget(res.Scenario),
			res.Summary.P99MS.P50, res.Summary.P99MS.P95,
			res.Summary.SLAProbabilityBreach*100,
			formatSaturation(res.Summary), res.Summary.RiskLevel)
	}
	if err := tw.Flush(); err != nil {
		fatal(fmt.Errorf("simulate compare: write table: %w", err))
	}

	fmt.Printf("\nmodel:  %s\nreport: %s\n", paths.ModelPath, paths.ReportPath)
	for _, art := range paths.SimulationPaths {
		fmt.Printf("result: %s\n", art.Path)
	}
	fmt.Printf("\nNote: these are model-based estimates, not guarantees.\n")

	if *failOn > 0 {
		worst := 0.0
		worstName := ""
		for _, name := range twin.PresetNames() {
			if res := results[name]; res.Summary.SLAProbabilityBreach > worst {
				worst = res.Summary.SLAProbabilityBreach
				worstName = name
			}
		}
		if worst > *failOn {
			fmt.Fprintf(os.Stderr, "simulate compare: scenario %q breach probability %.1f%% exceeds --fail-on-breach-prob %.1f%%\n",
				worstName, worst*100, *failOn*100)
			exitProcess(3)
		}
	}
}

// applyRamp resolves the --ramp flag. A negative value keeps the preset ramp,
// but a preset ramp longer than a shortened horizon is clamped instead of
// failing: shortening --duration should not require re-specifying the ramp.
func applyRamp(sc *twin.Scenario, ramp float64) {
	switch {
	case ramp >= 0:
		sc.RampSeconds = ramp
	case sc.RampSeconds > sc.DurationSeconds:
		sc.RampSeconds = sc.DurationSeconds
	}
}

// printSimulation renders a single scenario result.
func printSimulation(res twin.Result) {
	fmt.Printf("scenario %s (%s loop)\n", res.Scenario.Name, res.Scenario.Mode)
	fmt.Printf("  target load:       %s\n", scenarioTarget(res.Scenario))
	fmt.Printf("  horizon:           %s, %d iterations, seed %d\n",
		formatSeconds(res.Scenario.DurationSeconds), res.Scenario.Iterations, res.Scenario.Seed)
	if res.Scenario.SLAP99MS > 0 {
		fmt.Printf("  SLA p99:           <= %.2f ms\n", res.Scenario.SLAP99MS)
	}
	if res.Scenario.MaxErrorRatePct > 0 {
		fmt.Printf("  SLA error rate:    <= %.2f%%\n", res.Scenario.MaxErrorRatePct)
	}
	fmt.Printf("  achieved rps:      median %.2f (p95 %.2f)\n", res.Summary.AchievedRPS.P50, res.Summary.AchievedRPS.P95)
	fmt.Printf("  utilisation:       median %.3f (p95 %.3f)\n", res.Summary.Utilization.P50, res.Summary.Utilization.P95)
	fmt.Printf("  predicted p99:     median %.2f ms, p95 %.2f ms\n", res.Summary.P99MS.P50, res.Summary.P99MS.P95)
	fmt.Printf("  predicted errors:  median %.3f%%, p95 %.3f%%\n", res.Summary.ErrorRatePct.P50, res.Summary.ErrorRatePct.P95)
	fmt.Printf("  breach probability: %.1f%% (latency %.1f%%, errors %.1f%%), risk %s\n",
		res.Summary.SLAProbabilityBreach*100, res.Summary.P99BreachProbability*100,
		res.Summary.ErrorBreachProbability*100, res.Summary.RiskLevel)
	if res.Summary.PredictedSaturationSeconds != nil {
		fmt.Printf("  saturation:        %s into the ramp (in %.1f%% of draws)\n",
			formatSeconds(*res.Summary.PredictedSaturationSeconds), res.Summary.SaturationProbability*100)
	}
	for _, note := range res.Notes {
		fmt.Printf("  note: %s\n", note)
	}
}

// scenarioTarget and formatSeconds are shared with the Markdown renderer's
// vocabulary so the CLI and the artifact never disagree.
func scenarioTarget(sc twin.Scenario) string {
	if sc.Mode == twin.LoopClosed {
		return fmt.Sprintf("%.2f users", sc.TargetUsers)
	}
	return fmt.Sprintf("%.2f rps", sc.TargetRPS)
}

func formatSaturation(s twin.Summary) string {
	if s.PredictedSaturationSeconds == nil {
		return "-"
	}
	return formatSeconds(*s.PredictedSaturationSeconds)
}

func formatSeconds(v float64) string {
	if v <= 0 {
		return "0 s"
	}
	if v < 1 {
		return fmt.Sprintf("%.0f ms", v*1000)
	}
	if v < 60 {
		return fmt.Sprintf("%.1f s", v)
	}
	return fmt.Sprintf("%.1f min", v/60)
}

func fallback(v, alt string) string {
	if strings.TrimSpace(v) == "" {
		return alt
	}
	return v
}

func simulateUsage() {
	fmt.Fprint(os.Stderr, `Usage: Sift simulate <command> [flags]

Builds a capacity digital twin from a Sift report and answers what-if load
questions without touching the service. All output is a model-based estimate,
not a guarantee.

Commands:
  fit       Fit a capacity model from a report JSON
  run       Simulate one scenario against a fitted model
  compare   Simulate the best, likely and worst presets and compare them

Fit flags:
  --report string          path to a Sift report JSON (required)
  --out string             output directory (default "reports/twin")
  --target-p99-ms float    latency objective for capacity headroom (0 = default)

Run flags:
  --model string           path to twin-model.json (required)
  --scenario string        preset: best|likely|worst (required)
  --rps float              open-loop target rps (overrides the preset)
  --users float            closed-loop target users (overrides the preset)
  --duration float         scenario duration in seconds (0 = preset)
  --sla-p99-ms float       p99 objective in ms (0 = preset)
  --max-error-rate float   error-rate objective in percent (0 = disabled)
  --iterations int         Monte Carlo iterations (0 = preset, max 10000)
  --seed int               PRNG seed (default 42)
  --ramp float             ramp seconds (-1 = preset, 0 = immediate step)
  --out string             output directory (default "reports/twin")
  --fail-on-breach-prob float
                           exit 3 when the breach probability exceeds this
                           fraction of 1 (0 = disabled)

Compare flags: --model, --duration, --sla-p99-ms, --max-error-rate,
  --iterations, --seed, --ramp, --out, --fail-on-breach-prob.

Exit status: 0 success, 1 invalid input, 3 SLA breach gate tripped.

Examples:
  Sift simulate fit --report reports/api_20260101-120000.json --out reports/twin
  Sift simulate run --model reports/twin/twin-model.json --scenario likely --rps 500
  Sift simulate run --model reports/twin/twin-model.json --scenario worst --users 200 \
      --duration 120 --sla-p99-ms 300 --iterations 500 --fail-on-breach-prob 0.1
  Sift simulate compare --model reports/twin/twin-model.json --out reports/twin
`)
}
