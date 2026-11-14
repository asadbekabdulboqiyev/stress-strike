package twin

// report.go — deterministic, human- and machine-readable artifacts.
//
// Every artifact is written under the caller's directory with a fixed name, so
// a pipeline can address it without globbing: twin-model.json,
// simulation-<scenario>.json and simulation-report.md. JSON is produced from
// structs only (no maps in the serialized core) and scenarios are sorted by
// name, so the same model and results always produce the same bytes.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Artifact file names.
const (
	// ModelArtifactName is the fitted model written by `twin fit`.
	ModelArtifactName = "twin-model.json"
	// MarkdownArtifactName is the human-readable summary.
	MarkdownArtifactName = "simulation-report.md"
	// simulationPrefix precedes each per-scenario result file.
	simulationPrefix = "simulation-"
)

// ScenarioArtifact records where one scenario's result was written.
type ScenarioArtifact struct {
	Scenario string `json:"scenario"`
	Path     string `json:"path"`
}

// ArtifactPaths lists everything WriteArtifacts produced, in deterministic
// order. It is JSON-serializable so a wrapper tool can consume it.
type ArtifactPaths struct {
	ModelPath       string             `json:"model_path"`
	SimulationPaths []ScenarioArtifact `json:"simulation_paths"`
	ReportPath      string             `json:"report_path"`
}

// WriteModel writes only twin-model.json. It is used by `twin fit`, where no
// simulation exists yet.
func WriteModel(dir string, m Model) (string, error) {
	if err := m.Validate(); err != nil {
		return "", fmt.Errorf("twin: refusing to write an invalid model: %w", err)
	}
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("twin: output directory is required")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("twin: create output directory %s: %w", dir, err)
	}
	path := filepath.Join(dir, ModelArtifactName)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", fmt.Errorf("twin: encode model: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("twin: write %s: %w", path, err)
	}
	return path, nil
}

// WriteArtifacts writes the model, one result file per scenario and the
// Markdown report, and returns their paths. Scenarios are written in sorted
// order so the returned slice is stable.
func WriteArtifacts(dir string, m Model, results map[string]Result) (ArtifactPaths, error) {
	if strings.TrimSpace(dir) == "" {
		return ArtifactPaths{}, fmt.Errorf("twin: output directory is required")
	}

	names := make([]string, 0, len(results))
	seenFiles := make(map[string]string, len(results))
	for name := range results {
		if strings.TrimSpace(name) == "" {
			return ArtifactPaths{}, fmt.Errorf("twin: result map contains an empty scenario name")
		}
		res := results[name]
		if res.SchemaVersion != SchemaVersion {
			return ArtifactPaths{}, fmt.Errorf("twin: scenario %q result has schema %q (want %q)", name, res.SchemaVersion, SchemaVersion)
		}
		if res.Scenario.Name != name {
			return ArtifactPaths{}, fmt.Errorf("twin: result keyed %q carries scenario name %q", name, res.Scenario.Name)
		}
		file := simulationFilename(name)
		if other, ok := seenFiles[file]; ok {
			return ArtifactPaths{}, fmt.Errorf("twin: scenarios %q and %q map to the same artifact file %q", other, name, file)
		}
		seenFiles[file] = name
		names = append(names, name)
	}
	sort.Strings(names)

	modelPath, err := WriteModel(dir, m)
	if err != nil {
		return ArtifactPaths{}, err
	}

	paths := ArtifactPaths{ModelPath: modelPath}
	for _, name := range names {
		res := results[name]
		path := filepath.Join(dir, simulationFilename(name))
		data, mErr := json.MarshalIndent(res, "", "  ")
		if mErr != nil {
			return ArtifactPaths{}, fmt.Errorf("twin: encode scenario %q: %w", name, mErr)
		}
		if wErr := os.WriteFile(path, append(data, '\n'), 0o600); wErr != nil {
			return ArtifactPaths{}, fmt.Errorf("twin: write %s: %w", path, wErr)
		}
		paths.SimulationPaths = append(paths.SimulationPaths, ScenarioArtifact{Scenario: name, Path: path})
	}

	reportPath := filepath.Join(dir, MarkdownArtifactName)
	md := renderMarkdown(m, names, results)
	if err := os.WriteFile(reportPath, []byte(md), 0o600); err != nil {
		return ArtifactPaths{}, fmt.Errorf("twin: write %s: %w", reportPath, err)
	}
	paths.ReportPath = reportPath
	return paths, nil
}

// LoadModel reads a model artifact. The path is operator-selected, so it is
// cleaned before use; reading an arbitrary file chosen on the command line is
// the intended behaviour.
func LoadModel(path string) (Model, error) {
	clean := filepath.Clean(path)
	data, err := os.ReadFile(clean) // #nosec G304 -- operator-selected model artifact
	if err != nil {
		return Model{}, fmt.Errorf("twin: read model %s: %w", clean, err)
	}
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		return Model{}, fmt.Errorf("twin: parse model %s: %w", clean, err)
	}
	if err := m.Validate(); err != nil {
		return Model{}, fmt.Errorf("twin: model %s is not usable: %w", clean, err)
	}
	return m, nil
}

// LoadResult parses a simulation artifact. It is primarily useful to tests and
// downstream tooling; the CLI does not need it.
func LoadResult(path string) (Result, error) {
	clean := filepath.Clean(path)
	data, err := os.ReadFile(clean) // #nosec G304 -- operator-selected simulation artifact
	if err != nil {
		return Result{}, fmt.Errorf("twin: read result %s: %w", clean, err)
	}
	var r Result
	if err := json.Unmarshal(data, &r); err != nil {
		return Result{}, fmt.Errorf("twin: parse result %s: %w", clean, err)
	}
	if r.SchemaVersion != SchemaVersion {
		return Result{}, fmt.Errorf("twin: result %s has schema %q (want %q)", clean, r.SchemaVersion, SchemaVersion)
	}
	return r, nil
}

// simulationFilename derives a filesystem-safe name from a scenario name.
// Anything outside [a-z0-9_-] becomes '-', runs of '-' collapse, and an empty
// result falls back to "scenario".
func simulationFilename(name string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "scenario"
	}
	return simulationPrefix + out + ".json"
}

// renderMarkdown produces the human-readable artifact. It is intentionally
// plain: the audience is an engineer pasting it into a review, and every claim
// carries its uncertainty.
func renderMarkdown(m Model, names []string, results map[string]Result) string {
	var b strings.Builder

	b.WriteString("# Digital twin capacity simulation\n\n")
	b.WriteString("> **This is a model-based estimate, not a measurement and not a guarantee.**\n")
	b.WriteString("> The twin extrapolates from a single observed load-test operating point. It assumes\n")
	b.WriteString("> steady state, one bottleneck, no autoscaling, no cache warm-up and a traffic mix\n")
	b.WriteString("> matching the source run. Re-measure before making an irreversible capacity decision.\n\n")

	b.WriteString("## Fitted model\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Schema | `%s` |\n", m.SchemaVersion)
	fmt.Fprintf(&b, "| Source report | %s |\n", markdownCell(m.Source.ReportName, "n/a"))
	fmt.Fprintf(&b, "| Target | %s |\n", markdownCell(m.Source.TargetURL, "n/a"))
	fmt.Fprintf(&b, "| Load profile | %s |\n", markdownCell(m.Source.LoadProfile, "n/a"))
	fmt.Fprintf(&b, "| Run duration | %s |\n", formatSeconds(m.Source.DurationSeconds))
	fmt.Fprintf(&b, "| Fitted at | %s |\n", formatTime(m.Calibration.FittedAt))
	fmt.Fprintf(&b, "| Observed throughput | %.2f rps |\n", m.Workload.RPS)
	fmt.Fprintf(&b, "| Observed concurrency (Little's law) | %.2f |\n", m.Workload.Concurrency)
	fmt.Fprintf(&b, "| Observed error rate | %.3f%% |\n", m.Workload.ErrorRatePct)
	fmt.Fprintf(&b, "| Baseline latency | p50 %.2f ms / p95 %.2f ms / p99 %.2f ms |\n", m.Curve.Baseline.P50MS, m.Curve.Baseline.P95MS, m.Curve.Baseline.P99MS)
	fmt.Fprintf(&b, "| Estimated capacity | %.2f rps (%.2f - %.2f rps, +/-%.1f%%) |\n", m.Curve.CapacityRPS, m.Curve.CapacityLowRPS, m.Curve.CapacityHighRPS, m.Curve.CapacityRelativeUncertainty*100)
	fmt.Fprintf(&b, "| Reference utilisation | %.3f |\n", m.Curve.ReferenceUtilization)
	fmt.Fprintf(&b, "| Confidence | %s |\n", m.Confidence)
	b.WriteString("\n")

	b.WriteString("### How capacity was derived\n\n")
	b.WriteString("Capacity uses an M/M/1 tail approximation: `p99(rho) = L0 / (1 - rho)` with\n")
	b.WriteString("`L0 = p50 / ln 2`. Substituting the measured p99 yields the utilisation the run\n")
	b.WriteString("operated at, and capacity is the observed throughput divided by that utilisation.\n")
	b.WriteString("The utilisation is clamped to [0.10, 0.98] so a flat or pathological tail cannot\n")
	b.WriteString("produce an absurd extrapolation.\n\n")

	if len(m.Calibration.Notes) > 0 {
		b.WriteString("### Calibration notes\n\n")
		for _, note := range m.Calibration.Notes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Scenarios\n\n")
	if len(names) == 0 {
		b.WriteString("No scenarios were simulated.\n")
	} else {
		b.WriteString("| Scenario | Loop | Target | p99 median | p99 p95 | Breach probability | Saturation | Risk |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|\n")
		for _, name := range names {
			res := results[name]
			fmt.Fprintf(&b, "| %s | %s | %s | %.2f ms | %.2f ms | %.1f%% | %s | %s |\n",
				markdownCell(name, "n/a"),
				res.Scenario.Mode,
				scenarioTarget(res.Scenario),
				res.Summary.P99MS.P50,
				res.Summary.P99MS.P95,
				res.Summary.SLAProbabilityBreach*100,
				formatSaturation(res.Summary),
				res.Summary.RiskLevel,
			)
		}
		b.WriteString("\n")

		for _, name := range names {
			renderScenario(&b, results[name])
		}
	}

	b.WriteString("## Interpretation\n\n")
	b.WriteString("- `p99 median` is the median predicted p99 across Monte Carlo draws; `p99 p95` shows how bad a bad draw gets.\n")
	b.WriteString("- `Breach probability` is the share of draws in which the p99 objective, the error-rate objective, or both were exceeded.\n")
	b.WriteString("- Risk vocabulary: **low** is below 5% breach probability, **elevated** is 5-50%, **high** is 50% or more.\n")
	b.WriteString("- A low risk level is not a pass certificate: it quantifies model uncertainty, not the absence of unmodelled failure modes.\n")
	b.WriteString("- Closed-loop scenarios solve for throughput from the user count, so adding users past capacity adds latency, not throughput.\n")
	b.WriteString("\n")

	return b.String()
}

func renderScenario(b *strings.Builder, res Result) {
	fmt.Fprintf(b, "### %s\n\n", res.Scenario.Name)
	fmt.Fprintf(b, "- Load: %s over %s (ramp %s), %d iterations, seed %d.\n",
		scenarioTarget(res.Scenario), formatSeconds(res.Scenario.DurationSeconds), formatSeconds(res.Scenario.RampSeconds), res.Scenario.Iterations, res.Scenario.Seed)
	if res.Scenario.SLAP99MS > 0 {
		fmt.Fprintf(b, "- SLA: p99 <= %.2f ms.\n", res.Scenario.SLAP99MS)
	}
	if res.Scenario.MaxErrorRatePct > 0 {
		fmt.Fprintf(b, "- SLA: error rate <= %.2f%%.\n", res.Scenario.MaxErrorRatePct)
	}
	fmt.Fprintf(b, "- Achieved throughput: median %.2f rps (p95 %.2f rps).\n", res.Summary.AchievedRPS.P50, res.Summary.AchievedRPS.P95)
	fmt.Fprintf(b, "- Utilisation: median %.3f (p95 %.3f).\n", res.Summary.Utilization.P50, res.Summary.Utilization.P95)
	fmt.Fprintf(b, "- Predicted p99: median %.2f ms, p95 %.2f ms (range %.2f - %.2f ms).\n",
		res.Summary.P99MS.P50, res.Summary.P99MS.P95, res.Summary.P99MS.Min, res.Summary.P99MS.Max)
	fmt.Fprintf(b, "- Predicted error rate: median %.3f%%, p95 %.3f%%.\n", res.Summary.ErrorRatePct.P50, res.Summary.ErrorRatePct.P95)
	fmt.Fprintf(b, "- Breach probability: %.1f%% (latency %.1f%%, errors %.1f%%); risk %s.\n",
		res.Summary.SLAProbabilityBreach*100,
		res.Summary.P99BreachProbability*100,
		res.Summary.ErrorBreachProbability*100,
		res.Summary.RiskLevel)
	if res.Summary.PredictedSaturationSeconds != nil {
		fmt.Fprintf(b, "- Predicted saturation: %s into the ramp (in %.1f%% of draws).\n",
			formatSeconds(*res.Summary.PredictedSaturationSeconds), res.Summary.SaturationProbability*100)
	}
	if len(res.Notes) > 0 {
		b.WriteString("- Notes:\n")
		for _, note := range res.Notes {
			fmt.Fprintf(b, "  - %s\n", note)
		}
	}
	b.WriteString("\n")
}

func scenarioTarget(sc Scenario) string {
	if sc.Mode == LoopClosed {
		return fmt.Sprintf("%.2f users (closed)", sc.TargetUsers)
	}
	return fmt.Sprintf("%.2f rps (open)", sc.TargetRPS)
}

func formatSaturation(s Summary) string {
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

func markdownCell(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.ReplaceAll(v, "|", "\\|")
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "n/a"
	}
	return t.Format("2006-01-02T15:04:05Z07:00")
}
