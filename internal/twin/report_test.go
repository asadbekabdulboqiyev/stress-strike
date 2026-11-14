package twin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleResults(t *testing.T, m Model) map[string]Result {
	t.Helper()
	out := make(map[string]Result, 2)
	for _, name := range []string{"likely", "worst"} {
		sc, err := Preset(name, m)
		if err != nil {
			t.Fatalf("Preset(%q): %v", name, err)
		}
		sc.Iterations = 25
		res, err := Simulate(m, sc, 99)
		if err != nil {
			t.Fatalf("Simulate(%q): %v", name, err)
		}
		out[name] = res
	}
	return out
}

func TestWriteArtifacts(t *testing.T) {
	m := fittedModel(t)
	results := sampleResults(t, m)
	dir := t.TempDir()

	paths, err := WriteArtifacts(dir, m, results)
	if err != nil {
		t.Fatalf("WriteArtifacts: %v", err)
	}
	if filepath.Base(paths.ModelPath) != ModelArtifactName {
		t.Errorf("model path = %q", paths.ModelPath)
	}
	if filepath.Dir(paths.ModelPath) != dir {
		t.Errorf("model path escaped the output directory: %q", paths.ModelPath)
	}
	if len(paths.SimulationPaths) != 2 {
		t.Fatalf("simulation artifacts = %d, want 2", len(paths.SimulationPaths))
	}
	if paths.SimulationPaths[0].Scenario != "likely" || paths.SimulationPaths[1].Scenario != "worst" {
		t.Errorf("simulation artifacts are not sorted: %+v", paths.SimulationPaths)
	}
	if filepath.Base(paths.ReportPath) != MarkdownArtifactName {
		t.Errorf("report path = %q", paths.ReportPath)
	}

	for _, p := range []string{paths.ModelPath, paths.ReportPath} {
		if info, statErr := os.Stat(p); statErr != nil {
			t.Fatalf("stat %s: %v", p, statErr)
		} else if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", p, info.Mode().Perm())
		}
	}

	loaded, err := LoadModel(paths.ModelPath)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	if loaded.Curve.CapacityRPS != m.Curve.CapacityRPS {
		t.Errorf("round-tripped capacity = %v, want %v", loaded.Curve.CapacityRPS, m.Curve.CapacityRPS)
	}

	simPath := paths.SimulationPaths[0].Path
	sim, err := LoadResult(simPath)
	if err != nil {
		t.Fatalf("LoadResult: %v", err)
	}
	if sim.Scenario.Name != "likely" || len(sim.Iterations) != 25 {
		t.Errorf("round-tripped result is wrong: name=%q iterations=%d", sim.Scenario.Name, len(sim.Iterations))
	}
	if sim.SchemaVersion != SchemaVersion {
		t.Errorf("result schema = %q", sim.SchemaVersion)
	}

	md, err := os.ReadFile(paths.ReportPath)
	if err != nil {
		t.Fatalf("read markdown: %v", err)
	}
	text := string(md)
	for _, want := range []string{
		"not a guarantee",
		"Estimated capacity",
		"| likely |",
		"| worst |",
		"Breach probability",
		"Closed-loop",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("markdown is missing %q", want)
		}
	}
}

func TestWriteArtifactsIsByteStable(t *testing.T) {
	m := fittedModel(t)
	results := sampleResults(t, m)

	dirA := t.TempDir()
	dirB := t.TempDir()
	pathsA, err := WriteArtifacts(dirA, m, results)
	if err != nil {
		t.Fatalf("WriteArtifacts A: %v", err)
	}
	pathsB, err := WriteArtifacts(dirB, m, results)
	if err != nil {
		t.Fatalf("WriteArtifacts B: %v", err)
	}

	pairs := [][2]string{{pathsA.ModelPath, pathsB.ModelPath}, {pathsA.ReportPath, pathsB.ReportPath}}
	for _, art := range pathsA.SimulationPaths {
		for _, other := range pathsB.SimulationPaths {
			if other.Scenario == art.Scenario {
				pairs = append(pairs, [2]string{art.Path, other.Path})
			}
		}
	}
	for _, pair := range pairs {
		a, err := os.ReadFile(pair[0])
		if err != nil {
			t.Fatalf("read %s: %v", pair[0], err)
		}
		b, err := os.ReadFile(pair[1])
		if err != nil {
			t.Fatalf("read %s: %v", pair[1], err)
		}
		if string(a) != string(b) {
			t.Errorf("%s and %s differ despite identical inputs", pair[0], pair[1])
		}
	}
}

func TestWriteModelRejectsInvalidModel(t *testing.T) {
	if _, err := WriteModel(t.TempDir(), Model{}); err == nil {
		t.Fatal("expected an invalid model to be rejected")
	}
	if _, err := WriteModel("  ", fittedModel(t)); err == nil {
		t.Fatal("expected an empty output directory to be rejected")
	}
}

func TestWriteArtifactsRejectsBadInput(t *testing.T) {
	m := fittedModel(t)
	results := sampleResults(t, m)

	if _, err := WriteArtifacts(t.TempDir(), m, map[string]Result{"": results["likely"]}); err == nil {
		t.Fatal("expected an empty scenario name to be rejected")
	}

	mismatch := results["likely"]
	mismatch.Scenario.Name = "other"
	if _, err := WriteArtifacts(t.TempDir(), m, map[string]Result{"likely": mismatch}); err == nil {
		t.Fatal("expected a mismatched scenario key to be rejected")
	}

	badSchema := results["likely"]
	badSchema.SchemaVersion = "other"
	if _, err := WriteArtifacts(t.TempDir(), m, map[string]Result{"likely": badSchema}); err == nil {
		t.Fatal("expected a foreign result schema to be rejected")
	}
}

func TestSimulationFilename(t *testing.T) {
	cases := map[string]string{
		"best":             "simulation-best.json",
		"Worst Case":       "simulation-worst-case.json",
		"a/b\\c:d":         "simulation-a-b-c-d.json",
		"../../etc/passwd": "simulation-etc-passwd.json",
		"":                 "simulation-scenario.json",
	}
	for in, want := range cases {
		if got := simulationFilename(in); got != want {
			t.Errorf("simulationFilename(%q) = %q, want %q", in, got, want)
		}
	}
	// A hostile name must remain inside the output directory.
	if strings.Contains(simulationFilename("../../x"), "..") {
		t.Error("filename still contains a parent reference")
	}
}

func TestLoadModelRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadModel(path); err == nil {
		t.Fatal("expected malformed JSON to be rejected")
	}
	if _, err := LoadResult(path); err == nil {
		t.Fatal("expected malformed JSON to be rejected")
	}
	if _, err := LoadModel(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected a missing file to be rejected")
	}
}
