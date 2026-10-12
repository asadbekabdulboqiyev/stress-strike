package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// coordinated_omission must survive a YAML round-trip through Load, so the
// engine can read it from a scenario file.
func TestCoordinatedOmissionYAMLRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sc.yaml")
	const doc = `
name: co
load_profile:
  type: constant-rps
  target_rps: 100
  duration: 5
  coordinated_omission: true
steps:
  - name: hit
    method: GET
    url: https://example.com/
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !sc.Profile.CoordinatedOmission {
		t.Error("coordinated_omission did not round-trip through YAML")
	}

	// JSON tag must match too (reports and API payloads use it).
	b, err := json.Marshal(sc.Profile)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if v, ok := raw["coordinated_omission"]; !ok || v != true {
		t.Errorf("json coordinated_omission = %v (present=%v), want true", v, ok)
	}
}

// The field is opt-in: a scenario without it must default to false.
func TestCoordinatedOmissionDefaultsOff(t *testing.T) {
	sc, err := LoadJSON([]byte(`{"name":"x","load_profile":{"type":"steady","users":1,"duration":1},"steps":[{"url":"http://x/"}]}`))
	if err != nil {
		t.Fatalf("LoadJSON: %v", err)
	}
	if sc.Profile.CoordinatedOmission {
		t.Error("coordinated_omission should default to false")
	}
}
