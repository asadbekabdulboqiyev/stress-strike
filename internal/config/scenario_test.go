package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleYAML = `
name: demo
base_url: http://localhost:8080
load_profile:
  type: linear-ramp
  users: 1000
  duration: 60
  ramp_up: 20
variables:
  tenant: acme
steps:
  - name: login
    method: post
    url: /api/login
    body: '{"u":"{{user}}"}'
    extract:
      - name: token
        from: json
        path: data.token
  - name: me
    url: /api/me
`

func TestLoadScenario(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scenario.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	sc, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Name != "demo" {
		t.Errorf("name = %q", sc.Name)
	}
	if sc.BaseURL != "http://localhost:8080" {
		t.Errorf("base_url = %q", sc.BaseURL)
	}
	if sc.Profile.Type != ProfileLinearRamp {
		t.Errorf("profile type = %q", sc.Profile.Type)
	}
	if len(sc.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(sc.Steps))
	}
	if sc.Steps[0].Method != "POST" {
		t.Errorf("method not normalized: %q", sc.Steps[0].Method)
	}
	if sc.Steps[1].Method != "GET" {
		t.Errorf("default method = %q, want GET", sc.Steps[1].Method)
	}
	if sc.Variables["tenant"] != "acme" {
		t.Errorf("variables = %v", sc.Variables)
	}
}

func TestNormalizeDefaults(t *testing.T) {
	sc := &Scenario{
		Steps: []Step{{URL: "/x"}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	if sc.Profile.Type != ProfileSteady {
		t.Errorf("default profile = %q, want steady", sc.Profile.Type)
	}
	if sc.Profile.Users != 10 {
		t.Errorf("default users = %d, want 10", sc.Profile.Users)
	}
	if sc.Profile.Duration != 30 {
		t.Errorf("default duration = %d, want 30", sc.Profile.Duration)
	}
	if sc.Profile.Timeout != 5 {
		t.Errorf("default timeout = %d, want 5", sc.Profile.Timeout)
	}
	if sc.Name != "unnamed" {
		t.Errorf("default name = %q", sc.Name)
	}
	if sc.Steps[0].Name != "step1" {
		t.Errorf("default step name = %q", sc.Steps[0].Name)
	}
}

func TestNormalizeErrors(t *testing.T) {
	sc := &Scenario{Steps: []Step{{URL: "/x"}}, Profile: Profile{Type: "nope"}}
	if err := sc.Normalize(); err == nil {
		t.Error("expected error for unsupported profile")
	}

	sc2 := &Scenario{}
	if err := sc2.Normalize(); err == nil {
		t.Error("expected error for empty steps")
	}

	sc3 := &Scenario{Steps: []Step{{URL: ""}}}
	if err := sc3.Normalize(); err == nil {
		t.Error("expected error for empty step url")
	}

	sc4 := &Scenario{Steps: []Step{{URL: "/x", Extract: []Extract{{Name: "a", From: "xml", Path: "p"}}}}}
	if err := sc4.Normalize(); err == nil {
		t.Error("expected error for unsupported extract.from")
	}
}

func TestLoadBadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte(": bad: [yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected parse error")
	}
	if _, err := Load(strings.Repeat("x", 0)); err == nil {
		t.Error("expected not-found error")
	}
}

func TestLoadJSON(t *testing.T) {
	jsonData := []byte(`{"name":"j","load_profile":{"type":"spike","users":5,"spike_users":100,"spike_warmup":1,"spike_hold":2},"steps":[{"url":"/x"}]}`)
	sc, err := LoadJSON(jsonData)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Profile.Type != ProfileSpike {
		t.Errorf("profile = %q", sc.Profile.Type)
	}
	if sc.Profile.SpikeUsers != 100 {
		t.Errorf("spike_users = %d", sc.Profile.SpikeUsers)
	}
	if sc.Profile.TotalDuration() != 3 {
		t.Errorf("total duration = %d, want 3", sc.Profile.TotalDuration())
	}
}
