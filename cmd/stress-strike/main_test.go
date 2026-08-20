package main

import (
	"os"
	"path/filepath"
	"testing"

	"stress-strike/internal/config"
)

func TestQuickScenario(t *testing.T) {
	tests := []struct {
		name         string
		scenarioName string // name passed to quickScenario (for report name)
		url          string
		method       string
		data         string
		headers      headerFlags
		profile      string
		users        int
		duration     int
		rampUp       int
		spikeUsers   int
		spikeWarmup  int
		spikeHold    int
		wavePeriod   int
		rps          int
		timeout      int
		keepAlive    bool
		wantErr      bool
		check        func(*testing.T, *config.Scenario)
	}{
		{
			name:     "basic GET",
			url:      "https://api.example.com/health",
			method:   "GET",
			profile:  "steady",
			users:    10,
			duration: 30,
			check: func(t *testing.T, sc *config.Scenario) {
				if sc.Name != "quick-test" {
					t.Errorf("name = %s, want quick-test", sc.Name)
				}
				if len(sc.Steps) != 1 {
					t.Fatalf("steps = %d, want 1", len(sc.Steps))
				}
				if sc.Steps[0].Method != "GET" {
					t.Errorf("method = %s, want GET", sc.Steps[0].Method)
				}
				if sc.Steps[0].URL != "https://api.example.com/health" {
					t.Errorf("url = %s, want https://api.example.com/health", sc.Steps[0].URL)
				}
				if sc.Profile.Type != config.ProfileSteady {
					t.Errorf("profile = %s, want steady", sc.Profile.Type)
				}
				if sc.Profile.Users != 10 {
					t.Errorf("users = %d, want 10", sc.Profile.Users)
				}
				if sc.Profile.Duration != 30 {
					t.Errorf("duration = %d, want 30", sc.Profile.Duration)
				}
				if sc.Profile.RPS != 0 {
					t.Errorf("rps = %d, want 0", sc.Profile.RPS)
				}
				if sc.Profile.Timeout != 5 {
					t.Errorf("timeout = %d, want 5", sc.Profile.Timeout)
				}
			},
		},
		{
			name:      "POST with body and headers",
			url:       "https://api.example.com/login",
			method:    "POST",
			data:      `{"user":"test"}`,
			headers:   headerFlags{"Content-Type": "application/json", "Authorization": "Bearer token"},
			profile:   "linear-ramp",
			users:     100,
			duration:  60,
			rampUp:    30,
			rps:       500,
			timeout:   10,
			keepAlive: false,
			check: func(t *testing.T, sc *config.Scenario) {
				if sc.Steps[0].Method != "POST" {
					t.Errorf("method = %s, want POST", sc.Steps[0].Method)
				}
				if sc.Steps[0].Body != `{"user":"test"}` {
					t.Errorf("body = %s, want {\"user\":\"test\"}", sc.Steps[0].Body)
				}
				if sc.Steps[0].Headers["Content-Type"] != "application/json" {
					t.Errorf("header Content-Type = %s, want application/json", sc.Steps[0].Headers["Content-Type"])
				}
				if sc.Steps[0].Headers["Authorization"] != "Bearer token" {
					t.Errorf("header Authorization = %s, want Bearer token", sc.Steps[0].Headers["Authorization"])
				}
				if sc.Profile.Type != config.ProfileLinearRamp {
					t.Errorf("profile = %s, want linear-ramp", sc.Profile.Type)
				}
				if sc.Profile.RampUp != 30 {
					t.Errorf("rampUp = %d, want 30", sc.Profile.RampUp)
				}
				if sc.Profile.RPS != 500 {
					t.Errorf("rps = %d, want 500", sc.Profile.RPS)
				}
				if sc.Profile.Timeout != 10 {
					t.Errorf("timeout = %d, want 10", sc.Profile.Timeout)
				}
				if sc.Profile.KeepAlive != nil && *sc.Profile.KeepAlive != false {
					t.Errorf("keepAlive = %v, want false", sc.Profile.KeepAlive)
				}
			},
		},
		{
			name:        "spike profile",
			url:         "https://api.example.com",
			profile:     "spike",
			users:       10,
			duration:    30,
			spikeUsers:  1000,
			spikeWarmup: 5,
			spikeHold:   10,
			check: func(t *testing.T, sc *config.Scenario) {
				if sc.Profile.Type != config.ProfileSpike {
					t.Errorf("profile = %s, want spike", sc.Profile.Type)
				}
				if sc.Profile.SpikeUsers != 1000 {
					t.Errorf("spikeUsers = %d, want 1000", sc.Profile.SpikeUsers)
				}
				if sc.Profile.SpikeWarmup != 5 {
					t.Errorf("spikeWarmup = %d, want 5", sc.Profile.SpikeWarmup)
				}
				if sc.Profile.SpikeHold != 10 {
					t.Errorf("spikeHold = %d, want 10", sc.Profile.SpikeHold)
				}
			},
		},
		{
			name:     "wave profile",
			url:      "https://api.example.com",
			profile:  "wave",
			users:    50,
			duration: 120,
			check: func(t *testing.T, sc *config.Scenario) {
				if sc.Profile.Type != config.ProfileWave {
					t.Errorf("profile = %s, want wave", sc.Profile.Type)
				}
			},
		},
		{
			name:     "soak profile",
			url:      "https://api.example.com",
			profile:  "soak",
			users:    20,
			duration: 3600,
			check: func(t *testing.T, sc *config.Scenario) {
				if sc.Profile.Type != config.ProfileSoak {
					t.Errorf("profile = %s, want soak", sc.Profile.Type)
				}
			},
		},
		{
			name:         "custom name",
			scenarioName: "my-custom-test",
			url:          "https://api.example.com",
			check: func(t *testing.T, sc *config.Scenario) {
				if sc.Name != "my-custom-test" {
					t.Errorf("name = %s, want my-custom-test", sc.Name)
				}
			},
		},
		{
			name:    "empty url should error",
			url:     "",
			wantErr: true,
			check: func(t *testing.T, sc *config.Scenario) {
				// sc will be nil
			},
		},
		{
			name:     "zero users defaults to 10",
			url:      "https://api.example.com",
			users:    0,
			duration: 0,
			check: func(t *testing.T, sc *config.Scenario) {
				if sc.Profile.Users != 10 {
					t.Errorf("users = %d, want 10 (default)", sc.Profile.Users)
				}
				if sc.Profile.Duration != 30 {
					t.Errorf("duration = %d, want 30 (default)", sc.Profile.Duration)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := headerFlags{}
			for k, v := range tt.headers {
				h[k] = v
			}
			name := tt.scenarioName
			if name == "" {
				name = "quick-test"
			}
			sc, err := quickScenario(name, tt.url, tt.method, tt.data, h, tt.profile, tt.users, tt.duration, tt.rampUp, tt.spikeUsers, tt.spikeWarmup, tt.spikeHold, tt.wavePeriod, tt.rps, tt.timeout, tt.keepAlive)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error for empty URL, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, sc)
			}
		})
	}
}

func TestHeaderFlagsSet(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		wantKey string
		wantVal string
	}{
		{"Content-Type=application/json", false, "Content-Type", "application/json"},
		{"Authorization=Bearer token123", false, "Authorization", "Bearer token123"},
		{"X-Custom-Header=value", false, "X-Custom-Header", "value"},
		{"Key=Value=With=Equals", false, "Key", "Value=With=Equals"}, // only splits on first =
		{"", true, "", ""},         // empty
		{"NoEquals", true, "", ""}, // no =
		{"=Value", true, "", ""},   // empty key
		{"Key=", false, "Key", ""}, // empty value is ok
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			h := headerFlags{}
			err := h.Set(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h[tt.wantKey] != tt.wantVal {
				t.Errorf("header[%q] = %q, want %q", tt.wantKey, h[tt.wantKey], tt.wantVal)
			}
		})
	}
}

func TestHeaderFlagsString(t *testing.T) {
	h := headerFlags{"Key": "Value"}
	if h.String() != "" {
		t.Errorf("String() = %q, want empty string", h.String())
	}
}

func TestTargetDisplay(t *testing.T) {
	tests := []struct {
		name     string
		scenario *config.Scenario
		want     string
	}{
		{
			name: "with BaseURL",
			scenario: &config.Scenario{
				BaseURL: "https://api.example.com",
				Steps:   []config.Step{{URL: "https://api.example.com/health"}},
			},
			want: "https://api.example.com",
		},
		{
			name: "with first step URL",
			scenario: &config.Scenario{
				Steps: []config.Step{{URL: "https://api.example.com/health"}},
			},
			want: "https://api.example.com/health",
		},
		{
			name:     "empty scenario",
			scenario: &config.Scenario{},
			want:     "n/a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := targetDisplay(tt.scenario)
			if got != tt.want {
				t.Errorf("targetDisplay = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWarnLowFileLimit(t *testing.T) {
	// This tests the platform-specific function.
	// On Unix it checks rlimit, on Windows it's a no-op.
	// We can't easily test the actual rlimit check, but we can verify
	// it doesn't panic for various profile configurations.

	profiles := []config.Profile{
		{Type: config.ProfileSteady, Users: 10, Duration: 30},
		{Type: config.ProfileLinearRamp, Users: 1000, Duration: 60, RampUp: 30},
		{Type: config.ProfileSpike, Users: 10, SpikeUsers: 50000, SpikeWarmup: 5, SpikeHold: 10, Duration: 30},
		{Type: config.ProfileWave, Users: 100, Duration: 120, WavePeriod: 30},
		{Type: config.ProfileSoak, Users: 50, Duration: 3600},
	}

	for _, p := range profiles {
		t.Run(p.Type, func(t *testing.T) {
			// Should not panic
			warnLowFileLimit(p)
		})
	}
}

func TestQuickScenarioNormalizeError(t *testing.T) {
	// Test that invalid profile type returns error
	_, err := quickScenario("test", "https://api.example.com", "GET", "", headerFlags{}, "invalid-profile", 10, 30, 0, 0, 0, 0, 0, 0, 5, true)
	if err == nil {
		t.Error("expected error for invalid profile type")
	}
}

func TestQuickScenarioDefaults(t *testing.T) {
	// Test that defaults are applied when zero values provided
	sc, err := quickScenario("test", "https://api.example.com", "", "", headerFlags{}, "", 0, 0, 0, 0, 0, 0, 0, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Profile.Users != 10 {
		t.Errorf("default users = %d, want 10", sc.Profile.Users)
	}
	if sc.Profile.Duration != 30 {
		t.Errorf("default duration = %d, want 30", sc.Profile.Duration)
	}
	if sc.Profile.Type != config.ProfileSteady {
		t.Errorf("default profile = %s, want steady", sc.Profile.Type)
	}
	if sc.Profile.Timeout != 5 {
		t.Errorf("default timeout = %d, want 5", sc.Profile.Timeout)
	}
	if sc.Steps[0].Method != "GET" {
		t.Errorf("default method = %s, want GET", sc.Steps[0].Method)
	}
}

func TestQuickScenarioRampUpDefault(t *testing.T) {
	// When rampUp is 0, it should default to duration/2
	sc, err := quickScenario("test", "https://api.example.com", "GET", "", headerFlags{}, "linear-ramp", 100, 60, 0, 0, 0, 0, 0, 0, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	// RampUp should be duration/2 = 30
	if sc.Profile.RampUp != 30 {
		t.Errorf("default rampUp = %d, want 30 (duration/2)", sc.Profile.RampUp)
	}
}

func TestQuickScenarioSpikeDefaults(t *testing.T) {
	// When spike params are 0, they should get defaults
	sc, err := quickScenario("test", "https://api.example.com", "GET", "", headerFlags{}, "spike", 10, 30, 0, 0, 0, 0, 0, 0, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Profile.SpikeUsers != 100 { // users * 10
		t.Errorf("default spikeUsers = %d, want 100", sc.Profile.SpikeUsers)
	}
	if sc.Profile.SpikeWarmup != 0 {
		t.Errorf("default spikeWarmup = %d, want 0", sc.Profile.SpikeWarmup)
	}
	if sc.Profile.SpikeHold != 30 { // duration
		t.Errorf("default spikeHold = %d, want 30", sc.Profile.SpikeHold)
	}
}

func TestQuickScenarioWaveDefaults(t *testing.T) {
	sc, err := quickScenario("test", "https://api.example.com", "GET", "", headerFlags{}, "wave", 100, 30, 0, 0, 0, 0, 0, 0, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Profile.WavePeriod != 10 { // duration/3
		t.Errorf("default wavePeriod = %d, want 10 (duration/3)", sc.Profile.WavePeriod)
	}
}

func TestQuickScenarioWithHeaders(t *testing.T) {
	h := headerFlags{"X-Custom": "value1", "Authorization": "Bearer token"}
	sc, err := quickScenario("test", "https://api.example.com", "GET", "", h, "steady", 10, 30, 0, 0, 0, 0, 0, 0, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Steps[0].Headers["X-Custom"] != "value1" {
		t.Errorf("header X-Custom = %s, want value1", sc.Steps[0].Headers["X-Custom"])
	}
	if sc.Steps[0].Headers["Authorization"] != "Bearer token" {
		t.Errorf("header Authorization = %s, want Bearer token", sc.Steps[0].Headers["Authorization"])
	}
}

func TestQuickScenarioEmptyBody(t *testing.T) {
	sc, err := quickScenario("test", "https://api.example.com", "POST", "", headerFlags{}, "steady", 10, 30, 0, 0, 0, 0, 0, 0, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Steps[0].Body != "" {
		t.Errorf("body = %q, want empty", sc.Steps[0].Body)
	}
}

func TestQuickScenarioBodyWithVariables(t *testing.T) {
	sc, err := quickScenario("test", "https://api.example.com", "POST", `{"user":"{{user}}"}`, headerFlags{}, "steady", 10, 30, 0, 0, 0, 0, 0, 0, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Steps[0].Body != `{"user":"{{user}}"}` {
		t.Errorf("body = %q, want {\"user\":\"{{user}}\"}", sc.Steps[0].Body)
	}
}

func TestQuickScenarioKeepAliveFalse(t *testing.T) {
	sc, err := quickScenario("test", "https://api.example.com", "GET", "", headerFlags{}, "steady", 10, 30, 0, 0, 0, 0, 0, 0, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Profile.KeepAlive == nil || *sc.Profile.KeepAlive != false {
		t.Errorf("keepAlive = %v, want false", sc.Profile.KeepAlive)
	}
}

func TestQuickScenarioKeepAliveTrue(t *testing.T) {
	sc, err := quickScenario("test", "https://api.example.com", "GET", "", headerFlags{}, "steady", 10, 30, 0, 0, 0, 0, 0, 0, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Profile.KeepAlive == nil || *sc.Profile.KeepAlive != true {
		t.Errorf("keepAlive = %v, want true", sc.Profile.KeepAlive)
	}
}

// TestConfigLoading tests loading scenario from config file
func TestConfigLoading(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "scenario.yaml")

	yamlContent := `
name: test-config
base_url: https://api.example.com
load_profile:
  type: steady
  users: 50
  duration: 60
  timeout: 10
steps:
  - name: health
    method: GET
    url: /health
  - name: api
    method: POST
    url: /api
    body: '{"key":"value"}'
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	sc, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}

	if sc.Name != "test-config" {
		t.Errorf("name = %s, want test-config", sc.Name)
	}
	if sc.BaseURL != "https://api.example.com" {
		t.Errorf("base_url = %s, want https://api.example.com", sc.BaseURL)
	}
	if sc.Profile.Users != 50 {
		t.Errorf("users = %d, want 50", sc.Profile.Users)
	}
	if sc.Profile.Duration != 60 {
		t.Errorf("duration = %d, want 60", sc.Profile.Duration)
	}
	if len(sc.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(sc.Steps))
	}
	if sc.Steps[0].Name != "health" {
		t.Errorf("step 0 name = %s, want health", sc.Steps[0].Name)
	}
	if sc.Steps[1].Method != "POST" {
		t.Errorf("step 1 method = %s, want POST", sc.Steps[1].Method)
	}
}
