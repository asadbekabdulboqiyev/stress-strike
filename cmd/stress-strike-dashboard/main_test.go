package main

import (
	"reflect"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/dashboard"
)

func TestScenarioFromConfigMissingTarget(t *testing.T) {
	_, err := scenarioFromConfig(&dashboard.RunConfig{})
	if err == nil {
		t.Fatal("expected error for empty target_url")
	}
}

func TestScenarioFromConfigAppliesDefaults(t *testing.T) {
	cfg := &dashboard.RunConfig{TargetURL: "http://localhost:8080/health"}
	sc, err := scenarioFromConfig(cfg)
	if err != nil {
		t.Fatalf("scenarioFromConfig error: %v", err)
	}
	if sc.Profile.Type != config.ProfileSteady {
		t.Errorf("profile type = %q, want steady", sc.Profile.Type)
	}
	if sc.Profile.Users != 10 {
		t.Errorf("users = %d, want default 10", sc.Profile.Users)
	}
	if sc.Profile.Duration != 30 {
		t.Errorf("duration = %d, want default 30", sc.Profile.Duration)
	}
	if len(sc.Steps) != 1 || sc.Steps[0].Method != "GET" {
		t.Errorf("steps = %+v, want single GET step", sc.Steps)
	}
	if sc.Steps[0].URL != "http://localhost:8080/health" {
		t.Errorf("step URL = %q", sc.Steps[0].URL)
	}
}

func TestScenarioFromConfigCarriesFullConfig(t *testing.T) {
	cfg := &dashboard.RunConfig{
		TargetURL:       "http://example.com/api",
		Users:           50,
		DurationSeconds: 120,
		Method:          "POST",
		RateLimit:       500,
		Profile:         "spike",
		Headers:         map[string]string{"Authorization": "Bearer x"},
		Body:            `{"a":1}`,
	}
	sc, err := scenarioFromConfig(cfg)
	if err != nil {
		t.Fatalf("scenarioFromConfig error: %v", err)
	}
	if sc.Profile.Type != "spike" || sc.Profile.Users != 50 || sc.Profile.Duration != 120 || sc.Profile.RPS != 500 {
		t.Errorf("profile = %+v", sc.Profile)
	}
	st := sc.Steps[0]
	if st.Method != "POST" || st.Body != `{"a":1}` {
		t.Errorf("step = %+v", st)
	}
	if st.Headers["Authorization"] != "Bearer x" {
		t.Errorf("headers = %v", st.Headers)
	}
}

func TestScenarioFromConfigConstantRPS(t *testing.T) {
	cfg := &dashboard.RunConfig{
		TargetURL:       "http://example.com",
		Profile:         config.ProfileConstantRPS,
		RateLimit:       800,
		DurationSeconds: 10,
	}
	sc, err := scenarioFromConfig(cfg)
	if err != nil {
		t.Fatalf("scenarioFromConfig error: %v", err)
	}
	if sc.Profile.TargetRPS != 800 {
		t.Errorf("target_rps = %d, want 800 from rate limit", sc.Profile.TargetRPS)
	}
}

func TestScenarioFromConfigConstantRPSWithoutRateLimitFails(t *testing.T) {
	cfg := &dashboard.RunConfig{
		TargetURL:       "http://example.com",
		Profile:         config.ProfileConstantRPS,
		DurationSeconds: 10,
	}
	if _, err := scenarioFromConfig(cfg); err == nil {
		t.Fatal("expected error: constant-rps requires rate_limit > 0")
	}
}

func TestScenarioFromConfigNormalizesStep(t *testing.T) {
	// Unsupported profile must surface the Normalize error.
	cfg := &dashboard.RunConfig{TargetURL: "http://example.com", Profile: "bogus-profile"}
	if _, err := scenarioFromConfig(cfg); err == nil {
		t.Fatal("expected error for unsupported profile")
	}
}

func TestGetString(t *testing.T) {
	m := map[string]interface{}{"a": "x", "b": 42, "c": nil}
	if got := getString(m, "a", "def"); got != "x" {
		t.Errorf("getString(a) = %q", got)
	}
	if got := getString(m, "b", "def"); got != "def" {
		t.Errorf("getString(non-string) = %q, want default", got)
	}
	if got := getString(m, "zz", "def"); got != "def" {
		t.Errorf("getString(missing) = %q, want default", got)
	}
}

func TestGetInt(t *testing.T) {
	m := map[string]interface{}{"n": float64(7), "s": "12"}
	if got := getInt(m, "n", 0); got != 7 {
		t.Errorf("getInt(n) = %d", got)
	}
	if got := getInt(m, "s", 0); got != 0 {
		t.Errorf("getInt(string) = %d, want default", got)
	}
	if got := getInt(m, "zz", 3); got != 3 {
		t.Errorf("getInt(missing) = %d, want default 3", got)
	}
}

func TestGetStringMap(t *testing.T) {
	m := map[string]interface{}{
		"headers": map[string]interface{}{
			"a": "x",
			"b": float64(1.5),
			"c": true,
			"d": []string{"z"},
		},
	}
	got := getStringMap(m, "headers")
	want := map[string]string{"a": "x", "b": "1.5", "c": "true", "d": "[z]"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("getStringMap = %v, want %v", got, want)
	}
	if got := getStringMap(m, "nope"); got != nil {
		t.Errorf("getStringMap(missing) = %v, want nil", got)
	}
}
