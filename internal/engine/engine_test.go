package engine

import (
	"testing"
	"time"

	"stress-strike/internal/config"
)

func TestRender(t *testing.T) {
	vars := map[string]string{"user": "user42", "token": "abc123"}
	got := render("POST {{user}}?t={{token}}", vars)
	want := "POST user42?t=abc123"
	if got != want {
		t.Errorf("render = %q, want %q", got, want)
	}
	got = render("{{unknown}}", vars)
	if got != "{{unknown}}" {
		t.Errorf("render unknown = %q, want kept as-is", got)
	}
}

func TestRenderBodyJSONEncoding(t *testing.T) {
	vars := map[string]string{"user": "u1", "note": `say "hi" \ ok`}
	got := renderBody(`{"username":"{{user}}","note":"{{note}}"}}`, vars)
	want := `{"username":"u1","note":"say \"hi\" \\ ok"}}`
	if got != want {
		t.Errorf("renderBody = %q, want %q", got, want)
	}
	got = renderBody(`{"qty":{{id}},"u":"{{user}}"}`, map[string]string{"id": "7", "user": "u2"})
	if got != `{"qty":7,"u":"u2"}` {
		t.Errorf("renderBody unquoted = %q", got)
	}
	got = renderBody(`plain {{user}}`, map[string]string{"user": "u3"})
	if got != "plain u3" {
		t.Errorf("renderBody plain = %q", got)
	}
}

func TestExtractValue(t *testing.T) {
	body := []byte(`{"data":{"token":"tok-1","nested":{"id":7}}}`)
	v, err := extractValue("json", "data.token", body, "")
	if err != nil || v != "tok-1" {
		t.Errorf("json extract = %q, %v", v, err)
	}
	v, err = extractValue("json", "data.nested.id", body, "")
	if err != nil || v != "7" {
		t.Errorf("json nested extract = %q, %v", v, err)
	}
	if _, err := extractValue("json", "data.missing", body, ""); err == nil {
		t.Errorf("expected error for missing json path")
	}

	v, err = extractValue("header", "X-Trace", nil, "trace-1")
	if err != nil || v != "trace-1" {
		t.Errorf("header extract = %q, %v", v, err)
	}
	if _, err := extractValue("header", "X-Trace", nil, ""); err == nil {
		t.Errorf("expected error for missing header")
	}

	v, err = extractValue("body", `id="([0-9]+)"`, []byte(`<div id="99"></div>`), "")
	if err != nil || v != "99" {
		t.Errorf("body regex extract = %q, %v", v, err)
	}
	if _, err := extractValue("body", `id="([0-9]+)"`, []byte("no match"), ""); err == nil {
		t.Errorf("expected error for unmatched body regex")
	}
}

func TestProfiles(t *testing.T) {
	steady, err := buildProfile(config.Profile{Type: config.ProfileSteady, Users: 100, Duration: 10})
	if err != nil {
		t.Fatal(err)
	}
	if steady.ConcurrencyAt(0) != 100 || steady.MaxConcurrency() != 100 {
		t.Errorf("steady profile mismatch: %d/%d", steady.ConcurrencyAt(0), steady.MaxConcurrency())
	}

	ramp, err := buildProfile(config.Profile{Type: config.ProfileLinearRamp, Users: 100, Duration: 10, RampUp: 10})
	if err != nil {
		t.Fatal(err)
	}
	if ramp.ConcurrencyAt(0) != 1 {
		t.Errorf("ramp at 0 = %d, want 1", ramp.ConcurrencyAt(0))
	}
	if got := ramp.ConcurrencyAt(5 * time.Second); got < 45 || got > 55 {
		t.Errorf("ramp at 5s = %d, want ~50", got)
	}
	if ramp.ConcurrencyAt(10*time.Second) != 100 {
		t.Errorf("ramp at 10s = %d, want 100", ramp.ConcurrencyAt(10*time.Second))
	}

	spike, err := buildProfile(config.Profile{Type: config.ProfileSpike, Users: 10, SpikeUsers: 5000, SpikeWarmup: 5, SpikeHold: 10, Duration: 30})
	if err != nil {
		t.Fatal(err)
	}
	if spike.ConcurrencyAt(4*time.Second) != 10 {
		t.Errorf("spike warmup concurrency = %d, want 10", spike.ConcurrencyAt(4*time.Second))
	}
	if spike.ConcurrencyAt(6*time.Second) != 5000 {
		t.Errorf("spike burst concurrency = %d, want 5000", spike.ConcurrencyAt(6*time.Second))
	}
	if spike.ConcurrencyAt(16*time.Second) != 10 {
		t.Errorf("spike after-hold concurrency = %d, want 10", spike.ConcurrencyAt(16*time.Second))
	}
	if spike.MaxConcurrency() != 5000 {
		t.Errorf("spike max = %d, want 5000", spike.MaxConcurrency())
	}
}
