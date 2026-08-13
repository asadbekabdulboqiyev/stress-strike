package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stress-strike/internal/config"
	"stress-strike/internal/metrics"
)

func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		"simple":             "simple",
		"hello world":        "hello_world",
		"../etc/passwd":      "__etc_passwd",
		"a/b\\c:d":           "a_b_c_d",
		"<>&|%*?~'\"":        "__________",
		"uni\tcode\nx":       "uni_code_x",
		"a\x00b":             "a_b",
		"token:SUPER:SECRET": "token_SUPER_SECRET",
	}
	for in, want := range cases {
		if got := sanitizeFilename(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	if sanitizeFilename("") != "" {
		t.Error("expected empty for empty input")
	}
}

func TestBuildReport(t *testing.T) {
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("login")
	step.Record(10*time.Millisecond, 200, "")
	step.Record(20*time.Millisecond, 200, "")
	step.Record(30*time.Millisecond, 500, "status_5xx")
	tel.AddStep(step)
	tel.Overall.Record(60*time.Millisecond, 200, "")
	tel.Finish()

	sc := &config.Scenario{Name: "r", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)
	if r.Name != "r" || r.BaseURL != "http://x" {
		t.Errorf("report identity wrong: %+v", r)
	}
	if r.TotalRequests != 3 {
		t.Errorf("total requests = %d, want 3", r.TotalRequests)
	}
	if r.TotalErrors != 1 || r.ErrorRatePct != float64(1)/3*100 {
		t.Errorf("errors = %d (%.2f%%), want 1 (33.33%%)", r.TotalErrors, r.ErrorRatePct)
	}
	if r.Steps[0].P95 != 30*time.Millisecond {
		t.Errorf("p95 = %s, want 30ms", r.Steps[0].P95)
	}
	if len(r.Status) != 2 || r.Status[200] != 2 || r.Status[500] != 1 {
		t.Errorf("status codes wrong: %v", r.Status)
	}
	if r.Errors["status_5xx"] != 1 {
		t.Errorf("errors map wrong: %v", r.Errors)
	}
}

func TestSaveFiles(t *testing.T) {
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("health")
	step.Record(time.Millisecond, 200, "")
	tel.AddStep(step)
	tel.Overall.Record(time.Millisecond, 200, "")
	tel.Finish()

	sc := &config.Scenario{Name: "my report", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)

	dir := t.TempDir()
	jsonPath, err := r.SaveJSON(dir)
	if err != nil {
		t.Fatal(err)
	}
	txtPath, err := r.SaveTXT(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.Base(jsonPath), "my_report_") {
		t.Errorf("unexpected json filename %s", filepath.Base(jsonPath))
	}
	if !strings.HasSuffix(txtPath, ".txt") {
		t.Errorf("unexpected txt filename %s", txtPath)
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"name": "my report"`) {
		t.Errorf("json content missing name: %s", data)
	}
	fi, err := os.Stat(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("report file is not private (mode %o)", fi.Mode().Perm())
	}
}

func TestUniquePath(t *testing.T) {
	dir := t.TempDir()
	name := "same_20260101-000000.json"
	first := uniquePath(dir, name)
	if err := os.WriteFile(first, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := uniquePath(dir, name)
	if second == first {
		t.Errorf("uniquePath returned same path twice")
	}
	if err := os.WriteFile(second, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	third := uniquePath(dir, name)
	if third == first || third == second {
		t.Errorf("uniquePath returned existing path")
	}
}

func TestRender(t *testing.T) {
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("a")
	step.Record(5*time.Millisecond, 200, "")
	tel.AddStep(step)
	tel.Overall.Record(5*time.Millisecond, 200, "")
	tel.Finish()
	sc := &config.Scenario{Name: "x", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)
	var sb strings.Builder
	r.Render(&sb)
	out := sb.String()
	for _, want := range []string{"Stress Test Report: x", "Overall:", "STEP", "Status codes: 200=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("render output missing %q:\n%s", want, out)
		}
	}
}
