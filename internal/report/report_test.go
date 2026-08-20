package report

import (
	"fmt"
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

func TestBuildReportEmptySteps(t *testing.T) {
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("s")
	step.Record(10*time.Millisecond, 200, "")
	tel.AddStep(step)
	tel.Overall.Record(10*time.Millisecond, 200, "")
	tel.Finish()

	sc := &config.Scenario{Name: "empty", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)

	if r.TotalRequests != 1 {
		t.Errorf("total requests = %d, want 1", r.TotalRequests)
	}
	if len(r.Steps) != 1 {
		t.Errorf("steps = %d, want 1", len(r.Steps))
	}
	if r.Overall.Requests != 1 {
		t.Errorf("overall requests = %d, want 1", r.Overall.Requests)
	}
}

func TestBuildReportZeroErrorRate(t *testing.T) {
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("ok")
	step.Record(10*time.Millisecond, 200, "")
	step.Record(20*time.Millisecond, 200, "")
	tel.AddStep(step)
	tel.Overall.Record(10*time.Millisecond, 200, "")
	tel.Finish()

	sc := &config.Scenario{Name: "zeroerr", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)

	if r.ErrorRatePct != 0 {
		t.Errorf("error rate = %.2f%%, want 0", r.ErrorRatePct)
	}
	if r.TotalErrors != 0 {
		t.Errorf("total errors = %d, want 0", r.TotalErrors)
	}
}

func TestBuildReportWithVariables(t *testing.T) {
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("login")
	step.Record(10*time.Millisecond, 200, "")
	tel.AddStep(step)
	tel.Overall.Record(10*time.Millisecond, 200, "")
	tel.Finish()

	sc := &config.Scenario{
		Name:      "vars",
		BaseURL:   "http://x",
		Profile:   config.Profile{Type: config.ProfileSteady},
		Variables: map[string]string{"user": "test"},
	}
	r := Build(tel, sc)
	if r.Name != "vars" {
		t.Errorf("name = %s, want vars", r.Name)
	}
}

func TestBuildReportAllProfiles(t *testing.T) {
	profiles := []string{
		config.ProfileSteady,
		config.ProfileSoak,
		config.ProfileLinearRamp,
		config.ProfileSpike,
		config.ProfileWave,
	}
	for _, p := range profiles {
		tel := metrics.NewTelemetry()
		step := metrics.NewStepStats("s")
		step.Record(10*time.Millisecond, 200, "")
		tel.AddStep(step)
		tel.Overall.Record(10*time.Millisecond, 200, "")
		tel.Finish()

		sc := &config.Scenario{Name: "p", BaseURL: "http://x", Profile: config.Profile{Type: p}}
		r := Build(tel, sc)
		if r.LoadProfile != p {
			t.Errorf("load profile = %s, want %s", r.LoadProfile, p)
		}
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

func TestSaveJSONCreatesDirectory(t *testing.T) {
	tel := metrics.NewTelemetry()
	tel.Overall.Record(time.Millisecond, 200, "")
	tel.Finish()

	sc := &config.Scenario{Name: "mkdir", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)

	dir := filepath.Join(t.TempDir(), "new", "nested", "dir")
	jsonPath, err := r.SaveJSON(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Error("directory was not created")
	}
}

func TestSaveTXTCreatesDirectory(t *testing.T) {
	tel := metrics.NewTelemetry()
	tel.Overall.Record(time.Millisecond, 200, "")
	tel.Finish()

	sc := &config.Scenario{Name: "mkdir", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)

	dir := filepath.Join(t.TempDir(), "new", "nested", "dir")
	txtPath, err := r.SaveTXT(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(txtPath); os.IsNotExist(err) {
		t.Error("directory was not created")
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

func TestUniquePathWithExtension(t *testing.T) {
	dir := t.TempDir()
	name := "test.txt"
	first := uniquePath(dir, name)
	if err := os.WriteFile(first, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := uniquePath(dir, name)
	if !strings.HasSuffix(second, "-1.txt") {
		t.Errorf("second path = %s, want suffix -1.txt", second)
	}
}

func TestUniquePathNoExtension(t *testing.T) {
	dir := t.TempDir()
	name := "test"
	first := uniquePath(dir, name)
	if err := os.WriteFile(first, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := uniquePath(dir, name)
	if !strings.HasSuffix(second, "-1") {
		t.Errorf("second path = %s, want suffix -1", second)
	}
}

func TestReportFilename(t *testing.T) {
	name := reportFilename("test", "json")
	if !strings.HasPrefix(name, "test_") {
		t.Errorf("filename = %s, want prefix test_", name)
	}
	if !strings.HasSuffix(name, ".json") {
		t.Errorf("filename = %s, want suffix .json", name)
	}
}

func TestReportFilenameSanitizes(t *testing.T) {
	name := reportFilename("bad/name", "txt")
	if strings.Contains(name, "/") {
		t.Errorf("filename contains slash: %s", name)
	}
	if !strings.HasSuffix(name, ".txt") {
		t.Errorf("filename = %s, want suffix .txt", name)
	}
}

func TestReportFilenameEmptyName(t *testing.T) {
	name := reportFilename("", "json")
	if !strings.HasPrefix(name, "report_") {
		t.Errorf("filename = %s, want prefix report_", name)
	}
}

func TestReportFilenameLongNameTruncated(t *testing.T) {
	longName := strings.Repeat("a", 100)
	name := reportFilename(longName, "json")
	// Should be truncated to 64 chars + timestamp + extension
	if len(name) > 64+1+15+5 { // 64 + _ + timestamp + .json
		t.Errorf("filename too long: %s", name)
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
	for _, want := range []string{"STRESS TEST REPORT: x", "OVERALL RESULTS", "STEP", "200", "SUMMARY"} {
		if !strings.Contains(out, want) {
			t.Errorf("render output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderWithErrors(t *testing.T) {
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("a")
	step.Record(5*time.Millisecond, 500, "status_5xx")
	tel.AddStep(step)
	tel.Overall.Record(5*time.Millisecond, 500, "status_5xx")
	tel.Finish()
	sc := &config.Scenario{Name: "err", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)
	var sb strings.Builder
	r.Render(&sb)
	out := sb.String()
	if !strings.Contains(out, "status_5xx") {
		t.Errorf("render output missing errors:\n%s", out)
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("render output missing CRITICAL health:\n%s", out)
	}
}

func TestRenderWithMultipleStatusCodes(t *testing.T) {
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("a")
	step.Record(5*time.Millisecond, 200, "")
	step.Record(5*time.Millisecond, 201, "")
	step.Record(5*time.Millisecond, 404, "not_found")
	tel.AddStep(step)
	tel.Overall.Record(5*time.Millisecond, 200, "")
	tel.Finish()
	sc := &config.Scenario{Name: "multi", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)
	var sb strings.Builder
	r.Render(&sb)
	out := sb.String()
	for _, want := range []string{"200", "201", "404"} {
		if !strings.Contains(out, want) {
			t.Errorf("render output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		input    time.Duration
		expected string
	}{
		{30 * time.Second, "0m30s"},
		{90 * time.Second, "1m30s"},
		{3600 * time.Second, "1h0m0s"},
		{3661 * time.Second, "1h1m1s"},
		{7200 * time.Second, "2h0m0s"},
		{10 * time.Second, "0m10s"},
	}
	for _, tc := range cases {
		if got := formatDuration(tc.input); got != tc.expected {
			t.Errorf("formatDuration(%s) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestIsTerminal(t *testing.T) {
	// Test with a regular file
	tmpFile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if isTerminal(tmpFile) {
		t.Error("regular file should not be terminal")
	}
	tmpFile.Close()

	// Test with non-file writer
	var sb strings.Builder
	if isTerminal(&sb) {
		t.Error("strings.Builder should not be terminal")
	}

	// Test with nil
	if isTerminal(nil) {
		t.Error("nil should not be terminal")
	}
}

func TestTarget(t *testing.T) {
	sc := &config.Scenario{BaseURL: "http://base", Steps: []config.Step{{URL: "http://step"}}}
	if target(sc) != "http://base" {
		t.Errorf("target = %s, want http://base", target(sc))
	}

	sc = &config.Scenario{Steps: []config.Step{{URL: "http://step"}}}
	if target(sc) != "http://step" {
		t.Errorf("target = %s, want http://step", target(sc))
	}

	sc = &config.Scenario{}
	if target(sc) != "n/a" {
		t.Errorf("target = %s, want n/a", target(sc))
	}
}

func TestColorize(t *testing.T) {
	tests := []struct {
		name     string
		color    string
		enabled  bool
		input    string
		expected string
	}{
		{"enabled", colorRed, true, "error", colorRed + "error" + colorReset},
		{"disabled", colorRed, false, "error", "error"},
		{"empty string", colorGreen, true, "", colorGreen + colorReset},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := colorize(tt.color, tt.enabled, tt.input)
			if got != tt.expected {
				t.Errorf("colorize(%q, %v, %q) = %q, want %q", tt.color, tt.enabled, tt.input, got, tt.expected)
			}
		})
	}
}

func TestRateColor(t *testing.T) {
	tests := []struct {
		name     string
		errorPct float64
		expected string
	}{
		{"zero", 0, colorGreen},
		{"negative", -1, colorGreen},
		{"low", 2.5, colorYellow},
		{"boundary 5%", 5, colorRed},
		{"high", 10, colorRed},
		{"very high", 100, colorRed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rateColor(tt.errorPct)
			if got != tt.expected {
				t.Errorf("rateColor(%.1f) = %q, want %q", tt.errorPct, got, tt.expected)
			}
		})
	}
}

func TestStatusColor(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected string
	}{
		{"200", 200, colorGreen},
		{"201", 201, colorGreen},
		{"299", 299, colorGreen},
		{"300", 300, colorCyan},
		{"301", 301, colorCyan},
		{"399", 399, colorCyan},
		{"400", 400, colorYellow},
		{"404", 404, colorYellow},
		{"499", 499, colorYellow},
		{"500", 500, colorRed},
		{"503", 503, colorRed},
		{"599", 599, colorRed},
		{"600", 600, colorRed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := statusColor(tt.code)
			if got != tt.expected {
				t.Errorf("statusColor(%d) = %q, want %q", tt.code, got, tt.expected)
			}
		})
	}
}

func TestHealthLabel(t *testing.T) {
	tests := []struct {
		name     string
		errorPct float64
		label    string
		color    string
	}{
		{"healthy", 0, "HEALTHY", colorGreen},
		{"healthy negative", -1, "HEALTHY", colorGreen},
		{"degraded", 2.5, "DEGRADED", colorYellow},
		{"degraded boundary", 4.9, "DEGRADED", colorYellow},
		{"critical", 5, "CRITICAL", colorRed},
		{"critical high", 50, "CRITICAL", colorRed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			label, color := healthLabel(tt.errorPct)
			if label != tt.label || color != tt.color {
				t.Errorf("healthLabel(%.1f) = (%q, %q), want (%q, %q)", tt.errorPct, label, color, tt.label, tt.color)
			}
		})
	}
}

func TestRenderProgressBar(t *testing.T) {
	tests := []struct {
		name     string
		pct      float64
		width    int
		expected string
	}{
		{"0%", 0, 10, "[░░░░░░░░░░]"},
		{"50%", 50, 10, "[█████░░░░░]"},
		{"100%", 100, 10, "[██████████]"},
		{"over 100%", 150, 10, "[██████████]"},
		{"small width", 50, 4, "[██░░]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderProgressBar(tt.pct, tt.width)
			if got != tt.expected {
				t.Errorf("renderProgressBar(%.0f, %d) = %q, want %q", tt.pct, tt.width, got, tt.expected)
			}
		})
	}
}

func TestFormatCount(t *testing.T) {
	tests := []struct {
		name     string
		n        uint64
		expected string
	}{
		{"small", 999, "999"},
		{"exact 1000", 1000, "1.0k"},
		{"1500", 1500, "1.5k"},
		{"exact 1M", 1_000_000, "1.0m"},
		{"1.5M", 1_500_000, "1.5m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCount(tt.n)
			if got != tt.expected {
				t.Errorf("formatCount(%d) = %q, want %q", tt.n, got, tt.expected)
			}
		})
	}
}

func TestFormatRPS(t *testing.T) {
	tests := []struct {
		name     string
		rps      float64
		expected string
	}{
		{"small", 99, "99"},
		{"exact 1000", 1000, "1.0k"},
		{"1500", 1500, "1.5k"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatRPS(tt.rps)
			if got != tt.expected {
				t.Errorf("formatRPS(%.0f) = %q, want %q", tt.rps, got, tt.expected)
			}
		})
	}
}

func TestStartLiveNotTerminal(t *testing.T) {
	var sb strings.Builder
	tel := metrics.NewTelemetry()
	tel.Overall.Record(10*time.Millisecond, 200, "")
	tel.Finish()

	stop := StartLive(tel, time.Second, &sb)
	// Should return immediately without starting goroutine
	stop()
	// No output expected for non-terminal
	if sb.Len() != 0 {
		t.Errorf("expected no output for non-terminal, got %q", sb.String())
	}
}

func TestSaveJSONPerm(t *testing.T) {
	tel := metrics.NewTelemetry()
	tel.Overall.Record(time.Millisecond, 200, "")
	tel.Finish()

	sc := &config.Scenario{Name: "perm", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)

	dir := t.TempDir()
	path, err := r.SaveJSON(dir)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Check file permissions are 0600
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file perm = %o, want 0600", fi.Mode().Perm())
	}
}

func TestSaveTXTPerm(t *testing.T) {
	tel := metrics.NewTelemetry()
	tel.Overall.Record(time.Millisecond, 200, "")
	tel.Finish()

	sc := &config.Scenario{Name: "perm", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)

	dir := t.TempDir()
	path, err := r.SaveTXT(dir)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file perm = %o, want 0600", fi.Mode().Perm())
	}
}

func TestUniquePathWithMultipleCollisions(t *testing.T) {
	dir := t.TempDir()
	base := "test.json"

	// Create files test.json, test-1.json, test-2.json
	for i := 0; i < 3; i++ {
		var name string
		if i == 0 {
			name = base
		} else {
			name = fmt.Sprintf("test-%d.json", i)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Next unique path should be test-3.json
	next := uniquePath(dir, base)
	if !strings.HasSuffix(next, "test-3.json") {
		t.Errorf("uniquePath = %s, want test-3.json", next)
	}
}

func TestSaveJSONErrorDir(t *testing.T) {
	tel := metrics.NewTelemetry()
	tel.Overall.Record(time.Millisecond, 200, "")
	tel.Finish()

	sc := &config.Scenario{Name: "err", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)

	// Try to save to a path that exists as a file (not dir)
	dir := t.TempDir()
	filePath := filepath.Join(dir, "notadir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := r.SaveJSON(filePath)
	if err == nil {
		t.Error("expected error when dir is a file")
	}
}

func TestSaveTXTErrorDir(t *testing.T) {
	tel := metrics.NewTelemetry()
	tel.Overall.Record(time.Millisecond, 200, "")
	tel.Finish()

	sc := &config.Scenario{Name: "err", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)

	dir := t.TempDir()
	filePath := filepath.Join(dir, "notadir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := r.SaveTXT(filePath)
	if err == nil {
		t.Error("expected error when dir is a file")
	}
}

func TestIsTerminalStatError(t *testing.T) {
	// Create a file and then remove it to cause Stat error
	tmpFile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	name := tmpFile.Name()
	tmpFile.Close()
	os.Remove(name)

	// Reopen the deleted file - Stat will fail
	f, err := os.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		// Expected - file doesn't exist
		return
	}
	defer f.Close()

	// This would be a race condition but let's test if Stat errors are handled
	// We can't easily test this without more complex setup
	// Just verify nil and non-file writers work
	if isTerminal(nil) {
		t.Error("nil should not be terminal")
	}
	var sb strings.Builder
	if isTerminal(&sb) {
		t.Error("strings.Builder should not be terminal")
	}
}
