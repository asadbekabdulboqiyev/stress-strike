package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeTargetURL(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"localhost:8080/health", "http://localhost:8080/health", false},
		{"  example.com  ", "http://example.com", false},
		{"https://api.example.com/x", "https://api.example.com/x", false},
		{"ws://echo.test", "ws://echo.test", false},
		{"wss://secure.test/ws", "wss://secure.test/ws", false},
		{"", "", true},
		{"   ", "", true},
		{"http://", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := normalizeTargetURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("normalizeTargetURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDefaultTestName(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"http://localhost:8080/health", "localhost"},
		{"https://api.example.com/v1/users", "api-example-com"},
		{"https://WWW.Example.COM", "www-example-com"},
		{"notaurl:", "quick-test"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := defaultTestName(tt.url); got != tt.want {
				t.Errorf("defaultTestName(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestParseProfileChoice(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"", "steady", false},
		{"1", "steady", false},
		{"2", "soak", false},
		{"3", "linear-ramp", false},
		{"4", "spike", false},
		{"5", "wave", false},
		{"spike", "spike", false},
		{"SPIKE", "spike", false},
		{"  wave  ", "wave", false},
		{"9", "", true},
		{"banana", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseProfileChoice(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseProfileChoice(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func wizardInput(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

func withTempHistory(t *testing.T) {
	old := historyFilePath
	path := filepath.Join(t.TempDir(), "last-run.json")
	historyFilePath = func() string { return path }
	t.Cleanup(func() { historyFilePath = old })
}

func TestRunWizardDefaults(t *testing.T) {
	withTempHistory(t)
	ans, err := runWizard(strings.NewReader(wizardInput(
		"2",
		"http://localhost:8080/health",
		"",
		"",
		"",
		"",
		"1",
		"",
		"",
		"",
		"",
		"",
		"y",
	)), &strings.Builder{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ans.url != "http://localhost:8080/health" {
		t.Errorf("url = %q", ans.url)
	}
	if ans.method != "GET" {
		t.Errorf("method = %q, want GET", ans.method)
	}
	if ans.profile != "steady" {
		t.Errorf("profile = %q, want steady", ans.profile)
	}
	if ans.users != 10 || ans.duration != 30 || ans.timeout != 5 {
		t.Errorf("defaults users=%d duration=%d timeout=%d", ans.users, ans.duration, ans.timeout)
	}
	if !ans.keepAlive {
		t.Error("keepAlive = false, want true")
	}
	if ans.name != "localhost" {
		t.Errorf("name = %q, want localhost", ans.name)
	}
}

func TestRunWizardFullSpike(t *testing.T) {
	withTempHistory(t)
	in := wizardInput(
		"2",
		"api.example.com",
		"post",
		`{"user":"{{user}}"}`,
		"Content-Type=application/json",
		"Authorization=Bearer tok",
		"",
		"100",
		"60",
		"4",
		"5000",
		"5",
		"15",
		"2000",
		"10",
		"n",
		"",
		"black-friday",
		"y",
	)

	ans, err := runWizard(strings.NewReader(in), &strings.Builder{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ans.url != "http://api.example.com" {
		t.Errorf("url = %q", ans.url)
	}
	if ans.method != "POST" {
		t.Errorf("method = %q, want POST", ans.method)
	}
	if ans.data != `{"user":"{{user}}"}` {
		t.Errorf("data = %q", ans.data)
	}
	if len(ans.headers) != 2 {
		t.Fatalf("headers = %d entries, want 2", len(ans.headers))
	}
	if ans.headers["Authorization"] != "Bearer tok" {
		t.Errorf("Authorization header missing")
	}
	if ans.profile != "spike" {
		t.Errorf("profile = %q, want spike", ans.profile)
	}
	if ans.spikeUsers != 5000 || ans.spikeWarmup != 5 || ans.spikeHold != 15 {
		t.Errorf("spike params users=%d warmup=%d hold=%d", ans.spikeUsers, ans.spikeWarmup, ans.spikeHold)
	}
	if ans.rps != 2000 {
		t.Errorf("rps = %d, want 2000", ans.rps)
	}
	if ans.keepAlive {
		t.Error("keepAlive = true, want false")
	}
	if ans.name != "black-friday" {
		t.Errorf("name = %q, want black-friday", ans.name)
	}
}

func TestRunWizardRecoversFromInvalidURL(t *testing.T) {
	withTempHistory(t)
	in := wizardInput(
		"2",
		"http://",
		"also bad",
		"localhost:8080",
		"",
		"",
		"",
		"",
		"1",
		"",
		"",
		"",
		"",
		"",
		"y",
	)

	ans, err := runWizard(strings.NewReader(in), &strings.Builder{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ans.url != "http://localhost:8080" {
		t.Errorf("url = %q, want http://localhost:8080", ans.url)
	}
}

func TestRunWizardInvalidProfileReprompts(t *testing.T) {
	withTempHistory(t)
	in := wizardInput(
		"2",
		"localhost",
		"",
		"",
		"",
		"",
		"99",
		"banana",
		"3",
		"20",
		"",
		"",
		"",
		"",
		"",
		"y",
	)

	ans, err := runWizard(strings.NewReader(in), &strings.Builder{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ans.profile != "linear-ramp" {
		t.Errorf("profile = %q, want linear-ramp", ans.profile)
	}
	if ans.rampUp != 20 {
		t.Errorf("rampUp = %d, want 20", ans.rampUp)
	}
}

func TestRunWizardDeclinedConfirm(t *testing.T) {
	withTempHistory(t)
	in := wizardInput(
		"2",
		"localhost:8080",
		"",
		"",
		"",
		"",
		"1",
		"",
		"",
		"",
		"",
		"n",
	)

	_, err := runWizard(strings.NewReader(in), &strings.Builder{}, false)
	if !errors.Is(err, errCanceled) {
		t.Fatalf("err = %v, want errCanceled", err)
	}
}

func TestRunWizardRejectsOversizedUsers(t *testing.T) {
	withTempHistory(t)
	in := wizardInput(
		"2",
		"localhost:8080",
		"",
		"",
		"99999999",
		"50",
		"",
		"1",
		"",
		"",
		"",
		"",
		"",
		"y",
	)

	ans, err := runWizard(strings.NewReader(in), &strings.Builder{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ans.users != 50 {
		t.Errorf("users = %d, want 50 (after rejecting oversized input)", ans.users)
	}
}

func TestRunWizardCaptureDebug(t *testing.T) {
	withTempHistory(t)
	in := wizardInput(
		"2",
		"localhost:8080/health",
		"",
		"",
		"",
		"",
		"1",
		"",
		"",
		"",
		"5",
		"my-debug",
		"y",
	)

	ans, err := runWizard(strings.NewReader(in), &strings.Builder{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ans.capture != 5 {
		t.Errorf("capture = %d, want 5", ans.capture)
	}
	if ans.name != "my-debug" {
		t.Errorf("name = %q, want my-debug", ans.name)
	}
}

func TestRunWizardEOFOnRequiredURL(t *testing.T) {
	_, err := runWizard(strings.NewReader("\n"), &strings.Builder{}, false)
	if err == nil {
		t.Fatal("expected error on EOF during required URL prompt, got nil")
	}
}

func TestParseModeChoice(t *testing.T) {
	tests := []struct {
		input    string
		wantGuid bool
		wantErr  bool
	}{
		{"", true, false},
		{"1", true, false},
		{"guided", true, false},
		{"GUIDED", true, false},
		{"2", false, false},
		{"expert", false, false},
		{"3", false, true},
		{"wizard", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseModeChoice(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantGuid {
				t.Errorf("parseModeChoice(%q) = %v, want %v", tt.input, got, tt.wantGuid)
			}
		})
	}
}

func TestIsLocalHost(t *testing.T) {
	local := []string{"localhost", "127.0.0.1", "::1"}
	remote := []string{"api.example.com", "10.0.0.5", "192.168.1.1", ""}

	for _, h := range local {
		if !isLocalHost(h) {
			t.Errorf("isLocalHost(%q) = false, want true", h)
		}
	}
	for _, h := range remote {
		if isLocalHost(h) {
			t.Errorf("isLocalHost(%q) = true, want false", h)
		}
	}
}

func TestAutoTune(t *testing.T) {
	local := autoTune("http://localhost:8080/health")
	if local.users != guidedLocalUsers || local.duration != guidedLocalDur {
		t.Errorf("local users=%d dur=%d, want %d/%d", local.users, local.duration, guidedLocalUsers, guidedLocalDur)
	}
	if local.timeout != 5 || local.rps != 0 {
		t.Errorf("local timeout=%d rps=%d, want 5/0 (unlimited)", local.timeout, local.rps)
	}
	if local.profile != "steady" || local.method != "GET" || !local.keepAlive {
		t.Errorf("local profile/method/keepalive wrong: %+v", local)
	}

	remote := autoTune("https://api.example.com/v1")
	if remote.users != guidedRemoteUsers || remote.duration != guidedRemoteDur {
		t.Errorf("remote users=%d dur=%d, want %d/%d", remote.users, remote.duration, guidedRemoteUsers, guidedRemoteDur)
	}
	if remote.rps != politePublicRPS || remote.timeout != 10 {
		t.Errorf("remote rps=%d timeout=%d, want %d/10 (polite)", remote.rps, remote.timeout, politePublicRPS)
	}
}

func TestRunWizardGuidedLocal(t *testing.T) {
	withTempHistory(t)
	in := wizardInput(
		"1",
		"localhost:8080/health",
		"y",
	)

	ans, err := runWizard(strings.NewReader(in), &strings.Builder{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ans.url != "http://localhost:8080/health" {
		t.Errorf("url = %q", ans.url)
	}
	if ans.users != guidedLocalUsers || ans.duration != guidedLocalDur {
		t.Errorf("users=%d duration=%d, want auto-tuned locals", ans.users, ans.duration)
	}
	if ans.rps != 0 {
		t.Errorf("rps = %d, want 0 (unlimited locally)", ans.rps)
	}
	if ans.name != "localhost" {
		t.Errorf("name = %q, want localhost", ans.name)
	}
}

func TestRunWizardGuidedPublicPolite(t *testing.T) {
	withTempHistory(t)
	in := wizardInput(
		"",
		"api.foo.dev",
		"",
	)

	ans, err := runWizard(strings.NewReader(in), &strings.Builder{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ans.rps != politePublicRPS {
		t.Errorf("rps = %d, want %d (polite default)", ans.rps, politePublicRPS)
	}
	if ans.method != "GET" {
		t.Errorf("method = %q, want GET", ans.method)
	}
}

func TestRunWizardGuidedDeclinedConfirm(t *testing.T) {
	withTempHistory(t)
	in := wizardInput(
		"1",
		"localhost:8080",
		"n",
	)

	_, err := runWizard(strings.NewReader(in), &strings.Builder{}, false)
	if !errors.Is(err, errCanceled) {
		t.Fatalf("err = %v, want errCanceled", err)
	}
}

func TestLastRunRoundTrip(t *testing.T) {
	old := historyFilePath
	t.Cleanup(func() { historyFilePath = old })
	path := filepath.Join(t.TempDir(), "last-run.json")
	historyFilePath = func() string { return path }

	if got := loadLastRun(); got.URL != "" {
		t.Errorf("expected empty lastRun, got %+v", got)
	}

	saveLastRun(lastRun{Name: "my-test", URL: "http://localhost:9999"})
	got := loadLastRun()
	if got.Name != "my-test" || got.URL != "http://localhost:9999" {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestLastRunSkipsEmptyURL(t *testing.T) {
	old := historyFilePath
	t.Cleanup(func() { historyFilePath = old })
	path := filepath.Join(t.TempDir(), "last-run.json")
	historyFilePath = func() string { return path }

	saveLastRun(lastRun{Name: "x", URL: ""})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected no file for empty URL")
	}
}

func TestRunWizardWavePeriod(t *testing.T) {
	withTempHistory(t)
	in := wizardInput(
		"2",
		"localhost:8080",
		"",
		"",
		"",
		"",
		"5",
		"45",
		"",
		"",
		"",
		"",
		"",
		"y",
	)

	ans, err := runWizard(strings.NewReader(in), &strings.Builder{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ans.profile != "wave" {
		t.Errorf("profile = %q, want wave", ans.profile)
	}
	if ans.wavePeriod != 45 {
		t.Errorf("wavePeriod = %d, want 45", ans.wavePeriod)
	}
}
