package siem

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTelegramServer points telegramAPIBase at an httptest server for the
// duration of the test and restores the real API root afterwards.
func newTelegramServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	old := telegramAPIBase
	telegramAPIBase = srv.URL
	t.Cleanup(func() {
		telegramAPIBase = old
		srv.Close()
	})
	return srv
}

func TestSendTelegramSuccess(t *testing.T) {
	var (
		gotPath string
		gotCT   string
		gotBody struct {
			ChatID    string `json:"chat_id"`
			Text      string `json:"text"`
			ParseMode string `json:"parse_mode"`
		}
	)

	newTelegramServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	})

	cfg := TelegramConfig{BotToken: "123:ABC", ChatID: "-100200", Timeout: 2 * time.Second}
	alert := TelegramAlert{
		Timestamp: "2026-01-02T03:04:05Z",
		Source:    "scanner",
		Severity:  "high",
		Message:   "SQL injection confirmed",
		Fields:    map[string]string{"endpoint": "/login"},
	}

	if err := SendTelegram(cfg, alert); err != nil {
		t.Fatalf("SendTelegram: %v", err)
	}
	if gotPath != "/bot123:ABC/sendMessage" {
		t.Errorf("path = %q", gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if gotBody.ChatID != "-100200" {
		t.Errorf("chat_id = %q", gotBody.ChatID)
	}
	if gotBody.ParseMode != "Markdown" {
		t.Errorf("parse_mode = %q", gotBody.ParseMode)
	}
	for _, want := range []string{"high", "scanner", "SQL injection confirmed", "/login", "2026-01-02T03:04:05Z"} {
		if !strings.Contains(gotBody.Text, want) {
			t.Errorf("text missing %q:\n%s", want, gotBody.Text)
		}
	}
}

func TestSendTelegramMissingConfig(t *testing.T) {
	cases := []TelegramConfig{
		{ChatID: "1"},
		{BotToken: "t"},
		{},
	}
	for _, cfg := range cases {
		if err := SendTelegram(cfg, TelegramAlert{}); err == nil {
			t.Errorf("expected config error for %+v", cfg)
		} else if !strings.Contains(err.Error(), "must be configured") {
			t.Errorf("error = %v", err)
		}
	}
}

func TestSendTelegramRateLimited(t *testing.T) {
	newTelegramServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"ok":false,"description":"Too Many Requests: retry after 30","parameters":{"retry_after":30}}`))
	})

	err := SendTelegram(TelegramConfig{BotToken: "t", ChatID: "c"}, TelegramAlert{})
	if err == nil || !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "retry after 30") {
		t.Fatalf("error = %v, want 429 with description", err)
	}
}

func TestSendTelegramAPIReportsNotOK(t *testing.T) {
	newTelegramServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"description":"Bad Request: chat not found"}`))
	})

	err := SendTelegram(TelegramConfig{BotToken: "t", ChatID: "c"}, TelegramAlert{})
	if err == nil || !strings.Contains(err.Error(), "chat not found") {
		t.Fatalf("error = %v, want API description", err)
	}
}

func TestSendTelegramBadJSONResponse(t *testing.T) {
	newTelegramServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not-json`))
	})

	err := SendTelegram(TelegramConfig{BotToken: "t", ChatID: "c"}, TelegramAlert{})
	if err == nil || !strings.Contains(err.Error(), "parse response") {
		t.Fatalf("error = %v, want parse error", err)
	}
}

func TestSendTelegramHonoursTimeout(t *testing.T) {
	newTelegramServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	start := time.Now()
	err := SendTelegram(TelegramConfig{BotToken: "t", ChatID: "c", Timeout: 30 * time.Millisecond}, TelegramAlert{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("call took %v, timeout was not applied", elapsed)
	}
}

func TestFormatAlert(t *testing.T) {
	msg := formatAlert(TelegramAlert{
		Timestamp: "2026-01-02T03:04:05Z",
		Source:    "siem",
		Severity:  "critical",
		Message:   "beacon detected",
		Fields:    map[string]string{"host": "10.0.0.5"},
	})

	for _, want := range []string{
		"*Alert:* critical",
		"*Source:* siem",
		"*Message:* beacon detected",
		"`host`: 10.0.0.5",
		"*Timestamp:* 2026-01-02T03:04:05Z",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("alert missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "*Fields:*") == false {
		t.Errorf("expected fields section:\n%s", msg)
	}
}

func TestFormatAlertWithoutFields(t *testing.T) {
	msg := formatAlert(TelegramAlert{Severity: "low", Source: "x", Message: "m", Timestamp: "t"})
	if strings.Contains(msg, "*Fields:*") {
		t.Errorf("unexpected fields section:\n%s", msg)
	}
}

func TestEventToTelegramAlert(t *testing.T) {
	ts := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	ev := Event{
		Timestamp: ts,
		Source:    "fuzz",
		Severity:  "medium",
		Message:   "crash",
		Fields:    map[string]string{"file": "a.txt"},
	}

	alert := EventToTelegramAlert(ev)
	if alert.Timestamp != "2026-02-03T04:05:06Z" {
		t.Errorf("Timestamp = %q", alert.Timestamp)
	}
	if alert.Source != ev.Source || alert.Severity != ev.Severity || alert.Message != ev.Message {
		t.Errorf("alert fields not copied: %+v", alert)
	}
	if alert.Fields["file"] != "a.txt" {
		t.Errorf("Fields = %+v", alert.Fields)
	}
}

func TestDefaultTelegramConfig(t *testing.T) {
	cfg := DefaultTelegramConfig()
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", cfg.Timeout)
	}
	if cfg.BotToken != "" || cfg.ChatID != "" {
		t.Errorf("defaults should not invent credentials: %+v", cfg)
	}
}

func TestSendTelegramDefaultsTimeoutWhenUnset(t *testing.T) {
	newTelegramServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	// Timeout <= 0 must be replaced by a usable default rather than creating a
	// context that is already expired.
	if err := SendTelegram(TelegramConfig{BotToken: "t", ChatID: "c"}, TelegramAlert{}); err != nil {
		t.Fatalf("SendTelegram with zero timeout: %v", err)
	}
}
