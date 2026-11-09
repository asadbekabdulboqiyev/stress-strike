package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TelegramConfig holds the configuration for sending alerts to a Telegram chat.
type TelegramConfig struct {
	// BotToken is the Telegram Bot Token obtained from @BotFather.
	BotToken string
	// ChatID is the target chat ID (numeric for groups, @username for supergroups).
	ChatID string
	// Timeout per request. Default: 10s
	Timeout time.Duration
}

// DefaultTelegramConfig returns saner defaults.
func DefaultTelegramConfig() TelegramConfig {
	return TelegramConfig{
		Timeout: 10 * time.Second,
	}
}

// TelegramAlert represents a structured alert sent to Telegram.
type TelegramAlert struct {
	Timestamp string            `json:"timestamp"`
	Source    string            `json:"source"`
	Severity  string            `json:"severity"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// SendTelegram sends a Telegram alert to the configured chat.
//
// This is a "0 cost" operation — it only uses the operator's outbound HTTPS
// connection. No external services beyond Telegram's free API are used.
func SendTelegram(cfg TelegramConfig, alert TelegramAlert) error {
	if cfg.BotToken == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram: bot token and chat ID must be configured")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.BotToken)

	payload := map[string]any{
		"chat_id":    cfg.ChatID,
		"text":       formatAlert(alert),
		"parse_mode": "Markdown",
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram: marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("telegram: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("telegram: send request: %w", err)
	}
	defer resp.Body.Close()

	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("telegram: read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("telegram: server returned %d: %s", resp.StatusCode, string(resBody))
	}

	var result struct {
		Ok    bool   `json:"ok"`
		Error string `json:"description"`
	}
	if err := json.Unmarshal(resBody, &result); err != nil {
		return fmt.Errorf("telegram: parse response: %w", err)
	}
	if !result.Ok {
		return fmt.Errorf("telegram: API error: %s", result.Error)
	}

	return nil
}

// formatAlert formats a TelegramAlert into a Markdown string.
func formatAlert(a TelegramAlert) string {
	var b strings.Builder
	b.WriteString("*Alert:* " + a.Severity + "\n")
	b.WriteString("*Source:* " + a.Source + "\n")
	b.WriteString("*Message:* " + a.Message + "\n")
	if len(a.Fields) > 0 {
		b.WriteString("\n*Fields:*\n")
		for k, v := range a.Fields {
			b.WriteString(fmt.Sprintf("`%s`: %s\n", k, v))
		}
	}
	b.WriteString("\n*Timestamp:* " + a.Timestamp)
	return b.String()
}

// EventToTelegramAlert converts a siem.Event into a TelegramAlert.
func EventToTelegramAlert(ev Event) TelegramAlert {
	return TelegramAlert{
		Timestamp: ev.Timestamp.Format(time.RFC3339),
		Source:    ev.Source,
		Severity:  ev.Severity,
		Message:   ev.Message,
		Fields:    ev.Fields,
	}
}
