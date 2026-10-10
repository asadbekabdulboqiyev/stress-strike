package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultNotifyTimeout bounds a webhook call so a slow receiver can never stall
// a test run.
const DefaultNotifyTimeout = 5 * time.Second

// Notifier posts audit entries to a webhook. It is best-effort: a failure to
// notify is reported by the caller but must never abort the run.
type Notifier struct {
	// URL is the webhook endpoint. Empty disables notification.
	URL string
	// Format is "slack" (posts {"text": ...}) or "json" (posts the entry).
	Format string
	// Client is optional; a client with DefaultNotifyTimeout is used otherwise.
	Client *http.Client
}

// Enabled reports whether the notifier will do anything.
func (n Notifier) Enabled() bool { return strings.TrimSpace(n.URL) != "" }

// Notify posts e to the webhook.
func (n Notifier) Notify(ctx context.Context, e Entry) error {
	if !n.Enabled() {
		return nil
	}
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultNotifyTimeout}
	}

	var body []byte
	var err error
	switch strings.ToLower(n.Format) {
	case "json", "":
		if strings.Contains(n.URL, "hooks.slack.com") {
			body, err = json.Marshal(map[string]string{"text": slackText(e)})
		} else {
			body, err = json.Marshal(e)
		}
	case "slack":
		body, err = json.Marshal(map[string]string{"text": slackText(e)})
	default:
		return fmt.Errorf("unknown notify format %q", n.Format)
	}
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func slackText(e Entry) string {
	verb := "allowed"
	if !e.Allowed {
		verb = "BLOCKED"
	}
	return fmt.Sprintf("[stress-strike] %s: %s %s (target=%s, class=%s, actor=%s, rule=%s)",
		verb, e.Action, e.Time.Format(time.RFC3339), strings.Join(e.Targets, ","), e.Class, e.Actor, e.Rule)
}
