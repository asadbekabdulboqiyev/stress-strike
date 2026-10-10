// Package siem provides a best-effort webhook notifier for SIEM ingestion.
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Event is a minimal SIEM event.
type Event struct {
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Severity  string            `json:"severity"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// Notifier posts events to a webhook endpoint.
type Notifier struct {
	URL    string
	Client *http.Client
}

// Send posts event best-effort.
func (n Notifier) Send(ctx context.Context, ev Event) error {
	if n.URL == "" {
		return nil
	}
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(b))
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
		return fmt.Errorf("siem webhook returned %s", resp.Status)
	}
	return nil
}
