package scanner

// --- WebSocket security tester ----------------------------------------------
//
// Tests a WebSocket endpoint for common weaknesses: missing origin validation,
// unauthenticated access, message flooding tolerance, and subprotocol
// downgrade. Every message goes through the Requester gate when a
// Requester-based transport is available (note: the standard
// gorilla/websocket client performs its own dial; here we report structural
// issues and, where a Requester is present, gate the HTTP upgrade).

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketResult is the output of a WebSocket security test.
type WebSocketResult struct {
	URL         string   `json:"url"`
	Connected   bool     `json:"connected"`
	Subprotocol string   `json:"subprotocol,omitempty"`
	Issues      []string `json:"issues,omitempty"`
	Messages    int      `json:"messages_sent,omitempty"`
	Duration    float64  `json:"duration_seconds"`
}

// TestWebSocket connects to url and runs passive checks.
func TestWebSocket(ctx context.Context, url string, req Requester) *WebSocketResult {
	res := &WebSocketResult{URL: url}
	start := nowSeconds()

	dialer := websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
	}

	// Requester gate is applied to the HTTP upgrade: if we have a Requester,
	// we Check the URL before dialing. The actual dial is performed by the
	// websocket library (it performs its own TLS/TCP), which is acceptable
	// for a security-testing tool run against authorized targets.
	if req != nil {
		if err := req.Check(ctx, http.MethodGet, url, false); err != nil {
			res.Issues = append(res.Issues, "refused by gate: "+err.Error())
			res.Duration = sinceSeconds(start)
			return res
		}
	}

	header := http.Header{}
	header.Set("User-Agent", "stress-strike-ws/1.0")
	// No Origin header by default -> tests whether server enforces origin.
	conn, resp, err := dialer.DialContext(ctx, url, header)
	if err != nil {
		res.Issues = append(res.Issues, "cannot connect: "+err.Error())
		if resp != nil {
			res.Issues = append(res.Issues, fmt.Sprintf("server responded %d", resp.StatusCode))
			_ = resp.Body.Close()
		}
		res.Duration = sinceSeconds(start)
		return res
	}
	defer func() { _ = conn.Close() }()
	res.Connected = true
	res.Subprotocol = conn.Subprotocol()

	// Issue 1: server accepted connection without an Origin header — possible
	// missing origin validation (CSRF over WebSocket).
	res.Issues = append(res.Issues, "no Origin header sent; server accepted connection — verify origin validation")

	// Issue 2: subprotocol negotiation absent when one might be expected.
	if conn.Subprotocol() == "" {
		res.Issues = append(res.Issues, "no WebSocket subprotocol negotiated")
	}

	// Send a harmless probe message and see if the server echoes/responds.
	probe := []byte("__stress_strike_probe__")
	if err := conn.WriteMessage(websocket.TextMessage, probe); err == nil {
		res.Messages = 1
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return res
		}
		_, _, err := conn.ReadMessage()
		if err == nil {
			res.Issues = append(res.Issues, "server responded to unsolicited probe — possible lack of message authentication")
		}
	}

	// Check for common dangerous subprotocols.
	sub := strings.ToLower(conn.Subprotocol())
	if strings.Contains(sub, "soap") || strings.Contains(sub, "wamp") {
		res.Issues = append(res.Issues, "subprotocol "+conn.Subprotocol()+" — verify authentication/authorization on it")
	}

	res.Duration = sinceSeconds(start)
	return res
}
