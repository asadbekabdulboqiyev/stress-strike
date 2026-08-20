package engine

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"

	"stress-strike/internal/config"
)

// wsReadLimit caps the size of a single WebSocket frame read during a step.
const wsReadLimit = 8 << 10 // 8 KiB

// wsClient performs a single WebSocket request/response exchange: it dials the
// given ws:// or wss:// URL, optionally sends step.Body as a text frame, and
// waits for one frame back (bounded by timeout). On success it reports status
// 101 (Switching Protocols) and the received frame body.
func (e *Engine) wsClient(ctx context.Context, rawURL string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return stepResult{errName: errOther}, nil
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return stepResult{errName: errOther}, nil
	}

	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: timeout,
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, addr)
		},
	}

	header := http.Header{}
	for k, v := range step.Headers {
		header.Set(k, render(v, vars))
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	start := time.Now()
	conn, resp, err := dialer.DialContext(dialCtx, rawURL, header)
	cancel()
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		res := classifyNetError(err, time.Since(start))
		res.status = status
		return res, nil
	}
	defer conn.Close()
	conn.SetReadLimit(wsReadLimit)

	if step.Body != "" {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(renderBody(step.Body, vars))); err != nil {
			res := classifyNetError(err, time.Since(start))
			res.status = http.StatusSwitchingProtocols
			return res, nil
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	_, body, err := conn.ReadMessage()
	latency := time.Since(start)
	if err != nil {
		res := classifyNetError(err, latency)
		res.status = http.StatusSwitchingProtocols
		return res, nil
	}
	return stepResult{latency: latency, status: http.StatusSwitchingProtocols}, body
}
