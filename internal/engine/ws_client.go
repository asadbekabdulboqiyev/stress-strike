package engine

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// wsReadLimit caps the size of a single WebSocket frame read during a step.
const wsReadLimit = 8 << 10 // 8 KiB

// wsWriteWait bounds control-frame writes (ping/close).
const wsWriteWait = 5 * time.Second

// newWSDialer builds a websocket.Dialer honoring the step timeout and the
// ambient context (so Ctrl+C cancels an in-progress handshake).
func newWSDialer(ctx context.Context, timeout time.Duration) *websocket.Dialer {
	return &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: timeout,
		NetDialContext: func(netCtx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: timeout}
			return d.DialContext(netCtx, network, addr)
		},
	}
}

// wsDial performs the WebSocket handshake against rawURL with rendered headers.
func (e *Engine) wsDial(ctx context.Context, rawURL string, step config.Step, vars map[string]string, timeout time.Duration) (*websocket.Conn, int, error) {
	header := http.Header{}
	for k, v := range step.Headers {
		header.Set(k, render(v, vars))
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, resp, err := newWSDialer(ctx, timeout).DialContext(dialCtx, rawURL, header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return nil, status, err
	}
	conn.SetReadLimit(wsReadLimit)
	return conn, http.StatusSwitchingProtocols, nil
}

// wsClient performs a single WebSocket request/response exchange: it dials the
// given ws:// or wss:// URL, optionally sends step.Body as a text frame, and
// waits for one frame back (bounded by timeout). On success it reports status
// 101 (Switching Protocols) and the received frame body.
//
// This is the one-shot variant kept for library compatibility; the engine's
// load loop uses wsClientForUser, which reuses connections across iterations.
func (e *Engine) wsClient(ctx context.Context, rawURL string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	return e.wsClientForUser(-1, ctx, rawURL, step, vars, timeout)
}

// wsClientForUser drives a WebSocket exchange for virtual user userIndex.
// When keep-alive is enabled and step.Session is set, the connection is pooled
// and reused across iterations (a realistic long-lived socket session): each
// iteration sends one message and reads one reply, measuring pure message RTT.
// A dropped connection is transparently re-established on the next iteration.
// Without step.Session every iteration dials a fresh connection (default,
// matching classic one-shot semantics).
func (e *Engine) wsClientForUser(userIndex int, ctx context.Context, rawURL string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	u, err := url.Parse(rawURL)
	poolable := err == nil && (u.Scheme == "ws" || u.Scheme == "wss") && userIndex >= 0 && e.keepAlive && step.Session
	if !poolable {
		if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") {
			return stepResult{errName: errOther}, nil
		}
		return e.wsOneShot(ctx, rawURL, step, vars, timeout)
	}
	return e.wsPooled(userIndex, ctx, rawURL, step, vars, timeout)
}

// wsOneShot dials, exchanges one message, and closes the connection.
func (e *Engine) wsOneShot(ctx context.Context, rawURL string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	start := time.Now()
	conn, status, err := e.wsDial(ctx, rawURL, step, vars, timeout)
	if err != nil {
		res := classifyNetError(err, time.Since(start))
		res.status = status
		return res, nil
	}
	defer func() { closeWS(conn) }()
	return e.wsExchange(conn, ctx, step, vars, timeout, start)
}

// wsPooled reuses a per-worker WebSocket session across iterations.
func (e *Engine) wsPooled(userIndex int, ctx context.Context, rawURL string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	start := time.Now()
	conn, ok := e.takeWSConn(userIndex, rawURL)
	if !ok {
		// First use (or previous connection failed / URL changed): dial now.
		c, status, err := e.wsDial(ctx, rawURL, step, vars, timeout)
		if err != nil {
			res := classifyNetError(err, time.Since(start))
			res.status = status
			return res, nil
		}
		conn = c
		e.putWSConn(userIndex, rawURL, conn)
	} else {
		// Liveness probe on the reused connection; a stale socket fails fast
		// here so the next iteration re-dials instead of corrupting metrics.
		deadline := timeout
		if deadline > wsWriteWait {
			deadline = wsWriteWait
		}
		if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(deadline)); err != nil {
			closeWS(conn)
			e.dropWSConn(userIndex)
			c, status, err := e.wsDial(ctx, rawURL, step, vars, timeout)
			if err != nil {
				res := classifyNetError(err, time.Since(start))
				res.status = status
				return res, nil
			}
			conn = c
			e.putWSConn(userIndex, rawURL, conn)
		}
	}
	return e.wsExchange(conn, ctx, step, vars, timeout, start)
}

// wsExchange sends step.Body (if any) as a text/binary frame and reads one
// reply frame within timeout. Latency covers the full exchange from start.
func (e *Engine) wsExchange(conn *websocket.Conn, ctx context.Context, step config.Step, vars map[string]string, timeout time.Duration, start time.Time) (stepResult, []byte) {
	frameType := websocket.TextMessage
	if step.FrameType == "binary" {
		frameType = websocket.BinaryMessage
	}

	if step.Body != "" {
		if err := conn.WriteMessage(frameType, []byte(renderBody(step.Body, vars))); err != nil {
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

// closeWS performs a polite WebSocket close: send a Close control frame first
// (best effort), then tear down the underlying TCP connection.
func closeWS(conn *websocket.Conn) {
	if conn == nil {
		return
	}
	_ = conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(wsWriteWait))
	_ = conn.Close()
}

// --- Per-worker connection pools -------------------------------------------

// takeWSConn returns the pooled connection for userIndex. It reports ok=false
// when no healthy session exists (first iteration, prior failure, or the
// target URL changed), removing any stale entry.
func (e *Engine) takeWSConn(userIndex int, rawURL string) (*websocket.Conn, bool) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	c, exists := e.wsConns[userIndex]
	if !exists {
		return nil, false
	}
	if c == nil {
		delete(e.wsConns, userIndex)
		return nil, false
	}
	if _, urlOK := e.wsURLs[userIndex]; !urlOK || e.wsURLs[userIndex] != rawURL {
		closeWS(c)
		delete(e.wsConns, userIndex)
		delete(e.wsURLs, userIndex)
		return nil, false
	}
	return c, true
}

// putWSConn stores a freshly dialed session for userIndex at rawURL.
func (e *Engine) putWSConn(userIndex int, rawURL string, conn *websocket.Conn) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	e.initSessionMaps()
	e.wsConns[userIndex] = conn
	e.wsURLs[userIndex] = rawURL
}

// dropWSConn discards the session for userIndex after a failure.
func (e *Engine) dropWSConn(userIndex int) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	delete(e.wsConns, userIndex)
	delete(e.wsURLs, userIndex)
}

// initSessionMaps lazily allocates the session maps. Callers must hold sessMu.
func (e *Engine) initSessionMaps() {
	if e.wsConns == nil {
		e.wsConns = make(map[int]*websocket.Conn)
		e.wsURLs = make(map[int]string)
	}
	if e.tcpConns == nil {
		e.tcpConns = make(map[int]net.Conn)
	}
}

// closeSessions gracefully drains every pooled protocol session at the end of
// a run: WebSockets receive a proper Close handshake, raw sockets and gRPC
// ClientConns are closed.
func (e *Engine) closeSessions() {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	for _, c := range e.wsConns {
		closeWS(c)
	}
	e.wsConns = nil
	e.wsURLs = nil
	for _, c := range e.tcpConns {
		if c != nil {
			_ = c.Close()
		}
	}
	e.tcpConns = nil
	for _, c := range e.grpcConns {
		if c != nil {
			_ = c.Close()
		}
	}
	e.grpcConns = nil
	e.cookieJars = nil
}
