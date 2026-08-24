package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"stress-strike/internal/config"
)

// rawReadLimit caps how many bytes are read from a raw socket per step.
const rawReadLimit = 8 << 10 // 8 KiB

// rawClient performs a raw TCP or UDP exchange against target. For TCP it
// dials, sends step.Body (if any) and reads one response within timeout. For
// UDP it sends a single datagram and returns without waiting for a reply
// (unless step.AwaitResponse is set, in which case one reply is awaited).
//
// This is the compatibility wrapper; the engine's load loop uses
// rawClientForUser, which pools TCP connections across iterations.
func (e *Engine) rawClient(ctx context.Context, network, target string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	return e.rawClientForUser(-1, ctx, network, target, step, vars, timeout)
}

// rawClientForUser drives a raw TCP/UDP exchange for virtual user userIndex.
// With keep-alive enabled and step.Session set, TCP connections are pooled per
// worker and reused across iterations (persistent sessions); a broken socket
// is transparently re-dialed. UDP always dials fresh (connectionless).
func (e *Engine) rawClientForUser(userIndex int, ctx context.Context, network, target string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	if network != "tcp" && network != "udp" {
		return stepResult{errName: errOther}, nil
	}

	start := time.Now()

	var conn net.Conn
	if network == "tcp" && userIndex >= 0 && e.keepAlive && step.Session {
		conn = e.takeTCPConn(userIndex)
	}
	if conn == nil {
		dialer := &net.Dialer{Timeout: timeout}
		c, err := dialer.DialContext(ctx, network, target)
		if err != nil {
			return classifyNetError(err, time.Since(start)), nil
		}
		conn = c
		if network == "tcp" && userIndex >= 0 && e.keepAlive && step.Session {
			e.putTCPConn(userIndex, conn)
		}
	}

	if network == "tcp" {
		res, body := e.tcpExchange(conn, userIndex, step, vars, timeout, start)
		if res.errName == errConnection || res.errName == errTimeout {
			// The pooled socket went bad: evict so the next iteration re-dials.
			e.dropTCPConn(userIndex)
			_ = conn.Close()
		}
		return res, body
	}
	return e.udpExchange(conn.(*net.UDPConn), step, vars, timeout, start)
}

// tcpExchange writes step.Body (if any) and reads one response chunk.
func (e *Engine) tcpExchange(conn net.Conn, userIndex int, step config.Step, vars map[string]string, timeout time.Duration, start time.Time) (stepResult, []byte) {
	if step.Body != "" {
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			res := classifyNetError(err, time.Since(start))
			res.status = http.StatusOK
			return res, nil
		}
		if _, err := conn.Write([]byte(renderBody(step.Body, vars))); err != nil {
			return classifyNetError(err, time.Since(start)), nil
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, rawReadLimit)
	n, err := conn.Read(buf)
	latency := time.Since(start)
	if err != nil && !errors.Is(err, io.EOF) {
		res := classifyNetError(err, latency)
		res.status = http.StatusOK
		return res, nil
	}
	return stepResult{latency: latency, status: http.StatusOK}, buf[:n]
}

// udpExchange sends one datagram; when step.AwaitResponse is set it also waits
// for a single reply within timeout and measures the full round trip.
func (e *Engine) udpExchange(conn *net.UDPConn, step config.Step, vars map[string]string, timeout time.Duration, start time.Time) (stepResult, []byte) {
	if step.Body != "" {
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			res := classifyNetError(err, time.Since(start))
			res.status = http.StatusOK
			return res, nil
		}
		if _, err := conn.Write([]byte(renderBody(step.Body, vars))); err != nil {
			return classifyNetError(err, time.Since(start)), nil
		}
	}

	if !step.AwaitResponse {
		// Fire-and-forget: report the send as a successful exchange.
		return stepResult{latency: time.Since(start), status: http.StatusOK}, nil
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, rawReadLimit)
	n, err := conn.Read(buf)
	latency := time.Since(start)
	if err != nil {
		res := classifyNetError(err, latency)
		res.status = http.StatusOK
		return res, nil
	}
	return stepResult{latency: latency, status: http.StatusOK}, buf[:n]
}

// --- Per-worker TCP connection pool -----------------------------------------

// takeTCPConn returns the pooled TCP connection for userIndex, or nil when no
// session exists (first use or after a prior failure evicted the socket).
func (e *Engine) takeTCPConn(userIndex int) net.Conn {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	c := e.tcpConns[userIndex]
	if c == nil {
		delete(e.tcpConns, userIndex)
		return nil
	}
	return c
}

// putTCPConn stores a freshly dialed TCP connection for userIndex.
func (e *Engine) putTCPConn(userIndex int, conn net.Conn) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	e.initSessionMaps()
	e.tcpConns[userIndex] = conn
}

// dropTCPConn discards the pooled connection for userIndex after a failure.
func (e *Engine) dropTCPConn(userIndex int) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	delete(e.tcpConns, userIndex)
}

// classifyNetError maps a raw socket/websocket error to a stepResult, treating
// net timeouts as errTimeout and other net errors as errConnection.
func classifyNetError(err error, elapsed time.Duration) stepResult {
	switch {
	case errors.Is(err, context.Canceled):
		return stepResult{errName: errCanceled}
	case errors.Is(err, context.DeadlineExceeded):
		return stepResult{latency: elapsed, errName: errTimeout}
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return stepResult{latency: elapsed, errName: errTimeout}
		}
		return stepResult{latency: elapsed, errName: errConnection}
	}
	return stepResult{latency: elapsed, errName: errOther}
}
