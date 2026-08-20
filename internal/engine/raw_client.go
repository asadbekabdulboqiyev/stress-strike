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
// UDP it sends a single datagram and returns without waiting for a reply.
func (e *Engine) rawClient(ctx context.Context, network, target string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	if network != "tcp" && network != "udp" {
		return stepResult{errName: errOther}, nil
	}

	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, target)
	if err != nil {
		return classifyNetError(err, time.Since(start)), nil
	}
	defer conn.Close()

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

	if network == "udp" {
		// UDP is fire-and-forget: report the send as a successful exchange.
		return stepResult{latency: time.Since(start), status: http.StatusOK}, nil
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
