package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	tep "github.com/asadbekabdulboqiyev/teno-event-protocol/packages/tep-go/tep"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// tepClient forges a signed TEP envelope and pushes it to the consumer at
// step.URL. The payload is parsed from step.Body (invalid JSON falls back to
// an empty payload). Latency is measured end-to-end over the wire so the
// result feeds the same RPS/latency aggregates as every other protocol.
func (e *Engine) tepClient(ctx context.Context, step config.Step, timeout time.Duration) (stepResult, []byte) {
	var payload map[string]any
	if step.Body != "" {
		if err := json.Unmarshal([]byte(step.Body), &payload); err != nil {
			return stepResult{errName: errOther}, []byte(fmt.Sprintf("invalid TEP JSON payload: %v", err))
		}
	}
	if payload == nil {
		payload = map[string]any{}
	}

	capture := &responseCapture{}
	client, err := tep.NewClient(tep.ClientOptions{
		URL:    step.URL,
		Secret: []byte(step.TepSecret),
		Key:    step.TepKey,
		Source: step.TepSource,
		// TEP in-protocol retries are disabled for load testing: stress-strike
		// drives retries/loops itself, so a single fast attempt keeps timings
		// comparable with the other protocol clients. MaxRetries=1 means at
		// most 2 fast attempts (BaseDelay=1ms avoids Go's zero→default override).
		MaxRetries: 1,
		BaseDelay:  time.Millisecond,
		MaxDelay:   time.Millisecond,
		HTTP:       &http.Client{Transport: capture, Timeout: timeout},
	})
	if err != nil {
		return stepResult{errName: errOther}, []byte(err.Error())
	}

	env := tep.NewEnvelope(step.TepType, step.TepSource, payload)

	start := time.Now()
	result, err := client.Push(ctx, env)
	latency := time.Since(start)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return stepResult{latency: latency, errName: errTimeout}, nil
		}
		if capture.status >= 400 {
			// The consumer answered with an error status: classify by the real
			// HTTP code so 401/4xx/5xx split into the right error buckets.
			res := stepResult{latency: latency, status: capture.status}
			if capture.status >= 500 {
				res.errName = errStatus5xx
			} else {
				res.errName = errStatus4xx
			}
			return res, capture.body
		}
		return classifyError(err, latency), nil
	}

	status := 200
	switch result.Code {
	case tep.CodeOK, tep.CodeEventAccepted, tep.CodeDuplicateEvent:
		status = 200
	case tep.CodeEventNotFound:
		status = 404
	case tep.CodeUpstreamError:
		status = 502
	case tep.CodeSigInvalid, tep.CodeVersionUnsupported:
		status = 401
	default:
		status = 400
	}
	if status >= 500 {
		return stepResult{latency: latency, status: status, errName: errStatus5xx}, capture.body
	}
	if status >= 400 {
		return stepResult{latency: latency, status: status, errName: errStatus4xx}, capture.body
	}
	return stepResult{latency: latency, status: status}, capture.body
}

// responseCapture is an http.RoundTripper that mirrors the wire response body
// and status so step results can carry them for assertions/capture output.
type responseCapture struct {
	inner  http.RoundTripper
	status int
	body   []byte
}

func (c *responseCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.inner == nil {
		c.inner = http.DefaultTransport
	}
	resp, err := c.inner.RoundTrip(req)
	if err != nil {
		c.status = 0
		return resp, err
	}
	c.status = resp.StatusCode
	raw, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(strings.NewReader(string(raw)))
	if readErr == nil {
		c.body = raw
	}
	return resp, nil
}
