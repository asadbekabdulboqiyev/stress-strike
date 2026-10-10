// Package otel provides minimal OpenTelemetry hooks. It is no-op by default
// and can be enabled via environment variables.
package otel

import (
	"context"
	"os"
	"strings"
)

var enabled = strings.EqualFold(os.Getenv("STRESS_STRIKE_OTEL_ENABLED"), "true")

// Enabled reports whether OTel is enabled.
func Enabled() bool { return enabled }

// StartSpan returns a context and a no-op span. In a real implementation
// it would start a span and set attributes.
func StartSpan(ctx context.Context, name string) (context.Context, Span) {
	if !Enabled() {
		return ctx, noopSpan{}
	}
	// Minimal stub: real impl would create tracer span.
	return ctx, noopSpan{}
}

// Span is a minimal span interface.
type Span interface {
	End()
	SetString(key, value string)
}

type noopSpan struct{}

func (noopSpan) End()                        {}
func (noopSpan) SetString(string, string)    {}
