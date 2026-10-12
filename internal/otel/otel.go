// Package otel wires the OpenTelemetry tracing SDK into stress-strike.
//
// Tracing is opt-in: nothing is exported unless Start (or SetGlobal) is called
// with a configured Provider. When tracing is off every helper degrades to a
// zero-allocation no-op, so the hot path never pays for it.
package otel

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// Config controls the OTLP/HTTP trace exporter.
type Config struct {
	Enabled     bool              // master switch; false = no provider installed
	Endpoint    string            // OTLP/HTTP collector host:port (e.g. localhost:4318)
	URLPath     string            // exporter path, default /v1/traces
	Insecure    bool              // plaintext HTTP (default true for localhost)
	ServiceName string            // resource service.name
	SampleRatio float64           // 0..1 head sampling ratio, default 1
	Headers     map[string]string // extra headers (e.g. an auth token)
	Timeout     time.Duration     // per-export timeout, default 5s
}

// ConfigFromEnv builds a Config from the standard OTEL_* environment variables
// plus the stress-strike specific STRESS_STRIKE_OTEL_ENABLED switch.
func ConfigFromEnv() Config {
	cfg := Config{
		Enabled:     envBool("STRESS_STRIKE_OTEL_ENABLED", false),
		Endpoint:    firstNonEmpty(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")),
		ServiceName: firstNonEmpty(os.Getenv("OTEL_SERVICE_NAME"), "stress-strike"),
		SampleRatio: 1,
	}
	if v := os.Getenv("OTEL_EXPORTER_OTLP_INSECURE"); v != "" {
		cfg.Insecure = envBool("OTEL_EXPORTER_OTLP_INSECURE", true)
	} else {
		cfg.Insecure = true
	}
	if v := os.Getenv("OTEL_TRACES_SAMPLER_ARG"); v != "" {
		if r, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.SampleRatio = r
		}
	}
	// OTEL endpoints are usually full URLs; the SDK wants a bare host:port.
	cfg.Endpoint = strings.TrimPrefix(strings.TrimPrefix(cfg.Endpoint, "https://"), "http://")
	if i := strings.IndexByte(cfg.Endpoint, '/'); i >= 0 {
		cfg.Endpoint = cfg.Endpoint[:i]
	}
	return cfg
}

// Provider owns a TracerProvider and its exporter.
type Provider struct {
	tp     *sdktrace.TracerProvider
	tracer oteltrace.Tracer

	mu        sync.Mutex
	closed    bool
	closedErr error
}

// Start builds an OTLP/HTTP exporter and installs a TracerProvider. The
// exporter connects lazily, so Start succeeds even when the collector is not
// running yet; exports simply fail (and are reported through the error handler)
// until it comes up.
func Start(ctx context.Context, cfg Config) (*Provider, error) {
	exp, err := newExporter(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return newProvider(cfg, exp), nil
}

// newExporter builds the OTLP/HTTP trace exporter.
func newExporter(ctx context.Context, cfg Config) (sdktrace.SpanExporter, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, fmt.Errorf("otel: endpoint is required when tracing is enabled")
	}
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(cfg.Endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if cfg.URLPath != "" {
		opts = append(opts, otlptracehttp.WithURLPath(cfg.URLPath))
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
	}
	if cfg.Timeout > 0 {
		opts = append(opts, otlptracehttp.WithTimeout(cfg.Timeout))
	}
	return otlptracehttp.New(ctx, opts...)
}

// newProvider assembles a Provider around an arbitrary exporter. Kept separate
// so tests can inject an in-memory exporter instead of a network one.
func newProvider(cfg Config, exp sdktrace.SpanExporter) *Provider {
	ratio := cfg.SampleRatio
	if ratio <= 0 || ratio > 1 {
		ratio = 1
	}
	svc := cfg.ServiceName
	if svc == "" {
		svc = "stress-strike"
	}
	res := resource.NewSchemaless(attribute.String("service.name", svc))

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	)
	otel.SetTracerProvider(tp)
	p := &Provider{tp: tp, tracer: tp.Tracer("github.com/asadbekabdulboqiyev/stress-strike")}
	SetGlobal(p)
	return p
}

// Tracer returns the underlying OpenTelemetry tracer.
func (p *Provider) Tracer() oteltrace.Tracer { return p.tracer }

// Start begins a span named name and returns the updated context.
func (p *Provider) Start(ctx context.Context, name string) (context.Context, Span) {
	if p == nil {
		return ctx, noopSpan{}
	}
	ctx, s := p.tracer.Start(ctx, name)
	return ctx, otelSpan{s: s}
}

// Middleware traces each HTTP request: method, target, status and duration.
func (p *Provider) Middleware(next http.Handler) http.Handler {
	if p == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, sp := p.Start(r.Context(), r.Method+" "+r.URL.Path)
		defer sp.End()
		sp.SetString("http.method", r.Method)
		sp.SetString("http.target", r.URL.Path)
		sp.SetString("http.host", r.Host)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(ctx))
		sp.SetInt("http.status_code", int64(rec.status))
		if rec.status >= 500 {
			sp.RecordError(fmt.Errorf("http %d", rec.status))
		}
	})
}

// ForceFlush exports any spans still buffered in the batch processor without
// shutting the provider down. Call it before a long-lived process exits so the
// final traces are not lost.
func (p *Provider) ForceFlush(ctx context.Context) error {
	if p == nil {
		return nil
	}
	return p.tp.ForceFlush(ctx)
}

// Shutdown flushes buffered spans and stops the exporter. Safe to call more
// than once.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.closedErr
	}
	p.closed = true
	p.closedErr = p.tp.Shutdown(ctx)
	return p.closedErr
}

// --- global provider --------------------------------------------------------

var global struct {
	mu sync.RWMutex
	p  *Provider
}

// SetGlobal installs p as the process-wide provider used by StartSpan.
func SetGlobal(p *Provider) {
	global.mu.Lock()
	global.p = p
	global.mu.Unlock()
}

// Global returns the installed provider, or nil when tracing is off.
func Global() *Provider {
	global.mu.RLock()
	defer global.mu.RUnlock()
	return global.p
}

// Enabled reports whether tracing is active (a provider has been installed).
func Enabled() bool { return Global() != nil }

// StartSpan starts a span on the global provider, or returns a no-op span when
// tracing is disabled.
func StartSpan(ctx context.Context, name string) (context.Context, Span) {
	if p := Global(); p != nil {
		return p.Start(ctx, name)
	}
	return ctx, noopSpan{}
}

// --- Span abstraction -------------------------------------------------------

// Span is the minimal tracing surface used across stress-strike. It is backed
// by a real OpenTelemetry span when tracing is enabled.
type Span interface {
	End()
	SetString(key, value string)
	SetInt(key string, value int64)
	SetBool(key string, value bool)
	RecordError(err error)
	TraceID() string
	SpanID() string
	IsRecording() bool
}

type otelSpan struct{ s oteltrace.Span }

func (x otelSpan) End()                     { x.s.End() }
func (x otelSpan) SetString(k, v string)    { x.s.SetAttributes(attribute.String(k, v)) }
func (x otelSpan) SetInt(k string, v int64) { x.s.SetAttributes(attribute.Int64(k, v)) }
func (x otelSpan) SetBool(k string, v bool) { x.s.SetAttributes(attribute.Bool(k, v)) }
func (x otelSpan) TraceID() string          { return x.s.SpanContext().TraceID().String() }
func (x otelSpan) SpanID() string           { return x.s.SpanContext().SpanID().String() }
func (x otelSpan) IsRecording() bool        { return x.s.IsRecording() }
func (x otelSpan) RecordError(err error) {
	if err == nil {
		return
	}
	x.s.RecordError(err)
	x.s.SetStatus(codes.Error, err.Error())
}

type noopSpan struct{}

func (noopSpan) End()                     {}
func (noopSpan) SetString(string, string) {}
func (noopSpan) SetInt(string, int64)     {}
func (noopSpan) SetBool(string, bool)     {}
func (noopSpan) RecordError(error)        {}
func (noopSpan) TraceID() string          { return "" }
func (noopSpan) SpanID() string           { return "" }
func (noopSpan) IsRecording() bool        { return false }

// --- helpers ----------------------------------------------------------------

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
	}
	return r.ResponseWriter.Write(b)
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
