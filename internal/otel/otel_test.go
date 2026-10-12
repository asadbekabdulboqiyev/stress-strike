package otel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func withInMemory(t *testing.T, cfg Config) (*Provider, *tracetest.InMemoryExporter) {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	p := newProvider(cfg, exp)
	t.Cleanup(func() {
		_ = p.Shutdown(context.Background())
		SetGlobal(nil)
	})
	return p, exp
}

func attr(s tracetest.SpanStub, key string) (string, bool) {
	for _, kv := range s.Attributes {
		if string(kv.Key) == key {
			return kv.Value.String(), true
		}
	}
	return "", false
}

// Tracing is a no-op until a provider is installed.
func TestStartSpanNoopWhenDisabled(t *testing.T) {
	SetGlobal(nil)
	ctx, sp := StartSpan(context.Background(), "x")
	if ctx == nil {
		t.Fatal("ctx must not be nil")
	}
	if sp.IsRecording() {
		t.Error("noop span should not be recording")
	}
	sp.SetString("k", "v")
	sp.SetInt("n", 1)
	sp.SetBool("b", true)
	sp.RecordError(errors.New("boom")) // must not panic
	sp.End()
	if Enabled() {
		t.Error("Enabled() should be false with no provider")
	}
}

func TestProviderRecordsSpanWithAttributes(t *testing.T) {
	p, exp := withInMemory(t, Config{ServiceName: "svc"})
	if !Enabled() {
		t.Fatal("Enabled() should be true after newProvider")
	}
	_, sp := p.Start(context.Background(), "iteration")
	sp.SetString("step", "login")
	sp.SetInt("status", 200)
	sp.SetBool("ok", true)
	if !sp.IsRecording() {
		t.Error("span should be recording")
	}
	if sp.TraceID() == "" || sp.SpanID() == "" {
		t.Error("span ids should be populated")
	}
	sp.End()

	if err := p.ForceFlush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got := spans[0].Name; got != "iteration" {
		t.Errorf("span name = %q", got)
	}
	if v, ok := attr(spans[0], "step"); !ok || v != "login" {
		t.Errorf("step attr = %q ok=%v", v, ok)
	}
}

func TestMiddlewareRecordsStatusAndError(t *testing.T) {
	p, exp := withInMemory(t, Config{})
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("nope"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if err := p.ForceFlush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if v, _ := attr(spans[0], "http.status_code"); v != "503" {
		t.Errorf("http.status_code = %q, want 503", v)
	}
	if v, _ := attr(spans[0], "http.method"); v != "GET" {
		t.Errorf("http.method = %q, want GET", v)
	}
}

func TestShutdownIdempotent(t *testing.T) {
	p, _ := withInMemory(t, Config{})
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("second shutdown should be nil, got %v", err)
	}
}

func TestStartRequiresEndpoint(t *testing.T) {
	if _, err := Start(context.Background(), Config{Enabled: true}); err == nil {
		t.Error("Start without endpoint should fail")
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("STRESS_STRIKE_OTEL_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.example:4318/v1/traces")
	t.Setenv("OTEL_SERVICE_NAME", "my-svc")
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "0.25")

	cfg := ConfigFromEnv()
	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.Endpoint != "collector.example:4318" {
		t.Errorf("endpoint = %q, want collector.example:4318", cfg.Endpoint)
	}
	if cfg.ServiceName != "my-svc" {
		t.Errorf("service = %q", cfg.ServiceName)
	}
	if cfg.SampleRatio != 0.25 {
		t.Errorf("sample ratio = %v, want 0.25", cfg.SampleRatio)
	}
}

func TestNilProviderSafe(t *testing.T) {
	var p *Provider
	ctx, sp := p.Start(context.Background(), "x")
	if ctx == nil || sp.IsRecording() {
		t.Error("nil provider must degrade to a no-op span")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("nil provider Shutdown = %v", err)
	}
	called := false
	h := p.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Error("nil provider middleware must pass through")
	}
	_ = time.Second
}
