package opsserver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/health"
)

func TestHealthzAlwaysOK(t *testing.T) {
	s := New(Options{Addr: "127.0.0.1:0"})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("healthz body = %q", rec.Body.String())
	}
}

func TestReadyzPassesWithNoChecks(t *testing.T) {
	s := New(Options{Addr: "127.0.0.1:0"})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz = %d, want 200", rec.Code)
	}
}

func TestReadyzFailsWhenCheckFails(t *testing.T) {
	checker := health.NewChecker()
	checker.Register("boom", func(context.Context) error { return errors.New("down") })
	s := New(Options{Addr: "127.0.0.1:0", Readiness: checker})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d, want 503", rec.Code)
	}
}

func TestMetricsNotFoundWhenUnwired(t *testing.T) {
	s := New(Options{Addr: "127.0.0.1:0"})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("metrics = %d, want 404", rec.Code)
	}
}

func TestMetricsWired(t *testing.T) {
	mux := New(Options{
		Addr: "127.0.0.1:0",
		Metrics: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "ss_requests_total 1\n")
		}),
	})
	rec := httptest.NewRecorder()
	mux.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ss_requests_total") {
		t.Fatalf("metrics = %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestStartServeAndShutdown(t *testing.T) {
	s := New(Options{Addr: "127.0.0.1:0"})
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	addr := s.Addr()
	if addr == nil {
		t.Fatal("no bound address")
	}
	resp, err := http.Get("http://" + addr.String() + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("live status = %d", resp.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestStartBindError(t *testing.T) {
	s := New(Options{Addr: "256.256.256.256:99999"})
	if err := s.Start(); err == nil {
		t.Error("expected bind error for invalid address")
	}
}
