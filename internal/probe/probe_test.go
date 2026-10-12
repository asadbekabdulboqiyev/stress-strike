package probe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGetHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	if got := Get(srv.URL, time.Second); got != 0 {
		t.Errorf("Get(healthy) = %d, want 0", got)
	}
}

func TestGetUnhealthyStatus(t *testing.T) {
	for _, code := range []int{http.StatusServiceUnavailable, http.StatusInternalServerError, http.StatusNotFound} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		if got := Get(srv.URL, time.Second); got != 1 {
			t.Errorf("Get(status %d) = %d, want 1", code, got)
		}
		srv.Close()
	}
}

func TestGetConnectionRefused(t *testing.T) {
	// Port 1 on loopback is not listening in practice.
	if got := Get("http://127.0.0.1:1/healthz", 500*time.Millisecond); got != 1 {
		t.Errorf("Get(refused) = %d, want 1", got)
	}
}

func TestGetTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if got := Get(srv.URL, 50*time.Millisecond); got != 1 {
		t.Errorf("Get(timeout) = %d, want 1", got)
	}
}

func TestGetAccepts2xx(t *testing.T) {
	for _, code := range []int{200, 201, 204} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		if got := Get(srv.URL, time.Second); got != 0 {
			t.Errorf("Get(status %d) = %d, want 0", code, got)
		}
		srv.Close()
	}
}

func TestRunHealthyViaFlags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if got := Run([]string{"-addr", srv.URL + "/readyz"}, ""); got != 0 {
		t.Errorf("Run = %d, want 0", got)
	}
}

func TestRunURLFlagAlias(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if got := Run([]string{"-url", srv.URL}, ""); got != 0 {
		t.Errorf("Run(-url) = %d, want 0", got)
	}
}

func TestRunAddsScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	if got := Run([]string{"-addr", host}, ""); got != 0 {
		t.Errorf("Run(bare host) = %d, want 0", got)
	}
}

func TestRunUsageErrors(t *testing.T) {
	if got := Run([]string{"-bogus"}, ""); got != UsageError {
		t.Errorf("Run(bad flag) = %d, want %d", got, UsageError)
	}
	if got := Run([]string{"-addr", "   "}, ""); got != UsageError {
		t.Errorf("Run(blank addr) = %d, want %d", got, UsageError)
	}
}

func TestDefaultURLPrecedence(t *testing.T) {
	t.Setenv(EnvURL, "")
	if got := DefaultURL(""); got != fallbackURL {
		t.Errorf("DefaultURL(\"\") = %q, want %q", got, fallbackURL)
	}
	if got := DefaultURL("http://master:9090/healthz"); got != "http://master:9090/healthz" {
		t.Errorf("DefaultURL(default) = %q", got)
	}
	t.Setenv(EnvURL, "http://worker:9091/healthz")
	if got := DefaultURL("http://master:9090/healthz"); got != "http://worker:9091/healthz" {
		t.Errorf("DefaultURL(env wins) = %q", got)
	}
}
