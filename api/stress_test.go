package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := Run(ctx, Config{
		URL:      srv.URL,
		Users:    5,
		Duration: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalRequests == 0 {
		t.Error("no requests recorded")
	}
	if res.StatusCodes[200] == 0 {
		t.Errorf("expected 200 status codes, got %v", res.StatusCodes)
	}
	if len(res.Errors) != 0 {
		t.Errorf("unexpected errors: %v", res.Errors)
	}
}

func TestRunInvalidConfig(t *testing.T) {
	if _, err := Run(context.Background(), Config{URL: ""}); err == nil {
		t.Error("expected error for empty URL")
	}
}

// A TLS fingerprint only affects TLS dialing, so it must be a no-op against a
// plain-HTTP target and must never make the run fail.
func TestRunTLSFingerprintPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := Run(ctx, Config{
		URL:            srv.URL,
		Users:          2,
		Duration:       time.Second,
		TLSFingerprint: "chrome",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalRequests == 0 {
		t.Error("no requests recorded")
	}
	if res.StatusCodes[200] == 0 {
		t.Errorf("expected 200 status codes, got %v", res.StatusCodes)
	}
	if len(res.Errors) != 0 {
		t.Errorf("unexpected errors: %v", res.Errors)
	}
}

// Headers configured on the api.Config must reach the server on every request.
func TestRunHeaders(t *testing.T) {
	var (
		mu      sync.Mutex
		echoVal string
		seen    bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get("X-Stress-Test")
		mu.Lock()
		seen = true
		echoVal = v
		mu.Unlock()
		w.Header().Set("X-Stress-Test", v)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := Run(ctx, Config{
		URL:      srv.URL,
		Users:    2,
		Duration: time.Second,
		Headers:  map[string]string{"X-Stress-Test": "reach-server"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCodes[200] == 0 {
		t.Errorf("expected 200 status codes, got %v", res.StatusCodes)
	}
	mu.Lock()
	defer mu.Unlock()
	if !seen {
		t.Error("server never received a request")
	}
	if echoVal != "reach-server" {
		t.Errorf("server echoed header %q, want %q", echoVal, "reach-server")
	}
}
