package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanSecurity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	info, err := ScanSecurity(srv.URL)
	if err != nil {
		t.Fatalf("ScanSecurity: %v", err)
	}
	if info == nil {
		t.Fatal("ScanSecurity returned nil")
	}
	if info.Score == 0 {
		t.Errorf("Score = 0, want > 0")
	}
	if len(info.Details) == 0 {
		t.Error("Details = empty, want non-empty")
	}
	if _, ok := info.Headers["Strict-Transport-Security"]; !ok {
		t.Error("Headers missing Strict-Transport-Security")
	}
}

func TestScanSecurityDeadPort(t *testing.T) {
	_, err := ScanSecurity("http://127.0.0.1:1/")
	if err == nil {
		t.Error("ScanSecurity(dead port) = nil error, want error")
	}
}

func TestScanSecurityMissingHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	info, err := ScanSecurity(srv.URL)
	if err != nil {
		t.Fatalf("ScanSecurity: %v", err)
	}
	if len(info.MissingHeaders) == 0 {
		t.Error("MissingHeaders = empty, want non-empty (no security headers sent)")
	}
	if info.Score > 50 {
		t.Errorf("Score = %d, want <= 50 for a server with no security headers", info.Score)
	}
}
