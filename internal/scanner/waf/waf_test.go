package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanWAF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	waf, err := ScanWAF(srv.URL)
	if err != nil {
		t.Fatalf("ScanWAF: %v", err)
	}
	if waf == nil {
		t.Fatal("ScanWAF returned nil")
	}
	if waf.Headers == nil {
		t.Error("Headers = nil, want non-nil")
	}
}

func TestScanWAFDeadPort(t *testing.T) {
	_, err := ScanWAF("http://127.0.0.1:1/")
	if err == nil {
		t.Error("ScanWAF(dead port) = nil error, want error")
	}
}
