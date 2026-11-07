package tls

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestScanTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Extract host:port from the TLS server URL.
	srvURL := srv.URL[len("https://"):]
	host, portStr, err := net.SplitHostPort(srvURL)
	if err != nil {
		t.Fatalf("split hostport: %v", err)
	}
	port := mustAtoi(portStr)

	info, err := ScanTLS(host, port)
	if err != nil {
		t.Fatalf("ScanTLS: %v", err)
	}
	if info == nil {
		t.Fatal("ScanTLS returned nil")
	}
	if len(info.SupportedVersions) == 0 {
		t.Error("SupportedVersions = empty, want at least TLS 1.2 or 1.3")
	}
}

func TestScanTLSDeadPort(t *testing.T) {
	info, err := ScanTLS("127.0.0.1", 1)
	if err != nil {
		t.Fatalf("ScanTLS(dead port) = %v, want no error", err)
	}
	if len(info.SupportedVersions) != 0 {
		t.Errorf("SupportedVersions = %v, want empty for dead port", info.SupportedVersions)
	}
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}
