package scanner

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGuardConfigMethod(t *testing.T) {
	g := &Guard{cfg: GuardConfig{RPS: 10, MaxRequests: 100, Timeout: 5 * time.Second}}
	cfg := g.Config()
	if cfg.RPS != 10 || cfg.MaxRequests != 100 || cfg.Timeout != 5*time.Second {
		t.Errorf("Config() = %+v, want RPS=10 MaxRequests=100 Timeout=5s", cfg)
	}
}

func TestScanFunctionsDeadPort(t *testing.T) {
	// Scan with dead port: TLS fails, HTTP fails, WAF fails, Security fails.
	res, err := Scan("127.0.0.1", 1)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res == nil {
		t.Fatal("Scan returned nil")
	}
	if res.Target != "127.0.0.1" {
		t.Errorf("Target = %q, want 127.0.0.1", res.Target)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want positive", res.Duration)
	}

	// ScanTLS re-export (may not error on dead port, just returns empty info).
	_, _ = ScanTLS("127.0.0.1", 1)

	// ScanWAF re-export.
	_, err = ScanWAF("http://127.0.0.1:1/")
	if err == nil {
		t.Error("ScanWAF(dead port) = nil error, want error")
	}

	// ScanHTTP re-export.
	_, err = ScanHTTP("http://127.0.0.1:1/")
	if err == nil {
		t.Error("ScanHTTP(dead port) = nil error, want error")
	}

	// ScanSecurity re-export.
	_, err = ScanSecurity("http://127.0.0.1:1/")
	if err == nil {
		t.Error("ScanSecurity(dead port) = nil error, want error")
	}
}

func TestScanSSLDeadPort(t *testing.T) {
	ctx := context.Background()
	res := ScanSSL(ctx, "127.0.0.1:1")
	if res == nil {
		t.Fatal("ScanSSL returned nil")
	}
	if res.Target != "127.0.0.1:1" {
		t.Errorf("Target = %q, want 127.0.0.1:1", res.Target)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want positive", res.Duration)
	}
	// Connection refused → cannot connect issue.
	if len(res.Issues) == 0 {
		t.Error("Issues = empty, want cannot-connect issue")
	}
}

func TestTLSVersionName(t *testing.T) {
	cases := []struct {
		v    uint16
		want string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x9999, "0x9999"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.want, func(t *testing.T) {
			if got := tlsVersionName(tc.v); got != tc.want {
				t.Errorf("tlsVersionName(%#x) = %q, want %q", tc.v, got, tc.want)
			}
		})
	}
}

func TestTestWebSocketRefusedByGate(t *testing.T) {
	ctx := context.Background()

	// Use a Requester that refuses.
	refuser := &refusingRequester{}
	res := TestWebSocket(ctx, "ws://127.0.0.1:1/socket", refuser)
	if res == nil {
		t.Fatal("TestWebSocket returned nil")
	}
	if res.URL != "ws://127.0.0.1:1/socket" {
		t.Errorf("URL = %q", res.URL)
	}
	if len(res.Issues) == 0 {
		t.Error("Issues = empty, want gate refusal")
	}
	found := false
	for _, issue := range res.Issues {
		if strings.Contains(issue, "refused by gate") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Issues = %v, want a gate refusal message", res.Issues)
	}
}

func TestTestWebSocketCannotConnect(t *testing.T) {
	ctx := context.Background()
	res := TestWebSocket(ctx, "ws://127.0.0.1:1/socket", nil)
	if res == nil {
		t.Fatal("TestWebSocket returned nil")
	}
	if len(res.Issues) == 0 {
		t.Error("Issues = empty, want cannot-connect issue")
	}
	if !res.Connected {
		// expected: connection refused
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want positive", res.Duration)
	}
}

// refusingRequester always refuses Check.
type refusingRequester struct{}

func (r *refusingRequester) Check(ctx context.Context, method, rawURL string, intrusive bool) error {
	return ErrOutOfScope
}
func (r *refusingRequester) Do(req *http.Request) (*http.Response, error) {
	return nil, ErrOutOfScope
}
