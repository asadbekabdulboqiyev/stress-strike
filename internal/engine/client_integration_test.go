package engine

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"stress-strike/internal/config"
)

// TestWSClientIntegration tests WebSocket client with real server
func TestWSClientIntegration(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.TextMessage, []byte("echo:"+string(msg)))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	e := &Engine{}
	res, body := e.wsClient(context.Background(), wsURL, config.Step{Body: "hi"}, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("ws error: %v", res.errName)
	}
	if res.status != 101 {
		t.Errorf("ws status = %d, want 101", res.status)
	}
	if got := string(body); got != "echo:hi" {
		t.Errorf("ws body = %q, want %q", got, "echo:hi")
	}
}

// TestWSClientWithHeaders tests WebSocket client with custom headers
func TestWSClientWithHeaders(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, _, err = c.ReadMessage()
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.TextMessage, []byte("ok"))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	e := &Engine{}
	step := config.Step{
		Headers: map[string]string{"Authorization": "Bearer test-token"},
		Body:    "test",
	}
	res, body := e.wsClient(context.Background(), wsURL, step, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("ws error: %v", res.errName)
	}
	if res.status != 101 {
		t.Errorf("ws status = %d, want 101", res.status)
	}
	if string(body) != "ok" {
		t.Errorf("ws body = %q, want ok", string(body))
	}
}

// TestWSClientInvalidScheme tests WebSocket client with invalid URL scheme
func TestWSClientInvalidScheme(t *testing.T) {
	e := &Engine{}
	res, _ := e.wsClient(context.Background(), "http://example.com", config.Step{}, map[string]string{}, 5*time.Second)
	if res.errName != errOther {
		t.Errorf("expected errOther for invalid scheme, got %v", res.errName)
	}
}

// TestWSClientInvalidURL tests WebSocket client with invalid URL
func TestWSClientInvalidURL(t *testing.T) {
	e := &Engine{}
	res, _ := e.wsClient(context.Background(), "not-a-url", config.Step{}, map[string]string{}, 5*time.Second)
	if res.errName != errOther {
		t.Errorf("expected errOther for invalid URL, got %v", res.errName)
	}
}

// TestWSClientTimeout tests WebSocket client timeout
func TestWSClientTimeout(t *testing.T) {
	// Server that accepts connection but doesn't complete handshake
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack connection and close immediately without upgrading
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		conn.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	e := &Engine{}
	res, _ := e.wsClient(context.Background(), wsURL, config.Step{}, map[string]string{}, 100*time.Millisecond)
	// Connection closed before handshake -> errOther or errConnection
	if res.errName != errTimeout && res.errName != errConnection && res.errName != errOther {
		t.Errorf("expected errTimeout, errConnection, or errOther, got %v", res.errName)
	}
}

// TestWSClientSendError tests WebSocket client send error handling
func TestWSClientSendError(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		// Close immediately without reading
		c.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	e := &Engine{}
	res, _ := e.wsClient(context.Background(), wsURL, config.Step{Body: "large message"}, map[string]string{}, 5*time.Second)
	// Should handle write error gracefully
	if res.status != http.StatusSwitchingProtocols {
		t.Errorf("status = %d, want 101", res.status)
	}
}

// TestGRPCClientIntegration tests gRPC client with real health server
func TestGRPCClientIntegration(t *testing.T) {
	// Create a test gRPC server with health checking
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	grpcServer := grpc.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		grpcServer.Serve(lis)
	}()
	defer grpcServer.GracefulStop()

	target := "grpc://" + lis.Addr().String()
	e := &Engine{}
	res, body := e.grpcClient(context.Background(), target, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("grpc error: %v", res.errName)
	}
	if res.status != 200 {
		t.Errorf("grpc status = %d, want 200", res.status)
	}
	if !strings.Contains(string(body), "SERVING") {
		t.Errorf("grpc body = %q, want SERVING", string(body))
	}
}

// TestGRPCClientNotServing tests gRPC client when service is not serving
func TestGRPCClientNotServing(t *testing.T) {
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)

	grpcServer := grpc.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		grpcServer.Serve(lis)
	}()
	defer grpcServer.GracefulStop()

	target := "grpc://" + lis.Addr().String()
	e := &Engine{}
	res, body := e.grpcClient(context.Background(), target, 5*time.Second)
	if res.errName != errStatus5xx {
		t.Errorf("expected errStatus5xx, got %v", res.errName)
	}
	if res.status != 503 {
		t.Errorf("grpc status = %d, want 503", res.status)
	}
	if !strings.Contains(string(body), "NOT_SERVING") {
		t.Errorf("grpc body = %q, want NOT_SERVING", string(body))
	}
}

// TestGRPCClientWithTLS tests gRPC client with TLS (grpcs://)
func TestGRPCClientWithTLS(t *testing.T) {
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	// Create server with TLS
	cert, err := tls.LoadX509KeyPair("testdata/cert.pem", "testdata/key.pem")
	if err != nil {
		t.Skip("TLS cert not available, skipping TLS test")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		grpcServer.Serve(lis)
	}()
	defer grpcServer.GracefulStop()

	target := "grpcs://" + lis.Addr().String()
	e := &Engine{}
	res, _ := e.grpcClient(context.Background(), target, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("grpc error: %v", res.errName)
	}
	if res.status != 200 {
		t.Errorf("grpc status = %d, want 200", res.status)
	}
}

// TestGRPCClientTimeout tests gRPC client timeout
func TestGRPCClientTimeout(t *testing.T) {
	// Server that accepts and immediately closes
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, _ := lis.Accept()
		conn.Close()
	}()

	target := "grpc://" + lis.Addr().String()
	e := &Engine{}
	res, _ := e.grpcClient(context.Background(), target, 100*time.Millisecond)
	// Connection closed immediately -> could be timeout, connection error, or other
	if res.errName != errTimeout && res.errName != errConnection && res.errName != errOther {
		t.Errorf("expected errTimeout, errConnection, or errOther, got %v", res.errName)
	}
}

// TestGRPCClientInvalidTarget tests gRPC client with invalid target
func TestGRPCClientInvalidTarget(t *testing.T) {
	e := &Engine{}
	res, _ := e.grpcClient(context.Background(), "invalid://target", 5*time.Second)
	if res.errName != errConnection && res.errName != errOther {
		t.Errorf("expected connection error, got %v", res.errName)
	}
}

// TestRawTCPClientIntegration tests raw TCP client with real server
func TestRawTCPClientIntegration(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("reply:" + string(buf[:n])))
	}()

	e := &Engine{}
	res, body := e.rawClient(context.Background(), "tcp", ln.Addr().String(), config.Step{Body: "ping"}, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("tcp error: %v", res.errName)
	}
	if res.status != 200 {
		t.Errorf("tcp status = %d, want 200", res.status)
	}
	if got := string(body); got != "reply:ping" {
		t.Errorf("tcp body = %q, want %q", got, "reply:ping")
	}
}

// TestRawTCPClientNoBody tests raw TCP client without sending body
func TestRawTCPClientNoBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Server sends data without receiving
		_, _ = conn.Write([]byte("welcome"))
	}()

	e := &Engine{}
	res, body := e.rawClient(context.Background(), "tcp", ln.Addr().String(), config.Step{Body: ""}, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("tcp error: %v", res.errName)
	}
	if res.status != 200 {
		t.Errorf("tcp status = %d, want 200", res.status)
	}
	if string(body) != "welcome" {
		t.Errorf("tcp body = %q, want welcome", string(body))
	}
}

// TestRawTCPClientTimeout tests raw TCP client timeout
func TestRawTCPClientTimeout(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = lis.Accept()
		// Don't read/write, just hold connection
		select {}
	}()

	e := &Engine{}
	res, _ := e.rawClient(context.Background(), "tcp", lis.Addr().String(), config.Step{Body: "test"}, map[string]string{}, 100*time.Millisecond)
	if res.errName != errTimeout {
		t.Errorf("expected errTimeout, got %v", res.errName)
	}
}

// TestRawUDPClientIntegration tests raw UDP client
func TestRawUDPClientIntegration(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 256)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo([]byte("reply:"+string(buf[:n])), addr)
	}()

	e := &Engine{}
	res, body := e.rawClient(context.Background(), "udp", pc.LocalAddr().String(), config.Step{Body: "dgram"}, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("udp error: %v", res.errName)
	}
	if res.status != 200 {
		t.Errorf("udp status = %d, want 200", res.status)
	}
	if len(body) != 0 {
		t.Errorf("udp body = %q, want empty (fire-and-forget)", body)
	}
}

// TestRawUDPClientFireAndForget tests UDP fire-and-forget behavior
func TestRawUDPClientFireAndForget(t *testing.T) {
	// No server listening - UDP should still "succeed" as fire-and-forget
	e := &Engine{}
	res, body := e.rawClient(context.Background(), "udp", "127.0.0.1:9999", config.Step{Body: "test"}, map[string]string{}, 5*time.Second)
	// UDP dial doesn't actually connect, so it might succeed
	if res.errName != "" && res.errName != errConnection {
		// Some systems may return error on write to closed port
		t.Logf("udp result: err=%v, status=%d", res.errName, res.status)
	}
	if len(body) != 0 {
		t.Errorf("udp body = %q, want empty (fire-and-forget)", body)
	}
}

// TestRawClientInvalidNetwork tests raw client with invalid network
func TestRawClientInvalidNetwork(t *testing.T) {
	e := &Engine{}
	res, _ := e.rawClient(context.Background(), "unix", "/tmp/socket", config.Step{}, map[string]string{}, 5*time.Second)
	if res.errName != errOther {
		t.Errorf("expected errOther for invalid network, got %v", res.errName)
	}
}

// TestClassifyNetError tests net error classification
func TestClassifyNetError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		elapsed time.Duration
		wantErr string
		wantLat time.Duration
	}{
		{
			name:    "context canceled",
			err:     context.Canceled,
			elapsed: 10 * time.Millisecond,
			wantErr: errCanceled,
			wantLat: 0,
		},
		{
			name:    "context deadline exceeded",
			err:     context.DeadlineExceeded,
			elapsed: 100 * time.Millisecond,
			wantErr: errTimeout,
			wantLat: 100 * time.Millisecond,
		},
		{
			name:    "net timeout",
			err:     &netError{timeout: true},
			elapsed: 50 * time.Millisecond,
			wantErr: errTimeout,
			wantLat: 50 * time.Millisecond,
		},
		{
			name:    "net error no timeout",
			err:     &netError{timeout: false},
			elapsed: 25 * time.Millisecond,
			wantErr: errConnection,
			wantLat: 25 * time.Millisecond,
		},
		{
			name:    "other error",
			err:     &customError{msg: "custom"},
			elapsed: 10 * time.Millisecond,
			wantErr: errOther,
			wantLat: 10 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := classifyNetError(tt.err, tt.elapsed)
			if res.errName != tt.wantErr {
				t.Errorf("errName = %v, want %v", res.errName, tt.wantErr)
			}
			if res.latency != tt.wantLat {
				t.Errorf("latency = %v, want %v", res.latency, tt.wantLat)
			}
		})
	}
}

// netError implements net.Error for testing
type netError struct {
	timeout bool
}

func (e *netError) Error() string   { return "net error" }
func (e *netError) Timeout() bool   { return e.timeout }
func (e *netError) Temporary() bool { return true }

// customError for testing other errors
type customError struct {
	msg string
}

func (e *customError) Error() string { return e.msg }
