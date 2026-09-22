package engine

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// newWSEchoServer returns a WebSocket server echoing every frame back with an
// "echo:" prefix until the client disconnects.
func newWSEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(mt, append([]byte("echo:"), msg...)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestWSOneShotDefaultIsBackwardCompatible verifies the default behavior:
// without session:true every iteration dials a fresh connection and performs
// exactly one exchange — matching the classic one-shot semantics.
func TestWSOneShotDefaultIsBackwardCompatible(t *testing.T) {
	var conns atomic.Int32
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conns.Add(1)
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.TextMessage, append([]byte("echo:"), msg...))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	sc := &config.Scenario{
		Name:    "ws-oneshot",
		Profile: config.Profile{Type: config.ProfileSteady, Users: 1, Duration: 1, Timeout: 5},
		Steps: []config.Step{{
			Name: "ws", Type: "ws", URL: wsURL, Body: "ping",
		}},
	}
	tel := runScenario(t, sc, time.Second)
	if tel.TotalErrors() != 0 {
		t.Errorf("errors = %d, want 0: %v", tel.TotalErrors(), tel.Errors())
	}
	if tel.TotalRequests() < 2 {
		t.Errorf("requests = %d, want multiple one-shot iterations", tel.TotalRequests())
	}
}

// TestWSPersistentSession verifies that session:true keeps a single live
// WebSocket per virtual user across many message exchanges.
func TestWSPersistentSession(t *testing.T) {
	srv := newWSEchoServer(t)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	sc := &config.Scenario{
		Name:    "ws-session",
		Profile: config.Profile{Type: config.ProfileSteady, Users: 2, Duration: 1, Timeout: 5},
		Steps: []config.Step{{
			Name: "ws-chat", Type: "ws", URL: wsURL,
			Body:    "hello {{user}}",
			Session: true,
			Assertions: []config.Assertion{
				{Type: "regex", Value: "echo:hello"},
			},
		}},
	}
	tel := runScenario(t, sc, time.Second)
	if tel.TotalRequests() < 10 {
		t.Errorf("requests = %d, want >=10 pooled exchanges", tel.TotalRequests())
	}
	if tel.TotalErrors() != 0 {
		t.Errorf("errors = %d, want 0: %v", tel.TotalErrors(), tel.Errors())
	}
}

// TestWSBinaryFrame checks frame_type: binary round-trips binary payloads.
func TestWSBinaryFrame(t *testing.T) {
	srv := newWSEchoServer(t)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	e := &Engine{}
	step := config.Step{Body: "\x00\x01\x02bin", FrameType: "binary"}
	res, body := e.wsClient(context.Background(), wsURL, step, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("ws error: %s", res.errName)
	}
	if !strings.Contains(string(body), "\x00\x01\x02bin") {
		t.Errorf("body = %q, want echoed binary payload", string(body))
	}
}

// TestUDPAwaitResponse covers the UDP request-response mode.
func TestUDPAwaitResponse(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(append([]byte("resp:"), buf[:n]...), addr); err != nil {
				return
			}
		}
	}()

	step := config.Step{Body: "dgram", AwaitResponse: true}
	res, body := (&Engine{}).rawClient(context.Background(), "udp", pc.LocalAddr().String(), step, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("udp error: %s", res.errName)
	}
	if !strings.Contains(string(body), "resp:dgram") {
		t.Errorf("body = %q, want resp:dgram", string(body))
	}
}

// TestTCPPersistentSession verifies TCP session pooling across iterations.
func TestTCPPersistentSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(append([]byte("ack:"), buf[:n]...)); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	sc := &config.Scenario{
		Name:    "tcp-session",
		Profile: config.Profile{Type: config.ProfileSteady, Users: 2, Duration: 1, Timeout: 5},
		Steps: []config.Step{{
			Name: "tcp-echo", Type: "tcp", URL: ln.Addr().String(),
			Body:    "ping",
			Session: true,
			Assertions: []config.Assertion{
				{Type: "regex", Value: "ack:ping"},
			},
		}},
	}
	tel := runScenario(t, sc, time.Second)
	if tel.TotalRequests() < 10 {
		t.Errorf("requests = %d, want >=10 pooled exchanges", tel.TotalRequests())
	}
	if tel.TotalErrors() != 0 {
		t.Errorf("errors = %d, want 0: %v", tel.TotalErrors(), tel.Errors())
	}
}

// TestGrpcCustomMethodInvoke exercises the generic unary invoke path against
// a live gRPC server using an unknown full method name; the server must reply
// Unimplemented, which the client maps into the 4xx family.
func TestGrpcCustomMethodInvoke(t *testing.T) {
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	grpcServer := grpc.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.GracefulStop)

	target := "grpc://" + lis.Addr().String()
	e := &Engine{}
	step := config.Step{
		GrpcMethod: "/unknown.pkg.Service/DoThing",
		Headers:    map[string]string{"x-test": "1"},
		Body:       `{"ping":"pong"}`,
	}
	res, _ := e.grpcMethodClient(context.Background(), target, step, map[string]string{}, 5*time.Second)
	if res.errName == "" {
		t.Fatal("expected an error for an unimplemented method")
	}
	if res.errName != errStatus4xx {
		t.Errorf("errName = %q, want %q (Unimplemented mapped to 4xx)", res.errName, errStatus4xx)
	}
}

// TestGrpcSharedConnReuse verifies that repeated calls reuse one pooled
// ClientConn instead of dialing per call.
func TestGrpcSharedConnReuse(t *testing.T) {
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	grpcServer := grpc.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.GracefulStop)

	host, _, err := splitGRPCTarget(lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{keepAlive: true}
	for i := 0; i < 5; i++ {
		if res, _ := e.grpcClient(context.Background(), lis.Addr().String(), 5*time.Second); res.errName != "" {
			t.Fatalf("call %d failed: %s", i, res.errName)
		}
	}
	e.sessMu.Lock()
	n := len(e.grpcConns)
	e.sessMu.Unlock()
	if n != 1 {
		t.Errorf("pooled connections = %d, want exactly 1 after 5 calls", n)
	}
	_ = host // silence unused in case of refactors
}

// TestHTTP2TransportEnabled asserts the transport still attempts HTTP/2 so
// h2-capable targets benefit from multiplexing.
func TestHTTP2TransportEnabled(t *testing.T) {
	tr := newTransport(true, 256, "")
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 = false, want true")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLS MinVersion = %x, want 0303 (TLS 1.2)", tr.TLSClientConfig.MinVersion)
	}
	_ = http2.Transport{} // ensure dependency stays linked for h2 upgrades
}

// TestFingerprintTransportConfiguresDialer asserts that requesting a TLS
// fingerprint swaps the standard dialer for a uTLS-backed one, and that a
// plain (default) profile keeps the built-in dialer — so the extra layer only
// exists when explicitly asked for.
func TestFingerprintTransportConfiguresDialer(t *testing.T) {
	plain := newTransport(true, 256, "")
	if plain.DialTLSContext != nil {
		t.Fatal("default profile must not install a custom DialTLSContext")
	}
	fp := newTransport(true, 256, "chrome")
	if fp.DialTLSContext == nil {
		t.Fatal("chrome profile must install a uTLS-backed DialTLSContext")
	}
	if fp.ForceAttemptHTTP2 {
		t.Fatal("fingerprinted transport must pin HTTP/1.1 so Go's transport cannot misread the negotiated protocol")
	}
}
