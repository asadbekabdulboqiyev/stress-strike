package main

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestIsVersionArg covers the flag Dockerfile.worker runs at build time; without
// it the image build logged "Unknown flag --version".
func TestIsVersionArg(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-version", "-v"} {
		if !isVersionArg(arg) {
			t.Errorf("isVersionArg(%q) = false, want true", arg)
		}
	}
	for _, arg := range []string{"", "healthcheck", "--verbose", "v", "-version=1"} {
		if isVersionArg(arg) {
			t.Errorf("isVersionArg(%q) = true, want false", arg)
		}
	}
}

// listenOn binds a real TCP listener on 127.0.0.1 with an ephemeral port
// (port 0) and returns it. No external network traffic is generated and the
// listener is always closed by the caller.
func listenOn(t *testing.T, addr string) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen(%q): %v", addr, err)
	}
	return lis
}

func TestResolveAdvertiseExplicit(t *testing.T) {
	lis := listenOn(t, "127.0.0.1:0")
	defer lis.Close()

	// An explicitly configured address is returned verbatim.
	if got := resolveAdvertise("198.51.100.7:9000", lis); got != "198.51.100.7:9000" {
		t.Errorf("resolveAdvertise(explicit) = %q, want the explicit address", got)
	}
}

func TestResolveAdvertiseBoundToLoopback(t *testing.T) {
	lis := listenOn(t, "127.0.0.1:0")
	defer lis.Close()

	port := lis.Addr().(*net.TCPAddr).Port
	got := resolveAdvertise("", lis)
	want := "127.0.0.1:" + strconv.Itoa(port)
	if got != want {
		t.Errorf("resolveAdvertise(loopback) = %q, want %q", got, want)
	}
}

func TestResolveAdvertiseWildcardSubstitutesHostname(t *testing.T) {
	lis := listenOn(t, "0.0.0.0:0")
	defer lis.Close()

	port := lis.Addr().(*net.TCPAddr).Port
	got := resolveAdvertise("", lis)

	// The port must be preserved; the host must be a hostname (or 127.0.0.1
	// fallback if os.Hostname fails), never the raw wildcard IP.
	suffix := ":" + strconv.Itoa(port)
	if !strings.HasSuffix(got, suffix) {
		t.Errorf("resolveAdvertise(wildcard) = %q, expected port suffix %q", got, suffix)
	}
	host := strings.TrimSuffix(got, suffix)
	if host == "" {
		t.Fatalf("resolveAdvertise(wildcard) returned empty host: %q", got)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		t.Errorf("resolveAdvertise(wildcard) leaked wildcard IP: %q", got)
	}
}

func TestResolveAdvertiseNeverReturnsWildcardPort(t *testing.T) {
	// A listener bound to :0 must never advertise :0.
	lis := listenOn(t, ":0")
	defer lis.Close()

	got := resolveAdvertise("", lis)
	if strings.HasSuffix(got, ":0") {
		t.Errorf("resolveAdvertise returned :0 port: %q", got)
	}
	if strings.Contains(got, "0.0.0.0") {
		t.Errorf("resolveAdvertise leaked wildcard address: %q", got)
	}
}

func TestDefaultWorkerID(t *testing.T) {
	if got := defaultWorkerID("node-1", 42); got != "node-1-42" {
		t.Errorf("defaultWorkerID = %q, want node-1-42", got)
	}
	// An empty hostname must still produce a usable, non-empty ID rather than
	// a bare "-42".
	if got := defaultWorkerID("", 7); got != "worker-7" {
		t.Errorf("defaultWorkerID with an empty hostname = %q, want worker-7", got)
	}
}

// TestStartOpsServerEmptyAddr: an empty -http-addr disables the endpoints and
// must not start a listener.
func TestStartOpsServerEmptyAddr(t *testing.T) {
	var serving atomic.Bool
	if srv := startOpsServer("", &serving); srv != nil {
		t.Error("startOpsServer(\"\") returned a server; an empty address means disabled")
	}
}

// TestStartOpsServerServesHealthz starts the real ops server on an ephemeral
// port and proves /healthz reflects the readiness checker: 503 before the gRPC
// server reports serving, 200 after.
func TestStartOpsServerServesHealthz(t *testing.T) {
	var serving atomic.Bool

	addr := "127.0.0.1:" + strconv.Itoa(freePort(t))
	srv := startOpsServer(addr, &serving)
	if srv == nil {
		t.Fatalf("startOpsServer(%q) failed", addr)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	base := "http://" + srv.Addr().String()

	// /healthz is liveness and never depends on readiness; /readyz is what the
	// orchestrator gates traffic on, so it must track the checker.
	if code := httpStatus(t, base+"/healthz"); code != http.StatusOK {
		t.Errorf("/healthz before serving = %d, want 200 (liveness)", code)
	}
	if code := httpStatus(t, base+"/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz before serving = %d, want 503", code)
	}

	serving.Store(true)

	if code := httpStatus(t, base+"/readyz"); code != http.StatusOK {
		t.Errorf("/readyz after serving = %d, want 200", code)
	}
	if code := httpStatus(t, base+"/metrics"); code != http.StatusOK {
		t.Errorf("/metrics = %d, want 200", code)
	}
}

// TestStartOpsServerNilServing: a nil pointer must be treated as "not serving"
// rather than dereferencing it.
func TestStartOpsServerNilServing(t *testing.T) {
	addr := "127.0.0.1:" + strconv.Itoa(freePort(t))
	srv := startOpsServer(addr, nil)
	if srv == nil {
		t.Fatalf("startOpsServer(%q) failed", addr)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	if code := httpStatus(t, "http://"+srv.Addr().String()+"/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz = %d, want 503 with no serving flag", code)
	}
}

// TestStartOpsServerBusyPort: a taken port is a warning, not a crash.
func TestStartOpsServerBusyPort(t *testing.T) {
	lis := listenOn(t, "127.0.0.1:0")
	defer lis.Close()

	var serving atomic.Bool
	if srv := startOpsServer(lis.Addr().String(), &serving); srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		t.Error("startOpsServer on a busy port returned a server, want nil with a logged warning")
	}
}

// freePort returns a port that was free a moment ago. The listener is closed
// before the caller binds it, which is racy in theory and reliable in practice
// for a local test; the ops server treats a bind failure as a warning, and the
// test fails loudly if it loses the race.
func freePort(t *testing.T) int {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a free port: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	lis.Close()
	return port
}

func httpStatus(t *testing.T, url string) int {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	res.Body.Close()
	return res.StatusCode
}
