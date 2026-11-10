package main

import (
	"net"
	"strconv"
	"strings"
	"testing"
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
