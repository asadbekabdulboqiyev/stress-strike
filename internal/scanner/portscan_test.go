package scanner

// portscan_test.go — coverage for the TCP port scanner and its service
// fingerprinting. Real loopback listeners stand in for network services so the
// dial, banner-grab and probe branches all run for real; nothing leaves the
// machine.

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// startBannerListener listens on 127.0.0.1:0 and answers every accepted
// connection with banner before closing it. It returns the dialable address,
// the port, and a stop function (registered as cleanup automatically).
func startBannerListener(t *testing.T, banner string) (addr string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan struct{})
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Serve in a goroutine so one slow peer cannot stall the loop.
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if banner != "" {
					_, _ = c.Write([]byte(banner))
				}
			}(conn)
		}
	}()

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr is %T, want *net.TCPAddr", ln.Addr())
	}
	return ln.Addr().String(), tcpAddr.Port
}

// freePort returns a loopback port that nothing is listening on, by opening a
// listener and immediately closing it.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}

func TestScanPortsOpenPort(t *testing.T) {
	addr, port := startBannerListener(t, "SSH-2.0-CoverTest\r\n")

	res := ScanPorts(context.Background(), addr, []int{port}, nil)
	if res == nil {
		t.Fatal("ScanPorts returned nil")
	}
	if res.Target != addr {
		t.Errorf("Target = %q, want %q", res.Target, addr)
	}
	if res.Opened != 1 {
		t.Fatalf("Opened = %d, want 1 (Ports: %+v)", res.Opened, res.Ports)
	}
	if res.Closed != 0 {
		t.Errorf("Closed = %d, want 0", res.Closed)
	}
	if len(res.Ports) != 1 {
		t.Fatalf("Ports = %+v, want one entry", res.Ports)
	}
	entry := res.Ports[0]
	if entry.Port != port {
		t.Errorf("Port = %d, want %d", entry.Port, port)
	}
	if entry.State != "open" {
		t.Errorf("State = %q, want open", entry.State)
	}
	if entry.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want tcp", entry.Protocol)
	}
	if entry.Banner != "SSH-2.0-CoverTest" {
		t.Errorf("Banner = %q, want the trimmed banner", entry.Banner)
	}
	if entry.Service != "ssh" {
		t.Errorf("Service = %q, want ssh", entry.Service)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want positive", res.Duration)
	}
}

func TestScanPortsClosedPort(t *testing.T) {
	port := freePort(t)
	res := ScanPorts(context.Background(), "127.0.0.1", []int{port}, nil)
	if res.Opened != 0 {
		t.Errorf("Opened = %d, want 0", res.Opened)
	}
	if res.Closed != 1 {
		t.Errorf("Closed = %d, want 1", res.Closed)
	}
	if len(res.Ports) != 0 {
		t.Errorf("Ports = %+v, want none", res.Ports)
	}
}

func TestScanPortsHostWithPortSuffix(t *testing.T) {
	addr, port := startBannerListener(t, "hello\r\n")
	// Target already carries a port: SplitHostPort must strip it and the
	// scanned port comes from the list, not the target.
	res := ScanPorts(context.Background(), addr, []int{port}, nil)
	if res.Opened != 1 {
		t.Fatalf("Opened = %d, want 1", res.Opened)
	}
}

func TestScanPortsDefaultPortList(t *testing.T) {
	// An empty list falls back to commonPorts; every port is either counted
	// open or closed, and no dial panics.
	res := ScanPorts(context.Background(), "127.0.0.1", nil, nil)
	if res == nil {
		t.Fatal("ScanPorts returned nil")
	}
	if total := res.Opened + res.Closed; total != len(commonPorts) {
		t.Errorf("Opened+Closed = %d, want %d", total, len(commonPorts))
	}
}

func TestScanPortsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ports := make([]int, 200) // more than the 64-wide semaphore
	for i := range ports {
		ports[i] = 10000 + i
	}
	start := time.Now()
	res := ScanPorts(ctx, "127.0.0.1", ports, nil)
	elapsed := time.Since(start)
	if res == nil {
		t.Fatal("ScanPorts returned nil")
	}
	if res.Opened+res.Closed > len(ports) {
		t.Errorf("counted %d results for %d ports", res.Opened+res.Closed, len(ports))
	}
	if elapsed > 5*time.Second {
		t.Errorf("cancelled scan took %v, want it to return promptly", elapsed)
	}
}

func TestScanOneHTTPProbeAndBanner(t *testing.T) {
	// The stub reads the probe scanOne sends before answering: writing the
	// banner first and closing would make the client's probe write trigger an
	// RST that discards the buffered banner.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		// One read is enough: the client sends its probe in a single write and
		// then waits for the banner, so reading to EOF would deadlock.
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}()

	addr := ln.Addr().String()
	entry := scanOne(context.Background(), addr, 80)
	if entry.State != "open" {
		t.Fatalf("State = %q, want open", entry.State)
	}
	if !strings.Contains(entry.Banner, "HTTP/1.1 200 OK") {
		t.Errorf("Banner = %q", entry.Banner)
	}
	if entry.Service != "http" {
		t.Errorf("Service = %q, want http", entry.Service)
	}
}

func TestScanOneClosedAndCancelled(t *testing.T) {
	if entry := scanOne(context.Background(), net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))), 9); entry.State != "closed" {
		t.Errorf("refused dial: State = %q, want closed", entry.State)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if entry := scanOne(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))), 9); entry.State != "closed" {
		t.Errorf("cancelled dial: State = %q, want closed", entry.State)
	}
}

func TestGuessService(t *testing.T) {
	tests := []struct {
		port   int
		banner string
		want   string
	}{
		{21, "220 FTP server ready", "ftp"},
		{21, "", "ftp?"},
		{22, "SSH-2.0-OpenSSH_9.6", "ssh"},
		{22, "", "ssh?"},
		{25, "220 mail ESMTP", "smtp"},
		{53, "", "dns"},
		{80, "HTTP/1.1 200 OK", "http"},
		{80, "", "http?"},
		{8000, "HTTP/1.0 404 Not Found", "http"},
		{8080, "", "http?"},
		{8888, "http response", "http"},
		{443, "", "https"},
		{8443, "anything", "https"},
		{445, "", "smb"},
		{3306, "mysql_native_password", "mysql"},
		{3389, "", "rdp"},
		{5432, "", "postgresql"},
		{6379, "", "redis"},
		{27017, "", "mongodb"},
		{9200, "", "elasticsearch"},
		// Unknown port: the banner decides.
		{12345, "SSH-2.0-Go", "ssh"},
		{12345, "http/1.1", "http"},
		{12345, "garbage", "unknown"},
		{12345, "", "unknown"},
	}
	for _, tc := range tests {
		if got := guessService(tc.port, tc.banner); got != tc.want {
			t.Errorf("guessService(%d, %q) = %q, want %q", tc.port, tc.banner, got, tc.want)
		}
	}
}

// Guard against a listener helper that silently stops accepting: a stale
// goroutine would make the open-port assertions above flaky.
func TestStartBannerListenerServesRepeatedConns(t *testing.T) {
	addr, port := startBannerListener(t, "MULTI\r\n")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entry := scanOne(context.Background(), addr, port)
			if entry.State != "open" {
				t.Errorf("conn %d: State = %q", i, entry.State)
			}
		}()
	}
	wg.Wait()

	// A second full scan still sees the port open.
	res := ScanPorts(context.Background(), "127.0.0.1", []int{port}, &passiveFakeRequester{})
	if res.Opened != 1 {
		t.Errorf("re-scan Opened = %d, want 1 (%+v)", res.Opened, res.Ports)
	}
}
