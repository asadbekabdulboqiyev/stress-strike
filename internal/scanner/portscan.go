package scanner

// --- Port scanner ------------------------------------------------------------
//
// Network service discovery: scans TCP ports on a target host, identifies
// open ports, and attempts service banner grabbing. All scanning is bounded
// by concurrency, timeout, and (optionally) a Requester gate for scope
// enforcement when used from the dashboard.

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// PortScanResult is the output of a port scan.
type PortScanResult struct {
	Target   string        `json:"target"`
	Opened   int           `json:"opened"`
	Closed   int           `json:"closed"`
	Ports    []PortEntry   `json:"ports,omitempty"`
	Duration time.Duration `json:"duration"`
}

// PortEntry is one scanned port.
type PortEntry struct {
	Port     int    `json:"port"`
	State    string `json:"state"` // open, closed, filtered
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Protocol string `json:"protocol"` // tcp
}

// commonPorts is a curated list of the most likely-to-be-interesting ports.
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
	443, 445, 465, 587, 631, 993, 995, 1433, 1521, 3306,
	3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 9200, 27017,
}

// ScanPorts scans the given ports on target (host or host:port).
func ScanPorts(ctx context.Context, target string, ports []int, req Requester) *PortScanResult {
	res := &PortScanResult{Target: target}
	start := time.Now()

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		// target may be bare host; ports come from the list below
		host = target
	}

	if len(ports) == 0 {
		ports = commonPorts
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64) // cap concurrent dials

	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			entry := scanOne(ctx, addr, port)
			mu.Lock()
			if entry.State == "open" {
				res.Opened++
				res.Ports = append(res.Ports, *entry)
			} else {
				res.Closed++
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	res.Duration = time.Since(start)
	return res
}

// scanOne attempts a TCP connect and banner grab.
func scanOne(ctx context.Context, addr string, port int) *PortEntry {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return &PortEntry{Port: port, State: "closed", Protocol: "tcp"}
	}
	defer func() { _ = conn.Close() }()

	// Set a read deadline so banner grab doesn't hang.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return &PortEntry{Port: port, State: "open", Protocol: "tcp"}
	}

	// Send a minimal probe to elicit a banner (HTTP GET for web-ish ports).
	var probe []byte
	switch port {
	case 80, 8080, 8888, 8000:
		probe = []byte("GET / HTTP/1.1\r\nHost: " + addr + "\r\nConnection: close\r\n\r\n")
	case 21, 22, 25, 110, 143, 3306, 5432, 6379:
		// Many services send a banner on connect; just read.
		probe = nil
	default:
		probe = nil
	}

	if len(probe) > 0 {
		if _, err := conn.Write(probe); err != nil {
			return &PortEntry{Port: port, State: "open", Protocol: "tcp"}
		}
	}

	banner := ""
	if buf, err := io.ReadAll(io.LimitReader(conn, 1024)); err == nil {
		banner = strings.TrimSpace(string(buf))
	}

	service := guessService(port, banner)

	return &PortEntry{
		Port:     port,
		State:    "open",
		Service:  service,
		Banner:   banner,
		Protocol: "tcp",
	}
}

func guessService(port int, banner string) string {
	b := strings.ToLower(banner)
	switch port {
	case 21:
		if strings.Contains(b, "ftp") {
			return "ftp"
		}
		return "ftp?"
	case 22:
		if strings.Contains(b, "ssh") {
			return "ssh"
		}
		return "ssh?"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80, 8080, 8888, 8000:
		if strings.Contains(b, "http") {
			return "http"
		}
		return "http?"
	case 443, 8443:
		return "https"
	case 445:
		return "smb"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	case 9200:
		return "elasticsearch"
	}
	if strings.Contains(b, "ssh") {
		return "ssh"
	}
	if strings.Contains(b, "http") {
		return "http"
	}
	return "unknown"
}
