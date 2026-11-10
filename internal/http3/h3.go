// Package http3 provides HTTP/3 (QUIC) probing for the stress-strike scanner.
//
// HTTP/3 support lets stress-strike measure targets that only speak QUIC/H3,
// and report whether the target advertises H3 via Alt-Svc. This is a passive
// detection layer: it does not perform a full H3 load test, but it tells the
// operator whether H3 is available so they can decide whether to run one.
//
// Production-grade H3 load generation (many concurrent QUIC streams) is a
// follow-up item — see docs/ROADMAP.md.
package http3

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
)

// ProbeResult describes what we learned about a target's HTTP/3 support.
type ProbeResult struct {
	Host        string        `json:"host"`
	Port        int           `json:"port"`
	AltSvcH3    bool          `json:"alt_svc_h3"`   // target advertises h3 in Alt-Svc
	H3Reachable bool          `json:"h3_reachable"` // QUIC handshake succeeded
	H3Latency   time.Duration `json:"h3_latency"`   // QUIC handshake latency
	Negotiated  string        `json:"negotiated"`   // ALPN negotiated (h3 or "")
	Error       string        `json:"error,omitempty"`
}

// Probe checks whether host:port supports HTTP/3 over QUIC. It first tries to
// read the Alt-Svc header over plain HTTPS (port 443 by default), then
// attempts a QUIC handshake to confirm H3 is actually reachable.
func Probe(host string, port int) (*ProbeResult, error) {
	if port == 0 {
		port = 443
	}
	res := &ProbeResult{Host: host, Port: port}

	// 1. Check Alt-Svc via TLS handshake to the standard HTTPS port.
	altSvc, err := checkAltSvc(host, port)
	if err == nil {
		res.AltSvcH3 = altSvc
	}

	// 2. Attempt a QUIC handshake to confirm H3 reachability.
	start := time.Now()
	cfg := &quic.Config{
		HandshakeIdleTimeout:  5 * time.Second,
		MaxIdleTimeout:        5 * time.Second,
		KeepAlivePeriod:       0,
		Allow0RTT:             false,
		EnableDatagrams:       false,
		MaxIncomingStreams:    10,
		MaxIncomingUniStreams: 10,
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- probe targets may present self-signed certificates
		NextProtos:         []string{"h3"},
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	sess, err := quic.DialAddr(ctx, addr, tlsCfg, cfg)
	res.H3Latency = time.Since(start)
	if err != nil {
		res.H3Reachable = false
		res.Error = err.Error()
	} else {
		res.H3Reachable = true
		res.Negotiated = sess.ConnectionState().TLS.NegotiatedProtocol
		_ = sess.CloseWithError(0, "probe complete")
	}

	return res, nil
}

// Timeouts for the Alt-Svc probe. Without them a silent server would block
// Probe forever: tls.Dial and conn.Read have no deadline by default.
const (
	altSvcDialTimeout = 3 * time.Second
	altSvcReadTimeout = 5 * time.Second
	altSvcMaxHeader   = 64 << 10
)

// checkAltSvc attempts a TLS handshake and reads the Alt-Svc header to see if
// the server advertises HTTP/3. Returns true if "h3=" or "h3-29=" appears.
func checkAltSvc(host string, port int) (bool, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: altSvcDialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- Alt-Svc probe tolerates self-signed targets
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(altSvcReadTimeout))

	// Alt-Svc is a response header, so we need an HTTP response. Send a minimal
	// GET and read the header block.
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return false, err
	}

	br := bufio.NewReader(io.LimitReader(conn, altSvcMaxHeader))
	for {
		line, readErr := br.ReadString('\n')
		if line != "" && isAltSvcH3(line) {
			return true, nil
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return false, nil // headers ended without an H3 advertisement
			}
			return false, readErr
		}
		if line == "\r\n" || line == "\n" {
			return false, nil // end of header block
		}
	}
}

func isAltSvcH3(line string) bool {
	// Alt-Svc: h3=":443"; ma=86400  or  h3-29=":443"; ma=86400
	l := lower(line)
	return contains(l, "alt-svc") && (contains(l, "h3=\"") || contains(l, "h3-29=\""))
}

func lower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b = append(b, c)
	}
	return string(b)
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
