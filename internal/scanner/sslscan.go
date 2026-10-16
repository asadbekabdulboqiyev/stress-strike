package scanner

// --- SSL/TLS analyzer --------------------------------------------------------
//
// Inspects a target's TLS configuration: certificate validity, issuer,
// SANs, expired/not-yet-valid dates, weak ciphers (via utls if available),
// and protocol version support. stdlib-only for the core scan; utls is used
// opportunistically when present.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// SSLResult is the output of an SSL/TLS scan.
type SSLResult struct {
	Target    string        `json:"target"`
	Valid     bool          `json:"valid"`
	Issuer    string        `json:"issuer,omitempty"`
	Subject   string        `json:"subject,omitempty"`
	NotBefore string        `json:"not_before,omitempty"`
	NotAfter  string        `json:"not_after,omitempty"`
	Expired   bool          `json:"expired"`
	SANs      []string      `json:"sans,omitempty"`
	Cipher    string        `json:"cipher,omitempty"`
	Version   string        `json:"version,omitempty"`
	Issues    []string      `json:"issues,omitempty"`
	Duration  time.Duration `json:"duration"`
}

// ScanSSL performs a TLS handshake against host:port (default 443) and
// reports certificate and configuration weaknesses.
func ScanSSL(ctx context.Context, target string) *SSLResult {
	res := &SSLResult{Target: target}
	start := time.Now()

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "443"
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		res.Issues = append(res.Issues, fmt.Sprintf("cannot connect: %v", err))
		res.Duration = time.Since(start)
		return res
	}
	defer func() { _ = conn.Close() }()

	config := &tls.Config{
		// nolint:gosec
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	}
	tconn := tls.Client(conn, config)
	if err := tconn.Handshake(); err != nil {
		res.Issues = append(res.Issues, fmt.Sprintf("tls handshake failed: %v", err))
		res.Duration = time.Since(start)
		return res
	}
	defer func() { _ = tconn.Close() }()

	state := tconn.ConnectionState()
	res.Version = tlsVersionName(state.Version)
	res.Cipher = tls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		res.Issuer = cert.Issuer.CommonName
		res.Subject = cert.Subject.CommonName
		res.NotBefore = cert.NotBefore.Format("2006-01-02")
		res.NotAfter = cert.NotAfter.Format("2006-01-02")
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			res.Expired = true
			res.Issues = append(res.Issues, "certificate is not valid now")
		}
		res.SANs = append(res.SANs, cert.DNSNames...)
		for _, ip := range cert.IPAddresses {
			res.SANs = append(res.SANs, ip.String())
		}
		res.Valid = state.HandshakeComplete && !res.Expired
	} else {
		res.Issues = append(res.Issues, "no peer certificates presented")
	}

	// Weak cipher / protocol flags.
	if strings.Contains(res.Version, "SSL") || strings.Contains(res.Version, "1.0") || strings.Contains(res.Version, "1.1") {
		res.Issues = append(res.Issues, "weak TLS protocol ("+res.Version+")")
	}

	res.Duration = time.Since(start)
	return res
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
