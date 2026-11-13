// Package tls implements TLS/SSL scanning for the Sift scanner.
package tls

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner/core"
)

// KnownCiphers lists known TLS cipher suites.
var KnownCiphers = map[uint16]core.CipherInfo{
	// TLS 1.3
	0x1301: {Name: "TLS_AES_128_GCM_SHA256", Grade: "A", FS: true, AEAD: true},
	0x1302: {Name: "TLS_AES_256_GCM_SHA384", Grade: "A", FS: true, AEAD: true},
	0x1303: {Name: "TLS_CHACHA20_POLY1305_SHA256", Grade: "A", FS: true, AEAD: true},
	// ECDHE
	0xc02b: {Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", Grade: "A", FS: true, AEAD: true},
	0xc02c: {Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", Grade: "A", FS: true, AEAD: true},
	0xc02f: {Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Grade: "A", FS: true, AEAD: true},
	0xc030: {Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Grade: "A", FS: true, AEAD: true},
	0xcca8: {Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", Grade: "A", FS: true, AEAD: true},
	0xcca9: {Name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", Grade: "A", FS: true, AEAD: true},
	// Non-FS (weaker)
	0x009c: {Name: "TLS_RSA_WITH_AES_128_GCM_SHA256", Grade: "B", FS: false, AEAD: true},
	0x009d: {Name: "TLS_RSA_WITH_AES_256_GCM_SHA384", Grade: "B", FS: false, AEAD: true},
	// Insecure
	0x0005: {Name: "TLS_RSA_WITH_RC4_128_SHA", Grade: "F", FS: false, AEAD: false},
	0x000a: {Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Grade: "D", FS: false, AEAD: false},
	0x0004: {Name: "TLS_RSA_WITH_RC4_128_MD5", Grade: "F", FS: false, AEAD: false},
	0x0016: {Name: "TLS_RSA_WITH_IDEA_CBC_SHA", Grade: "D", FS: false, AEAD: false},
	0x0013: {Name: "TLS_RSA_WITH_DES_CBC_SHA", Grade: "F", FS: false, AEAD: false},
}

// InsecurePatterns lists insecure cipher name patterns.
var InsecurePatterns = []string{
	"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
}

// Secure TLS versions.
var secureVersions = []string{"TLS 1.3", "TLS 1.2"}

// ScanTLS performs a full TLS scan on the target host:port.
func ScanTLS(host string, port int) (*core.TLSInfo, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	info := &core.TLSInfo{
		SupportedVersions: make([]string, 0),
		SupportedCiphers:  make([]core.CipherInfo, 0),
		Vulnerabilities:   make([]string, 0),
	}

	tlsVersions := []struct {
		name string
		min  uint16
		max  uint16
	}{
		{"TLS 1.3", tls.VersionTLS13, tls.VersionTLS13},
		{"TLS 1.2", tls.VersionTLS12, tls.VersionTLS12},
		{"TLS 1.1", tls.VersionTLS11, tls.VersionTLS11},
		{"TLS 1.0", tls.VersionTLS10, tls.VersionTLS10},
	}

	for _, tv := range tlsVersions {
		config := &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- authorized pentest targets may use self-signed certificates
			MinVersion:         tv.min,
			MaxVersion:         tv.max,
		}

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 5 * time.Second},
			"tcp", addr, config,
		)
		if err != nil {
			continue
		}

		info.SupportedVersions = append(info.SupportedVersions, tv.name)

		if len(info.SupportedVersions) == 1 {
			state := conn.ConnectionState()
			info.Version = tv.name

			if state.CipherSuite != 0 {
				cipher := KnownCiphers[state.CipherSuite]
				if cipher.Name == "" {
					cipher = core.CipherInfo{
						Name:  fmt.Sprintf("UNKNOWN_%d", state.CipherSuite),
						ID:    state.CipherSuite,
						Grade: "B",
					}
				}
				info.CipherSuite = cipher.Name
				info.CipherSuiteID = state.CipherSuite
				info.ForwardSecrecy = cipher.FS

				info.IsSecure = true
				for _, p := range InsecurePatterns {
					if strings.Contains(strings.ToUpper(cipher.Name), p) {
						info.IsSecure = false
						info.Vulnerabilities = append(info.Vulnerabilities, fmt.Sprintf("Insecure cipher: %s", cipher.Name))
						break
					}
				}
			}

			if len(state.PeerCertificates) > 0 {
				certInfo := extractCertInfo(state.PeerCertificates[0])
				info.Certificate = &certInfo
				for _, cert := range state.PeerCertificates {
					ci := extractCertInfo(cert)
					info.CertificateChain = append(info.CertificateChain, ci)
				}
			}

			info.HTTP2Supported = state.NegotiatedProtocol == "h2"
		}

		conn.Close()
	}

	// Session resumption check
	config := &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- authorized pentest targets may use self-signed certificates
	conn1, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, config)
	if err == nil {
		conn1.Close()
		conn2, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, config)
		if err == nil {
			info.SessionResumption = true
			conn2.Close()
		}
	}

	return info, nil
}

func extractCertInfo(cert *x509.Certificate) core.CertInfo {
	info := core.CertInfo{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsExpired:    time.Now().After(cert.NotAfter),
		SerialNumber: cert.SerialNumber.String(),
		SANs:         cert.DNSNames,
		SignatureAlg: cert.SignatureAlgorithm.String(),
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyType = "RSA"
		info.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeyType = "ECDSA"
		info.KeySize = pub.Curve.Params().BitSize
	default:
		info.KeyType = "Unknown"
	}

	info.IsSelfSigned = cert.Issuer.CommonName == cert.Subject.CommonName

	return info
}
