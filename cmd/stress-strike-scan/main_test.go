package main

import (
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

func TestPrintTLSInfo(t *testing.T) {
	tls := &scanner.TLSInfo{
		Version:        "TLS 1.3",
		CipherSuite:    "TLS_AES_128_GCM_SHA256",
		IsSecure:       true,
		ForwardSecrecy: true,
		HTTP2Supported: true,
		Certificate: &scanner.CertInfo{
			Subject:    "example.com",
			Issuer:     "Let's Encrypt",
			KeyType:    "RSA",
			KeySize:    2048,
			IsExpired:  false,
			IsSelfSigned: false,
		},
		SupportedVersions: []string{"TLS 1.3", "TLS 1.2"},
	}
	printTLSInfo(tls)
}

func TestPrintHTTPInfo(t *testing.T) {
	http := &scanner.HTTPInfo{
		Server:        "nginx",
		XPoweredBy:    "PHP/8.1",
		HTTPVersion:   "HTTP/1.1",
		Technologies:  []string{"Nginx", "PHP"},
		Methods:       []string{"GET", "POST"},
		CORS:          &scanner.CORSInfo{AllowOrigin: "*"},
	}
	printHTTPInfo(http)
}

func TestPrintWAFInfo(t *testing.T) {
	waf := &scanner.WAFInfo{
		Detected:  true,
		Name:      "Cloudflare",
		Vendor:    "Cloudflare, Inc.",
		Confidence: 95.0,
	}
	printWAFInfo(waf)
}

func TestPrintSecurityInfo(t *testing.T) {
	sec := &scanner.SecurityInfo{
		Score:          80,
		MissingHeaders: []string{"X-Frame-Options"},
		Headers:        map[string]string{"X-Content-Type-Options": "nosniff"},
	}
	printSecurityInfo(sec)
}
