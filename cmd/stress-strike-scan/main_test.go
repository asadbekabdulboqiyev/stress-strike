package main

import (
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
)

func TestPrintTLSInfo(t *testing.T) {
	tls := &scanner.TLSInfo{
		Version:        "TLS 1.3",
		CipherSuite:    "TLS_AES_128_GCM_SHA256",
		IsSecure:       true,
		ForwardSecrecy: true,
		HTTP2Supported: true,
		Certificate: &scanner.CertInfo{
			Subject:      "example.com",
			Issuer:       "Let's Encrypt",
			KeyType:      "RSA",
			KeySize:      2048,
			IsExpired:    false,
			IsSelfSigned: false,
		},
		SupportedVersions: []string{"TLS 1.3", "TLS 1.2"},
	}
	printTLSInfo(tls)
}

func TestPrintHTTPInfo(t *testing.T) {
	http := &scanner.HTTPInfo{
		Server:       "nginx",
		XPoweredBy:   "PHP/8.1",
		HTTPVersion:  "HTTP/1.1",
		Technologies: []string{"Nginx", "PHP"},
		Methods:      []string{"GET", "POST"},
		CORS:         &scanner.CORSInfo{AllowOrigin: "*"},
	}
	printHTTPInfo(http)
}

func TestPrintWAFInfo(t *testing.T) {
	waf := &scanner.WAFInfo{
		Detected:   true,
		Name:       "Cloudflare",
		Vendor:     "Cloudflare, Inc.",
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

func TestMin(t *testing.T) {
	if got := min(10, 20); got != 10 {
		t.Errorf("min(10,20) = %d, want 10", got)
	}
	if got := min(20, 10); got != 10 {
		t.Errorf("min(20,10) = %d, want 10", got)
	}
	if got := min(5, 5); got != 5 {
		t.Errorf("min(5,5) = %d, want 5", got)
	}
}

func TestCalculateVulns(t *testing.T) {
	// No findings when everything is clean
	r := &scanner.ScanResult{}
	vulns := calculateVulns(r)
	if len(vulns) != 0 {
		t.Errorf("calculateVulns(clean) = %d vulns, want 0", len(vulns))
	}

	// Expired TLS cert
	r = &scanner.ScanResult{
		TLS: &scanner.TLSInfo{
			Certificate: &scanner.CertInfo{IsExpired: true},
		},
	}
	vulns = calculateVulns(r)
	if len(vulns) == 0 {
		t.Error("calculateVulns(expired cert) should find 1 vuln")
	}
	if vulns[0].ID != "TLS-001" {
		t.Errorf("first vuln ID = %q, want TLS-001", vulns[0].ID)
	}

	// Self-signed cert
	r = &scanner.ScanResult{
		TLS: &scanner.TLSInfo{
			Certificate: &scanner.CertInfo{IsSelfSigned: true},
		},
	}
	vulns = calculateVulns(r)
	if len(vulns) == 0 {
		t.Error("calculateVulns(self-signed) should find 1 vuln")
	}
	if vulns[0].ID != "TLS-002" {
		t.Errorf("first vuln ID = %q, want TLS-002", vulns[0].ID)
	}

	// Deprecated TLS version
	r = &scanner.ScanResult{
		TLS: &scanner.TLSInfo{Version: "TLS 1.0"},
	}
	vulns = calculateVulns(r)
	if len(vulns) == 0 {
		t.Error("calculateVulns(TLS 1.0) should find 1 vuln")
	}

	// Missing security header
	r = &scanner.ScanResult{
		Security: &scanner.SecurityInfo{MissingHeaders: []string{"X-Frame-Options"}},
	}
	vulns = calculateVulns(r)
	if len(vulns) == 0 {
		t.Error("calculateVulns(missing header) should find 1 vuln")
	}

	// Permissive CORS
	r = &scanner.ScanResult{
		HTTP: &scanner.HTTPInfo{CORS: &scanner.CORSInfo{IsPermissive: true}},
	}
	vulns = calculateVulns(r)
	if len(vulns) == 0 {
		t.Error("calculateVulns(permissive CORS) should find 1 vuln")
	}
}

func TestCalculateRiskScore(t *testing.T) {
	// Clean scan = 100
	r := &scanner.ScanResult{}
	if got := calculateRiskScore(r); got != 100 {
		t.Errorf("calculateRiskScore(clean) = %d, want 100", got)
	}

	// Insecure TLS
	r = &scanner.ScanResult{TLS: &scanner.TLSInfo{IsSecure: false}}
	if got := calculateRiskScore(r); got != 80 {
		t.Errorf("calculateRiskScore(insecure TLS) = %d, want 80", got)
	}

	// Expired cert (-30 for expiry, -20 for IsSecure=false default)
	r = &scanner.ScanResult{TLS: &scanner.TLSInfo{Certificate: &scanner.CertInfo{IsExpired: true}}}
	if got := calculateRiskScore(r); got != 50 {
		t.Errorf("calculateRiskScore(expired cert) = %d, want 50", got)
	}

	// Critical vuln (-25)
	r = &scanner.ScanResult{Vulns: []scanner.Vuln{{Severity: "critical"}}}
	if got := calculateRiskScore(r); got != 75 {
		t.Errorf("calculateRiskScore(critical) = %d, want 75", got)
	}

	// Multiple deductions floor at 0
	r = &scanner.ScanResult{
		TLS: &scanner.TLSInfo{
			IsSecure: false,
			Certificate: &scanner.CertInfo{
				IsExpired:    true,
				IsSelfSigned: true,
			},
			Version: "TLS 1.0",
		},
		Security: &scanner.SecurityInfo{Score: 0},
		Vulns: []scanner.Vuln{
			{Severity: "critical"},
			{Severity: "high"},
			{Severity: "medium"},
			{Severity: "low"},
		},
	}
	if got := calculateRiskScore(r); got != 0 {
		t.Errorf("calculateRiskScore(many deductions) = %d, want 0", got)
	}
}
