package main

import (
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

func TestCalculateVulnsNone(t *testing.T) {
	r := &scanner.ScanResult{
		TLS: &scanner.TLSInfo{Version: "TLS 1.3", IsSecure: true, Certificate: &scanner.CertInfo{IsExpired: false, IsSelfSigned: false}},
		Security: &scanner.SecurityInfo{
			Score: 90,
			Details: []scanner.SecurityDetail{
				{Header: "strict-transport-security", Status: "present"},
			},
		},
		HTTP: &scanner.HTTPInfo{CORS: &scanner.CORSInfo{AllowOrigin: "https://app.example.com", IsPermissive: false}},
	}
	vulns := calculateVulns(r)
	if len(vulns) != 0 {
		t.Fatalf("expected no vulns, got %+v", vulns)
	}
}

func TestCalculateVulnsTLS(t *testing.T) {
	r := &scanner.ScanResult{
		TLS: &scanner.TLSInfo{
			Version:     "TLS 1.0",
			IsSecure:    false,
			Certificate: &scanner.CertInfo{IsExpired: true, IsSelfSigned: true, NotAfter: time.Now().Add(-24 * time.Hour)},
		},
	}
	vulns := calculateVulns(r)
	ids := make(map[string]bool)
	for _, v := range vulns {
		ids[v.ID] = true
	}
	for _, want := range []string{"TLS-001", "TLS-002", "TLS-003"} {
		if !ids[want] {
			t.Errorf("missing vuln %s in %v", want, ids)
		}
	}
	// TLS-001 must be critical severity.
	for _, v := range vulns {
		if v.ID == "TLS-001" && v.Severity != "critical" {
			t.Errorf("TLS-001 severity = %q, want critical", v.Severity)
		}
	}
}

func TestCalculateVulnsSecurityHeaders(t *testing.T) {
	r := &scanner.ScanResult{
		Security: &scanner.SecurityInfo{
			Score:          40,
			MissingHeaders: []string{"x-frame-options", "content-security-policy"},
		},
	}
	vulns := calculateVulns(r)
	if len(vulns) != 2 {
		t.Fatalf("expected 2 header vulns, got %d: %+v", len(vulns), vulns)
	}
	ids := map[string]bool{vulns[0].ID: true, vulns[1].ID: true}
	if !ids["SEC-XFRAMEOPTIONS"] || !ids["SEC-CONTENTSECURITYPOLICY"] {
		t.Errorf("unexpected header vuln IDs: %v", ids)
	}
	for _, v := range vulns {
		if v.Severity != "medium" {
			t.Errorf("header vuln severity = %q, want medium", v.Severity)
		}
	}
}

func TestCalculateVulnsPermissiveCORS(t *testing.T) {
	r := &scanner.ScanResult{
		HTTP: &scanner.HTTPInfo{CORS: &scanner.CORSInfo{AllowOrigin: "*", IsPermissive: true}},
	}
	vulns := calculateVulns(r)
	if len(vulns) != 1 || vulns[0].ID != "CORS-001" {
		t.Fatalf("expected CORS-001 vuln, got %+v", vulns)
	}
}

func TestCalculateRiskScoreClean(t *testing.T) {
	r := &scanner.ScanResult{
		TLS: &scanner.TLSInfo{Version: "TLS 1.3", IsSecure: true},
	}
	if got := calculateRiskScore(r); got != 100 {
		t.Errorf("clean scan risk score = %d, want 100", got)
	}
}

func TestCalculateRiskScoreNilEverything(t *testing.T) {
	if got := calculateRiskScore(&scanner.ScanResult{}); got != 100 {
		t.Errorf("nil-sections risk score = %d, want 100", got)
	}
}

func TestCalculateRiskScoreTLSFlags(t *testing.T) {
	cases := []struct {
		name string
		r    *scanner.ScanResult
		want int
	}{
		{
			name: "insecure only",
			r:    &scanner.ScanResult{TLS: &scanner.TLSInfo{Version: "TLS 1.2", IsSecure: false}},
			want: 80,
		},
		{
			name: "insecure + expired",
			r: &scanner.ScanResult{TLS: &scanner.TLSInfo{
				Version:     "TLS 1.2",
				IsSecure:    false,
				Certificate: &scanner.CertInfo{IsExpired: true},
			}},
			want: 50,
		},
		{
			name: "insecure + expired + self-signed + TLS 1.0",
			r: &scanner.ScanResult{TLS: &scanner.TLSInfo{
				Version:     "TLS 1.0",
				IsSecure:    false,
				Certificate: &scanner.CertInfo{IsExpired: true, IsSelfSigned: true},
			}},
			want: 20, // 100 - 20 - 30 - 15 - 15
		},
	}
	for _, c := range cases {
		if got := calculateRiskScore(c.r); got != c.want {
			t.Errorf("%s: risk score = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestCalculateRiskScoreSecurityDeduction(t *testing.T) {
	r := &scanner.ScanResult{Security: &scanner.SecurityInfo{Score: 0}}
	if got := calculateRiskScore(r); got != 80 { // 100 - (100-0)/5
		t.Errorf("security score 0 -> risk = %d, want 80", got)
	}
	r = &scanner.ScanResult{Security: &scanner.SecurityInfo{Score: 75}}
	if got := calculateRiskScore(r); got != 95 { // 100 - (100-75)/5 = 95
		t.Errorf("security score 75 -> risk = %d, want 95", got)
	}
}

func TestCalculateRiskScoreClampsToZero(t *testing.T) {
	r := &scanner.ScanResult{
		TLS: &scanner.TLSInfo{Version: "TLS 1.0", IsSecure: false, Certificate: &scanner.CertInfo{IsExpired: true, IsSelfSigned: true}}, // -80
		Vulns: []scanner.Vuln{
			{ID: "X1", Severity: "critical"}, // -25
			{ID: "X2", Severity: "critical"}, // -25
			{ID: "X3", Severity: "high"},     // -15
		},
	}
	if got := calculateRiskScore(r); got != 0 {
		t.Errorf("risk score = %d, want clamped 0", got)
	}
}

func TestMin(t *testing.T) {
	if got := min(3, 5); got != 3 {
		t.Errorf("min(3,5) = %d", got)
	}
	if got := min(5, 3); got != 3 {
		t.Errorf("min(5,3) = %d", got)
	}
	if got := min(4, 4); got != 4 {
		t.Errorf("min(4,4) = %d", got)
	}
}
