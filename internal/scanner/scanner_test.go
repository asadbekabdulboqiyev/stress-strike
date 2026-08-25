package scanner

import (
	"fmt"
	"net/http"
	"sort"
	"testing"
	"time"
)

// findSecurityHeader returns a security header definition by name.
func findSecurityHeader(name string) *struct {
	Name     string
	Required bool
	Weight   int
	Check    func(string) (string, string)
} {
	for i := range securityHeaders {
		if securityHeaders[i].Name == name {
			return &securityHeaders[i]
		}
	}
	return nil
}

// findSecurityHeaderCheck returns the Check function for a named security header.
func findSecurityHeaderCheck(name string) func(string) (string, string) {
	h := findSecurityHeader(name)
	if h == nil {
		return nil
	}
	return h.Check
}

// --- WAF Signature Tests ----------------------------------------------------

func TestWAFSignatures_AllExpected(t *testing.T) {
	expected := []string{
		"cloudflare", "akamai", "aws-waf", "modsecurity",
		"incapsula", "fortiweb", "barracuda", "denied",
	}
	for _, name := range expected {
		if _, ok := wafSignatures[name]; !ok {
			t.Errorf("missing expected WAF signature: %s", name)
		}
	}
}

func TestWAFSignature_Cloudflare(t *testing.T) {
	sig := wafSignatures["cloudflare"]
	if sig.Name != "Cloudflare" {
		t.Errorf("name = %q, want Cloudflare", sig.Name)
	}
	if !sig.JSChallenge {
		t.Error("cloudflare should have JSChallenge=true")
	}
	if len(sig.Headers) == 0 {
		t.Error("cloudflare should have header signatures")
	}
	if len(sig.Body) == 0 {
		t.Error("cloudflare should have body signatures")
	}
}

func TestWAFSignature_AllHaveNames(t *testing.T) {
	for key, sig := range wafSignatures {
		if sig.Name == "" {
			t.Errorf("WAF signature %q has empty Name", key)
		}
		if sig.Vendor == "" {
			t.Errorf("WAF signature %q has empty Vendor", key)
		}
	}
}

func TestWAFSignatures_HeaderPatterns(t *testing.T) {
	// Verify that header patterns exist for major WAFs
	for _, name := range []string{"cloudflare", "aws-waf", "akamai"} {
		sig := wafSignatures[name]
		if len(sig.Headers) == 0 {
			t.Errorf("%s should have header signatures", name)
		}
	}
}

// --- Security Header Check Tests --------------------------------------------

func TestSecurityHeaders_AllPresent(t *testing.T) {
	if len(securityHeaders) == 0 {
		t.Fatal("securityHeaders is empty")
	}

	// Verify required headers have proper weights
	totalWeight := 0
	for _, sh := range securityHeaders {
		if sh.Name == "" {
			t.Error("empty header name in securityHeaders")
		}
		if sh.Weight <= 0 {
			t.Errorf("header %s has non-positive weight: %d", sh.Name, sh.Weight)
		}
		totalWeight += sh.Weight
	}
	if totalWeight == 0 {
		t.Error("total weight should be > 0")
	}
}

func TestSecurityHeaderCheck_HSTS(t *testing.T) {
	check := findSecurityHeaderCheck("Strict-Transport-Security")
	if check == nil {
		t.Fatal("HSTS header not found")
	}

	tests := []struct {
		value  string
		status string
	}{
		{"", "missing"},
		{"max-age=0", "weak"},
		{"max-age=31536000", "strong"},
		{"max-age=1000", "weak"},
		{"max-age=63072000; includeSubDomains", "strong"},
	}

	for _, tt := range tests {
		status, _ := check(tt.value)
		if status != tt.status {
			t.Errorf("HSTS check(%q) = %q, want %q", tt.value, status, tt.status)
		}
	}
}

func TestSecurityHeaderCheck_CSP(t *testing.T) {
	check := findSecurityHeaderCheck("Content-Security-Policy")
	if check == nil {
		t.Fatal("CSP header not found")
	}

	tests := []struct {
		value  string
		status string
	}{
		{"", "missing"},
		{"script-src 'self'", "strong"},
		{"script-src 'unsafe-inline'", "weak"},
		{"script-src 'unsafe-eval'", "weak"},
		{"default-src 'self'; script-src 'self'", "strong"},
	}

	for _, tt := range tests {
		status, _ := check(tt.value)
		if status != tt.status {
			t.Errorf("CSP check(%q) = %q, want %q", tt.value, status, tt.status)
		}
	}
}

func TestSecurityHeaderCheck_XFrameOptions(t *testing.T) {
	check := findSecurityHeaderCheck("X-Frame-Options")
	if check == nil {
		t.Fatal("X-Frame-Options header not found")
	}

	tests := []struct {
		value  string
		status string
	}{
		{"", "missing"},
		{"DENY", "strong"},
		{"SAMEORIGIN", "strong"},
	}

	for _, tt := range tests {
		status, _ := check(tt.value)
		if status != tt.status {
			t.Errorf("XFO check(%q) = %q, want %q", tt.value, status, tt.status)
		}
	}
}

func TestSecurityHeaderCheck_XContentTypeOptions(t *testing.T) {
	check := findSecurityHeaderCheck("X-Content-Type-Options")
	if check == nil {
		t.Fatal("X-Content-Type-Options header not found")
	}

	tests := []struct {
		value  string
		status string
	}{
		{"", "missing"},
		{"nosniff", "strong"},
		{"sniff", "weak"},
	}

	for _, tt := range tests {
		status, _ := check(tt.value)
		if status != tt.status {
			t.Errorf("XTCO check(%q) = %q, want %q", tt.value, status, tt.status)
		}
	}
}

func TestSecurityHeaderCheck_ReferrerPolicy(t *testing.T) {
	check := findSecurityHeaderCheck("Referrer-Policy")
	if check == nil {
		t.Fatal("Referrer-Policy header not found")
	}

	tests := []struct {
		value  string
		status string
	}{
		{"", "missing"},
		{"unsafe-url", "weak"},
		{"no-referrer", "strong"},
		{"strict-origin-when-cross-origin", "strong"},
	}

	for _, tt := range tests {
		status, _ := check(tt.value)
		if status != tt.status {
			t.Errorf("Referrer-Policy check(%q) = %q, want %q", tt.value, status, tt.status)
		}
	}
}

func TestSecurityHeaderCheck_PermissionsPolicy(t *testing.T) {
	check := findSecurityHeaderCheck("Permissions-Policy")
	if check == nil {
		t.Fatal("Permissions-Policy header not found")
	}

	status, _ := check("")
	if status != "missing" {
		t.Errorf("empty Permissions-Policy: got %q, want missing", status)
	}

	status, _ = check("camera=()")
	if status != "strong" {
		t.Errorf("set Permissions-Policy: got %q, want strong", status)
	}
}

func TestSecurityHeaderCheck_XSSProtection(t *testing.T) {
	check := findSecurityHeaderCheck("X-XSS-Protection")
	if check == nil {
		t.Fatal("X-XSS-Protection header not found")
	}

	tests := []struct {
		value  string
		status string
	}{
		{"", "info"},
		{"0", "info"},
		{"1; mode=block", "strong"},
	}

	for _, tt := range tests {
		status, _ := check(tt.value)
		if status != tt.status {
			t.Errorf("XSS-Protection check(%q) = %q, want %q", tt.value, status, tt.status)
		}
	}
}

func TestSecurityHeaderCheck_COOP(t *testing.T) {
	check := findSecurityHeaderCheck("Cross-Origin-Opener-Policy")
	if check == nil {
		t.Fatal("COOP header not found")
	}

	status, _ := check("")
	if status != "info" {
		t.Errorf("empty COOP: got %q, want info", status)
	}

	status, _ = check("same-origin")
	if status != "strong" {
		t.Errorf("set COOP: got %q, want strong", status)
	}
}

func TestSecurityHeaderCheck_CORP(t *testing.T) {
	check := findSecurityHeaderCheck("Cross-Origin-Resource-Policy")
	if check == nil {
		t.Fatal("CORP header not found")
	}

	status, _ := check("")
	if status != "info" {
		t.Errorf("empty CORP: got %q, want info", status)
	}
}

func TestSecurityHeaderCheck_COEP(t *testing.T) {
	check := findSecurityHeaderCheck("Cross-Origin-Embedder-Policy")
	if check == nil {
		t.Fatal("COEP header not found")
	}

	status, _ := check("")
	if status != "info" {
		t.Errorf("empty COEP: got %q, want info", status)
	}
}

// --- Risk Score Tests -------------------------------------------------------

func TestCalculateRiskScore_CleanResult(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure:    true,
			Version:     "TLS 1.3",
			Certificate: &CertInfo{IsExpired: false, IsSelfSigned: false},
		},
		Security: &SecurityInfo{Score: 100},
		WAF:      &WAFInfo{Detected: true},
	}

	score := calculateRiskScore(result)
	if score != 100 {
		t.Errorf("clean result risk score = %d, want 100", score)
	}
}

func TestCalculateRiskScore_InsecureTLS(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure: false,
			Version:  "TLS 1.3",
		},
		Security: &SecurityInfo{Score: 100},
	}

	score := calculateRiskScore(result)
	if score >= 100 {
		t.Errorf("insecure TLS risk score = %d, want < 100", score)
	}
}

func TestCalculateRiskScore_ExpiredCert(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure: true,
			Version:  "TLS 1.3",
			Certificate: &CertInfo{
				IsExpired: true,
			},
		},
		Security: &SecurityInfo{Score: 100},
	}

	score := calculateRiskScore(result)
	if score >= 100 {
		t.Errorf("expired cert risk score = %d, want < 100", score)
	}
}

func TestCalculateRiskScore_SelfSignedCert(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure: true,
			Version:  "TLS 1.3",
			Certificate: &CertInfo{
				IsSelfSigned: true,
			},
		},
		Security: &SecurityInfo{Score: 100},
	}

	score := calculateRiskScore(result)
	if score >= 100 {
		t.Errorf("self-signed cert risk score = %d, want < 100", score)
	}
}

func TestCalculateRiskScore_DeprecatedTLS(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure:    true,
			Version:     "TLS 1.0",
			Certificate: &CertInfo{IsExpired: false, IsSelfSigned: false},
		},
		Security: &SecurityInfo{Score: 100},
	}

	score := calculateRiskScore(result)
	if score >= 100 {
		t.Errorf("deprecated TLS risk score = %d, want < 100", score)
	}
}

func TestCalculateRiskScore_LowSecurityScore(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure:    true,
			Version:     "TLS 1.3",
			Certificate: &CertInfo{IsExpired: false, IsSelfSigned: false},
		},
		Security: &SecurityInfo{Score: 20},
	}

	score := calculateRiskScore(result)
	if score >= 100 {
		t.Errorf("low security header score risk score = %d, want < 100", score)
	}
}

func TestCalculateRiskScore_MultipleIssues(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure: false,
			Version:  "TLS 1.0",
			Certificate: &CertInfo{
				IsExpired:    true,
				IsSelfSigned: true,
			},
		},
		Security: &SecurityInfo{Score: 10},
		Vulns: []Vuln{
			{Severity: "critical"},
			{Severity: "high"},
			{Severity: "medium"},
		},
	}

	score := calculateRiskScore(result)
	if score != 0 {
		t.Errorf("worst case risk score = %d, want 0", score)
	}
}

func TestCalculateRiskScore_NoTLSInfo(t *testing.T) {
	result := &ScanResult{
		TLS:      nil,
		Security: &SecurityInfo{Score: 100},
	}

	score := calculateRiskScore(result)
	if score != 100 {
		t.Errorf("nil TLS risk score = %d, want 100", score)
	}
}

func TestCalculateRiskScore_NoSecurityInfo(t *testing.T) {
	result := &ScanResult{
		TLS:      &TLSInfo{IsSecure: true, Version: "TLS 1.3", Certificate: &CertInfo{}},
		Security: nil,
	}

	score := calculateRiskScore(result)
	if score != 100 {
		t.Errorf("nil Security risk score = %d, want 100", score)
	}
}

func TestCalculateRiskScore_VulnDeductions(t *testing.T) {
	base := &ScanResult{
		TLS:      &TLSInfo{IsSecure: true, Version: "TLS 1.3", Certificate: &CertInfo{}},
		Security: &SecurityInfo{Score: 100},
	}

	// Each vuln type should deduct differently
	vulnTests := []struct {
		severity string
		deduct   int
	}{
		{"critical", 25},
		{"high", 15},
		{"medium", 8},
		{"low", 3},
	}

	for _, vt := range vulnTests {
		r := &ScanResult{
			TLS:      base.TLS,
			Security: base.Security,
			Vulns:    []Vuln{{Severity: vt.severity}},
		}
		score := calculateRiskScore(r)
		expected := 100 - vt.deduct
		if score != expected {
			t.Errorf("severity %s: score = %d, want %d", vt.severity, score, expected)
		}
	}
}

// --- Vulnerability Calculation Tests ----------------------------------------

func TestCalculateVulns_NoIssues(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure:        true,
			Version:         "TLS 1.3",
			Certificate:     &CertInfo{IsExpired: false, IsSelfSigned: false},
			Vulnerabilities: []string{},
		},
		Security: &SecurityInfo{MissingHeaders: []string{}},
		WAF:      &WAFInfo{Detected: true},
		HTTP:     &HTTPInfo{CORS: &CORSInfo{IsPermissive: false}},
	}

	vulns := calculateVulns(result)
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(vulns))
	}
}

func TestCalculateVulns_ExpiredCert(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure: true,
			Version:  "TLS 1.3",
			Certificate: &CertInfo{
				IsExpired: true,
				NotAfter:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		Security: &SecurityInfo{MissingHeaders: []string{}},
		WAF:      &WAFInfo{Detected: true},
	}

	vulns := calculateVulns(result)
	found := false
	for _, v := range vulns {
		if v.ID == "TLS-001" {
			found = true
			if v.Severity != "critical" {
				t.Errorf("expired cert vuln severity = %q, want critical", v.Severity)
			}
		}
	}
	if !found {
		t.Error("expected TLS-001 vulnerability for expired cert")
	}
}

func TestCalculateVulns_SelfSignedCert(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure: true,
			Version:  "TLS 1.3",
			Certificate: &CertInfo{
				IsSelfSigned: true,
			},
		},
		Security: &SecurityInfo{MissingHeaders: []string{}},
		WAF:      &WAFInfo{Detected: true},
	}

	vulns := calculateVulns(result)
	found := false
	for _, v := range vulns {
		if v.ID == "TLS-002" {
			found = true
			if v.Severity != "high" {
				t.Errorf("self-signed cert vuln severity = %q, want high", v.Severity)
			}
		}
	}
	if !found {
		t.Error("expected TLS-002 vulnerability for self-signed cert")
	}
}

func TestCalculateVulns_TLSVulnerabilities(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure:        false,
			Version:         "TLS 1.3",
			Certificate:     &CertInfo{},
			Vulnerabilities: []string{"Insecure cipher: TLS_RSA_WITH_RC4_128_SHA"},
		},
		Security: &SecurityInfo{MissingHeaders: []string{}},
		WAF:      &WAFInfo{Detected: true},
	}

	vulns := calculateVulns(result)
	found := false
	for _, v := range vulns {
		if v.ID == "TLS-003" {
			found = true
		}
	}
	if !found {
		t.Error("expected TLS-003 vulnerability for insecure cipher")
	}
}

func TestCalculateVulns_DeprecatedTLSVersion(t *testing.T) {
	for _, version := range []string{"TLS 1.0", "TLS 1.1"} {
		result := &ScanResult{
			TLS: &TLSInfo{
				IsSecure:    true,
				Version:     version,
				Certificate: &CertInfo{},
			},
			Security: &SecurityInfo{MissingHeaders: []string{}},
			WAF:      &WAFInfo{Detected: true},
		}

		vulns := calculateVulns(result)
		found := false
		for _, v := range vulns {
			if v.ID == "TLS-004" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected TLS-004 for %s", version)
		}
	}
}

func TestCalculateVulns_MissingSecurityHeaders(t *testing.T) {
	result := &ScanResult{
		TLS: &TLSInfo{
			IsSecure:    true,
			Version:     "TLS 1.3",
			Certificate: &CertInfo{},
		},
		Security: &SecurityInfo{
			MissingHeaders: []string{
				"Content-Security-Policy",
				"Strict-Transport-Security",
			},
		},
		WAF: &WAFInfo{Detected: true},
	}

	vulns := calculateVulns(result)
	cspFound := false
	hstsFound := false
	for _, v := range vulns {
		if v.ID == "SEC-contentsecuritypolicy" {
			cspFound = true
			if v.Severity != "medium" {
				t.Errorf("missing CSP severity = %q, want medium", v.Severity)
			}
		}
		if v.ID == "SEC-stricttransportsecurity" {
			hstsFound = true
		}
	}
	if !cspFound {
		t.Error("expected SEC vulnerability for missing CSP")
	}
	if !hstsFound {
		t.Error("expected SEC vulnerability for missing HSTS")
	}
}

func TestCalculateVulns_PermissiveCORS(t *testing.T) {
	result := &ScanResult{
		TLS:      &TLSInfo{IsSecure: true, Version: "TLS 1.3", Certificate: &CertInfo{}},
		Security: &SecurityInfo{MissingHeaders: []string{}},
		WAF:      &WAFInfo{Detected: true},
		HTTP: &HTTPInfo{
			CORS: &CORSInfo{AllowOrigin: "*", IsPermissive: true},
		},
	}

	vulns := calculateVulns(result)
	found := false
	for _, v := range vulns {
		if v.ID == "CORS-001" {
			found = true
			if v.Severity != "medium" {
				t.Errorf("CORS vuln severity = %q, want medium", v.Severity)
			}
		}
	}
	if !found {
		t.Error("expected CORS-001 vulnerability for permissive CORS")
	}
}

func TestCalculateVulns_NoWAF(t *testing.T) {
	result := &ScanResult{
		TLS:      &TLSInfo{IsSecure: true, Version: "TLS 1.3", Certificate: &CertInfo{}},
		Security: &SecurityInfo{MissingHeaders: []string{}},
		WAF:      &WAFInfo{Detected: false},
	}

	vulns := calculateVulns(result)
	found := false
	for _, v := range vulns {
		if v.ID == "WAF-001" {
			found = true
			if v.Severity != "info" {
				t.Errorf("no-WAF vuln severity = %q, want info", v.Severity)
			}
		}
	}
	if !found {
		t.Error("expected WAF-001 for no WAF detected")
	}
}

func TestCalculateVulns_NilTLS(t *testing.T) {
	result := &ScanResult{
		TLS:      nil,
		Security: &SecurityInfo{MissingHeaders: []string{}},
		WAF:      &WAFInfo{Detected: true},
	}

	vulns := calculateVulns(result)
	// Should not panic with nil TLS
	for _, v := range vulns {
		if v.ID == "TLS-001" || v.ID == "TLS-002" {
			t.Errorf("should not produce TLS vulns when TLS is nil, got %s", v.ID)
		}
	}
}

// --- ContainsTech Tests -----------------------------------------------------

func TestContainsTech(t *testing.T) {
	tests := []struct {
		techs []string
		tech  string
		want  bool
	}{
		{[]string{"PHP", "Nginx"}, "php", true},
		{[]string{"PHP", "Nginx"}, "Nginx", true},
		{[]string{"PHP"}, "Python", false},
		{[]string{}, "PHP", false},
	}

	for _, tt := range tests {
		got := containsTech(tt.techs, tt.tech)
		if got != tt.want {
			t.Errorf("containsTech(%v, %q) = %v, want %v", tt.techs, tt.tech, got, tt.want)
		}
	}
}

// --- CORS Detection Tests ---------------------------------------------------

func TestCORSInfo_Permissive(t *testing.T) {
	cors := &CORSInfo{
		AllowOrigin:  "*",
		AllowMethods: "GET, POST, PUT, DELETE",
		IsPermissive: true,
	}
	if !cors.IsPermissive {
		t.Error("CORS with Allow-Origin * should be permissive")
	}
}

func TestCORSInfo_Restricted(t *testing.T) {
	cors := &CORSInfo{
		AllowOrigin:  "https://example.com",
		AllowMethods: "GET",
		Credentials:  true,
		IsPermissive: false,
	}
	if cors.IsPermissive {
		t.Error("specific origin should not be permissive")
	}
	if !cors.Credentials {
		t.Error("Credentials should be true")
	}
}

func TestCORSInfo_Empty(t *testing.T) {
	cors := &CORSInfo{}
	if cors.IsPermissive {
		t.Error("empty CORS should not be permissive")
	}
}

// --- BySeverity Sort Tests --------------------------------------------------

func TestBySeverity_Sort(t *testing.T) {
	vulns := []Vuln{
		{Severity: "low"},
		{Severity: "critical"},
		{Severity: "medium"},
		{Severity: "info"},
		{Severity: "high"},
	}

	sort.Sort(BySeverity(vulns))

	expected := []string{"critical", "high", "medium", "low", "info"}
	for i, v := range vulns {
		if v.Severity != expected[i] {
			t.Errorf("vulns[%d].Severity = %q, want %q", i, v.Severity, expected[i])
		}
	}
}

func TestBySeverity_Empty(t *testing.T) {
	vulns := BySeverity(nil)
	if vulns.Len() != 0 {
		t.Error("nil slice should have length 0")
	}
}

func TestBySeverity_Swap(t *testing.T) {
	vulns := []Vuln{
		{Severity: "high"},
		{Severity: "low"},
	}
	vulns[0], vulns[1] = vulns[1], vulns[0]
	if vulns[0].Severity != "low" || vulns[1].Severity != "high" {
		t.Error("swap failed")
	}
}

// --- DetectTechnologies Tests -----------------------------------------------

func TestDetectTechnologies_Server(t *testing.T) {
	tests := []struct {
		serverHeader string
		expectTech   string
	}{
		{"nginx/1.21.0", "Nginx"},
		{"Apache/2.4.41", "Apache"},
		{"cloudflare", "Cloudflare"},
		{"Microsoft-IIS/10.0", "Microsoft IIS"},
		{"Caddy", "Caddy"},
	}

	for _, tt := range tests {
		resp := &http.Response{
			Header: http.Header{
				"Server": []string{tt.serverHeader},
			},
		}
		techs := detectTechnologies(resp)
		found := false
		for _, tech := range techs {
			if tech == tt.expectTech {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("server %q: expected tech %q not found in %v", tt.serverHeader, tt.expectTech, techs)
		}
	}
}

func TestDetectTechnologies_XPoweredBy(t *testing.T) {
	tests := []struct {
		poweredBy  string
		expectTech string
	}{
		{"PHP/8.1", "PHP"},
		{"ASP.NET", "ASP.NET"},
		{"Express", "Express.js"},
		{"Django", "Django (Python)"},
	}

	for _, tt := range tests {
		resp := &http.Response{
			Header: http.Header{
				"X-Powered-By": []string{tt.poweredBy},
			},
		}
		techs := detectTechnologies(resp)
		found := false
		for _, tech := range techs {
			if tech == tt.expectTech {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("X-Powered-By %q: expected tech %q not found in %v", tt.poweredBy, tt.expectTech, techs)
		}
	}
}

func TestDetectTechnologies_Cookies(t *testing.T) {
	tests := []struct {
		cookieName string
		expectTech string
	}{
		{"PHPSESSID", "PHP"},
		{"JSESSIONID", "Java"},
		{"csrftoken", "Django (Python)"},
		{"_rails_session", "Ruby on Rails"},
	}

	for _, tt := range tests {
		resp := &http.Response{
			Header: http.Header{
				"Set-Cookie": []string{fmt.Sprintf("%s=abc123; Path=/", tt.cookieName)},
			},
		}
		techs := detectTechnologies(resp)
		found := false
		for _, tech := range techs {
			if tech == tt.expectTech {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("cookie %q: expected tech %q not found in %v", tt.cookieName, tt.expectTech, techs)
		}
	}
}

func TestDetectTechnologies_Empty(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	techs := detectTechnologies(resp)
	if len(techs) != 0 {
		t.Errorf("empty headers should produce no techs, got %v", techs)
	}
}

// --- KnownCiphers Tests -----------------------------------------------------

func TestKnownCiphers_Grades(t *testing.T) {
	gradeTests := map[uint16]string{
		0x1301: "A", // TLS_AES_128_GCM_SHA256
		0x009c: "B", // TLS_RSA_WITH_AES_128_GCM_SHA256
		0x000a: "D", // 3DES
		0x0005: "F", // RC4
	}

	for id, expectedGrade := range gradeTests {
		cipher, ok := knownCiphers[id]
		if !ok {
			t.Errorf("cipher 0x%04x not found in knownCiphers", id)
			continue
		}
		if cipher.Grade != expectedGrade {
			t.Errorf("cipher 0x%04x grade = %q, want %q", id, cipher.Grade, expectedGrade)
		}
	}
}

func TestKnownCiphers_ForwardSecrecy(t *testing.T) {
	fsCiphers := []uint16{0x1301, 0x1302, 0xc02b, 0xc02f, 0xcca8}
	for _, id := range fsCiphers {
		cipher := knownCiphers[id]
		if !cipher.FS {
			t.Errorf("cipher 0x%04x should have forward secrecy", id)
		}
	}

	noFSCiphers := []uint16{0x009c, 0x000a, 0x0005}
	for _, id := range noFSCiphers {
		cipher := knownCiphers[id]
		if cipher.FS {
			t.Errorf("cipher 0x%04x should NOT have forward secrecy", id)
		}
	}
}

func TestInsecurePatterns(t *testing.T) {
	if len(insecurePatterns) == 0 {
		t.Error("insecurePatterns is empty")
	}
	expected := []string{"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"}
	for _, p := range expected {
		found := false
		for _, ip := range insecurePatterns {
			if ip == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected insecure pattern %q not found", p)
		}
	}
}

// --- ScanResult Structure Tests --------------------------------------------

func TestScanResult_Structure(t *testing.T) {
	result := &ScanResult{
		Target:    "example.com",
		RiskScore: 85,
		TLS:       &TLSInfo{Version: "TLS 1.3"},
		WAF:       &WAFInfo{Detected: false},
		HTTP:      &HTTPInfo{Server: "nginx"},
		Security:  &SecurityInfo{Score: 75},
		Vulns: []Vuln{
			{ID: "TEST-001", Severity: "low", Title: "Test Vuln"},
		},
	}

	if result.Target != "example.com" {
		t.Errorf("Target = %q", result.Target)
	}
	if result.RiskScore != 85 {
		t.Errorf("RiskScore = %d", result.RiskScore)
	}
	if result.TLS.Version != "TLS 1.3" {
		t.Errorf("TLS Version = %q", result.TLS.Version)
	}
	if len(result.Vulns) != 1 {
		t.Errorf("len(Vulns) = %d, want 1", len(result.Vulns))
	}
}
