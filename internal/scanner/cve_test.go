package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- Mock Servers for Testing ------------------------------------------------

func mockApache2449() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.49 (Unix)")
		w.Header().Set("X-Powered-By", "PHP/8.0.13")
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>Test Page</body></html>")
	}))
}

func mockApache2450() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.50 (Ubuntu)")
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>Test Page</body></html>")
	}))
}

func mockSpringApp() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.Header().Set("X-Powered-By", "Spring Framework")
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body><div class=\"whitelabel\">Whitelabel Error Page</div></body></html>")
	}))
}

func mockGitLab() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Gitlab", "true")
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>GitLab Community Edition</body></html>")
	}))
}

func mockWordPress() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		cookie := &http.Cookie{Name: "wordpress_logged_in_test", Value: "abc"}
		http.SetCookie(w, cookie)
		w.WriteHeader(200)
		fmt.Fprintf(w, `<html><head><meta name="generator" content="WordPress 5.8.1"></head><body>wp-content test</body></html>`)
	}))
}

func mockDrupal() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		cookie := &http.Cookie{Name: "SSESSabc123", Value: "xyz"}
		http.SetCookie(w, cookie)
		w.WriteHeader(200)
		fmt.Fprintf(w, `<html><head><meta name="generator" content="Drupal 8.9.0"></head><body>Powered by Drupal</body></html>`)
	}))
}

func mockJoomla() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41")
		w.WriteHeader(200)
		fmt.Fprintf(w, `<html><head><meta name="generator" content="Joomla! - Open Source Content Management"></head><body>Welcome</body></html>`)
	}))
}

func mockNginxHTTP2() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.21.6")
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>OK</body></html>")
	}))
}

func mockCleanServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>OK</body></html>")
	}))
}

func mockTomcat() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>Tomcat</body></html>")
	}))
}

func mockCGIServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>CGI Script</body></html>")
	}))
}

// --- Fingerprint Tests -------------------------------------------------------

func TestCVEDetector_NewCVEDetector(t *testing.T) {
	det := NewCVEDetector("http://example.com")
	if det == nil {
		t.Fatal("NewCVEDetector returned nil")
	}
	if det.Target != "http://example.com" {
		t.Errorf("expected target http://example.com, got %s", det.Target)
	}
	if det.Client == nil {
		t.Fatal("HTTP client should not be nil")
	}
	if det.Results == nil {
		t.Fatal("Results should not be nil")
	}
}

func TestFingerprint_Apache(t *testing.T) {
	server := mockApache2449()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	if tech["server"] == "" {
		t.Error("server header not detected")
	}
	if tech["apache_version"] != "2.4.49" {
		t.Errorf("expected apache version 2.4.49, got %s", tech["apache_version"])
	}
	if tech["php"] != "true" {
		t.Error("PHP not detected from X-Powered-By")
	}
	if tech["php_version"] != "8.0.13" {
		t.Errorf("expected PHP version 8.0.13, got %s", tech["php_version"])
	}
}

func TestFingerprint_Spring(t *testing.T) {
	server := mockSpringApp()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	if tech["spring"] != "true" {
		t.Error("Spring not detected from X-Powered-By header")
	}
	if tech["java"] != "true" {
		t.Error("Java not detected from JSESSIONID cookie")
	}
}

func TestFingerprint_GitLab(t *testing.T) {
	server := mockGitLab()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	if tech["gitlab"] != "true" {
		t.Error("GitLab not detected from X-Gitlab header")
	}
}

func TestFingerprint_WordPress(t *testing.T) {
	server := mockWordPress()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	if tech["wordpress"] != "true" {
		t.Error("WordPress not detected")
	}
	if tech["php"] != "true" {
		t.Error("PHP not detected from cookie")
	}
}

func TestFingerprint_Drupal(t *testing.T) {
	server := mockDrupal()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	if tech["drupal"] != "true" {
		t.Error("Drupal not detected from meta tag")
	}
}

func TestFingerprint_Joomla(t *testing.T) {
	server := mockJoomla()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	if tech["joomla"] != "true" {
		t.Error("Joomla not detected from meta tag")
	}
}

func TestFingerprint_CleanServer(t *testing.T) {
	server := mockCleanServer()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	// A clean server should have minimal detection
	if tech["wordpress"] == "true" {
		t.Error("WordPress false positive on clean server")
	}
	if tech["drupal"] == "true" {
		t.Error("Drupal false positive on clean server")
	}
}

// --- CVE Matching Tests ------------------------------------------------------

func TestCheckCVE_Apache2449(t *testing.T) {
	server := mockApache2449()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	found := false
	for _, sig := range cveDatabase {
		if sig.CVEID == "CVE-2021-41773" {
			match := det.checkCVE(sig, tech)
			if match == nil {
				t.Error("CVE-2021-41773 should match Apache 2.4.49")
			} else {
				found = true
				if match.CVEID != "CVE-2021-41773" {
					t.Errorf("expected CVE-2021-41773, got %s", match.CVEID)
				}
				if match.Severity != "critical" {
					t.Errorf("expected severity critical, got %s", match.Severity)
				}
				if match.CVSS != 9.8 {
					t.Errorf("expected CVSS 9.8, got %.1f", match.CVSS)
				}
				if match.Product != "Apache httpd" {
					t.Errorf("expected product Apache httpd, got %s", match.Product)
				}
			}
			break
		}
	}
	if !found {
		t.Error("CVE-2021-41773 not found in database")
	}
}

func TestCheckCVE_Apache2450(t *testing.T) {
	server := mockApache2450()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	for _, sig := range cveDatabase {
		if sig.CVEID == "CVE-2021-42013" {
			match := det.checkCVE(sig, tech)
			if match == nil {
				t.Error("CVE-2021-42013 should match Apache 2.4.50")
			}
			break
		}
	}
}

func TestCheckCVE_Spring(t *testing.T) {
	server := mockSpringApp()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	for _, sig := range cveDatabase {
		if sig.CVEID == "CVE-2022-22965" {
			match := det.checkCVE(sig, tech)
			if match == nil {
				t.Error("CVE-2022-22965 (Spring4Shell) should match Spring app")
			}
			break
		}
	}
}

func TestCheckCVE_GitLab(t *testing.T) {
	server := mockGitLab()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	for _, sig := range cveDatabase {
		if sig.CVEID == "CVE-2021-22205" {
			match := det.checkCVE(sig, tech)
			if match == nil {
				t.Error("CVE-2021-22205 should match GitLab")
			}
			break
		}
	}
}

func TestCheckCVE_CleanServer(t *testing.T) {
	server := mockCleanServer()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	tech := det.fingerprint()

	// Most CVEs should NOT match on a clean server
	matchCount := 0
	for _, sig := range cveDatabase {
		match := det.checkCVE(sig, tech)
		if match != nil {
			matchCount++
		}
	}

	// A minimal server should have few or no matches
	if matchCount > 5 {
		t.Errorf("clean server matched too many CVEs: %d", matchCount)
	}
}

func TestCheckCVE_NoMatch(t *testing.T) {
	tech := map[string]string{
		"server":     "",
		"powered_by": "",
		"body":       "<html>hello</html>",
	}

	det := NewCVEDetector("http://example.com")

	// This specific CVE requires "Apache/2.4.49" in server header
	for _, sig := range cveDatabase {
		if sig.CVEID == "CVE-2021-41773" {
			match := det.checkCVE(sig, tech)
			if match != nil {
				t.Error("CVE-2021-41773 should NOT match without Apache header")
			}
			break
		}
	}
}

// --- PoC Generation Tests ----------------------------------------------------

func TestGeneratePoC_ApachePathTraversal(t *testing.T) {
	det := NewCVEDetector("http://victim.example.com")

	match := &CVEFinding{
		CVEID:    "CVE-2021-41773",
		Product:  "Apache httpd",
		Version:  "2.4.49",
		Severity: "critical",
	}

	poc := det.generatePoC(match)

	if poc.Type != "request" {
		t.Errorf("expected PoC type 'request', got '%s'", poc.Type)
	}
	if poc.Request == "" {
		t.Error("PoC request should not be empty")
	}
	if !strings.Contains(poc.Request, "victim.example.com") {
		t.Error("PoC request should contain target host")
	}
	if poc.Conditions == "" {
		t.Error("PoC conditions should not be empty")
	}
	if len(poc.Steps) == 0 {
		t.Error("PoC steps should not be empty")
	}
}

func TestGeneratePoC_Log4Shell(t *testing.T) {
	det := NewCVEDetector("http://target.corp")

	match := &CVEFinding{
		CVEID:    "CVE-2021-44228",
		Product:  "Apache Log4j2",
		Severity: "critical",
	}

	poc := det.generatePoC(match)

	if !strings.Contains(poc.Request, "target.corp") {
		t.Error("PoC should replace TARGET with actual host")
	}
	if !strings.Contains(poc.Request, "jndi") {
		t.Error("Log4Shell PoC should contain JNDI payload")
	}
}

func TestGeneratePoC_ShellShock(t *testing.T) {
	det := NewCVEDetector("http://cgi-server.local")

	match := &CVEFinding{
		CVEID:    "CVE-2014-6271",
		Product:  "GNU Bash",
		Severity: "critical",
	}

	poc := det.generatePoC(match)

	if !strings.Contains(poc.Request, "cgi-server.local") {
		t.Error("ShellShock PoC should contain target host")
	}
	if !strings.Contains(poc.Request, "() { :;};") {
		t.Error("ShellShock PoC should contain Bash function definition")
	}
}

func TestGeneratePoC_Spring4Shell(t *testing.T) {
	det := NewCVEDetector("http://spring-app.io")

	match := &CVEFinding{
		CVEID:    "CVE-2022-22965",
		Product:  "Spring Framework",
		Severity: "critical",
	}

	poc := det.generatePoC(match)

	if !strings.Contains(poc.Request, "spring-app.io") {
		t.Error("Spring4Shell PoC should contain target host")
	}
	if !strings.Contains(poc.Request, "class.module") {
		t.Error("Spring4Shell PoC should contain classLoader manipulation")
	}
}

func TestGeneratePoC_Unknown(t *testing.T) {
	det := NewCVEDetector("http://example.com")

	match := &CVEFinding{
		CVEID:    "CVE-9999-9999",
		Product:  "Unknown Product",
		Severity: "medium",
	}

	poc := det.generatePoC(match)

	if poc.Type != "manual" {
		t.Errorf("unknown CVE should get manual PoC type, got %s", poc.Type)
	}
}

// --- Risk Calculation Tests --------------------------------------------------

func TestCalculateRisk_NoCVEs(t *testing.T) {
	det := NewCVEDetector("http://example.com")
	score := det.calculateRisk()

	if score != 0 {
		t.Errorf("expected 0 risk for no CVEs, got %d", score)
	}
}

func TestCalculateRisk_CriticalCVEs(t *testing.T) {
	det := NewCVEDetector("http://example.com")
	det.Results.CVEs = []CVEFinding{
		{CVEID: "CVE-2021-41773", Severity: "critical", CVSS: 9.8},
		{CVEID: "CVE-2021-44228", Severity: "critical", CVSS: 10.0},
	}

	score := det.calculateRisk()

	if score < 25 {
		t.Errorf("expected risk >= 25 for critical CVEs, got %d", score)
	}
	if score > 100 {
		t.Errorf("risk should not exceed 100, got %d", score)
	}
}

func TestCalculateRisk_MixedSeverity(t *testing.T) {
	det := NewCVEDetector("http://example.com")
	det.Results.CVEs = []CVEFinding{
		{CVEID: "CVE-001", Severity: "critical", CVSS: 9.8},
		{CVEID: "CVE-002", Severity: "high", CVSS: 7.5},
		{CVEID: "CVE-003", Severity: "medium", CVSS: 5.0},
		{CVEID: "CVE-004", Severity: "low", CVSS: 3.0},
	}

	score := det.calculateRisk()

	if score <= 0 {
		t.Error("risk should be > 0 for mixed CVEs")
	}
	if score > 100 {
		t.Errorf("risk should not exceed 100, got %d", score)
	}
}

func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		score    int
		expected string
	}{
		{0, "A+"},
		{3, "A"},
		{10, "B"},
		{25, "C"},
		{40, "D"},
		{60, "F"},
		{100, "F"},
	}

	det := NewCVEDetector("http://example.com")
	for _, tt := range tests {
		grade := det.scoreToGrade(tt.score)
		if grade != tt.expected {
			t.Errorf("score %d: expected grade %s, got %s", tt.score, tt.expected, grade)
		}
	}
}

// --- Full Scan Integration Tests ---------------------------------------------

func TestScan_ApacheVulnerable(t *testing.T) {
	server := mockApache2449()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	report := det.Scan()

	if report == nil {
		t.Fatal("Scan returned nil report")
	}
	if report.Target != server.URL {
		t.Errorf("expected target %s, got %s", server.URL, report.Target)
	}
	if len(report.CVEs) == 0 {
		t.Fatal("expected at least 1 CVE match for Apache 2.4.49")
	}

	found41773 := false
	for _, cve := range report.CVEs {
		if cve.CVEID == "CVE-2021-41773" {
			found41773 = true
			break
		}
	}
	if !found41773 {
		t.Error("CVE-2021-41773 not found in scan results")
	}

	if report.RiskScore == 0 {
		t.Error("risk score should be > 0")
	}
	if report.Grade == "" {
		t.Error("grade should not be empty")
	}
}

func TestScan_SpringVulnerable(t *testing.T) {
	server := mockSpringApp()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	report := det.Scan()

	if len(report.CVEs) == 0 {
		t.Fatal("expected CVE matches for Spring application")
	}

	found := false
	for _, cve := range report.CVEs {
		if cve.CVEID == "CVE-2022-22965" {
			found = true
			if cve.PoC.Type == "" {
				t.Error("PoC should not be empty for matched CVE")
			}
			break
		}
	}
	if !found {
		t.Error("CVE-2022-22965 not found in Spring scan results")
	}
}

func TestScan_GitLabVulnerable(t *testing.T) {
	server := mockGitLab()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	report := det.Scan()

	found := false
	for _, cve := range report.CVEs {
		if cve.CVEID == "CVE-2021-22205" {
			found = true
			if cve.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", cve.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("CVE-2021-22205 not found in GitLab scan results")
	}
}

func TestScan_CleanServer(t *testing.T) {
	server := mockCleanServer()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	report := det.Scan()

	// A clean server should have low risk
	if report.RiskScore > 20 {
		t.Errorf("clean server risk too high: %d", report.RiskScore)
	}
}

func TestScan_CVECount(t *testing.T) {
	// Verify the database has 50+ entries
	if len(cveDatabase) < 50 {
		t.Errorf("CVE database too small: %d entries (expected 50+)", len(cveDatabase))
	}
}

// --- Render Tests ------------------------------------------------------------

func TestRender_EmptyReport(t *testing.T) {
	det := NewCVEDetector("http://example.com")
	output := det.Render()

	if !strings.Contains(output, "No known CVEs detected") {
		t.Error("empty report should say 'No known CVEs detected'")
	}
	if !strings.Contains(output, "example.com") {
		t.Error("report should contain target")
	}
}

func TestRender_WithCVEs(t *testing.T) {
	server := mockApache2449()
	defer server.Close()

	det := NewCVEDetector(server.URL)
	report := det.Scan()
	output := det.Render()

	if !strings.Contains(output, "CVE SCAN REPORT") {
		t.Error("report should contain header")
	}
	if !strings.Contains(output, server.URL) {
		t.Error("report should contain target URL")
	}
	if !strings.Contains(output, "Critical") || !strings.Contains(output, "CRITICAL") {
		if len(report.CVEs) > 0 {
			t.Error("report should show critical CVEs")
		}
	}
}

func TestRender_FullFormat(t *testing.T) {
	det := NewCVEDetector("http://example.com")
	det.Results.CVEs = []CVEFinding{
		{
			CVEID:       "CVE-2024-99999",
			Description: "Test vulnerability",
			Severity:    "critical",
			CVSS:        9.9,
			CWE:         "CWE-99",
			Product:     "Test Product",
			Version:     "1.0.0",
			FixedIn:     "1.0.1",
			Evidence:    "server:Test Product/1.0.0",
			Impact:      "Full system compromise",
			Remediation: "Upgrade to 1.0.1",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-99999"},
			PoC: ExploitPoC{
				Type:        "request",
				Description: "Test PoC",
				Steps:       []string{"Step 1", "Step 2"},
				Request:     "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n",
				Conditions:  "Must be vulnerable",
			},
		},
	}
	det.Results.RiskScore = 75
	det.Results.Grade = "F"

	output := det.Render()

	checks := []string{
		"CVE SCAN REPORT",
		"CVE-2024-99999",
		"Test vulnerability",
		"9.9",
		"CRITICAL",
		"CWE-99",
		"Test Product",
		"1.0.0",
		"1.0.1",
		"Full system compromise",
		"Upgrade to 1.0.1",
		"nvd.nist.gov",
		"request",
		"Test PoC",
		"Step 1",
		"Step 2",
		"GET /test",
		"Must be vulnerable",
		"Grade: F",
		"75/100",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("render output missing: %q", check)
		}
	}
}

// --- Multiple Severities Render Test -----------------------------------------

func TestRender_MultipleSeverities(t *testing.T) {
	det := NewCVEDetector("http://example.com")
	det.Results.CVEs = []CVEFinding{
		{CVEID: "CVE-1", Severity: "critical", CVSS: 9.0},
		{CVEID: "CVE-2", Severity: "high", CVSS: 7.0},
		{CVEID: "CVE-3", Severity: "medium", CVSS: 5.0},
		{CVEID: "CVE-4", Severity: "low", CVSS: 2.0},
	}
	det.Results.RiskScore = 50
	det.Results.Grade = "D"

	output := det.Render()

	if !strings.Contains(output, "Total: 4 CVEs") {
		t.Error("report should show total CVE count")
	}
	if !strings.Contains(output, "Critical: 1") {
		t.Error("report should show critical count")
	}
	if !strings.Contains(output, "High: 1") {
		t.Error("report should show high count")
	}
	if !strings.Contains(output, "Medium: 1") {
		t.Error("report should show medium count")
	}
	if !strings.Contains(output, "Low: 1") {
		t.Error("report should show low count")
	}
}

// --- Pattern Matching Edge Cases ---------------------------------------------

func TestPatternMatching_CaseInsensitive(t *testing.T) {
	det := NewCVEDetector("http://example.com")

	tech := map[string]string{
		"server": "APACHE/2.4.49",
		"body":   "",
	}

	for _, sig := range cveDatabase {
		if sig.CVEID == "CVE-2021-41773" {
			match := det.checkCVE(sig, tech)
			if match == nil {
				t.Error("pattern matching should be case-insensitive for Apache version")
			}
			break
		}
	}
}

func TestPatternMatching_MultiplePatternOR(t *testing.T) {
	det := NewCVEDetector("http://example.com")

	// Spring detected via body only (no X-Powered-By)
	tech := map[string]string{
		"server":     "Apache-Coyote/1.1",
		"powered_by": "",
		"body":       "Whitelabel Error Page",
	}

	for _, sig := range cveDatabase {
		if sig.CVEID == "CVE-2022-22965" {
			match := det.checkCVE(sig, tech)
			if match == nil {
				t.Error("CVE-2022-22965 should match via body pattern alone")
			}
			break
		}
	}
}

// --- Database Integrity Tests ------------------------------------------------

func TestCVEDatabase_UniqueIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, sig := range cveDatabase {
		if seen[sig.CVEID] {
			t.Errorf("duplicate CVE ID: %s", sig.CVEID)
		}
		seen[sig.CVEID] = true
	}
}

func TestCVEDatabase_AllHavePatterns(t *testing.T) {
	for _, sig := range cveDatabase {
		if len(sig.Patterns) == 0 {
			t.Errorf("CVE %s has no detection patterns", sig.CVEID)
		}
	}
}

func TestCVEDatabase_AllHaveSeverity(t *testing.T) {
	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	for _, sig := range cveDatabase {
		if !validSeverities[sig.Severity] {
			t.Errorf("CVE %s has invalid severity: %s", sig.CVEID, sig.Severity)
		}
	}
}

func TestCVEDatabase_AllHaveReferences(t *testing.T) {
	for _, sig := range cveDatabase {
		if len(sig.References) == 0 {
			t.Errorf("CVE %s has no references", sig.CVEID)
		}
	}
}

func TestCVEDatabase_AllHavePoCTemplate(t *testing.T) {
	for _, sig := range cveDatabase {
		if sig.PoCTemplate.Type == "" {
			t.Errorf("CVE %s has no PoC type", sig.CVEID)
		}
		if sig.PoCTemplate.Description == "" {
			t.Errorf("CVE %s has no PoC description", sig.CVEID)
		}
	}
}

func TestCVEDatabase_ProductCategories(t *testing.T) {
	categories := map[string]int{}
	for _, sig := range cveDatabase {
		categories[sig.Product]++
	}

	if categories["Apache httpd"] < 3 {
		t.Error("expected at least 3 Apache httpd CVEs")
	}
	if categories["Spring Framework"] < 2 {
		t.Error("expected at least 2 Spring Framework CVEs")
	}
	if categories["Drupal"] < 2 {
		t.Error("expected at least 2 Drupal CVEs")
	}
	if categories["F5 BIG-IP"] < 2 {
		t.Error("expected at least 2 F5 BIG-IP CVEs")
	}
}

// --- Race Condition Test -----------------------------------------------------

func TestScan_Concurrent(t *testing.T) {
	server := mockApache2449()
	defer server.Close()

	done := make(chan bool, 3)
	for i := 0; i < 3; i++ {
		go func() {
			det := NewCVEDetector(server.URL)
			report := det.Scan()
			if report == nil {
				t.Error("concurrent scan returned nil")
			}
			done <- true
		}()
	}
	for i := 0; i < 3; i++ {
		<-done
	}
}
