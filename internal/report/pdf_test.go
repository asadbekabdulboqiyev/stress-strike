package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func samplePentestReport() *PentestReport {
	return &PentestReport{
		Title:          "Penetration Test Report — Acme Corp",
		ClientName:     "Acme Corporation",
		AssessmentDate: time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC),
		ReportDate:     time.Date(2026, 8, 25, 14, 30, 0, 0, time.UTC),
		Assessor:       "Security Team Alpha",
		Version:        "1.0.0",

		ExecutiveSummary: "The assessment revealed multiple vulnerabilities across the web application stack. Two critical issues require immediate attention, including remote code execution and SQL injection.",
		RiskRating:       "High",
		OverallScore:     38,
		Grade:            "D",

		TargetURLs:  []string{"https://app.example.com", "https://api.example.com"},
		IPAddresses: []string{"203.0.113.10", "203.0.113.11"},
		Exclusions:  []string{"https://staging.example.com", "Internal admin panel"},

		Findings: []PentestFinding{
			{
				ID:                1,
				Title:             "Remote Code Execution via File Upload",
				Severity:          "Critical",
				CVSS:              9.8,
				CWE:               "CWE-434",
				OWASPCategory:     "A03:2021 - Injection",
				Description:       "Unrestricted file upload allows execution of arbitrary PHP code on the server through a crafted webshell.",
				AffectedURL:       "https://app.example.com/upload",
				Parameter:         "file",
				StepsToReproduce:  []string{"Navigate to /upload", "Upload a PHP file with .jpg extension", "Access the uploaded file directly to execute code"},
				Evidence:          "POST /upload HTTP/1.1\nContent-Type: multipart/form-data\n\n[webshell payload]\n\nHTTP/1.1 200 OK\nFile uploaded: /uploads/shell.php.jpg",
				Impact:            "Full server compromise, data exfiltration, lateral movement possible.",
				Remediation:       "Implement server-side file type validation. Use a whitelist of allowed extensions. Store uploaded files outside the web root.",
				RemediationEffort: "Medium",
				References:        []string{"https://cwe.mitre.org/data/definitions/434.html", "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"},
			},
			{
				ID:                2,
				Title:             "SQL Injection in Login Form",
				Severity:          "Critical",
				CVSS:              9.1,
				CWE:               "CWE-89",
				OWASPCategory:     "A03:2021 - Injection",
				Description:       "The username parameter in the login form is vulnerable to SQL injection, allowing authentication bypass.",
				AffectedURL:       "https://app.example.com/login",
				Parameter:         "username",
				StepsToReproduce:  []string{"Enter ' OR '1'='1' -- in the username field", "Submit the form with any password"},
				Evidence:          "POST /login HTTP/1.1\n\nusername=%27+OR+%271%27%3D%271%27+--&password=anything\n\nHTTP/1.1 302 Found\nLocation: /dashboard",
				Impact:            "Complete authentication bypass, unauthorized access to all user accounts.",
				Remediation:       "Use parameterized queries (prepared statements) for all database interactions. Implement input validation.",
				RemediationEffort: "Low",
				References:        []string{"https://cwe.mitre.org/data/definitions/89.html"},
			},
			{
				ID:                3,
				Title:             "Cross-Site Scripting (XSS) in Search",
				Severity:          "High",
				CVSS:              7.5,
				CWE:               "CWE-79",
				OWASPCategory:     "A03:2021 - Injection",
				Description:       "Reflected XSS in the search query parameter allows injection of arbitrary JavaScript.",
				AffectedURL:       "https://app.example.com/search?q=",
				Parameter:         "q",
				StepsToReproduce:  []string{"Navigate to /search?q=<script>alert(1)</script>"},
				Evidence:          "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\n\nHTTP/1.1 200 OK\n<body>Results for: <script>alert(1)</script></body>",
				Impact:            "Session hijacking, credential theft, phishing attacks.",
				Remediation:       "Implement context-aware output encoding. Use Content-Security-Policy headers.",
				RemediationEffort: "Low",
				References:        []string{"https://cwe.mitre.org/data/definitions/79.html"},
			},
			{
				ID:                4,
				Title:             "Missing Security Headers",
				Severity:          "Medium",
				CVSS:              5.0,
				CWE:               "CWE-693",
				Description:       "The application is missing several important security headers including X-Content-Type-Options, X-Frame-Options, and Strict-Transport-Security.",
				AffectedURL:       "https://app.example.com",
				Remediation:       "Add security headers to all HTTP responses.",
				RemediationEffort: "Low",
			},
			{
				ID:                5,
				Title:             "Version Disclosure",
				Severity:          "Low",
				CVSS:              2.6,
				CWE:               "CWE-200",
				Description:       "Server response headers disclose the exact software version (Apache/2.4.51, PHP/8.0.12).",
				AffectedURL:       "https://app.example.com",
				Remediation:       "Remove version information from server headers.",
				RemediationEffort: "Low",
			},
			{
				ID:                6,
				Title:             "Cookie Without Secure Flag",
				Severity:          "Info",
				CVSS:              0.0,
				CWE:               "CWE-614",
				Description:       "The session cookie is set without the Secure flag, though the site uses HTTPS.",
				AffectedURL:       "https://app.example.com",
				Remediation:       "Set the Secure flag on all cookies.",
				RemediationEffort: "Low",
			},
		},

		TotalChecks:   147,
		TotalFound:    6,
		CriticalCount: 2,
		HighCount:     1,
		MediumCount:   1,
		LowCount:      1,
		InfoCount:     1,

		ScanDuration: 4*time.Hour + 23*time.Minute + 15*time.Second,

		OWASPCompliance: map[string]bool{
			"A01:2021 - Broken Access Control":                      true,
			"A02:2021 - Cryptographic Failures":                     true,
			"A03:2021 - Injection":                                  false,
			"A04:2021 - Insecure Design":                            true,
			"A05:2021 - Security Misconfiguration":                  false,
			"A06:2021 - Vulnerable and Outdated Components":         true,
			"A07:2021 - Identification and Authentication Failures": true,
			"A08:2021 - Software and Data Integrity Failures":       true,
			"A09:2021 - Security Logging and Monitoring Failures":   true,
			"A10:2021 - Server-Side Request Forgery":                true,
		},
	}
}

func TestPentestGenerateHTML(t *testing.T) {
	r := samplePentestReport()
	data := GenerateHTML(r)

	if len(data) == 0 {
		t.Fatal("GenerateHTML returned empty")
	}
	html := string(data)

	for _, want := range []string{
		"<!DOCTYPE html>",
		"<html",
		"Penetration Test Report",
		"Acme Corporation",
		"Security Team Alpha",
		"Executive Summary",
		"Risk Assessment",
		"Scope",
		"Findings Summary",
		"Detailed Findings",
		"OWASP Top 10 (2021) Compliance Matrix",
		"Timeline",
		"Disclaimer",
		"Remote Code Execution",
		"SQL Injection",
		"Cross-Site Scripting",
		"Missing Security Headers",
		"Version Disclosure",
		"Cookie Without Secure Flag",
		"#dc3545",
		"#fd7e14",
		"#ffc107",
		"#28a745",
		"#17a2b8",
		"9.8",
		"CWE-434",
		"conic-gradient",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

func TestPentestGenerateHTMLNoFindings(t *testing.T) {
	r := &PentestReport{
		Title:           "Empty Report",
		ClientName:      "Test",
		AssessmentDate:  time.Now(),
		ReportDate:      time.Now(),
		Assessor:        "Tester",
		Version:         "1.0",
		TotalChecks:     10,
		RiskRating:      "Low",
		OverallScore:    90,
		Grade:           "A",
		OWASPCompliance: map[string]bool{},
	}
	data := GenerateHTML(r)
	html := string(data)

	if !strings.Contains(html, "No findings recorded") {
		t.Error("expected no-findings message")
	}
	if !strings.Contains(html, "Empty Report") {
		t.Error("HTML missing title")
	}
}

func TestPentestGenerateMarkdown(t *testing.T) {
	r := samplePentestReport()
	data := GenerateMarkdown(r)

	if len(data) == 0 {
		t.Fatal("GenerateMarkdown returned empty")
	}
	md := string(data)

	for _, want := range []string{
		"# Penetration Test Report",
		"**Client:** Acme Corporation",
		"**Assessor:** Security Team Alpha",
		"## Executive Summary",
		"## Risk Assessment",
		"## Scope",
		"## Findings Summary",
		"## Detailed Findings",
		"## OWASP Top 10 (2021) Compliance Matrix",
		"## Timeline",
		"## Disclaimer",
		"Remote Code Execution via File Upload",
		"SQL Injection in Login Form",
		"Cross-Site Scripting (XSS)",
		"Missing Security Headers",
		"Version Disclosure",
		"Cookie Without Secure Flag",
		"Critical | **CVSS:** 9.8",
		"CWE-434",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown missing %q", want)
		}
	}
}

func TestPentestGenerateMarkdownTable(t *testing.T) {
	r := samplePentestReport()
	md := string(GenerateMarkdown(r))

	if !strings.Contains(md, "| Critical | 2 |") {
		t.Error("markdown missing critical count in table")
	}
	if !strings.Contains(md, "| High | 1 |") {
		t.Error("markdown missing high count")
	}
	if !strings.Contains(md, "| Total | 6 |") {
		t.Error("markdown missing total count")
	}
}

func TestPentestSeverityCounts(t *testing.T) {
	r := samplePentestReport()
	total := r.CriticalCount + r.HighCount + r.MediumCount + r.LowCount + r.InfoCount
	if total != r.TotalFound {
		t.Errorf("severity counts sum %d != TotalFound %d", total, r.TotalFound)
	}
}

func TestPentestOWASPComplianceMatrix(t *testing.T) {
	r := samplePentestReport()
	if len(r.OWASPCompliance) != 10 {
		t.Errorf("OWASP compliance has %d entries, want 10", len(r.OWASPCompliance))
	}
	// Check that A03 and A05 are failing
	if r.OWASPCompliance["A03:2021 - Injection"] {
		t.Error("A03 should be false")
	}
	if r.OWASPCompliance["A05:2021 - Security Misconfiguration"] {
		t.Error("A05 should be false")
	}
	// Check that all others pass
	for _, cat := range owaspOrder() {
		if cat == "A03:2021 - Injection" || cat == "A05:2021 - Security Misconfiguration" {
			continue
		}
		if !r.OWASPCompliance[cat] {
			t.Errorf("expected %s to pass", cat)
		}
	}
}

func TestPentestSaveReportHTML(t *testing.T) {
	dir := t.TempDir()
	r := samplePentestReport()
	path := filepath.Join(dir, "test-report.html")

	if err := SaveReport(r, "html", path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "<!DOCTYPE html>") {
		t.Error("file does not contain HTML doctype")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("report file permissions not private: %o", fi.Mode().Perm())
	}
}

func TestPentestSaveReportMarkdown(t *testing.T) {
	dir := t.TempDir()
	r := samplePentestReport()
	path := filepath.Join(dir, "test-report.md")

	if err := SaveReport(r, "md", path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "# Penetration Test Report") {
		t.Error("file does not contain markdown heading")
	}
}

func TestPentestSaveReportCreatesDir(t *testing.T) {
	dir := t.TempDir()
	r := samplePentestReport()
	path := filepath.Join(dir, "nested", "deep", "report.html")

	if err := SaveReport(r, "html", path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("directory was not created")
	}
}

func TestPentestSaveReportUnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	r := samplePentestReport()
	path := filepath.Join(dir, "report.xml")

	err := SaveReport(r, "xml", path)
	if err == nil {
		t.Error("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPentestSeverityColor(t *testing.T) {
	tests := []struct {
		severity string
		color    string
	}{
		{"Critical", "#dc3545"},
		{"critical", "#dc3545"},
		{"High", "#fd7e14"},
		{"Medium", "#ffc107"},
		{"Low", "#28a745"},
		{"Info", "#17a2b8"},
		{"Unknown", "#6c757d"},
	}
	for _, tt := range tests {
		if got := severityColor(tt.severity); got != tt.color {
			t.Errorf("severityColor(%q) = %q, want %q", tt.severity, got, tt.color)
		}
	}
}

func TestPentestHTMLContainsAllFindings(t *testing.T) {
	r := samplePentestReport()
	html := string(GenerateHTML(r))

	for _, f := range r.Findings {
		if !strings.Contains(html, f.Title) {
			t.Errorf("HTML missing finding %q", f.Title)
		}
		if !strings.Contains(html, f.Severity) {
			t.Errorf("HTML missing severity %q for finding %d", f.Severity, f.ID)
		}
	}
}

func TestPentestMarkdownContainsAllFindings(t *testing.T) {
	r := samplePentestReport()
	md := string(GenerateMarkdown(r))

	for _, f := range r.Findings {
		if !strings.Contains(md, f.Title) {
			t.Errorf("Markdown missing finding %q", f.Title)
		}
	}
}

func TestPentestGradeColor(t *testing.T) {
	tests := []struct {
		grade string
		color string
	}{
		{"A", "#28a745"},
		{"B", "#6cb33f"},
		{"C", "#ffc107"},
		{"D", "#fd7e14"},
		{"F", "#dc3545"},
		{"X", "#6c757d"},
	}
	for _, tt := range tests {
		if got := gradeColor(tt.grade); got != tt.color {
			t.Errorf("gradeColor(%q) = %q, want %q", tt.grade, got, tt.color)
		}
	}
}

func TestPentestEmptyOWASPTable(t *testing.T) {
	r := &PentestReport{
		Title:           "No OWASP",
		OWASPCompliance: nil,
	}
	html := string(GenerateHTML(r))
	if strings.Contains(html, "OWASP Compliance Matrix") {
		t.Error("should not render OWASP section when map is nil")
	}
}

func TestPentestEmptyMarkdownOWASP(t *testing.T) {
	r := &PentestReport{
		Title:           "No OWASP",
		OWASPCompliance: nil,
	}
	md := string(GenerateMarkdown(r))
	if strings.Contains(md, "OWASP Compliance Matrix") {
		t.Error("should not render OWASP section when map is nil")
	}
}

func TestPentestHTMLEvidenceFormatting(t *testing.T) {
	r := samplePentestReport()
	html := string(GenerateHTML(r))
	if !strings.Contains(html, "evidence-box") {
		t.Error("HTML missing evidence box styling")
	}
	if !strings.Contains(html, "POST /upload HTTP/1.1") {
		t.Error("HTML missing evidence content")
	}
}

func TestPentestSaveReportPDFAlias(t *testing.T) {
	dir := t.TempDir()
	r := samplePentestReport()
	path := filepath.Join(dir, "report.pdf")

	if err := SaveReport(r, "pdf", path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// "pdf" must now produce a real PDF document (not an HTML alias).
	if !strings.HasPrefix(string(data), "%PDF-") {
		t.Errorf("pdf format should produce real PDF output, got magic: %q", string(data[:min(len(data), 8)]))
	}
	if !strings.Contains(string(data), "%%EOF") {
		t.Error("pdf output missing EOF terminator marker")
	}
}
