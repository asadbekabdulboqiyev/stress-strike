package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Mock server helpers
// ---------------------------------------------------------------------------

func newMockServer(handler http.HandlerFunc) *httptest.Server {
	srv := httptest.NewServer(handler)
	return srv
}

func mockHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	query := r.URL.Query()

	// SQL Injection: reflect payload in error
	if q := query.Get("id"); q != "" || query.Get("search") != "" {
		val := q
		if val == "" {
			val = query.Get("search")
		}
		if strings.Contains(val, "'") || strings.Contains(val, "\"") || strings.Contains(val, "UNION") {
			w.WriteHeader(500)
			fmt.Fprintf(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
			return
		}
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>OK</body></html>")
		return
	}

	// XSS: reflect parameters
	if q := query.Get("q"); q != "" || query.Get("search") != "" || query.Get("name") != "" {
		val := q
		if val == "" {
			val = query.Get("search")
		}
		if val == "" {
			val = query.Get("name")
		}
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>You searched for: %s</body></html>", val)
		return
	}

	// Directory traversal: check file param
	if file := query.Get("file"); file != "" {
		if strings.Contains(file, "etc/passwd") || strings.Contains(file, "proc/self") {
			w.WriteHeader(200)
			fmt.Fprintf(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
			return
		}
	}

	// Open redirect
	if redir := query.Get("redirect"); redir != "" || query.Get("url") != "" || query.Get("next") != "" {
		val := redir
		if val == "" {
			val = query.Get("url")
		}
		if val == "" {
			val = query.Get("next")
		}
		if strings.Contains(val, "evil.com") {
			http.Redirect(w, r, val, 302)
			return
		}
	}

	// Default credentials
	if r.Method == "POST" && (path == "/login" || path == "/wp-login.php" || path == "/admin/login") {
		r.ParseForm()
		user := r.FormValue("username")
		pass := r.FormValue("password")
		if user == "admin" && pass == "admin" {
			w.WriteHeader(200)
			fmt.Fprintf(w, "<html><body>Welcome dashboard user admin</body></html>")
			return
		}
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>Invalid credentials error</body></html>")
		return
	}

	// CORS
	if origin := r.Header.Get("Origin"); origin != "" {
		if origin == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}

	// Debug
	if path == "/debug/" {
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>DEBUG mode active\nstack trace\nException in thread main</body></html>")
		return
	}

	// Git
	if path == "/.git/HEAD" || path == "/.git/config" {
		w.WriteHeader(200)
		fmt.Fprintf(w, "ref: refs/heads/main")
		return
	}

	// .env
	if path == "/.env" {
		w.WriteHeader(200)
		fmt.Fprintf(w, "APP_KEY=base64:abc123\nDB_PASSWORD=secret123\nAPI_KEY=sk-12345")
		return
	}

	// robots.txt
	if path == "/robots.txt" {
		w.WriteHeader(200)
		fmt.Fprintf(w, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/")
		return
	}

	// swagger
	if path == "/api/swagger.json" {
		w.WriteHeader(200)
		fmt.Fprintf(w, `{"swagger":"2.0","info":{"title":"API"},"paths":{}}`)
		return
	}

	// API endpoints
	if strings.HasPrefix(path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)

		if path == "/api/users/1" {
			fmt.Fprintf(w, `{"id":1,"name":"Alice","email":"alice@example.com","password":"hash123","token":"abc"}`)
			return
		}
		if path == "/api/users/2" {
			fmt.Fprintf(w, `{"id":2,"name":"Bob","email":"bob@example.com","password":"hash456","token":"def"}`)
			return
		}
		fmt.Fprintf(w, `{"status":"ok"}`)
		return
	}

	// Default: normal response with security headers set
	w.Header().Set("Server", "nginx/1.21.0")
	w.Header().Set("X-Powered-By", "Express")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=()")

	w.Header().Set("Set-Cookie", "session_id=abc123; Path=/; SameSite=Lax")
	w.WriteHeader(200)
	fmt.Fprintf(w, "<html><body>Hello</body></html>")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestVulnScanner_SQLInjection(t *testing.T) {
	srv := newMockServer(mockHandler)
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanSQLInjection()
	if len(vs.Results.Critical) == 0 {
		t.Error("expected at least one SQL injection finding")
	}

	found := false
	for _, v := range vs.Results.Critical {
		if v.CWE == "CWE-89" {
			found = true
			if v.Parameter == "" {
				t.Error("SQL injection finding missing parameter")
			}
			if v.Evidence == "" {
				t.Error("SQL injection finding missing evidence")
			}
			if v.PoC == "" {
				t.Error("SQL injection finding missing PoC")
			}
			if v.CVSS < 9.0 {
				t.Errorf("SQL injection CVSS = %.1f, want >= 9.0", v.CVSS)
			}
			break
		}
	}
	if !found {
		t.Error("no CWE-89 finding found")
	}
}

func TestVulnScanner_XSS(t *testing.T) {
	srv := newMockServer(mockHandler)
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanXSS()

	if len(vs.Results.High) == 0 {
		t.Error("expected at least one XSS finding")
	}

	found := false
	for _, v := range vs.Results.High {
		if v.CWE == "CWE-79" {
			found = true
			if v.Parameter == "" {
				t.Error("XSS finding missing parameter")
			}
			break
		}
	}
	if !found {
		t.Error("no CWE-79 finding found")
	}
}

func TestVulnScanner_DirectoryTraversal(t *testing.T) {
	srv := newMockServer(mockHandler)
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanDirectoryTraversal()

	if len(vs.Results.Critical) == 0 {
		t.Error("expected at least one directory traversal finding")
	}

	found := false
	for _, v := range vs.Results.Critical {
		if v.CWE == "CWE-22" {
			found = true
			if v.Impact == "" {
				t.Error("directory traversal finding missing impact")
			}
			if v.Remediation == "" {
				t.Error("directory traversal finding missing remediation")
			}
			break
		}
	}
	if !found {
		t.Error("no CWE-22 finding found")
	}
}

func TestVulnScanner_OpenRedirect(t *testing.T) {
	srv := newMockServer(mockHandler)
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanOpenRedirect()

	if len(vs.Results.Medium) == 0 {
		t.Error("expected at least one open redirect finding")
	}

	found := false
	for _, v := range vs.Results.Medium {
		if v.CWE == "CWE-601" {
			found = true
			if v.Parameter == "" {
				t.Error("open redirect finding missing parameter")
			}
			break
		}
	}
	if !found {
		t.Error("no CWE-601 finding found")
	}
}

func TestVulnScanner_SecurityHeaders(t *testing.T) {
	srv := newMockServer(mockHandler)
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanSecurityHeaders()

	// Mock server is missing HSTS and CSP
	foundHSTS := false
	foundXPoweredBy := false
	for _, v := range vs.Results.Medium {
		if strings.Contains(v.Title, "Strict-Transport-Security") {
			foundHSTS = true
		}
	}
	for _, v := range vs.Results.Low {
		if strings.Contains(v.Title, "X-Powered-By") {
			foundXPoweredBy = true
		}
	}

	if !foundHSTS {
		t.Error("expected missing HSTS finding")
	}
	if !foundXPoweredBy {
		t.Error("expected X-Powered-By finding")
	}
}

func TestVulnScanner_SecurityHeaders_FullHeaders(t *testing.T) {
	srv := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.21.0")
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.WriteHeader(200)
		fmt.Fprintf(w, "OK")
	})
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanSecurityHeaders()

	for _, v := range vs.Results.Medium {
		if strings.Contains(v.Title, "Strict-Transport-Security") {
			t.Error("should not flag HSTS when properly configured")
		}
	}
	for _, v := range vs.Results.High {
		if strings.Contains(v.Title, "Security Header") {
			t.Errorf("should not flag security header as high: %s", v.Title)
		}
	}
}

func TestVulnScanner_InfoDisclosure(t *testing.T) {
	srv := newMockServer(mockHandler)
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanInfoDisclosure()

	// Mock serves .env, .git/HEAD, robots.txt, debug, swagger
	criticalCount := len(vs.Results.Critical)
	highCount := len(vs.Results.High)

	if criticalCount == 0 {
		t.Error("expected critical findings for .env or .git exposure")
	}

	totalInfoDisc := 0
	for _, v := range vs.Results.Critical {
		if v.CWE == "CWE-200" {
			totalInfoDisc++
		}
	}
	for _, v := range vs.Results.High {
		if v.CWE == "CWE-200" || v.CWE == "CWE-215" {
			totalInfoDisc++
		}
	}
	for _, v := range vs.Results.Medium {
		if v.CWE == "CWE-200" {
			totalInfoDisc++
		}
	}

	if totalInfoDisc < 3 {
		t.Errorf("expected at least 3 information disclosure findings, got %d", totalInfoDisc)
	}
	_ = highCount
}

func TestVulnScanner_DefaultCredentials(t *testing.T) {
	srv := newMockServer(mockHandler)
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanDefaultCredentials()

	found := false
	for _, v := range vs.Results.Critical {
		if v.CWE == "CWE-798" {
			found = true
			if v.PoC == "" {
				t.Error("default credential finding missing PoC")
			}
			if v.CVSS < 9.0 {
				t.Errorf("default credential CVSS = %.1f, want >= 9.0", v.CVSS)
			}
			break
		}
	}
	if !found {
		t.Error("expected default credential finding for admin/admin")
	}
}

func TestVulnScanner_APISecurity(t *testing.T) {
	srv := newMockServer(mockHandler)
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanAPISecurity()

	// Mock returns sensitive data in /api/users/1 and /api/users/2
	hasDataExposure := false
	for _, v := range vs.Results.High {
		if v.CWE == "CWE-200" {
			hasDataExposure = true
			break
		}
	}

	hasBOLA := false
	for _, v := range vs.Results.High {
		if v.CWE == "CWE-639" {
			hasBOLA = true
			break
		}
	}

	if !hasDataExposure {
		t.Error("expected excessive data exposure finding")
	}
	if !hasBOLA {
		t.Error("expected BOLA/IDOR finding")
	}
}

func TestVulnScanner_Cookies(t *testing.T) {
	srv := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session_id=abc123; Path=/; SameSite=None")
		w.WriteHeader(200)
		fmt.Fprintf(w, "OK")
	})
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanCookies()

	foundSecure := false
	foundHttpOnly := false
	foundSameSite := false

	for _, v := range vs.Results.Low {
		if strings.Contains(v.Title, "Secure Flag") {
			foundSecure = true
		}
		if strings.Contains(v.Title, "SameSite") {
			foundSameSite = true
		}
	}
	for _, v := range vs.Results.Medium {
		if strings.Contains(v.Title, "HttpOnly") {
			foundHttpOnly = true
		}
	}

	if !foundSecure {
		t.Error("expected missing Secure flag finding")
	}
	if !foundHttpOnly {
		t.Error("expected missing HttpOnly flag finding")
	}
	if !foundSameSite {
		t.Error("expected SameSite=None finding")
	}
}

func TestVulnScanner_CORS(t *testing.T) {
	srv := newMockServer(mockHandler)
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanCORS()

	foundOriginReflection := false
	for _, v := range vs.Results.High {
		if v.CWE == "CWE-942" {
			foundOriginReflection = true
			break
		}
	}

	foundCredentials := false
	for _, v := range vs.Results.Medium {
		if strings.Contains(v.Title, "Credentials") && v.CWE == "CWE-942" {
			foundCredentials = true
			break
		}
	}

	if !foundOriginReflection {
		t.Error("expected CORS origin reflection finding")
	}
	if !foundCredentials {
		t.Error("expected CORS credentials finding")
	}
}

func TestVulnScanner_CORS_Wildcard(t *testing.T) {
	srv := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
		fmt.Fprintf(w, "OK")
	})
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	vs.scanCORS()

	foundWildcard := false
	for _, v := range vs.Results.Medium {
		if strings.Contains(v.Title, "Wildcard") && v.CWE == "CWE-942" {
			foundWildcard = true
			break
		}
	}
	if !foundWildcard {
		t.Error("expected wildcard CORS finding")
	}
}

func TestVulnScanner_RiskScoreCalculation(t *testing.T) {
	vs := NewVulnScanner("http://example.com")
	vs.Results = &VulnReport{
		OWASP: make(map[string][]Vulnerability),
	}

	// Add findings of various severities
	for i := 0; i < 3; i++ {
		vs.addFinding(Vulnerability{ID: fmt.Sprintf("T-C%d", i), Severity: "critical", CVSS: 9.5})
	}
	for i := 0; i < 5; i++ {
		vs.addFinding(Vulnerability{ID: fmt.Sprintf("T-H%d", i), Severity: "high", CVSS: 7.5})
	}
	for i := 0; i < 10; i++ {
		vs.addFinding(Vulnerability{ID: fmt.Sprintf("T-M%d", i), Severity: "medium", CVSS: 5.0})
	}

	vs.compileReport(vs.Results)

	if vs.Results.RiskScore >= 50 {
		t.Errorf("risk score with many vulns = %d, want < 50", vs.Results.RiskScore)
	}
	if vs.Results.Grade != "D" && vs.Results.Grade != "F" {
		t.Errorf("grade with many vulns = %s, want D or F", vs.Results.Grade)
	}
}

func TestVulnScanner_RiskScore_Clean(t *testing.T) {
	vs := NewVulnScanner("http://example.com")
	vs.Results = &VulnReport{
		OWASP: make(map[string][]Vulnerability),
	}

	vs.compileReport(vs.Results)

	if vs.Results.RiskScore != 100 {
		t.Errorf("clean report risk score = %d, want 100", vs.Results.RiskScore)
	}
	if vs.Results.Grade != "A" {
		t.Errorf("clean report grade = %s, want A", vs.Results.Grade)
	}
}

func TestVulnScanner_Grades(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{100, "A"},
		{90, "A"},
		{85, "B"},
		{75, "C"},
		{55, "D"},
		{30, "F"},
	}

	for _, tt := range tests {
		vs := NewVulnScanner("http://example.com")
		vs.Results = &VulnReport{
			RiskScore: tt.score,
			OWASP:     make(map[string][]Vulnerability),
		}
		vs.compileReport(vs.Results)
		if vs.Results.Grade != tt.grade {
			t.Errorf("score %d: grade = %s, want %s", tt.score, vs.Results.Grade, tt.grade)
		}
	}
}

func TestVulnScanner_OWASPCategories(t *testing.T) {
	vs := NewVulnScanner("http://example.com")
	vs.Results = &VulnReport{
		OWASP: make(map[string][]Vulnerability),
	}

	vs.addFinding(Vulnerability{
		Severity: "critical",
		Category: "A03:2021 Injection",
		CVSS:     9.8,
	})
	vs.addFinding(Vulnerability{
		Severity: "high",
		Category: "A01:2021 Broken Access Control",
		CVSS:     7.5,
	})
	vs.addFinding(Vulnerability{
		Severity: "medium",
		Category: "A03:2021 Injection",
		CVSS:     6.1,
	})

	if len(vs.Results.OWASP["A03:2021 Injection"]) != 2 {
		t.Errorf("expected 2 A03 findings, got %d", len(vs.Results.OWASP["A03:2021 Injection"]))
	}
	if len(vs.Results.OWASP["A01:2021 Broken Access Control"]) != 1 {
		t.Errorf("expected 1 A01 finding, got %d", len(vs.Results.OWASP["A01:2021 Broken Access Control"]))
	}
}

func TestVulnScanner_ConcurrentScan(t *testing.T) {
	srv := newMockServer(mockHandler)
	defer srv.Close()

	const numScanners = 5
	var wg sync.WaitGroup
	reports := make([]*VulnReport, numScanners)

	for i := 0; i < numScanners; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			vs := NewVulnScanner(srv.URL)
			reports[idx] = vs.Scan()
		}(i)
	}
	wg.Wait()

	for i, report := range reports {
		if report == nil {
			t.Errorf("scanner %d returned nil report", i)
			continue
		}
		if report.Target != srv.URL {
			t.Errorf("scanner %d: target = %q, want %q", i, report.Target, srv.URL)
		}
		if report.Duration == 0 {
			t.Errorf("scanner %d: duration is 0", i)
		}
		if report.TotalChecks == 0 {
			t.Errorf("scanner %d: total checks is 0", i)
		}
	}
}

func TestVulnScanner_FullScan(t *testing.T) {
	srv := newMockServer(mockHandler)
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	report := vs.Scan()

	if report == nil {
		t.Fatal("Scan() returned nil")
	}
	if report.Target != srv.URL {
		t.Errorf("target = %q, want %q", report.Target, srv.URL)
	}
	if report.Duration == 0 {
		t.Error("duration is 0")
	}
	if report.ScanTime.IsZero() {
		t.Error("scan time is zero")
	}
	if report.TotalChecks == 0 {
		t.Error("total checks is 0")
	}
	if report.TotalFound == 0 {
		t.Error("total found is 0")
	}
	if report.Grade == "" {
		t.Error("grade is empty")
	}
	if report.RiskScore < 0 || report.RiskScore > 100 {
		t.Errorf("risk score = %d, want 0-100", report.RiskScore)
	}

	totalVulns := len(report.Critical) + len(report.High) + len(report.Medium) + len(report.Low) + len(report.Info)
	if int64(totalVulns) != report.TotalFound {
		t.Errorf("total vulns from categories (%d) != TotalFound (%d)", totalVulns, report.TotalFound)
	}

	t.Logf("Scan complete: %d checks, %d findings, score=%d grade=%s", report.TotalChecks, report.TotalFound, report.RiskScore, report.Grade)
	t.Logf("  Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d",
		len(report.Critical), len(report.High), len(report.Medium), len(report.Low), len(report.Info))
}

func TestVulnScanner_NormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "http://example.com"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
		{"http://example.com:8080", "http://example.com:8080"},
	}

	for _, tt := range tests {
		got := normalizeURL(tt.input)
		if got != tt.want {
			t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestVulnScanner_VulnerabilityStructure(t *testing.T) {
	v := Vulnerability{
		ID:          "TEST-001",
		Title:       "Test Vuln",
		Severity:    "critical",
		Category:    "A03:2021 Injection",
		CVSS:        9.8,
		CWE:         "CWE-89",
		URL:         "http://example.com",
		Parameter:   "id",
		Evidence:    "SQL error in response",
		Impact:      "Data breach",
		Remediation: "Use parameterized queries",
		References:  []string{"https://cwe.mitre.org/data/definitions/89.html"},
		PoC:         "GET /?id=1'%20OR%201=1--",
	}

	if v.ID != "TEST-001" {
		t.Error("ID mismatch")
	}
	if v.CVSS != 9.8 {
		t.Error("CVSS mismatch")
	}
	if len(v.References) != 1 {
		t.Error("References mismatch")
	}
}

func TestVulnScanner_NextVulnID(t *testing.T) {
	resetVulnCounter()
	id1 := nextVulnID("TEST")
	id2 := nextVulnID("TEST")
	id3 := nextVulnID("VULN")

	if id1 != "TEST-001" {
		t.Errorf("first ID = %q, want TEST-001", id1)
	}
	if id2 != "TEST-002" {
		t.Errorf("second ID = %q, want TEST-002", id2)
	}
	if id3 != "VULN-003" {
		t.Errorf("third ID = %q, want VULN-003", id3)
	}
}

func TestVulnScanner_CVEFinding(t *testing.T) {
	cve := CVEFinding{
		CVEID:       "CVE-2021-44228",
		Description: "Apache Log4j2 RCE",
		Severity:    "critical",
		CVSS:        10.0,
		CWE:         "CWE-502",
		Product:     "Apache Log4j2",
		Version:     "2.14.1",
		FixedIn:     "2.15.0",
	}

	if cve.CVSS != 10.0 {
		t.Error("CVSS mismatch")
	}
	if cve.CVEID != "CVE-2021-44228" {
		t.Error("CVE ID mismatch")
	}
}

func TestVulnScanner_AddFindingThreadSafety(t *testing.T) {
	vs := NewVulnScanner("http://example.com")
	vs.Results = &VulnReport{
		OWASP: make(map[string][]Vulnerability),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			vs.addFinding(Vulnerability{
				ID:       fmt.Sprintf("T-%d", idx),
				Severity: []string{"critical", "high", "medium", "low", "info"}[idx%5],
				CVSS:     float64(idx % 10),
			})
		}(i)
	}
	wg.Wait()

	total := len(vs.Results.Critical) + len(vs.Results.High) + len(vs.Results.Medium) + len(vs.Results.Low) + len(vs.Results.Info)
	if total != 100 {
		t.Errorf("expected 100 findings, got %d", total)
	}
	if vs.Results.TotalFound != 100 {
		t.Errorf("TotalFound = %d, want 100", vs.Results.TotalFound)
	}
}

func TestVulnScanner_NoVulnsCleanTarget(t *testing.T) {
	srv := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.Header().Set("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Strict; Path=/")
		w.WriteHeader(200)
		fmt.Fprintf(w, "<html><body>Safe</body></html>")
	})
	defer srv.Close()

	vs := NewVulnScanner(srv.URL)
	report := vs.Scan()

	if len(report.Critical) != 0 {
		t.Errorf("clean target has %d critical vulns, want 0", len(report.Critical))
	}
	if report.RiskScore < 90 {
		t.Errorf("clean target score = %d, want >= 90", report.RiskScore)
	}
	if report.Grade != "A" && report.Grade != "B" {
		t.Errorf("clean target grade = %s, want A or B", report.Grade)
	}
}

func TestVulnScanner_SeverityCounts(t *testing.T) {
	vs := NewVulnScanner("http://example.com")
	vs.Results = &VulnReport{
		OWASP: make(map[string][]Vulnerability),
	}

	for i := 0; i < 5; i++ {
		vs.addFinding(Vulnerability{ID: fmt.Sprintf("C-%d", i), Severity: "critical", CVSS: 10.0})
	}
	for i := 0; i < 3; i++ {
		vs.addFinding(Vulnerability{ID: fmt.Sprintf("H-%d", i), Severity: "high", CVSS: 8.0})
	}
	for i := 0; i < 7; i++ {
		vs.addFinding(Vulnerability{ID: fmt.Sprintf("M-%d", i), Severity: "medium", CVSS: 5.0})
	}
	for i := 0; i < 2; i++ {
		vs.addFinding(Vulnerability{ID: fmt.Sprintf("L-%d", i), Severity: "low", CVSS: 3.0})
	}
	vs.addFinding(Vulnerability{ID: "I-0", Severity: "info", CVSS: 0.0})

	if len(vs.Results.Critical) != 5 {
		t.Errorf("critical count = %d, want 5", len(vs.Results.Critical))
	}
	if len(vs.Results.High) != 3 {
		t.Errorf("high count = %d, want 3", len(vs.Results.High))
	}
	if len(vs.Results.Medium) != 7 {
		t.Errorf("medium count = %d, want 7", len(vs.Results.Medium))
	}
	if len(vs.Results.Low) != 2 {
		t.Errorf("low count = %d, want 2", len(vs.Results.Low))
	}
	if len(vs.Results.Info) != 1 {
		t.Errorf("info count = %d, want 1", len(vs.Results.Info))
	}
}
