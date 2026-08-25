package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockVulnerableServer creates a deliberately vulnerable test server
func mockVulnerableServer() *httptest.Server {
	mux := http.NewServeMux()

	// Root: serves vulnerable content that triggers all OWASP checks
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.49 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.0.33")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		path := r.URL.Path

		// A09: verbose error for certain paths
		if strings.Contains(path, "nonexistent-endpoint-xyz") ||
			strings.Contains(path, "99999999") {
			w.WriteHeader(500)
			fmt.Fprint(w, "Internal Server Error\nstack trace:\n\tat main.go:42\n\tat handler.go:15")
			return
		}
		if strings.HasSuffix(path, "'") {
			w.WriteHeader(500)
			fmt.Fprint(w, "Internal Server Error\nstack trace:\n\tat main.go:42")
			return
		}

		// A03: injection responses based on query params
		q := r.URL.Query().Get("q")
		if q != "" {
			fmt.Fprintf(w, "Results for: %s", q)
			return
		}
		id := r.URL.Query().Get("id")
		if id != "" {
			if strings.Contains(id, "'") {
				fmt.Fprintf(w, "ERROR: You have an error in your SQL syntax near '%s'", id)
			}
			return
		}
		host := r.URL.Query().Get("host")
		if host != "" {
			if strings.Contains(host, ";") || strings.Contains(host, "|") {
				fmt.Fprint(w, "uid=33(www-data) gid=33(www-data)")
			}
			return
		}
		ip := r.URL.Query().Get("ip")
		if ip != "" {
			if strings.Contains(ip, ";") || strings.Contains(ip, "|") {
				fmt.Fprint(w, "uid=33(www-data) gid=33(www-data)")
			}
			return
		}
		cmd := r.URL.Query().Get("cmd")
		if cmd != "" {
			if strings.Contains(cmd, ";") {
				fmt.Fprint(w, "uid=33(www-data) gid=33(www-data)")
			}
			return
		}
		user := r.URL.Query().Get("user")
		if user != "" {
			if strings.Contains(user, "ldap") || strings.Contains(user, "bind") {
				fmt.Fprint(w, "LDAP error: bind failed")
				return
			}
		}

		// A10: SSRF responses
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			if strings.Contains(urlParam, "127.0.0.1") || strings.Contains(urlParam, "localhost") {
				fmt.Fprint(w, "uid=0(root) gid=0(root)")
				return
			}
			if strings.HasPrefix(urlParam, "file://") && strings.Contains(urlParam, "passwd") {
				fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
				return
			}
			if strings.Contains(urlParam, "169.254.169.254") {
				fmt.Fprint(w, "ami-id\ninstance-id\nlocal-ipv4")
				return
			}
		}

		// A08: SRI - serve HTML with external script (no integrity)
		fmt.Fprint(w, `<html><head></head><body>
			<script src="https://cdn.example.com/lib.js"></script>
			<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/2.1.0/jquery.min.js"></script>
			Welcome</body></html>`)
	})

	// A01: Admin panel
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>Admin Panel</title><div>Welcome to admin dashboard</div></html>")
	})
	mux.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>Admin Panel</title><div>Welcome to admin dashboard</div></html>")
	})
	mux.HandleFunc("/api/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>Admin</title><div>Welcome to admin panel</div></html>`)
	})
	mux.HandleFunc("/wp-admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>WordPress Admin</title><div>Control Panel</div></html>`)
	})
	mux.HandleFunc("/administrator", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>Joomla Admin</title><div>Control Panel</div></html>`)
	})

	// A01: Directory listing
	mux.HandleFunc("/images/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>Index of /images</title><a href=\"file1.jpg\">file1.jpg</a></html>")
	})

	// A03: Search endpoint (injection tests)
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "Results for: %s", q)
	})

	// A04: Order endpoint
	mux.HandleFunc("/api/order", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			fmt.Fprint(w, `{"status":"success","message":"Order created"}`)
		}
	})

	// A05: Login endpoint (default creds)
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body := make([]byte, 1024)
			n, _ := r.Body.Read(body)
			content := string(body[:n])
			if strings.Contains(content, "admin") && strings.Contains(content, "admin") {
				fmt.Fprint(w, `{"token":"abc123","status":"success"}`)
			} else if strings.Contains(content, "test") {
				fmt.Fprint(w, `{"error":"invalid credentials"}`)
			} else if strings.Contains(content, "$gt") {
				fmt.Fprint(w, `{"token":"bypassed","status":"success"}`)
			} else {
				fmt.Fprint(w, `{"error":"invalid credentials"}`)
			}
		}
	})
	mux.HandleFunc("/trace", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "TRACE" {
			fmt.Fprintf(w, "Method: %s", r.Method)
		}
	})
	mux.HandleFunc("/api/admin/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"users":[{"name":"admin"}]}`)
	})
	mux.HandleFunc("/api/admin/config", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"config":{"debug":true}}`)
	})
	mux.HandleFunc("/api/internal/debug", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"debug":true}`)
	})
	mux.HandleFunc("/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"settings":{}}`)
	})

	// A01: Directory traversal
	mux.HandleFunc("/..%2f", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "etc/passwd") || strings.Contains(r.URL.RawPath, "etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
			return
		}
		fmt.Fprint(w, "OK")
	})

	// A06: CMS login pages
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>Powered by WordPress</body></html>`)
	})
	mux.HandleFunc("/xmlrpc.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<xml>xmlrpc</xml>`)
	})
	mux.HandleFunc("/administrator/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>joomla admin</body></html>`)
	})
	mux.HandleFunc("/user/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>drupal login</body></html>`)
	})

	// A08: Exposed config files
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true")
	})
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ref: refs/heads/main")
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "DATABASE_URL=postgres://user:pass@localhost/db")
	})

	// A09: Debug endpoints
	mux.HandleFunc("/debug/vars", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"memstats":{"HeapAlloc":1234},"numgoroutine":10}`)
	})
	mux.HandleFunc("/debug/pprof", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "goroutine profile:\n\n")
	})

	return httptest.NewServer(mux)
}

func TestOWASPCheckAll(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	_ = checker.CheckAll()
	report := checker.Results

	if report == nil {
		t.Fatal("Report should not be nil")
	}

	if len(report.Categories) != 10 {
		t.Errorf("Expected 10 categories, got %d", len(report.Categories))
	}

	for id, name := range owaspCategories {
		cat, ok := report.Categories[id]
		if !ok {
			t.Errorf("Category %s (%s) missing", id, name)
			continue
		}
		if cat.Name != name {
			t.Errorf("Category %s name: got %q, want %q", id, cat.Name, name)
		}
	}

	if report.Score < 0 || report.Score > 100 {
		t.Errorf("Score out of range: %d", report.Score)
	}

	validGrades := map[string]bool{"A": true, "B": true, "C": true, "D": true, "F": true}
	if !validGrades[report.Grade] {
		t.Errorf("Invalid grade: %s", report.Grade)
	}
}

func TestOWASPA01(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA01()

	if cat.ID != "A01" {
		t.Errorf("Expected ID A01, got %s", cat.ID)
	}

	if cat.Name != "Broken Access Control" {
		t.Errorf("Expected name 'Broken Access Control', got %s", cat.Name)
	}

	// Should find CORS issue (Access-Control-Allow-Origin: *)
	foundCORS := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "CORS") || strings.Contains(f, "cors") {
			foundCORS = true
			break
		}
	}
	if !foundCORS {
		t.Error("A01 should detect permissive CORS")
	}
}

func TestOWASPA02(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA02()

	if cat.ID != "A02" {
		t.Errorf("Expected ID A02, got %s", cat.ID)
	}

	// Mock server doesn't redirect HTTP -> HTTPS, should flag it
	foundHTTPS := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "HTTPS") || strings.Contains(f, "redirect") || strings.Contains(f, "HSTS") {
			foundHTTPS = true
			break
		}
	}
	if !foundHTTPS {
		t.Error("A02 should detect missing HTTPS enforcement or HSTS")
	}
}

func TestOWASPA03(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA03()

	if cat.ID != "A03" {
		t.Errorf("Expected ID A03, got %s", cat.ID)
	}

	// Should find SQL injection at /search
	foundSQL := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "SQL") || strings.Contains(f, "sql") {
			foundSQL = true
			break
		}
	}
	if !foundSQL {
		t.Error("A03 should detect SQL injection")
	}

	// Should find XSS at /search
	foundXSS := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "XSS") || strings.Contains(f, "xss") {
			foundXSS = true
			break
		}
	}
	if !foundXSS {
		t.Error("A03 should detect reflected XSS")
	}

	// Should find command injection
	foundCmd := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "Command") || strings.Contains(f, "command") {
			foundCmd = true
			break
		}
	}
	if !foundCmd {
		t.Error("A03 should detect command injection")
	}
}

func TestOWASPA04(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA04()

	if cat.ID != "A04" {
		t.Errorf("Expected ID A04, got %s", cat.ID)
	}

	// Should detect no rate limiting
	foundRate := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "rate limit") || strings.Contains(f, "Rate limit") {
			foundRate = true
			break
		}
	}
	if !foundRate {
		t.Error("A04 should detect missing rate limiting")
	}
}

func TestOWASPA05(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA05()

	if cat.ID != "A05" {
		t.Errorf("Expected ID A05, got %s", cat.ID)
	}

	// Should find default credentials (admin/admin accepted)
	foundCreds := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "default credentials") || strings.Contains(f, "Default credentials") {
			foundCreds = true
			break
		}
	}
	if !foundCreds {
		t.Error("A05 should detect default credentials")
	}

	// Should find TRACE method allowed
	foundTrace := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "TRACE") || strings.Contains(f, "trace") {
			foundTrace = true
			break
		}
	}
	if !foundTrace {
		t.Error("A05 should detect dangerous HTTP methods")
	}

	// Should find admin endpoint accessible
	foundAdmin := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "admin") || strings.Contains(f, "Admin") {
			foundAdmin = true
			break
		}
	}
	if !foundAdmin {
		t.Error("A05 should detect admin endpoint without auth")
	}
}

func TestOWASPA06(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA06()

	if cat.ID != "A06" {
		t.Errorf("Expected ID A06, got %s", cat.ID)
	}

	// Mock server has Apache/2.4.49 and PHP/7.0.33 and WordPress
	foundVuln := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "Apache") || strings.Contains(f, "PHP") ||
			strings.Contains(f, "WordPress") || strings.Contains(f, "jQuery") {
			foundVuln = true
			break
		}
	}
	if !foundVuln {
		t.Error("A06 should detect vulnerable software components")
	}
}

func TestOWASPA07(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA07()

	if cat.ID != "A07" {
		t.Errorf("Expected ID A07, got %s", cat.ID)
	}

	// Should detect missing cookie flags (session cookie without Secure/HttpOnly)
	foundCookie := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "cookie") || strings.Contains(f, "Cookie") ||
			strings.Contains(f, "brute force") || strings.Contains(f, "Brute") {
			foundCookie = true
			break
		}
	}
	if !foundCookie {
		t.Error("A07 should detect cookie security issues or missing brute force protection")
	}
}

func TestOWASPA08(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA08()

	if cat.ID != "A08" {
		t.Errorf("Expected ID A08, got %s", cat.ID)
	}

	// Should find SRI missing on external scripts
	foundSRI := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "SRI") || strings.Contains(f, "sri") || strings.Contains(f, "integrity") {
			foundSRI = true
			break
		}
	}
	if !foundSRI {
		t.Error("A08 should detect missing SRI on external scripts")
	}

	// Should find exposed config files (.git, .env)
	foundCICD := false
	for _, f := range cat.Findings {
		if strings.Contains(f, ".git") || strings.Contains(f, ".env") ||
			strings.Contains(f, "CI/CD") || strings.Contains(f, "configuration") {
			foundCICD = true
			break
		}
	}
	if !foundCICD {
		t.Error("A08 should detect exposed CI/CD or config files")
	}
}

func TestOWASPA09(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA09()

	if cat.ID != "A09" {
		t.Errorf("Expected ID A09, got %s", cat.ID)
	}

	// Should detect verbose error messages
	foundVerbose := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "Verbose") || strings.Contains(f, "verbose") ||
			strings.Contains(f, "error") || strings.Contains(f, "Error") {
			foundVerbose = true
			break
		}
	}
	if !foundVerbose {
		t.Error("A09 should detect verbose error messages")
	}
}

func TestOWASPA10(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA10()

	if cat.ID != "A10" {
		t.Errorf("Expected ID A10, got %s", cat.ID)
	}

	// Should detect SSRF via 127.0.0.1 and file://
	foundSSRF := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "SSRF") || strings.Contains(f, "ssrf") {
			foundSSRF = true
			break
		}
	}
	if !foundSSRF {
		t.Error("A10 should detect SSRF vulnerabilities")
	}
}

func TestOWASPScoreCalculation(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)

	// Test with all passing
	report := &OWASPReport{
		Categories: make(map[string]*OWASPCategory),
	}
	report.Categories["A01"] = &OWASPCategory{Score: 100}
	report.Categories["A02"] = &OWASPCategory{Score: 100}
	report.Categories["A03"] = &OWASPCategory{Score: 100}
	report.Categories["A04"] = &OWASPCategory{Score: 100}
	report.Categories["A05"] = &OWASPCategory{Score: 100}
	report.Categories["A06"] = &OWASPCategory{Score: 100}
	report.Categories["A07"] = &OWASPCategory{Score: 100}
	report.Categories["A08"] = &OWASPCategory{Score: 100}
	report.Categories["A09"] = &OWASPCategory{Score: 100}
	report.Categories["A10"] = &OWASPCategory{Score: 100}

	score := checker.CalculateScore(report)
	if score != 100 {
		t.Errorf("All passing score should be 100, got %d", score)
	}

	// Test with mixed scores
	report.Categories["A01"] = &OWASPCategory{Score: 50}
	report.Categories["A03"] = &OWASPCategory{Score: 0}
	score = checker.CalculateScore(report)
	if score != 85 {
		t.Errorf("Mixed score should be 85, got %d", score)
	}

	// Test with all failing
	for id := range report.Categories {
		report.Categories[id] = &OWASPCategory{Score: 0}
	}
	score = checker.CalculateScore(report)
	if score != 0 {
		t.Errorf("All failing score should be 0, got %d", score)
	}

	// Test empty report
	emptyReport := &OWASPReport{Categories: make(map[string]*OWASPCategory)}
	score = checker.CalculateScore(emptyReport)
	if score != 0 {
		t.Errorf("Empty report score should be 0, got %d", score)
	}
}

func TestOWASPGradeCalculation(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)

	tests := []struct {
		score int
		grade string
	}{
		{95, "A"},
		{90, "A"},
		{85, "B"},
		{80, "B"},
		{75, "C"},
		{70, "C"},
		{65, "D"},
		{60, "D"},
		{50, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		report := &OWASPReport{Categories: make(map[string]*OWASPCategory)}
		report.Score = tt.score
		grade := checker.calculateGrade(tt.score)
		if grade != tt.grade {
			t.Errorf("Score %d: expected grade %s, got %s", tt.score, tt.grade, grade)
		}
	}
}

func TestOWASPRender(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	_ = checker.CheckAll()

	output := checker.Render()

	if output == "" {
		t.Error("Render should produce non-empty output")
	}

	if !strings.Contains(output, "OWASP TOP 10") {
		t.Error("Render should contain header")
	}

	if !strings.Contains(output, "A01") || !strings.Contains(output, "A10") {
		t.Error("Render should contain all OWASP categories")
	}

	if !strings.Contains(output, "Broken Access Control") || !strings.Contains(output, "Server-Side Request Forgery") {
		t.Error("Render should contain category names")
	}

	if !strings.Contains(output, "SUMMARY") {
		t.Error("Render should contain summary section")
	}

	if !strings.Contains(output, "GRADE:") {
		t.Error("Render should contain grade")
	}
}

func TestOWASPRenderNoResults(t *testing.T) {
	server := mockVulnerableServer()
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	output := checker.Render()

	if !strings.Contains(output, "No results available") {
		t.Error("Render without results should show message")
	}
}

func TestNewOWASPChecker(t *testing.T) {
	checker := NewOWASPChecker("http://example.com")

	if checker.Target != "http://example.com" {
		t.Errorf("Target mismatch: got %s", checker.Target)
	}

	if checker.Client == nil {
		t.Error("Client should not be nil")
	}

	if checker.Transport == nil {
		t.Error("Transport should not be nil")
	}

	if checker.Results != nil {
		t.Error("Results should be nil before CheckAll()")
	}
}

func TestOWASPStatusTransitions(t *testing.T) {
	checker := &OWASPChecker{}

	cat := checker.newCategory("A01")
	if cat.Status != "PASS" {
		t.Errorf("New category should be PASS, got %s", cat.Status)
	}
	if cat.Score != 100 {
		t.Errorf("New category score should be 100, got %d", cat.Score)
	}

	// Add critical finding -> should drop to FAIL
	checker.addFinding(cat, "critical issue", "fix it", "critical")
	if cat.Score != 70 {
		t.Errorf("After critical finding, score should be 70, got %d", cat.Score)
	}
	if cat.Status != "WARNING" {
		t.Errorf("Score 70 should be WARNING, got %s", cat.Status)
	}

	// Add more to drop below 30
	checker.addFinding(cat, "another critical", "fix", "critical")
	checker.addFinding(cat, "third critical", "fix", "critical")
	if cat.Score != 10 {
		t.Errorf("Score should be 10, got %d", cat.Score)
	}
	if cat.Status != "FAIL" {
		t.Errorf("Score 10 should be FAIL, got %s", cat.Status)
	}

	// Score should not go below 0
	checker.addFinding(cat, "yet another", "fix", "critical")
	if cat.Score != 0 {
		t.Errorf("Score should floor at 0, got %d", cat.Score)
	}
}

func TestOWASPCategoryRemediation(t *testing.T) {
	checker := &OWASPChecker{}
	cat := checker.newCategory("A03")

	checker.addFinding(cat, "SQL injection found", "Use prepared statements", "critical")
	checker.addFinding(cat, "XSS found", "Encode output", "high")

	if len(cat.Findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(cat.Findings))
	}
	if len(cat.Remediation) != 2 {
		t.Errorf("Expected 2 remediation items, got %d", len(cat.Remediation))
	}
	if cat.Remediation[0] != "Use prepared statements" {
		t.Errorf("First remediation mismatch: %s", cat.Remediation[0])
	}
	if cat.Remediation[1] != "Encode output" {
		t.Errorf("Second remediation mismatch: %s", cat.Remediation[1])
	}
}

func TestOWASPCleanServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Server", "CustomServer")
		fmt.Fprint(w, "Welcome")
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	report := checker.CheckAll()

	// A clean server should score better than a vulnerable one
	if report.Score < 50 {
		t.Errorf("Clean server score %d seems too low", report.Score)
	}

	// A02 should be mostly clean (HSTS present, HTTPS redirect may fail)
	a02 := report.Categories["A02"]
	if a02 != nil && a02.Status == "FAIL" {
		t.Error("Clean server A02 should not FAIL (has HSTS)")
	}
}

func TestOWASPA03NoSQL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body := make([]byte, 1024)
			n, _ := r.Body.Read(body)
			content := string(body[:n])
			if strings.Contains(content, "$gt") {
				fmt.Fprint(w, `{"token":"bypassed","status":"success"}`)
			}
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA03()

	foundNoSQL := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "NoSQL") || strings.Contains(f, "nosql") {
			foundNoSQL = true
			break
		}
	}
	if !foundNoSQL {
		t.Error("A03 should detect NoSQL injection")
	}
}

func TestOWASPA10FileProtocol(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if strings.HasPrefix(urlParam, "file://") {
			if strings.Contains(urlParam, "passwd") {
				fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
			}
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA10()

	foundFileSSRF := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "file://") {
			foundFileSSRF = true
			break
		}
	}
	if !foundFileSSRF {
		t.Error("A10 should detect SSRF via file:// protocol")
	}
}

func TestOWASPA05DirectoryTraversal(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
			return
		}
		fmt.Fprint(w, "OK")
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	checker := NewOWASPChecker(server.URL)
	cat := checker.checkA05()

	foundTraversal := false
	for _, f := range cat.Findings {
		if strings.Contains(f, "traversal") || strings.Contains(f, "Traversal") {
			foundTraversal = true
			break
		}
	}
	if !foundTraversal {
		t.Error("A05 should detect directory traversal")
	}
}
