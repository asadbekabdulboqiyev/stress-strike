package scanner

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// VulnScanner performs comprehensive vulnerability scanning
type VulnScanner struct {
	Target  string
	Client  *http.Client
	Results *VulnReport
	mu      sync.Mutex
}

// VulnReport contains all scan results
type VulnReport struct {
	Target   string        `json:"target"`
	ScanTime time.Time     `json:"scan_time"`
	Duration time.Duration `json:"duration"`

	Critical []Vulnerability `json:"critical"`
	High     []Vulnerability `json:"high"`
	Medium   []Vulnerability `json:"medium"`
	Low      []Vulnerability `json:"low"`
	Info     []Vulnerability `json:"info"`

	OWASP map[string][]Vulnerability `json:"owasp"`

	RiskScore int    `json:"risk_score"`
	Grade     string `json:"grade"`

	TotalChecks int64 `json:"total_checks"`
	TotalFound  int64 `json:"total_found"`
	URLsChecked int64 `json:"urls_checked"`
}

// Vulnerability represents a single finding
type Vulnerability struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	CVSS        float64  `json:"cvss"`
	CWE         string   `json:"cwe"`
	URL         string   `json:"url"`
	Parameter   string   `json:"parameter"`
	Evidence    string   `json:"evidence"`
	Impact      string   `json:"impact"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
	PoC         string   `json:"poc"`
}

var (
	vulnCounter int
	counterMu   sync.Mutex
)

func nextVulnID(prefix string) string {
	counterMu.Lock()
	defer counterMu.Unlock()
	vulnCounter++
	return fmt.Sprintf("%s-%03d", prefix, vulnCounter)
}

func resetVulnCounter() {
	counterMu.Lock()
	defer counterMu.Unlock()
	vulnCounter = 0
}

// NewVulnScanner creates a new vulnerability scanner
func NewVulnScanner(target string) *VulnScanner {
	return &VulnScanner{
		Target: target,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Results: &VulnReport{
			OWASP: make(map[string][]Vulnerability),
		},
	}
}

// Scan runs all vulnerability checks and returns the report
func (vs *VulnScanner) Scan() *VulnReport {
	start := time.Now()
	resetVulnCounter()

	report := &VulnReport{
		Target:   vs.Target,
		ScanTime: start,
		OWASP:    make(map[string][]Vulnerability),
	}

	vs.Results = report

	var wg sync.WaitGroup
	checks := []func(){
		vs.scanSQLInjection,
		vs.scanXSS,
		vs.scanDirectoryTraversal,
		vs.scanOpenRedirect,
		vs.scanSecurityHeaders,
		vs.scanInfoDisclosure,
		vs.scanDefaultCredentials,
		vs.scanAPISecurity,
		vs.scanCookies,
		vs.scanCORS,
	}

	for _, check := range checks {
		wg.Add(1)
		fn := check
		go func() {
			defer wg.Done()
			fn()
		}()
	}
	wg.Wait()

	vs.compileReport(report)
	report.Duration = time.Since(start)
	return report
}

// addFinding is thread-safe and appends a vulnerability to the report
func (vs *VulnScanner) addFinding(v Vulnerability) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	report := vs.Results
	if report == nil {
		return
	}

	switch v.Severity {
	case "critical":
		report.Critical = append(report.Critical, v)
	case "high":
		report.High = append(report.High, v)
	case "medium":
		report.Medium = append(report.Medium, v)
	case "low":
		report.Low = append(report.Low, v)
	default:
		report.Info = append(report.Info, v)
	}

	if v.Category != "" {
		report.OWASP[v.Category] = append(report.OWASP[v.Category], v)
	}
	atomic.AddInt64(&report.TotalFound, 1)
}

// doRequest sends an HTTP request and returns the response
func (vs *VulnScanner) doRequest(method, url string, body io.Reader, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "stress-strike-vulnscanner/1.0")
	if headers != nil {
		for k, vals := range headers {
			for _, v := range vals {
				req.Header.Set(k, v)
			}
		}
	}
	return vs.Client.Do(req)
}

// get performs a GET request
func (vs *VulnScanner) get(targetURL string) (*http.Response, error) {
	return vs.doRequest("GET", targetURL, nil, nil)
}

// postForm performs a POST with form data
func (vs *VulnScanner) postForm(targetURL string, data url.Values, headers http.Header) (*http.Response, error) {
	if headers == nil {
		headers = http.Header{}
	}
	if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return vs.doRequest("POST", targetURL, bytes.NewBufferString(data.Encode()), headers)
}

// normalizeURL ensures the target has a scheme
func normalizeURL(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "http://" + target
	}
	return target
}

// ---------------------------------------------------------------------------
// 1. SQL Injection Detection
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanSQLInjection() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	params := []string{"id", "user", "search", "q", "page", "cat", "item", "sort", "order", "filter", "type", "name", "email"}
	payloads := []struct {
		payload  string
		signature string
	}{
		{"' OR 1=1--", "sql"},
		{`" OR ""="`, "sql"},
		{"1' UNION SELECT NULL--", "sql"},
		{"1' AND SLEEP(5)--", "time"},
		{"'; WAITFOR DELAY '0:0:5'--", "time"},
		{"1' AND '1'='1", "sql"},
		{"1; DROP TABLE users--", "sql"},
		{"' UNION SELECT username,password FROM users--", "sql"},
	}

	sqlErrorPatterns := []string{
		"sql syntax", "mysql", "sqlite", "postgresql", "oracle",
		"unclosed quotation mark", "quoted string not properly terminated",
		"Microsoft OLE DB", "ODBC SQL Server", "ORA-01756",
		"syntax error", "SQLSTATE", "mysql_fetch", "pg_query",
		"valid MySQL result", "MySqlClient", "pg_exec",
		"Warning: mysql", "Fatal error: Uncaught PDOException",
		"SQL syntax.*MySQL", "valid PostgreSQL result",
		"Npgsql\\.", "PG::SyntaxError", "org.postgresql",
		"SQLite/JDBCDriver", "SQLite\\.Exception",
		"System\\.Data\\.SQLite\\.SQLiteException",
		"Unclosed quotation mark after the character string",
		"Microsoft SQL Native Client error",
	}

	for _, param := range params {
		for _, p := range payloads {
			atomic.AddInt64(&vs.Results.TotalChecks, 1)

			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set(param, p.payload)
			u.RawQuery = q.Encode()

			start := time.Now()
			resp, err := vs.get(u.String())
			elapsed := time.Since(start)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			bodyStr := string(body)

			found := false

			if p.signature == "time" {
				if elapsed > 4*time.Second {
					found = true
				}
			} else {
				for _, pattern := range sqlErrorPatterns {
					if matched, _ := regexp.MatchString("(?i)"+pattern, bodyStr); matched {
						found = true
						break
					}
				}
			}

			if found {
				vs.addFinding(Vulnerability{
					ID:          nextVulnID("SQL"),
					Title:       "SQL Injection Detected",
					Severity:    "critical",
					Category:    "A03:2021 Injection",
					CVSS:        9.8,
					CWE:         "CWE-89",
					URL:         u.String(),
					Parameter:   param,
					Evidence:    fmt.Sprintf("Payload '%s' triggered SQL error response (status %d)", p.payload, resp.StatusCode),
					Impact:      "Attacker can execute arbitrary SQL queries, read/modify/delete data, potentially achieve RCE",
					Remediation: "Use parameterized queries/prepared statements. Implement input validation and WAF rules.",
					References:  []string{"https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/89.html"},
					PoC:         fmt.Sprintf("GET %s?%s=%s", u.Path, param, url.QueryEscape(p.payload)),
				})
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 2. XSS Detection
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanXSS() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	params := []string{"q", "search", "name", "comment", "input", "text", "query", "title", "description", "redirect", "url"}
	payloads := []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`"><svg onload=alert(1)>`,
		`<body onload=alert(1)>`,
		`javascript:alert(1)`,
		`<iframe src="javascript:alert(1)">`,
		`<input onfocus=alert(1) autofocus>`,
		`<details open ontoggle=alert(1)>`,
		`"><img src=x onerror=alert(String.fromCharCode(88,83,83))>`,
		`'-alert(1)-'`,
	}

	for _, param := range params {
		for _, payload := range payloads {
			atomic.AddInt64(&vs.Results.TotalChecks, 1)

			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set(param, payload)
			u.RawQuery = q.Encode()

			resp, err := vs.get(u.String())
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			bodyStr := string(body)

			if strings.Contains(bodyStr, payload) {
				vs.addFinding(Vulnerability{
					ID:          nextVulnID("XSS"),
					Title:       "Cross-Site Scripting (XSS) Detected",
					Severity:    "high",
					Category:    "A03:2021 Injection",
					CVSS:        6.1,
					CWE:         "CWE-79",
					URL:         u.String(),
					Parameter:   param,
					Evidence:    fmt.Sprintf("Reflected payload '%s' found in response body", payload),
					Impact:      "Attacker can execute arbitrary JavaScript in victim's browser, steal session tokens, redirect users, deface websites",
					Remediation: "Implement context-aware output encoding, Content-Security-Policy header, and input validation",
					References:  []string{"https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/79.html"},
					PoC:         fmt.Sprintf("GET %s?%s=%s", u.Path, param, url.QueryEscape(payload)),
				})
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 3. Directory Traversal
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanDirectoryTraversal() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	endpoints := []string{"/", "/view", "/file", "/include", "/page", "/download", "/static", "/images"}
	payloads := []struct {
		payload  string
		signature string
	}{
		{"../../../etc/passwd", "root:"},
		{"....//....//....//etc/passwd", "root:"},
		{"..%2F..%2F..%2Fetc%2Fpasswd", "root:"},
		{"..%252f..%252f..%252fetc/passwd", "root:"},
		{"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "root:"},
		{"../../../etc/shadow", "root:"},
		{"../../../proc/self/environ", "PATH="},
		{"..\\..\\..\\etc\\passwd", "root:"},
		{"../../../win.ini", "[extensions]"},
		{"..\\..\\..\\windows\\win.ini", "[extensions]"},
	}

	for _, endpoint := range endpoints {
		for _, p := range payloads {
			atomic.AddInt64(&vs.Results.TotalChecks, 1)

			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set("file", p.payload)
			q.Set("path", p.payload)
			u.RawQuery = q.Encode()
			u.Path = endpoint

			resp, err := vs.get(u.String())
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			bodyStr := string(body)

			if strings.Contains(bodyStr, p.signature) {
				vs.addFinding(Vulnerability{
					ID:          nextVulnID("DIR"),
					Title:       "Directory Traversal / Path Traversal Detected",
					Severity:    "critical",
					Category:    "A01:2021 Broken Access Control",
					CVSS:        9.1,
					CWE:         "CWE-22",
					URL:         u.String(),
					Evidence:    fmt.Sprintf("Payload '%s' returned system file content (matched '%s')", p.payload, p.signature),
					Impact:      "Attacker can read arbitrary files on the server including /etc/passwd, application source code, credentials, and private keys",
					Remediation: "Validate and sanitize file paths, use chroot/jails, prevent path separators in user input",
					References:  []string{"https://owasp.org/Top10/A01_2021-Broken_Access_Control/", "https://cwe.mitre.org/data/definitions/22.html"},
					PoC:         fmt.Sprintf("GET %s?file=%s", u.Path, url.QueryEscape(p.payload)),
				})
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Open Redirect
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanOpenRedirect() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	redirectParams := []string{"url", "redirect", "next", "return", "continue", "dest", "destination", "redir", "redirect_url", "return_to", "checkout_url", "return_url", "go", "out"}
	payloads := []string{
		"//evil.com",
		"//evil.com/path",
		"/redirect?url=//evil.com",
		"https://evil.com",
		"//evil.com%2F.evil.com",
		`//evil.com%0aevil.com`,
	}

	for _, param := range redirectParams {
		for _, payload := range payloads {
			atomic.AddInt64(&vs.Results.TotalChecks, 1)

			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set(param, payload)
			u.RawQuery = q.Encode()

			resp, err := vs.get(u.String())
			if err != nil {
				continue
			}
			resp.Body.Close()

			location := resp.Header.Get("Location")
			if location == "" {
				continue
			}

			parsedLoc, err := url.Parse(location)
			if err != nil {
				continue
			}

			isRedirect := false
			if strings.Contains(parsedLoc.Host, "evil.com") {
				isRedirect = true
			}
			if strings.Contains(location, "evil.com") && resp.StatusCode >= 300 && resp.StatusCode < 400 {
				isRedirect = true
			}

			if isRedirect {
				vs.addFinding(Vulnerability{
					ID:          nextVulnID("REDIR"),
					Title:       "Open Redirect Vulnerability",
					Severity:    "medium",
					Category:    "A01:2021 Broken Access Control",
					CVSS:        6.1,
					CWE:         "CWE-601",
					URL:         u.String(),
					Parameter:   param,
					Evidence:    fmt.Sprintf("Parameter '%s' caused redirect to '%s' (status %d)", param, location, resp.StatusCode),
					Impact:      "Attacker can craft phishing URLs that appear legitimate, bypass open redirect filters for OAuth token theft",
					Remediation: "Validate redirect URLs against a whitelist of allowed domains, use relative URLs",
					References:  []string{"https://owasp.org/Top10/A01_2021-Broken_Access_Control/", "https://cwe.mitre.org/data/definitions/601.html"},
					PoC:         fmt.Sprintf("GET %s?%s=%s", u.Path, param, url.QueryEscape(payload)),
				})
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 5. Security Headers
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanSecurityHeaders() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	resp, err := vs.get(target)
	if err != nil {
		return
	}
	resp.Body.Close()
	atomic.AddInt64(&vs.Results.URLsChecked, 1)

	type headerCheck struct {
		name       string
		required   bool
		severity   string
		checkFunc  func(string) string
	}

	checks := []headerCheck{
		{
			name:     "Strict-Transport-Security",
			required: true,
			severity: "medium",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing HSTS header - allows HTTP downgrade attacks and SSL stripping"
				}
				return ""
			},
		},
		{
			name:     "Content-Security-Policy",
			required: true,
			severity: "medium",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing CSP header - no protection against XSS"
				}
				if strings.Contains(v, "'unsafe-inline'") || strings.Contains(v, "'unsafe-eval'") {
					return "CSP contains 'unsafe-inline' or 'unsafe-eval' - significantly weakens XSS protection"
				}
				return ""
			},
		},
		{
			name:     "X-Frame-Options",
			required: true,
			severity: "medium",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing X-Frame-Options - vulnerable to clickjacking"
				}
				return ""
			},
		},
		{
			name:     "X-Content-Type-Options",
			required: true,
			severity: "low",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing X-Content-Type-Options - MIME type sniffing possible"
				}
				return ""
			},
		},
		{
			name:     "Referrer-Policy",
			required: true,
			severity: "low",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing Referrer-Policy - sensitive URL data may leak in Referer header"
				}
				return ""
			},
		},
		{
			name:     "Permissions-Policy",
			required: false,
			severity: "low",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing Permissions-Policy - browser features not restricted"
				}
				return ""
			},
		},
	}

	for _, hc := range checks {
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		value := resp.Header.Get(hc.name)
		if msg := hc.checkFunc(value); msg != "" {
			vs.addFinding(Vulnerability{
				ID:          nextVulnID("HDR"),
				Title:       fmt.Sprintf("Missing/Weak Security Header: %s", hc.name),
				Severity:    hc.severity,
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        5.3,
				CWE:         "CWE-693",
				URL:         target,
				Evidence:    msg,
				Impact:      msg,
				Remediation: fmt.Sprintf("Add '%s' header to HTTP responses", hc.name),
				References:  []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "https://securityheaders.com/"},
			})
		}
	}

	// Server header version leak
	atomic.AddInt64(&vs.Results.TotalChecks, 1)
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		versionPattern := regexp.MustCompile(`[\d]+\.[\d]+[\d.]*`)
		if versionPattern.MatchString(serverHeader) {
			vs.addFinding(Vulnerability{
				ID:          nextVulnID("HDR"),
				Title:       "Server Header Leaks Version Information",
				Severity:    "low",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        2.6,
				CWE:         "CWE-200",
				URL:         target,
				Evidence:    fmt.Sprintf("Server header reveals: %s", serverHeader),
				Impact:      "Version info helps attackers identify known vulnerabilities for the specific server version",
				Remediation: "Remove or obfuscate version information from the Server header",
				References:  []string{"https://cwe.mitre.org/data/definitions/200.html"},
			})
		}
	}

	// X-Powered-By leak
	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		vs.addFinding(Vulnerability{
			ID:          nextVulnID("HDR"),
			Title:       "X-Powered-By Header Reveals Technology Stack",
			Severity:    "low",
			Category:    "A05:2021 Security Misconfiguration",
			CVSS:        2.6,
			CWE:         "CWE-200",
			URL:         target,
			Evidence:    fmt.Sprintf("X-Powered-By: %s", xPoweredBy),
			Impact:      "Technology fingerprinting helps attackers target known vulnerabilities",
			Remediation: "Remove the X-Powered-By header",
			References:  []string{"https://cwe.mitre.org/data/definitions/200.html"},
		})
	}
}

// ---------------------------------------------------------------------------
// 6. Information Disclosure
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanInfoDisclosure() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)

	type disclosureCheck struct {
		path     string
		title    string
		severity string
		cvss     float64
		cwe      string
		impact   string
		fix      string
		sigs     []string
	}

	checks := []disclosureCheck{
		{
			path:     "/robots.txt",
			title:    "robots.txt May Reveal Sensitive Paths",
			severity: "info",
			cvss:     0.0,
			cwe:      "CWE-200",
			impact:   "Disallowed paths may reveal admin panels, backup files, or internal endpoints",
			fix:      "Review robots.txt and ensure it does not expose sensitive paths",
			sigs:     []string{"Disallow:", "allow:", "Sitemap:"},
		},
		{
			path:     "/.env",
			title:    "Exposed .env File",
			severity: "critical",
			cvss:     9.1,
			cwe:      "CWE-200",
			impact:   "Environment variables often contain database credentials, API keys, and secrets",
			fix:      "Move .env outside web root, block access with web server configuration",
			sigs:     []string{"APP_KEY=", "DB_PASSWORD=", "API_KEY=", "SECRET=", "AWS_", "DATABASE_URL=", "MAIL_PASSWORD="},
		},
		{
			path:     "/wp-config.php.bak",
			title:    "WordPress Config Backup Exposed",
			severity: "critical",
			cvss:     9.1,
			cwe:      "CWE-200",
			impact:   "WordPress configuration contains database credentials and authentication keys",
			fix:      "Remove backup files from web-accessible directories",
			sigs:     []string{"DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"},
		},
		{
			path:     "/server-status",
			title:    "Apache Server-Status Page Exposed",
			severity: "medium",
			cvss:     5.3,
			cwe:      "CWE-200",
			impact:   "Reveals connected IPs, request rates, server load, and active connections",
			fix:      "Restrict access to server-status with IP allowlisting or disable mod_status",
			sigs:     []string{"Apache Server Status", "Server Version:", "Current Time:", "Total accesses:"},
		},
		{
			path:     "/.git/HEAD",
			title:    "Git Repository Exposed",
			severity: "critical",
			cvss:     7.5,
			cwe:      "CWE-200",
			impact:   "Attackers can clone the entire repository and extract source code, secrets, and history",
			fix:      "Block access to .git directory in web server configuration",
			sigs:     []string{"ref: refs/heads/"},
		},
		{
			path:     "/debug/",
			title:    "Debug Endpoint Exposed",
			severity: "high",
			cvss:     7.5,
			cwe:      "CWE-215",
			impact:   "Debug endpoints may expose stack traces, environment variables, and internal state",
			fix:      "Disable debug endpoints in production, restrict with authentication",
			sigs:     []string{"debug", "stack trace", "TRACE", "DEBUG", "Exception"},
		},
		{
			path:     "/api/swagger.json",
			title:    "API Documentation Exposed (Swagger/OpenAPI)",
			severity: "medium",
			cvss:     5.3,
			cwe:      "CWE-200",
			impact:   "Full API schema revealed - attackers can map all endpoints and parameters",
			fix:      "Restrict API documentation to authenticated users or internal networks",
			sigs:     []string{"swagger", "openapi", "info", "paths", "definitions"},
		},
		{
			path:     "/.git/config",
			title:    "Git Configuration Exposed",
			severity: "critical",
			cvss:     7.5,
			cwe:      "CWE-200",
			impact:   "Reveals repository URLs, user names, and remote configurations",
			fix:      "Block access to .git directory in web server configuration",
			sigs:     []string{"[core]", "repositoryformatversion", "[remote"},
		},
		{
			path:     "/.svn/entries",
			title:    "SVN Repository Exposed",
			severity: "high",
			cvss:     7.5,
			cwe:      "CWE-200",
			impact:   "SVN metadata reveals source code structure and revision history",
			fix:      "Block access to .svn directory",
			sigs:     []string{"svn:", "dir", "file"},
		},
		{
			path:     "/composer.json",
			title:    "Composer Dependencies Exposed",
			severity: "low",
			cvss:     3.1,
			cwe:      "CWE-200",
			impact:   "Reveals PHP dependencies and versions, aiding vulnerability research",
			fix:      "Move composer.json outside web root or block access",
			sigs:     []string{"require", "autoload", "php"},
		},
		{
			path:     "/package.json",
			title:    "Node.js package.json Exposed",
			severity: "low",
			cvss:     3.1,
			cwe:      "CWE-200",
			impact:   "Reveals Node.js dependencies, scripts, and project configuration",
			fix:      "Move package.json outside web root or block access",
			sigs:     []string{"\"dependencies\"", "\"scripts\"", "\"devDependencies\""},
		},
		{
			path:     "/web.config",
			title:    "IIS Web.config Exposed",
			severity: "high",
			cvss:     7.5,
			cwe:      "CWE-200",
			impact:   "May contain connection strings, app settings, and machine keys",
			fix:      "Restrict access to web.config in IIS configuration",
			sigs:     []string{"connectionStrings", "appSettings", "system.web"},
		},
	}

	for _, check := range checks {
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		checkURL := target + check.path
		resp, err := vs.get(checkURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		bodyStr := string(body)

		if resp.StatusCode == 200 {
			for _, sig := range check.sigs {
				if strings.Contains(bodyStr, sig) || strings.Contains(strings.ToLower(bodyStr), strings.ToLower(sig)) {
					vs.addFinding(Vulnerability{
						ID:          nextVulnID("INFO"),
						Title:       check.title,
						Severity:    check.severity,
						Category:    "A05:2021 Security Misconfiguration",
						CVSS:        check.cvss,
						CWE:         check.cwe,
						URL:         checkURL,
						Evidence:    fmt.Sprintf("HTTP 200 at %s with content matching '%s'", check.path, sig),
						Impact:      check.impact,
						Remediation: check.fix,
						References:  []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"},
					})
					break
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 7. Default Credentials
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanDefaultCredentials() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)

	type credPair struct {
		username string
		password string
	}

	creds := []credPair{
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "1234"},
		{"admin", "admin123"},
		{"admin", ""},
		{"root", "root"},
		{"root", "toor"},
		{"root", "password"},
		{"root", ""},
		{"administrator", "administrator"},
		{"test", "test"},
		{"guest", "guest"},
		{"user", "user"},
		{"demo", "demo"},
	}

	loginEndpoints := []string{"/login", "/admin/login", "/wp-login.php", "/wp-admin/", "/administrator/", "/auth/login", "/signin", "/api/login", "/user/login"}

	for _, endpoint := range loginEndpoints {
		for _, cred := range creds {
			atomic.AddInt64(&vs.Results.TotalChecks, 1)

			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			u.Path = endpoint

			formData := url.Values{
				"username": {cred.username},
				"password": {cred.password},
				"user":     {cred.username},
				"pass":     {cred.password},
				"email":    {cred.username},
			}

			resp, err := vs.postForm(u.String(), formData, nil)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			bodyStr := string(body)

			// Check for successful login indicators
			isLoginSuccess := false
			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				successIndicators := []string{"dashboard", "welcome", "profile", "logout", "account", "settings"}
				failureIndicators := []string{"invalid", "incorrect", "wrong", "failed", "error", "denied", "unauthorized", "forbidden"}

				hasSuccess := false
				for _, ind := range successIndicators {
					if strings.Contains(strings.ToLower(bodyStr), ind) {
						hasSuccess = true
						break
					}
				}

				hasFailure := false
				for _, ind := range failureIndicators {
					if strings.Contains(strings.ToLower(bodyStr), ind) {
						hasFailure = true
						break
					}
				}

				if hasSuccess && !hasFailure {
					isLoginSuccess = true
				}
			}

			if isLoginSuccess && cred.password != "" {
				vs.addFinding(Vulnerability{
					ID:          nextVulnID("AUTH"),
					Title:       "Default Credentials Accepted",
					Severity:    "critical",
					Category:    "A07:2021 Identification and Authentication Failures",
					CVSS:        9.8,
					CWE:         "CWE-798",
					URL:         u.String(),
					Parameter:   fmt.Sprintf("username=%s&password=%s", cred.username, cred.password),
					Evidence:    fmt.Sprintf("Login with %s/%s returned HTTP %d with success indicators", cred.username, cred.password, resp.StatusCode),
					Impact:      "Full unauthorized access to the application as an authenticated user",
					Remediation: "Change default credentials immediately, enforce strong password policies",
					References:  []string{"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/", "https://cwe.mitre.org/data/definitions/798.html"},
					PoC:         fmt.Sprintf("POST %s with username=%s&password=%s", endpoint, cred.username, cred.password),
				})
				return
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 8. API Security
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanAPISecurity() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)

	// Check common API endpoints
	apiPaths := []string{
		"/api/", "/api/v1/", "/api/v2/", "/api/users",
		"/api/admin/", "/graphql", "/api/config", "/api/debug",
	}

	for _, path := range apiPaths {
		atomic.AddInt64(&vs.Results.TotalChecks, 1)

		u, err := url.Parse(target)
		if err != nil {
			continue
		}
		u.Path = path

		resp, err := vs.get(u.String())
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		// Check for excessive data exposure
		vs.checkSensitiveExposure(u.String(), body)

		// Check for mass assignment — send extra params and see if accepted
		if resp.StatusCode == 200 || resp.StatusCode == 405 {
			extraParams := url.Values{
				"admin":       {"true"},
				"role":        {"admin"},
				"is_admin":    {"1"},
				"privileged":  {"true"},
				"permissions": {"all"},
			}
			baselineResp, err := vs.postForm(u.String(), url.Values{}, nil)
			if err != nil {
				continue
			}
			baselineBody, _ := io.ReadAll(io.LimitReader(baselineResp.Body, 1<<20))
			baselineResp.Body.Close()

			massResp, err := vs.postForm(u.String(), extraParams, nil)
			if err == nil {
				massBody, _ := io.ReadAll(io.LimitReader(massResp.Body, 1<<20))
				massResp.Body.Close()
				if massResp.StatusCode == 200 && len(massBody) > 0 &&
					(massResp.StatusCode != baselineResp.StatusCode || !strings.EqualFold(string(massBody), string(baselineBody))) {
					vs.addFinding(Vulnerability{
						ID:          nextVulnID("API"),
						Title:       "Possible Mass Assignment Vulnerability",
						Severity:    "medium",
						Category:    "A04:2021 Insecure Design",
						CVSS:        5.3,
						CWE:         "CWE-915",
						URL:         u.String(),
						Evidence:    fmt.Sprintf("POST with extra privileged parameters accepted (HTTP %d), response differs from baseline", massResp.StatusCode),
						Impact:      "Attacker may escalate privileges by setting admin=true or role=admin in requests",
						Remediation: "Use allow-lists for bindable parameters, implement DTOs, validate all input",
						References:  []string{"https://owasp.org/Top10/A04_2021-Insecure_Design/", "https://cwe.mitre.org/data/definitions/915.html"},
					})
				}
			}
		}
	}

	// BOLA/IDOR check — try changing IDs in common patterns
	idEndpoints := []string{
		"/api/users/1", "/api/users/2",
		"/api/v1/users/1", "/api/v1/users/2",
		"/api/orders/1", "/api/orders/2",
		"/api/profile/1", "/api/profile/2",
	}

	for i := 0; i < len(idEndpoints)-1; i += 2 {
		atomic.AddInt64(&vs.Results.TotalChecks, 1)

		u1, err1 := url.Parse(target + idEndpoints[i])
		u2, err2 := url.Parse(target + idEndpoints[i+1])
		if err1 != nil || err2 != nil {
			continue
		}

		resp1, err1 := vs.get(u1.String())
		if err1 != nil {
			continue
		}
		body1, _ := io.ReadAll(io.LimitReader(resp1.Body, 1<<20))
		resp1.Body.Close()

		resp2, err2 := vs.get(u2.String())
		if err2 != nil {
			continue
		}
		body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
		resp2.Body.Close()

		if resp1.StatusCode == 200 && resp2.StatusCode == 200 && len(body1) > 0 && len(body2) > 0 {
			vs.checkSensitiveExposure(u1.String(), body1)
			vs.checkSensitiveExposure(u2.String(), body2)

			if !strings.EqualFold(string(body1), string(body2)) {
				vs.addFinding(Vulnerability{
					ID:          nextVulnID("API"),
					Title:       "Potential BOLA/IDOR Vulnerability",
					Severity:    "high",
					Category:    "A01:2021 Broken Access Control",
					CVSS:        7.5,
					CWE:         "CWE-639",
					URL:         fmt.Sprintf("%s vs %s", u1.String(), u2.String()),
					Evidence:    fmt.Sprintf("Sequential IDs return different data (resp1: %d bytes, resp2: %d bytes)", len(body1), len(body2)),
					Impact:      "Attacker can access other users' data by incrementing IDs",
					Remediation: "Implement object-level authorization checks, use UUIDs instead of sequential IDs",
					References:  []string{"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/", "https://cwe.mitre.org/data/definitions/639.html"},
				})
			}
		}
	}

	// Missing rate limiting
	atomic.AddInt64(&vs.Results.TotalChecks, 1)
	u, _ := url.Parse(target)
	u.Path = "/api/"
	rateLimitSuccess := 0
	for i := 0; i < 20; i++ {
		resp, err := vs.get(u.String())
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != 429 {
			rateLimitSuccess++
		}
	}
	if rateLimitSuccess == 20 {
		vs.addFinding(Vulnerability{
			ID:          nextVulnID("API"),
			Title:       "Missing Rate Limiting",
			Severity:    "medium",
			Category:    "A05:2021 Security Misconfiguration",
			CVSS:        5.3,
			CWE:         "CWE-770",
			URL:         u.String(),
			Evidence:    "20 rapid requests returned no 429 (Too Many Requests) responses",
			Impact:      "Application vulnerable to brute force, credential stuffing, and denial of service",
			Remediation: "Implement rate limiting with exponential backoff, use WAF or API gateway rate limits",
			References:  []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "https://cwe.mitre.org/data/definitions/770.html"},
		})
	}
}

// checkSensitiveExposure flags API responses that leak sensitive fields
func (vs *VulnScanner) checkSensitiveExposure(targetURL string, body []byte) {
	bodyStr := string(body)

	// Only structured data (JSON) counts — avoid false positives on HTML login pages
	if !strings.Contains(bodyStr, "{") && !strings.Contains(bodyStr, "[") {
		return
	}

	sensitivePatterns := []string{
		"password", "token", "secret", "api_key", "apikey",
		"credit_card", "ssn", "social_security",
	}
	for _, pattern := range sensitivePatterns {
		if strings.Contains(strings.ToLower(bodyStr), pattern) {
			vs.addFinding(Vulnerability{
				ID:          nextVulnID("API"),
				Title:       "Excessive Data Exposure in API Response",
				Severity:    "high",
				Category:    "A02:2021 Cryptographic Failures",
				CVSS:        7.5,
				CWE:         "CWE-200",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("API response (%d bytes) contains sensitive pattern '%s'", len(body), pattern),
				Impact:      "Sensitive data returned to unauthorized users via API responses",
				Remediation: "Implement response filtering, use DTOs, apply field-level authorization",
				References:  []string{"https://owasp.org/API-Security/editions/2023/en/0xa2-broken-object-level-authorization/", "https://cwe.mitre.org/data/definitions/200.html"},
			})
			return
		}
	}
}

// ---------------------------------------------------------------------------
// 9. Cookie Security
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanCookies() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	resp, err := vs.get(target)
	if err != nil {
		return
	}
	resp.Body.Close()
	atomic.AddInt64(&vs.Results.URLsChecked, 1)

	cookies := resp.Cookies()
	for _, cookie := range cookies {
		// Check Secure flag
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		if !cookie.Secure {
			vs.addFinding(Vulnerability{
				ID:          nextVulnID("CK"),
				Title:       fmt.Sprintf("Cookie '%s' Missing Secure Flag", cookie.Name),
				Severity:    "low",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        3.7,
				CWE:         "CWE-614",
				URL:         target,
				Parameter:   cookie.Name,
				Evidence:    fmt.Sprintf("Cookie '%s' set without Secure flag", cookie.Name),
				Impact:      "Cookie transmitted over unencrypted HTTP connections, susceptible to interception",
				Remediation: "Set the Secure flag on all cookies: Set-Cookie: ...; Secure",
				References:  []string{"https://cwe.mitre.org/data/definitions/614.html", "https://owasp.org/www-community/controls/SecureCookieAttribute"},
			})
		}

		// Check HttpOnly flag
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		if !cookie.HttpOnly {
			vs.addFinding(Vulnerability{
				ID:          nextVulnID("CK"),
				Title:       fmt.Sprintf("Cookie '%s' Missing HttpOnly Flag", cookie.Name),
				Severity:    "medium",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        4.7,
				CWE:         "CWE-1004",
				URL:         target,
				Parameter:   cookie.Name,
				Evidence:    fmt.Sprintf("Cookie '%s' set without HttpOnly flag", cookie.Name),
				Impact:      "JavaScript can access the cookie, enabling session theft via XSS",
				Remediation: "Set the HttpOnly flag on all cookies: Set-Cookie: ...; HttpOnly",
				References:  []string{"https://cwe.mitre.org/data/definitions/1004.html", "https://owasp.org/www-community/controls/HttpOnly"},
			})
		}

		// Check SameSite
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		if cookie.SameSite == http.SameSiteNoneMode {
			vs.addFinding(Vulnerability{
				ID:          nextVulnID("CK"),
				Title:       fmt.Sprintf("Cookie '%s' SameSite=None", cookie.Name),
				Severity:    "low",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        3.1,
				CWE:         "CWE-1275",
				URL:         target,
				Parameter:   cookie.Name,
				Evidence:    fmt.Sprintf("Cookie '%s' has SameSite=None, vulnerable to CSRF in older browsers", cookie.Name),
				Impact:      "Cookie sent with cross-origin requests, enabling CSRF attacks",
				Remediation: "Set SameSite=Lax or SameSite=Strict on sensitive cookies",
				References:  []string{"https://cwe.mitre.org/data/definitions/1275.html", "https://owasp.org/www-community/SameSite"},
			})
		}

		// Session cookie without expiry
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		nameLower := strings.ToLower(cookie.Name)
		isSessionCookie := strings.Contains(nameLower, "session") || strings.Contains(nameLower, "sid") ||
			strings.Contains(nameLower, "token") || strings.Contains(nameLower, "auth")
		if isSessionCookie && cookie.Expires.IsZero() && cookie.MaxAge == 0 {
			// Session cookie - no persistent expiry, which is actually good
		} else if isSessionCookie && !cookie.Expires.IsZero() && cookie.Expires.Sub(time.Now()) > 24*time.Hour {
			vs.addFinding(Vulnerability{
				ID:          nextVulnID("CK"),
				Title:       fmt.Sprintf("Session Cookie '%s' Has Long Expiry", cookie.Name),
				Severity:    "low",
				Category:    "A07:2021 Identification and Authentication Failures",
				CVSS:        3.1,
				CWE:         "CWE-613",
				URL:         target,
				Parameter:   cookie.Name,
				Evidence:    fmt.Sprintf("Session cookie '%s' expires at %s (> 24h)", cookie.Name, cookie.Expires.Format(time.RFC3339)),
				Impact:      "Long-lived session tokens increase the window of opportunity for session hijacking",
				Remediation: "Set short session expiry times and implement session rotation",
				References:  []string{"https://cwe.mitre.org/data/definitions/613.html"},
			})
		}
	}
}

// ---------------------------------------------------------------------------
// 10. CORS Misconfiguration
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanCORS() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	atomic.AddInt64(&vs.Results.TotalChecks, 1)

	// Test with various Origin headers
	origins := []string{
		"https://evil.com",
		"http://evil.com",
		"https://evil.com.attacker.com",
		"https://attacker.com%0aevil.com",
		"null",
	}

	foundWildcard := false
	foundReflection := false
	foundNull := false
	foundCreds := false

	for _, origin := range origins {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("User-Agent", "stress-strike-vulnscanner/1.0")

		resp, err := vs.Client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if acao == "" {
			continue
		}

		if acac == "true" && !foundCreds {
			foundCreds = true
			vs.addFinding(Vulnerability{
				ID:          nextVulnID("CORS"),
				Title:       "CORS Credentials Allowed with Permissive Origin",
				Severity:    "medium",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        5.3,
				CWE:         "CWE-942",
				URL:         target,
				Evidence:    fmt.Sprintf("Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: %s", acao),
				Impact:      "Browsers will send cookies/credentials with cross-origin requests to this origin",
				Remediation: "Never combine Access-Control-Allow-Credentials: true with wildcard or reflected origins",
				References:  []string{"https://cwe.mitre.org/data/definitions/942.html"},
			})
		}

		switch {
		case acao == "*" && !foundWildcard:
			foundWildcard = true
			vs.addFinding(Vulnerability{
				ID:          nextVulnID("CORS"),
				Title:       "CORS Wildcard Origin Allowed",
				Severity:    "medium",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        5.3,
				CWE:         "CWE-942",
				URL:         target,
				Evidence:    "Access-Control-Allow-Origin: * — accepts requests from any origin",
				Impact:      "Any website can make cross-origin requests to this API",
				Remediation: "Restrict CORS to specific trusted origins",
				References:  []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "https://cwe.mitre.org/data/definitions/942.html"},
			})

		case acao == origin && origin != "null" && !foundReflection:
			foundReflection = true
			vs.addFinding(Vulnerability{
				ID:          nextVulnID("CORS"),
				Title:       "CORS Origin Reflection Vulnerability",
				Severity:    "high",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        7.5,
				CWE:         "CWE-942",
				URL:         target,
				Evidence:    fmt.Sprintf("Request with Origin '%s' returned Access-Control-Allow-Origin: %s", origin, acao),
				Impact:      "Attacker-controlled origin is reflected in CORS headers, enabling credential theft",
				Remediation: "Validate Origin against a whitelist before reflecting it in CORS headers",
				References:  []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "https://cwe.mitre.org/data/definitions/942.html"},
			})

		case acao == "null" && origin == "null" && !foundNull:
			foundNull = true
			vs.addFinding(Vulnerability{
				ID:          nextVulnID("CORS"),
				Title:       "CORS Allows 'null' Origin",
				Severity:    "medium",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        5.3,
				CWE:         "CWE-942",
				URL:         target,
				Evidence:    "Access-Control-Allow-Origin: null — allows sandboxed iframe requests",
				Impact:      "Attacker can use sandboxed iframes to make authenticated cross-origin requests",
				Remediation: "Remove 'null' from the CORS origin whitelist",
				References:  []string{"https://cwe.mitre.org/data/definitions/942.html"},
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Report Compilation
// ---------------------------------------------------------------------------

func (vs *VulnScanner) compileReport(report *VulnReport) {
	// Calculate risk score from findings; a preset RiskScore with no findings
	// is honored so callers can re-derive only the grade for a given score.
	totalFindings := len(report.Critical) + len(report.High) + len(report.Medium) +
		len(report.Low) + len(report.Info)

	score := 100
	switch {
	case totalFindings > 0:
		score -= len(report.Critical) * 20
		score -= len(report.High) * 12
		score -= len(report.Medium) * 5
		score -= len(report.Low) * 2
		score -= len(report.Info) * 1
	case report.RiskScore > 0:
		score = report.RiskScore
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	report.RiskScore = score

	// Grade
	switch {
	case score >= 90:
		report.Grade = "A"
	case score >= 80:
		report.Grade = "B"
	case score >= 70:
		report.Grade = "C"
	case score >= 50:
		report.Grade = "D"
	default:
		report.Grade = "F"
	}

	// Sort each severity bucket
	sortVulns(report.Critical)
	sortVulns(report.High)
	sortVulns(report.Medium)
	sortVulns(report.Low)
	sortVulns(report.Info)

	// Sort OWASP categories
	for cat := range report.OWASP {
		sortVulns(report.OWASP[cat])
	}
}

func sortVulns(vulns []Vulnerability) {
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].CVSS > vulns[j].CVSS
	})
}
