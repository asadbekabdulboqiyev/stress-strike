package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// OWASPChecker performs automated OWASP Top 10 checks
type OWASPChecker struct {
	Target    string
	Client    *http.Client
	Results   *OWASPReport
	Transport *http.Transport
}

// OWASPReport contains results for all 10 categories
type OWASPReport struct {
	Categories map[string]*OWASPCategory
	Score      int    // 0-100 (100 = fully compliant)
	Grade      string // A-F
}

// OWASPCategory represents one OWASP category
type OWASPCategory struct {
	ID          string
	Name        string
	Status      string // PASS, WARNING, FAIL
	Score       int    // 0-100
	Findings    []string
	Remediation []string
}

var owaspCategories = map[string]string{
	"A01": "Broken Access Control",
	"A02": "Cryptographic Failures",
	"A03": "Injection",
	"A04": "Insecure Design",
	"A05": "Security Misconfiguration",
	"A06": "Vulnerable and Outdated Components",
	"A07": "Identification and Authentication Failures",
	"A08": "Software and Data Integrity Failures",
	"A09": "Security Logging and Monitoring Failures",
	"A10": "Server-Side Request Forgery (SSRF)",
}

// NewOWASPChecker creates a new OWASP checker for the given target.
//
// NOTE: TLS certificate verification is intentionally disabled
// (InsecureSkipVerify) because pentest targets frequently use self-signed,
// expired, or internally-CA-signed certificates that must still be audited.
// This is standard behavior for security scanners (nmap, Nessus, Burp).
// Only use against targets you are authorized to test.
func NewOWASPChecker(target string) *OWASPChecker {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &OWASPChecker{
		Target:    target,
		Client:    client,
		Transport: transport,
	}
}

// CheckAll runs all OWASP Top 10 checks and returns the report
func (c *OWASPChecker) CheckAll() *OWASPReport {
	report := &OWASPReport{
		Categories: make(map[string]*OWASPCategory),
	}

	report.Categories["A01"] = c.checkA01()
	report.Categories["A02"] = c.checkA02()
	report.Categories["A03"] = c.checkA03()
	report.Categories["A04"] = c.checkA04()
	report.Categories["A05"] = c.checkA05()
	report.Categories["A06"] = c.checkA06()
	report.Categories["A07"] = c.checkA07()
	report.Categories["A08"] = c.checkA08()
	report.Categories["A09"] = c.checkA09()
	report.Categories["A10"] = c.checkA10()

	report.Score = c.CalculateScore(report)
	report.Grade = c.calculateGrade(report.Score)

	c.Results = report
	return report
}

func (c *OWASPChecker) newCategory(id string) *OWASPCategory {
	return &OWASPCategory{
		ID:          id,
		Name:        owaspCategories[id],
		Status:      "PASS",
		Score:       100,
		Findings:    make([]string, 0),
		Remediation: make([]string, 0),
	}
}

func (c *OWASPChecker) addFinding(cat *OWASPCategory, finding, remediation, severity string) {
	cat.Findings = append(cat.Findings, fmt.Sprintf("[%s] %s", strings.ToUpper(severity), finding))
	cat.Remediation = append(cat.Remediation, remediation)

	switch severity {
	case "critical":
		cat.Score -= 30
	case "high":
		cat.Score -= 20
	case "medium":
		cat.Score -= 10
	case "low":
		cat.Score -= 5
	}

	if cat.Score < 0 {
		cat.Score = 0
	}

	if cat.Score <= 30 {
		cat.Status = "FAIL"
	} else if cat.Score <= 70 {
		cat.Status = "WARNING"
	} else {
		cat.Status = "PASS"
	}
}

func (c *OWASPChecker) makeRequest(method, path string, headers http.Header, body io.Reader) (*http.Response, string) {
	u, err := url.Parse(c.Target)
	if err != nil {
		return nil, ""
	}

	if idx := strings.Index(path, "?"); idx != -1 {
		u.Path = path[:idx]
		u.RawQuery = path[idx+1:]
	} else {
		u.Path = path
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, ""
	}

	req.Header.Set("User-Agent", "stress-strike-owasp/1.0")
	if headers != nil {
		for k, vs := range headers {
			for _, v := range vs {
				req.Header.Set(k, v)
			}
		}
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, ""
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	resp.Body.Close()

	return resp, string(respBody)
}

// --- A01: Broken Access Control ---

func (c *OWASPChecker) checkA01() *OWASPCategory {
	cat := c.newCategory("A01")

	// Test IDOR: access different user IDs without auth
	idorPaths := []string{"/api/users/1", "/api/users/2", "/api/users/3"}
	responses := make([]int, 0)
	for _, p := range idorPaths {
		resp, _ := c.makeRequest("GET", p, nil, nil)
		if resp != nil {
			responses = append(responses, resp.StatusCode)
		}
	}
	if len(responses) > 0 {
		allSame := true
		for _, s := range responses {
			if s != responses[0] {
				allSame = false
				break
			}
		}
		if allSame && responses[0] == 200 {
			c.addFinding(cat,
				"Potential IDOR: multiple user endpoints return 200 without authentication",
				"Implement proper authorization checks on all API endpoints",
				"high")
		}
	}

	// Test admin endpoints without auth
	adminPaths := []string{"/admin", "/admin/dashboard", "/api/admin", "/wp-admin", "/administrator"}
	for _, p := range adminPaths {
		resp, body := c.makeRequest("GET", p, nil, nil)
		if resp != nil && resp.StatusCode == 200 {
			lowerBody := strings.ToLower(body)
			if strings.Contains(lowerBody, "dashboard") || strings.Contains(lowerBody, "admin panel") ||
				strings.Contains(lowerBody, "welcome") || strings.Contains(lowerBody, "control panel") {
				c.addFinding(cat,
					fmt.Sprintf("Admin endpoint accessible without auth: %s", p),
					"Restrict admin endpoints to authenticated and authorized users only",
					"critical")
				break
			}
		}
	}

	// Test CORS misconfiguration
	resp, _ := c.makeRequest("GET", "/", http.Header{
		"Origin": {"https://evil.com"},
	}, nil)
	if resp != nil {
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		if acao == "*" || acao == "https://evil.com" {
			c.addFinding(cat,
				fmt.Sprintf("Permissive CORS: Access-Control-Allow-Origin = %s", acao),
				"Restrict CORS to specific trusted origins",
				"medium")
		}
	}

	// Test directory listing
	listPaths := []string{"/images", "/static", "/assets", "/uploads", "/files"}
	for _, p := range listPaths {
		resp, body := c.makeRequest("GET", p, nil, nil)
		if resp != nil && resp.StatusCode == 200 {
			lowerBody := strings.ToLower(body)
			if strings.Contains(lowerBody, "index of") || strings.Contains(lowerBody, "<title>directory listing") {
				c.addFinding(cat,
					fmt.Sprintf("Directory listing enabled at %s", p),
					"Disable directory listing in web server configuration",
					"medium")
				break
			}
		}
	}

	return cat
}

// --- A02: Cryptographic Failures ---

func (c *OWASPChecker) checkA02() *OWASPCategory {
	cat := c.newCategory("A02")

	// Check HTTPS enforcement
	httpTarget := c.Target
	if !strings.HasPrefix(httpTarget, "http") {
		httpTarget = "http://" + httpTarget
	}

	noRedirectClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", httpTarget, nil)
	if err == nil {
		resp, err := noRedirectClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 301 && resp.StatusCode != 302 &&
				resp.StatusCode != 307 && resp.StatusCode != 308 {
				c.addFinding(cat,
					"HTTP does not redirect to HTTPS",
					"Configure HTTP to HTTPS redirect (301/308 permanent)",
					"high")
			}
		}
	}

	// Check HSTS header
	httpsTarget := strings.Replace(httpTarget, "http://", "https://", 1)
	resp, pageBody := c.makeRequest("GET", "/", nil, nil)
	if resp != nil {
		hsts := resp.Header.Get("Strict-Transport-Security")
		if hsts == "" {
			c.addFinding(cat,
				"HSTS header missing",
				"Add Strict-Transport-Security header with max-age >= 31536000",
				"high")
		} else {
			re := regexp.MustCompile(`max-age=(\d+)`)
			matches := re.FindStringSubmatch(hsts)
			if len(matches) > 1 {
				maxAge, _ := strconv.Atoi(matches[1])
				if maxAge < 31536000 {
					c.addFinding(cat,
						fmt.Sprintf("HSTS max-age too low: %d (minimum 31536000)", maxAge),
						"Increase HSTS max-age to at least 31536000 (1 year)",
						"medium")
				}
			}
		}

		// Check mixed content (body already read by makeRequest)
		if strings.Contains(httpsTarget, "https://") {
			httpRefs := regexp.MustCompile(`src=["']http://`).FindAllString(pageBody, -1)
			if len(httpRefs) > 0 {
				c.addFinding(cat,
					fmt.Sprintf("Mixed content detected: %d HTTP resources on HTTPS page", len(httpRefs)),
					"Use HTTPS for all resources or use protocol-relative URLs",
					"medium")
			}
		}
	}

	// Check TLS version (try connecting with deprecated versions)
	host := c.extractHost()
	port := c.extractPort()
	if host != "" && port > 0 {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		for _, tv := range []struct {
			name string
			min  uint16
			max  uint16
		}{
			{"TLS 1.0", tls.VersionTLS10, tls.VersionTLS10},
			{"TLS 1.1", tls.VersionTLS11, tls.VersionTLS11},
		} {
			config := &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tv.min,
				MaxVersion:         tv.max,
			}
			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: 5 * time.Second},
				"tcp", addr, config,
			)
			if err == nil {
				conn.Close()
				c.addFinding(cat,
					fmt.Sprintf("Deprecated TLS version supported: %s", tv.name),
					fmt.Sprintf("Disable %s and enforce TLS 1.2 or higher", tv.name),
					"high")
			}
		}
	}

	return cat
}

// --- A03: Injection ---

func (c *OWASPChecker) checkA03() *OWASPCategory {
	cat := c.newCategory("A03")

	// SQL Injection
	sqlPayloads := []struct {
		param   string
		payload string
		pattern string
	}{
		{"id", "1' OR '1'=",
			"(sql syntax|mysql|ora-|postgresql|sqlite|unclosed quotation|quoted string not properly terminated)"},
		{"search", "' UNION SELECT NULL--",
			"(sql syntax|mysql|ora-|postgresql|sqlite|column|table)"},
		{"q", "1; SELECT 1",
			"(sql syntax|mysql|ora-|postgresql|sqlite)"},
		{"user", "admin'--",
			"(sql syntax|mysql|ora-|postgresql|sqlite|welcome|dashboard)"},
	}

	for _, sp := range sqlPayloads {
		resp, body := c.makeRequest("GET",
			fmt.Sprintf("/?%s=%s", sp.param, url.QueryEscape(sp.payload)),
			nil, nil)
		if resp != nil {
			bodyLower := strings.ToLower(body)
			re := regexp.MustCompile(sp.pattern)
			if re.MatchString(bodyLower) {
				c.addFinding(cat,
					fmt.Sprintf("SQL Injection in parameter '%s': error/message exposed", sp.param),
					"Use parameterized queries/prepared statements. Never concatenate user input into SQL",
					"critical")
				break
			}
		}
	}

	// XSS
	xssPayloads := []struct {
		param   string
		payload string
	}{
		{"q", "<script>alert(1)</script>"},
		{"name", "<img src=x onerror=alert(1)>"},
		{"input", "'-alert(1)-'"},
		{"ref", "<svg/onload=alert(1)>"},
	}

	for _, xp := range xssPayloads {
		resp, body := c.makeRequest("GET",
			fmt.Sprintf("/?%s=%s", xp.param, url.QueryEscape(xp.payload)),
			nil, nil)
		if resp != nil && strings.Contains(body, xp.payload) {
			c.addFinding(cat,
				fmt.Sprintf("Reflected XSS in parameter '%s': payload reflected in response", xp.param),
				"Implement output encoding/escaping and Content-Security-Policy header",
				"high")
			break
		}
	}

	// Command Injection
	cmdPayloads := []struct {
		param   string
		payload string
		pattern string
	}{
		{"host", "127.0.0.1; ls",
			"(root|bin|etc|usr|var)"},
		{"ip", "127.0.0.1|cat /etc/passwd",
			"(root:.:0:0)"},
		{"cmd", "; id",
			"(uid=|gid=)"},
	}

	for _, cp := range cmdPayloads {
		resp, body := c.makeRequest("GET",
			fmt.Sprintf("/?%s=%s", cp.param, url.QueryEscape(cp.payload)),
			nil, nil)
		if resp != nil {
			re := regexp.MustCompile(cp.pattern)
			if re.MatchString(body) {
				c.addFinding(cat,
					fmt.Sprintf("OS Command Injection in parameter '%s'", cp.param),
					"Never pass user input to system commands. Use safe APIs instead",
					"critical")
				break
			}
		}
	}

	// LDAP Injection
	ldapPayloads := []string{"*()|&'", "*)(objectClass=*"}
	for _, lp := range ldapPayloads {
		resp, body := c.makeRequest("GET",
			fmt.Sprintf("/?user=%s", url.QueryEscape(lp)),
			nil, nil)
		if resp != nil {
			bodyLower := strings.ToLower(body)
			if strings.Contains(bodyLower, "ldap") || strings.Contains(bodyLower, "bind") ||
				strings.Contains(bodyLower, "dn:") {
				c.addFinding(cat,
					"LDAP Injection possible in authentication parameter",
					"Use parameterized LDAP queries and validate/escape user input",
					"high")
				break
			}
		}
	}

	// NoSQL Injection
	nosqlPayloads := []string{
		`{"username": {"$gt": ""}, "password": {"$gt": ""}}`,
		`{"$ne": ""}`,
	}

	for _, np := range nosqlPayloads {
		headers := http.Header{"Content-Type": {"application/json"}}
		resp, body := c.makeRequest("POST", "/api/login",
			headers, strings.NewReader(np))
		if resp != nil && resp.StatusCode == 200 {
			bodyLower := strings.ToLower(body)
			if strings.Contains(bodyLower, "token") || strings.Contains(bodyLower, "success") ||
				strings.Contains(bodyLower, "welcome") || strings.Contains(bodyLower, "dashboard") {
				c.addFinding(cat,
					"NoSQL Injection: authentication bypass via NoSQL operator",
					"Validate input types, use strict queries, and reject unexpected types",
					"critical")
				break
			}
		}
	}

	return cat
}

// --- A04: Insecure Design ---

func (c *OWASPChecker) checkA04() *OWASPCategory {
	cat := c.newCategory("A04")

	// Rate limiting test: send rapid requests
	allowedCount := 0
	for i := 0; i < 50; i++ {
		resp, _ := c.makeRequest("GET", "/", nil, nil)
		if resp != nil && resp.StatusCode == 200 {
			allowedCount++
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
	if allowedCount == 50 {
		c.addFinding(cat,
			"No rate limiting detected: 50/50 rapid requests succeeded",
			"Implement rate limiting (e.g., 100 requests/minute per IP)",
			"medium")
	}

	// Business logic: test price manipulation in POST
	payloads := []string{
		`{"item":"test","price":-1}`,
		`{"item":"test","price":0}`,
		`{"item":"test","discount":999}`,
	}
	for _, p := range payloads {
		resp, body := c.makeRequest("POST", "/api/order",
			http.Header{"Content-Type": {"application/json"}},
			strings.NewReader(p))
		if resp != nil && resp.StatusCode == 200 {
			bodyLower := strings.ToLower(body)
			if strings.Contains(bodyLower, "success") || strings.Contains(bodyLower, "created") ||
				strings.Contains(bodyLower, "confirmed") {
				c.addFinding(cat,
					"Business logic flaw: order with manipulated price accepted",
					"Validate all business logic server-side. Never trust client-side price/quantity",
					"high")
				break
			}
		}
	}

	// Function-level access control: test common admin endpoints without auth
	adminAPIs := []string{
		"/api/admin/users",
		"/api/admin/config",
		"/api/internal/debug",
		"/api/v1/admin/settings",
	}
	for _, api := range adminAPIs {
		resp, body := c.makeRequest("GET", api, nil, nil)
		if resp != nil && resp.StatusCode == 200 {
			bodyLower := strings.ToLower(body)
			if strings.Contains(bodyLower, "user") || strings.Contains(bodyLower, "admin") ||
				strings.Contains(bodyLower, "config") || strings.Contains(bodyLower, "setting") {
				c.addFinding(cat,
					fmt.Sprintf("Function-level access control missing: %s accessible without auth", api),
					"Enforce authorization checks on every function/endpoint",
					"high")
				break
			}
		}
	}

	return cat
}

// --- A05: Security Misconfiguration ---

func (c *OWASPChecker) checkA05() *OWASPCategory {
	cat := c.newCategory("A05")

	// Default credentials
	defaultCreds := []struct {
		user string
		pass string
	}{
		{"admin", "admin"},
		{"admin", "password"},
		{"root", "root"},
		{"admin", "123456"},
		{"test", "test"},
	}

	for _, dc := range defaultCreds {
		loginData := fmt.Sprintf(`{"username":"%s","password":"%s"}`, dc.user, dc.pass)
		resp, body := c.makeRequest("POST", "/api/login",
			http.Header{"Content-Type": {"application/json"}},
			strings.NewReader(loginData))
		if resp != nil && resp.StatusCode == 200 {
			bodyLower := strings.ToLower(body)
			if strings.Contains(bodyLower, "token") || strings.Contains(bodyLower, "success") ||
				strings.Contains(bodyLower, "session") {
				c.addFinding(cat,
					fmt.Sprintf("Default credentials accepted: %s/%s", dc.user, dc.pass),
					"Change all default credentials immediately and enforce strong password policy",
					"critical")
				break
			}
		}
	}

	// Unnecessary HTTP methods
	dangerousMethods := []string{"TRACE", "TRACK", "DEBUG", "CONNECT"}
	for _, method := range dangerousMethods {
		resp, _ := c.makeRequest(method, "/", nil, nil)
		if resp != nil && resp.StatusCode != 405 && resp.StatusCode != 403 &&
			resp.StatusCode != 501 && resp.StatusCode != 400 {
			c.addFinding(cat,
				fmt.Sprintf("Dangerous HTTP method allowed: %s", method),
				fmt.Sprintf("Disable %s method in web server configuration", method),
				"medium")
			break
		}
	}

	// Server version disclosure
	resp, body := c.makeRequest("GET", "/", nil, nil)
	if resp != nil {
		server := resp.Header.Get("Server")
		if server != "" {
			versionRe := regexp.MustCompile(`[\d]+\.[\d]+[\.\d]*`)
			if versionRe.MatchString(server) {
				c.addFinding(cat,
					fmt.Sprintf("Server version disclosed: %s", server),
					"Remove version information from Server header",
					"low")
			}
		}

		xPowered := resp.Header.Get("X-Powered-By")
		if xPowered != "" {
			c.addFinding(cat,
				fmt.Sprintf("X-Powered-By header disclosed: %s", xPowered),
				"Remove X-Powered-By header",
				"low")
		}
	}

	// Directory traversal
	traversalPaths := []string{
		"/../../../../etc/passwd",
		"/..%2f..%2f..%2fetc/passwd",
		"/static/../../../etc/passwd",
		"/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
	}
	for _, tp := range traversalPaths {
		resp, body := c.makeRequest("GET", tp, nil, nil)
		if resp != nil && resp.StatusCode == 200 {
			if strings.Contains(body, "root:x:0:0") || strings.Contains(body, "root:*:0:0") {
				c.addFinding(cat,
					"Directory traversal: /etc/passwd accessible via path traversal",
					"Sanitize file paths and use chroot/sandboxing",
					"critical")
				break
			}
		}
	}

	// Open ports
	host := c.extractHost()
	importantPorts := []struct {
		port int
		name string
	}{
		{21, "FTP"},
		{23, "Telnet"},
		{445, "SMB"},
		{1433, "MSSQL"},
		{3306, "MySQL"},
		{5432, "PostgreSQL"},
		{6379, "Redis"},
		{27017, "MongoDB"},
	}
	if host != "" {
		for _, ip := range importantPorts {
			addr := net.JoinHostPort(host, strconv.Itoa(ip.port))
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err == nil {
				conn.Close()
				c.addFinding(cat,
					fmt.Sprintf("Database/service port exposed: %s (port %d)", ip.name, ip.port),
					fmt.Sprintf("Block port %d (%s) from external access via firewall", ip.port, ip.name),
					"high")
			}
		}
	}

	// Debug mode
	if resp != nil {
		bodyLower := strings.ToLower(body)
		debugIndicators := []string{"stack trace", "debug mode", "debug=true",
			"traceback", "exception in", "runtime error", "panic:"}
		for _, di := range debugIndicators {
			if strings.Contains(bodyLower, di) {
				c.addFinding(cat,
					"Debug information exposed in HTTP response",
					"Disable debug mode in production environment",
					"medium")
				break
			}
		}
	}

	return cat
}

// --- A06: Vulnerable and Outdated Components ---

func (c *OWASPChecker) checkA06() *OWASPCategory {
	cat := c.newCategory("A06")

	resp, body := c.makeRequest("GET", "/", nil, nil)
	if resp == nil {
		return cat
	}

	server := strings.ToLower(resp.Header.Get("Server"))
	bodyLower := strings.ToLower(body)

	// Check for known vulnerable software
	vulnerableSoftware := []struct {
		name    string
		pattern string
		cve     string
	}{
		{"Apache 2.2.x", `apache/2\.2`, "CVE-2021-41773, CVE-2021-42013"},
		{"Apache 2.4.49", `apache/2\.4\.49`, "CVE-2021-41773"},
		{"Apache 2.4.50", `apache/2\.4\.50`, "CVE-2021-42013"},
		{"Nginx 0.x", `nginx/0\.`, "Multiple CVEs"},
		{"Nginx 1.0.x", `nginx/1\.0\.`, "Multiple CVEs"},
		{"PHP 5.x", `php/5\.`, "End of life, multiple CVEs"},
		{"PHP 7.0", `php/7\.0\.`, "End of life, multiple CVEs"},
		{"IIS 6.0", `microsoft-iis/6\.0`, "CVE-2017-7269"},
		{"jQuery 1.x", `jquery[/-]1\.`, "CVE-2019-11358, CVE-2020-11022"},
		{"jQuery 2.x", `jquery[/-]2\.`, "CVE-2020-11022"},
		{"WordPress", `wp-content|wp-includes`, "Check plugins for CVEs"},
		{"Joomla", `joomla`, "Check version for CVEs"},
		{"Drupal", `drupal`, "Check version for CVEs (Drupalgeddon)"},
	}

	combined := server + " " + bodyLower
	for _, vs := range vulnerableSoftware {
		re := regexp.MustCompile(vs.pattern)
		if re.MatchString(combined) {
			c.addFinding(cat,
				fmt.Sprintf("Potentially vulnerable software detected: %s (%s)", vs.name, vs.cve),
				"Update to latest stable version and check security advisories",
				"high")
		}
	}

	// Check for outdated JS libraries
	jsLibraryPatterns := []struct {
		name    string
		pattern string
	}{
		{"jQuery <3.5.0", `jquery[/-][12]\.\d+\.\d+|jquery[/-]3\.[0-4]\.`},
		{"Bootstrap <4.6.2", `bootstrap[/-][34]\.[0-5]\.`},
		{"AngularJS (1.x)", `angular[/-]1\.`},
		{"Backbone.js", `backbone[/-]\d+\.`},
		{"Underscore.js", `underscore[/-]\d+\.`},
		{"Lodash <4.17.21", `lodash[/-]4\.17\.[0-19]\.|lodash[/-]4\.16\.`},
	}

	for _, jlp := range jsLibraryPatterns {
		re := regexp.MustCompile(jlp.pattern)
		if re.MatchString(combined) {
			c.addFinding(cat,
				fmt.Sprintf("Outdated JavaScript library: %s", jlp.name),
				"Update to latest version of the library",
				"medium")
		}
	}

	// Check for vulnerable CMS endpoints
	cmsPaths := []struct {
		path    string
		cms     string
		pattern string
	}{
		{"/wp-login.php", "WordPress", "wp-login"},
		{"/xmlrpc.php", "WordPress XML-RPC", "xmlrpc"},
		{"/administrator/", "Joomla", "joomla"},
		{"/user/login", "Drupal", "drupal"},
	}

	for _, cp := range cmsPaths {
		resp2, body2 := c.makeRequest("GET", cp.path, nil, nil)
		if resp2 != nil && resp2.StatusCode == 200 {
			body2Lower := strings.ToLower(body2)
			if strings.Contains(body2Lower, cp.pattern) {
				c.addFinding(cat,
					fmt.Sprintf("CMS login page exposed: %s at %s", cp.cms, cp.path),
					"Restrict access to CMS admin panels, use VPN or IP whitelisting",
					"medium")
			}
		}
	}

	return cat
}

// --- A07: Identification and Authentication Failures ---

func (c *OWASPChecker) checkA07() *OWASPCategory {
	cat := c.newCategory("A07")

	// Check session token length and cookie security
	resp, body := c.makeRequest("GET", "/login", nil, nil)
	if resp == nil {
		resp, body = c.makeRequest("GET", "/", nil, nil)
	}

	if resp != nil {
		// Check cookies for security flags
		cookies := resp.Cookies()
		for _, cookie := range cookies {
			cookieName := strings.ToLower(cookie.Name)
			if strings.Contains(cookieName, "session") || strings.Contains(cookieName, "token") ||
				strings.Contains(cookieName, "auth") || strings.Contains(cookieName, "sid") {

				if !cookie.Secure {
					c.addFinding(cat,
						fmt.Sprintf("Session cookie '%s' missing Secure flag", cookie.Name),
						"Set Secure flag on all session cookies",
						"medium")
				}
				if !cookie.HttpOnly {
					c.addFinding(cat,
						fmt.Sprintf("Session cookie '%s' missing HttpOnly flag", cookie.Name),
						"Set HttpOnly flag to prevent XSS access to session cookies",
						"medium")
				}
				if cookie.SameSite != http.SameSiteLaxMode && cookie.SameSite != http.SameSiteStrictMode {
					c.addFinding(cat,
						fmt.Sprintf("Session cookie '%s' missing SameSite attribute", cookie.Name),
						"Set SameSite=Lax or SameSite=Strict on session cookies",
						"low")
				}
			}
		}

		// Check token length in response body
		tokenPatterns := []string{`"token":"([^"]+)"`, `"access_token":"([^"]+)"`,
			`"session":"([^"]+)"`, `set-cookie: session=([^;]+)`}
		for _, tp := range tokenPatterns {
			re := regexp.MustCompile(tp)
			matches := re.FindStringSubmatch(strings.ToLower(body))
			if len(matches) > 1 {
				token := matches[1]
				if len(token) < 16 {
					c.addFinding(cat,
						fmt.Sprintf("Session token too short: %d chars (minimum 32 recommended)", len(token)),
						"Use cryptographically random tokens of at least 128 bits (16 bytes)",
						"high")
				}
				break
			}
		}
	}

	// Brute force protection: test rapid login attempts
	lockoutDetected := false
	for i := 0; i < 20; i++ {
		resp2, body2 := c.makeRequest("POST", "/api/login",
			http.Header{"Content-Type": {"application/json"}},
			strings.NewReader(fmt.Sprintf(`{"username":"test%d","password":"wrongpass"}`, i)))
		if resp2 != nil && (resp2.StatusCode == 429 || resp2.StatusCode == 503) {
			lockoutDetected = true
			break
		}
		if resp2 != nil {
			body2Lower := strings.ToLower(body2)
			if strings.Contains(body2Lower, "too many") || strings.Contains(body2Lower, "rate limit") ||
				strings.Contains(body2Lower, "temporarily locked") || strings.Contains(body2Lower, "brute force") {
				lockoutDetected = true
				break
			}
		}
	}
	if !lockoutDetected {
		c.addFinding(cat,
			"No brute force protection: 20 failed login attempts with no lockout/rate limit",
			"Implement account lockout, rate limiting, and CAPTCHA after failed attempts",
			"high")
	}

	// Credential stuffing: test common username patterns
	commonUsers := []string{"admin", "administrator", "root", "user", "test"}
	validUser := ""
	for _, u := range commonUsers {
		resp3, body3 := c.makeRequest("POST", "/api/login",
			http.Header{"Content-Type": {"application/json"}},
			strings.NewReader(fmt.Sprintf(`{"username":"%s","password":"wrongpass"}`, u)))
		if resp3 != nil {
			body3Lower := strings.ToLower(body3)
			if resp3.StatusCode != 401 && resp3.StatusCode != 403 &&
				!strings.Contains(body3Lower, "invalid credentials") &&
				!strings.Contains(body3Lower, "incorrect password") &&
				!strings.Contains(body3Lower, "user not found") {
				validUser = u
				break
			}
		}
	}
	if validUser != "" {
		c.addFinding(cat,
			fmt.Sprintf("User enumeration possible: '%s' returns different response than invalid users", validUser),
			"Use generic error messages that don't reveal whether username exists",
			"medium")
	}

	_ = body
	return cat
}

// --- A08: Software and Data Integrity Failures ---

func (c *OWASPChecker) checkA08() *OWASPCategory {
	cat := c.newCategory("A08")

	resp, body := c.makeRequest("GET", "/", nil, nil)
	if resp == nil {
		return cat
	}

	// Check for SRI on external scripts
	scriptRe := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	scripts := scriptRe.FindAllStringSubmatch(body, -1)
	sriRe := regexp.MustCompile(`integrity=`)

	externalScripts := 0
	sriProtected := 0
	for _, s := range scripts {
		src := s[1]
		if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") ||
			strings.Contains(src, "cdn.") || strings.Contains(src, "cdnjs.") {
			externalScripts++
			if sriRe.MatchString(s[0]) {
				sriProtected++
			}
		}
	}

	if externalScripts > 0 && sriProtected == 0 {
		c.addFinding(cat,
			fmt.Sprintf("No SRI on %d external scripts", externalScripts),
			"Add integrity attribute to all external script tags",
			"medium")
	} else if externalScripts > 0 && sriProtected < externalScripts {
		c.addFinding(cat,
			fmt.Sprintf("SRI missing on %d of %d external scripts", externalScripts-sriProtected, externalScripts),
			"Add integrity attribute to all external script tags",
			"low")
	}

	// Check for insecure deserialization indicators
	// Look for common patterns in API responses
	apiResp, apiBody := c.makeRequest("GET", "/api/", nil, nil)
	if apiResp != nil {
		apiBodyLower := strings.ToLower(apiBody)
		deserializePatterns := []string{
			"java.deserialization", "pickle", "marshal.loads",
			"yaml.load", "unserialize", "object deserialization",
		}
		for _, dp := range deserializePatterns {
			if strings.Contains(apiBodyLower, dp) {
				c.addFinding(cat,
					fmt.Sprintf("Insecure deserialization indicator found: %s", dp),
					"Use safe deserialization methods. Avoid deserializing untrusted data",
					"high")
				break
			}
		}
	}

	// Check for CI/CD pipeline exposure
	cicdPaths := []string{
		"/.git/config", "/.git/HEAD",
		"/.env", "/.env.local", "/.env.production",
		"/docker-compose.yml", "/Dockerfile",
		"/.github/workflows/", "/.gitlab-ci.yml",
		"/Jenkinsfile", "/.circleci/config.yml",
		"/.travis.yml", "/bitbucket-pipelines.yml",
	}

	for _, cp := range cicdPaths {
		resp2, body2 := c.makeRequest("GET", cp, nil, nil)
		if resp2 != nil && resp2.StatusCode == 200 {
			body2Lower := strings.ToLower(body2)
			if strings.Contains(body2Lower, "database") || strings.Contains(body2Lower, "password") ||
				strings.Contains(body2Lower, "secret") || strings.Contains(body2Lower, "api_key") ||
				strings.Contains(body2Lower, "[core]") || strings.Contains(body2Lower, "ref:") ||
				strings.Contains(body2Lower, "version:") || strings.Contains(body2Lower, "build") {
				c.addFinding(cat,
					fmt.Sprintf("CI/CD or configuration file exposed: %s", cp),
					"Restrict access to configuration and CI/CD files",
					"high")
			}
		}
	}

	return cat
}

// --- A09: Security Logging and Monitoring Failures ---

func (c *OWASPChecker) checkA09() *OWASPCategory {
	cat := c.newCategory("A09")

	// Test for verbose error messages
	errorTriggers := []struct {
		path    string
		method  string
		body    string
		headers http.Header
	}{
		{"/api/users/'", "GET", "", nil},
		{"/api/login", "POST", `{"username":"test","password":"test"}`, nil},
		{"/nonexistent-endpoint-xyz", "GET", "", nil},
		{"/api/users/99999999", "GET", "", nil},
		{"/api/search?q=", "GET", "", nil},
	}

	verboseErrors := 0
	for _, et := range errorTriggers {
		var bodyReader io.Reader
		if et.body != "" {
			bodyReader = strings.NewReader(et.body)
		}
		if et.headers == nil {
			et.headers = http.Header{"Content-Type": {"application/json"}}
		}
		resp, body := c.makeRequest(et.method, et.path, et.headers, bodyReader)
		if resp != nil && resp.StatusCode >= 400 {
			bodyLower := strings.ToLower(body)
			verbosePatterns := []string{
				"stack trace", "traceback", "exception",
				"file:", "line:", "column:",
				"query:", "sql", "mysql", "postgresql",
				"internal server error", "debug",
			}
			for _, vp := range verbosePatterns {
				if strings.Contains(bodyLower, vp) {
					verboseErrors++
					break
				}
			}
		}
	}

	if verboseErrors > 0 {
		c.addFinding(cat,
			fmt.Sprintf("Verbose error messages detected on %d endpoints (information leakage)", verboseErrors),
			"Use generic error messages. Log detailed errors server-side only",
			"medium")
	}

	// Check for error pages that leak server info
	resp, body := c.makeRequest("GET", "/nonexistent-page-12345", nil, nil)
	if resp != nil && resp.StatusCode >= 400 {
		bodyLower := strings.ToLower(body)
		leakPatterns := []string{"nginx/", "apache/", "php/", "asp.net", "express",
			"x-powered-by", "server version", "runtime version"}
		for _, lp := range leakPatterns {
			if strings.Contains(bodyLower, lp) {
				c.addFinding(cat,
					"Custom error page leaks server technology information",
					"Configure generic error pages that don't reveal technology stack",
					"low")
				break
			}
		}
	}

	// Check for logging/monitoring endpoints
	loggingPaths := []string{
		"/health", "/healthz", "/status", "/metrics",
		"/debug/vars", "/debug/pprof", "/actuator",
	}

	for _, lp := range loggingPaths {
		resp2, body2 := c.makeRequest("GET", lp, nil, nil)
		if resp2 != nil && resp2.StatusCode == 200 {
			body2Lower := strings.ToLower(body2)
			if strings.Contains(body2Lower, "uptime") || strings.Contains(body2Lower, "healthy") ||
				strings.Contains(body2Lower, "version") || strings.Contains(body2Lower, "goroutines") ||
				strings.Contains(body2Lower, "heap") || strings.Contains(body2Lower, "memstats") {
				c.addFinding(cat,
					fmt.Sprintf("Monitoring/debug endpoint exposed: %s", lp),
					"Restrict monitoring endpoints to internal network only",
					"low")
			}
		}
	}

	return cat
}

// --- A10: Server-Side Request Forgery (SSRF) ---

func (c *OWASPChecker) checkA10() *OWASPCategory {
	cat := c.newCategory("A10")

	// URL parameters to test for SSRF
	urlParams := []string{"url", "uri", "link", "href", "src", "dest", "redirect",
		"next", "return", "callback", "webhook", "fetch", "load", "page"}

	internalTargets := []struct {
		url     string
		pattern string
	}{
		{"http://127.0.0.1", "(root:x:0:0|uid=|localhost)"},
		{"http://localhost", "(root:x:0:0|uid=|localhost)"},
		{"http://169.254.169.254/latest/meta-data/", "(ami-id|instance-id|local-ipv4)"},
		{"http://[::1]", "(root:x:0:0|uid=)"},
	}

	for _, param := range urlParams {
		for _, target := range internalTargets {
			testURL := fmt.Sprintf("/?%s=%s", param, url.QueryEscape(target.url))
			resp, body := c.makeRequest("GET", testURL, nil, nil)
			if resp != nil {
				re := regexp.MustCompile(target.pattern)
				if re.MatchString(body) {
					c.addFinding(cat,
						fmt.Sprintf("SSRF in parameter '%s': internal resource %s accessible", param, target.url),
						"Validate and sanitize URL inputs. Use allowlists for permitted domains",
						"critical")
					return cat
				}
			}
		}
	}

	// Test file:// protocol
	filePayloads := []string{
		"file:///etc/passwd",
		"file:///proc/self/environ",
		"file:///c:/windows/system32/drivers/etc/hosts",
	}

	for _, fp := range filePayloads {
		resp, body := c.makeRequest("GET",
			fmt.Sprintf("/?url=%s", url.QueryEscape(fp)), nil, nil)
		if resp != nil {
			if strings.Contains(body, "root:x:0:0") || strings.Contains(body, "PATH=") {
				c.addFinding(cat,
					fmt.Sprintf("SSRF via file:// protocol: %s accessible", fp),
					"Block file:// protocol in URL inputs",
					"critical")
				return cat
			}
		}
	}

	// Test gopher:// protocol
	gopherPayloads := []string{
		"gopher://127.0.0.1:6379/_INFO",
		"gopher://127.0.0.1:11211/_stats",
	}

	for _, gp := range gopherPayloads {
		resp, bodyStr := func() (*http.Response, string) {
			r, b := c.makeRequest("GET",
				fmt.Sprintf("/?url=%s", url.QueryEscape(gp)), nil, nil)
			return r, b
		}()
		if resp != nil && resp.StatusCode == 200 {
			if strings.Contains(bodyStr, "redis_version") || strings.Contains(bodyStr, "STAT") ||
				strings.Contains(bodyStr, "OK") {
				c.addFinding(cat,
					fmt.Sprintf("SSRF via gopher:// protocol: %s reachable", gp),
					"Block gopher:// and other dangerous protocols in URL inputs",
					"critical")
				return cat
			}
		}
	}

	return cat
}

// --- Score & Grade Calculation ---

// CalculateScore calculates the overall score from all categories
func (c *OWASPChecker) CalculateScore(report *OWASPReport) int {
	if len(report.Categories) == 0 {
		return 0
	}

	totalScore := 0
	for _, cat := range report.Categories {
		totalScore += cat.Score
	}

	return totalScore / len(report.Categories)
}

func (c *OWASPChecker) calculateGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// Render produces a formatted text report
func (c *OWASPChecker) Render() string {
	if c.Results == nil {
		return "No results available. Run CheckAll() first."
	}

	r := c.Results
	var b strings.Builder

	b.WriteString("\n╔══════════════════════════════════════════════════════════════╗\n")
	b.WriteString("║           OWASP TOP 10 — AUTOMATED SECURITY AUDIT          ║\n")
	b.WriteString("╠══════════════════════════════════════════════════════════════╣\n")
	b.WriteString(fmt.Sprintf("║  Target: %-50s ║\n", r.Categories["A01"].Name))
	b.WriteString(fmt.Sprintf("║  Score:  %d/100  Grade: %-35s ║\n", r.Score, r.Grade))
	b.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	// Category order
	order := []string{"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"}

	for _, id := range order {
		cat := r.Categories[id]
		if cat == nil {
			continue
		}

		statusIcon := "✅"
		switch cat.Status {
		case "FAIL":
			statusIcon = "❌"
		case "WARNING":
			statusIcon = "⚠️"
		}

		b.WriteString(fmt.Sprintf("┌─── %s: %s ─── %s [%d/100]\n", cat.ID, cat.Name, statusIcon, cat.Score))

		if len(cat.Findings) == 0 {
			b.WriteString("│  No findings\n")
		} else {
			for i, f := range cat.Findings {
				b.WriteString(fmt.Sprintf("│  %s\n", f))
				if i < len(cat.Remediation) {
					b.WriteString(fmt.Sprintf("│    → %s\n", cat.Remediation[i]))
				}
			}
		}
		b.WriteString("└──────────────────────────────────────────────\n\n")
	}

	// Summary
	passCount, warnCount, failCount := 0, 0, 0
	for _, cat := range r.Categories {
		switch cat.Status {
		case "PASS":
			passCount++
		case "WARNING":
			warnCount++
		case "FAIL":
			failCount++
		}
	}

	b.WriteString("════════════════════════════════════════════════════════════════\n")
	b.WriteString(fmt.Sprintf(" SUMMARY: ✅ %d PASS  ⚠️  %d WARNING  ❌ %d FAIL\n", passCount, warnCount, failCount))
	b.WriteString(fmt.Sprintf(" OVERALL SCORE: %d/100  GRADE: %s\n", r.Score, r.Grade))
	b.WriteString("════════════════════════════════════════════════════════════════\n")

	return b.String()
}

// --- Helpers ---

func (c *OWASPChecker) extractHost() string {
	u, err := url.Parse(c.Target)
	if err != nil {
		host := c.Target
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}
		return host
	}
	return u.Hostname()
}

func (c *OWASPChecker) extractPort() int {
	u, err := url.Parse(c.Target)
	if err != nil {
		return 80
	}
	portStr := u.Port()
	if portStr == "" {
		if u.Scheme == "https" {
			return 443
		}
		return 80
	}
	port, _ := strconv.Atoi(portStr)
	return port
}
