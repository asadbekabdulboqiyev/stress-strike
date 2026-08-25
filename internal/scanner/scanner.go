package scanner

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// --- Scan Result Types ------------------------------------------------------

type ScanResult struct {
	Target    string        `json:"target"`
	ScanTime  time.Time     `json:"scan_time"`
	Duration  time.Duration `json:"duration"`
	TLS       *TLSInfo      `json:"tls"`
	WAF       *WAFInfo      `json:"waf"`
	HTTP      *HTTPInfo     `json:"http"`
	Security  *SecurityInfo `json:"security"`
	Vulns     []Vuln        `json:"vulns"`
	RiskScore int           `json:"risk_score"` // 0-100
}

type Vuln struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"` // critical, high, medium, low, info
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// --- TLS Scanner ------------------------------------------------------------

type TLSInfo struct {
	Version           string       `json:"version"`
	CipherSuite       string       `json:"cipher_suite"`
	CipherSuiteID     uint16       `json:"cipher_suite_id"`
	IsSecure          bool         `json:"is_secure"`
	Certificate       *CertInfo    `json:"certificate"`
	SupportedVersions []string     `json:"supported_versions"`
	SupportedCiphers  []CipherInfo `json:"supported_ciphers"`
	HasHSTS           bool         `json:"has_hsts"`
	SessionResumption bool         `json:"session_resumption"`
	ForwardSecrecy    bool         `json:"forward_secrecy"`
	OCSPStapling      bool         `json:"ocsp_stapling"`
	HTTP2Supported    bool         `json:"http2_supported"`
	CertificateChain  []CertInfo   `json:"certificate_chain"`
	Vulnerabilities   []string     `json:"vulnerabilities"`
}

type CertInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	IsExpired    bool      `json:"is_expired"`
	IsSelfSigned bool      `json:"is_self_signed"`
	KeyType      string    `json:"key_type"`
	KeySize      int       `json:"key_size"`
	SerialNumber string    `json:"serial_number"`
	SANs         []string  `json:"sans"`
	SignatureAlg string    `json:"signature_algorithm"`
}

type CipherInfo struct {
	Name  string `json:"name"`
	ID    uint16 `json:"id"`
	Grade string `json:"grade"` // A, B, C, D, F
	FS    bool   `json:"forward_secrecy"`
	AEAD  bool   `json:"aead"`
}

// Known cipher suites
var knownCiphers = map[uint16]CipherInfo{
	// TLS 1.3
	0x1301: {Name: "TLS_AES_128_GCM_SHA256", Grade: "A", FS: true, AEAD: true},
	0x1302: {Name: "TLS_AES_256_GCM_SHA384", Grade: "A", FS: true, AEAD: true},
	0x1303: {Name: "TLS_CHACHA20_POLY1305_SHA256", Grade: "A", FS: true, AEAD: true},
	// ECDHE
	0xc02b: {Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", Grade: "A", FS: true, AEAD: true},
	0xc02c: {Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", Grade: "A", FS: true, AEAD: true},
	0xc02f: {Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Grade: "A", FS: true, AEAD: true},
	0xc030: {Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Grade: "A", FS: true, AEAD: true},
	0xcca8: {Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", Grade: "A", FS: true, AEAD: true},
	0xcca9: {Name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", Grade: "A", FS: true, AEAD: true},
	// Non-FS (weaker)
	0x009c: {Name: "TLS_RSA_WITH_AES_128_GCM_SHA256", Grade: "B", FS: false, AEAD: true},
	0x009d: {Name: "TLS_RSA_WITH_AES_256_GCM_SHA384", Grade: "B", FS: false, AEAD: true},
	// Insecure
	0x0005: {Name: "TLS_RSA_WITH_RC4_128_SHA", Grade: "F", FS: false, AEAD: false},
	0x000a: {Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Grade: "D", FS: false, AEAD: false},
	0x0004: {Name: "TLS_RSA_WITH_RC4_128_MD5", Grade: "F", FS: false, AEAD: false},
	0x0016: {Name: "TLS_RSA_WITH_IDEA_CBC_SHA", Grade: "D", FS: false, AEAD: false},
	0x0013: {Name: "TLS_RSA_WITH_DES_CBC_SHA", Grade: "F", FS: false, AEAD: false},
}

// Insecure cipher patterns
var insecurePatterns = []string{
	"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
}

// Secure TLS versions
var secureVersions = []string{"TLS 1.3", "TLS 1.2"}

// ScanTLS performs a full TLS scan on the target
func ScanTLS(host string, port int) (*TLSInfo, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	info := &TLSInfo{
		SupportedVersions: make([]string, 0),
		SupportedCiphers:  make([]CipherInfo, 0),
		Vulnerabilities:   make([]string, 0),
	}

	// Try different TLS versions
	tlsVersions := []struct {
		name string
		min  uint16
		max  uint16
	}{
		{"TLS 1.3", tls.VersionTLS13, tls.VersionTLS13},
		{"TLS 1.2", tls.VersionTLS12, tls.VersionTLS12},
		{"TLS 1.1", tls.VersionTLS11, tls.VersionTLS11},
		{"TLS 1.0", tls.VersionTLS10, tls.VersionTLS10},
	}

	for _, tv := range tlsVersions {
		config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tv.min,
			MaxVersion:         tv.max,
		}

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 5 * time.Second},
			"tcp", addr, config,
		)
		if err != nil {
			continue
		}

		info.SupportedVersions = append(info.SupportedVersions, tv.name)
		state := conn.ConnectionState()

		if len(info.SupportedVersions) == 1 {
			// First successful connection = negotiated version
			info.Version = tv.name
			if state.CipherSuite != 0 {
				cipher := knownCiphers[state.CipherSuite]
				if cipher.Name == "" {
					cipher = CipherInfo{
						Name:  fmt.Sprintf("UNKNOWN_%d", state.CipherSuite),
						ID:    state.CipherSuite,
						Grade: "B",
					}
				}
				info.CipherSuite = cipher.Name
				info.CipherSuiteID = state.CipherSuite
				info.ForwardSecrecy = cipher.FS

				// Check if cipher is secure
				info.IsSecure = true
				for _, p := range insecurePatterns {
					if strings.Contains(strings.ToUpper(cipher.Name), p) {
						info.IsSecure = false
						info.Vulnerabilities = append(info.Vulnerabilities, fmt.Sprintf("Insecure cipher: %s", cipher.Name))
						break
					}
				}
			}

			// Certificate info
			if len(state.PeerCertificates) > 0 {
				certInfo := extractCertInfo(state.PeerCertificates[0])
				info.Certificate = &certInfo
				for _, cert := range state.PeerCertificates {
					ci := extractCertInfo(cert)
					info.CertificateChain = append(info.CertificateChain, ci)
				}
			}

			// HTTP/2 support
			info.HTTP2Supported = state.NegotiatedProtocol == "h2"
		}

		conn.Close()
	}

	// Check session resumption
	config := &tls.Config{InsecureSkipVerify: true}
	conn1, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, config)
	if err == nil {
		conn1.Close()
		// Try second connection - if same session ID, resumption works
		conn2, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, config)
		if err == nil {
			info.SessionResumption = true
			conn2.Close()
		}
	}

	return info, nil
}

func extractCertInfo(cert *x509.Certificate) CertInfo {
	info := CertInfo{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsExpired:    time.Now().After(cert.NotAfter),
		SerialNumber: cert.SerialNumber.String(),
		SANs:         cert.DNSNames,
		SignatureAlg: cert.SignatureAlgorithm.String(),
	}

	// Key type and size
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyType = "RSA"
		info.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeyType = "ECDSA"
		info.KeySize = pub.Curve.Params().BitSize
	default:
		info.KeyType = "Unknown"
	}

	// Self-signed check
	info.IsSelfSigned = cert.Issuer.CommonName == cert.Subject.CommonName

	return info
}

// --- WAF Fingerprinting -----------------------------------------------------

type WAFInfo struct {
	Detected   bool              `json:"detected"`
	Name       string            `json:"name"`
	Vendor     string            `json:"vendor"`
	Version    string            `json:"version"`
	Confidence int               `json:"confidence"` // 0-100
	Headers    map[string]string `json:"headers"`
	Indicators []string          `json:"indicators"`
}

// WAF signatures for detection
var wafSignatures = map[string]WAFSignature{
	"cloudflare": {
		Name:        "Cloudflare",
		Vendor:      "Cloudflare, Inc.",
		Headers:     []string{"cf-ray", "cf-cache-status", "cf-connecting-ip"},
		Body:        []string{"cloudflare", "cf-browser-verification", "cf_chl_"},
		Cookie:      []string{"__cflb", "__cfuid", "cf_clearance"},
		Status:      []int{503, 403},
		JSChallenge: true,
	},
	"akamai": {
		Name:    "Akamai",
		Vendor:  "Akamai Technologies",
		Headers: []string{"x-akamai-transformed", "x-akamai-request-id"},
		Body:    []string{"akamai", "Reference #", "Access Denied"},
		Cookie:  []string{"akamai_bmc", "akamai_bmc_cap"},
		Status:  []int{403, 503},
	},
	"aws-waf": {
		Name:    "AWS WAF",
		Vendor:  "Amazon Web Services",
		Headers: []string{"x-amzn-waf-", "x-amzn-trace-id", "x-amz-cf-id"},
		Body:    []string{"aws-waf", "x-amzn-waf", "awswaf"},
		Cookie:  []string{"aws-waf-token", "aws-waf-token-time"},
		Status:  []int{403, 405},
	},
	"modsecurity": {
		Name:    "ModSecurity",
		Vendor:  "Trustwave / OWASP",
		Headers: []string{"modsecurity", "x-mod-security"},
		Body:    []string{"ModSecurity", "This error was generated by Mod_Security"},
		Status:  []int{403, 406},
	},
	"incapsula": {
		Name:    "Incapsula",
		Vendor:  "Imperva",
		Headers: []string{"x-iinfo", "x-cdn"},
		Body:    []string{"incap_ses", "visid_incap_"},
		Cookie:  []string{"incap_ses", "visid_incap_"},
		Status:  []int{403, 503},
	},
	"fortiweb": {
		Name:    "FortiWeb",
		Vendor:  "Fortinet",
		Headers: []string{"x-fortiweb", "server: FortiWeb"},
		Body:    []string{"FortiWeb", "fortiweb"},
		Status:  []int{403},
	},
	"barracuda": {
		Name:    "Barracuda",
		Vendor:  "Barracuda Networks",
		Headers: []string{"x-barracuda"},
		Body:    []string{"Barracuda", "barracuda"},
		Cookie:  []string{"barra_counter_session"},
		Status:  []int{403},
	},
	"denied": {
		Name:   "Generic WAF",
		Vendor: "Unknown",
		Body:   []string{"Access Denied", "blocked", "firewall", "security"},
		Status: []int{403, 406, 429, 503},
	},
}

type WAFSignature struct {
	Name        string
	Vendor      string
	Headers     []string
	Body        []string
	Cookie      []string
	Status      []int
	JSChallenge bool
}

// ScanWAF performs WAF fingerprinting
func ScanWAF(target string) (*WAFInfo, error) {
	waf := &WAFInfo{
		Headers:    make(map[string]string),
		Indicators: make([]string, 0),
	}

	// Send test request with suspicious payload
	resp, err := sendProbe(target, "GET", "/<script>alert(1)</script>", nil)
	if err != nil {
		return waf, fmt.Errorf("probe failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB
	bodyStr := string(body)

	// Collect all response headers
	allHeaders := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			allHeaders[strings.ToLower(key)] = values[0]
		}
	}

	// Test each WAF signature
	bestMatch := 0
	for _, sig := range wafSignatures {
		confidence := 0

		// Check headers
		for _, h := range sig.Headers {
			for k, v := range allHeaders {
				if strings.Contains(k, strings.ToLower(h)) {
					confidence += 30
					waf.Indicators = append(waf.Indicators, fmt.Sprintf("header:%s=%s", k, v))
				}
			}
		}

		// Check body
		for _, b := range sig.Body {
			if strings.Contains(bodyStr, b) {
				confidence += 25
				waf.Indicators = append(waf.Indicators, fmt.Sprintf("body:%s", b))
			}
		}

		// Check cookies
		for _, c := range sig.Cookie {
			for _, cookie := range resp.Cookies() {
				if strings.Contains(cookie.Name, c) {
					confidence += 20
					waf.Indicators = append(waf.Indicators, fmt.Sprintf("cookie:%s", cookie.Name))
				}
			}
		}

		// Check status
		for _, s := range sig.Status {
			if resp.StatusCode == s {
				confidence += 15
			}
		}

		if confidence > bestMatch {
			bestMatch = confidence
			waf.Detected = true
			waf.Name = sig.Name
			waf.Vendor = sig.Vendor
			waf.Confidence = confidence
		}
	}

	// Store headers
	waf.Headers = allHeaders

	return waf, nil
}

// --- HTTP Fingerprinting ----------------------------------------------------

type HTTPInfo struct {
	Server       string            `json:"server"`
	XPoweredBy   string            `json:"x_powered_by"`
	Technologies []string          `json:"technologies"`
	CORS         *CORSInfo         `json:"cors"`
	Headers      map[string]string `json:"headers"`
	Cookies      []string          `json:"cookies"`
	Methods      []string          `json:"allowed_methods"`
	HTTPVersion  string            `json:"http_version"`
}

type CORSInfo struct {
	AllowOrigin  string `json:"allow_origin"`
	AllowMethods string `json:"allow_methods"`
	AllowHeaders string `json:"allow_headers"`
	Credentials  bool   `json:"credentials"`
	MaxAge       string `json:"max_age"`
	IsPermissive bool   `json:"is_permissive"`
}

// ScanHTTP performs HTTP fingerprinting
func ScanHTTP(target string) (*HTTPInfo, error) {
	info := &HTTPInfo{
		Technologies: make([]string, 0),
		Headers:      make(map[string]string),
		Cookies:      make([]string, 0),
		Methods:      make([]string, 0),
	}

	resp, err := sendProbe(target, "GET", "/", nil)
	if err != nil {
		return info, fmt.Errorf("probe failed: %w", err)
	}
	defer resp.Body.Close()

	// Collect headers
	for key, values := range resp.Header {
		if len(values) > 0 {
			info.Headers[key] = values[0]
		}
	}

	// Server header
	info.Server = resp.Header.Get("Server")

	// X-Powered-By
	info.XPoweredBy = resp.Header.Get("X-Powered-By")

	// HTTP version
	info.HTTPVersion = resp.Proto

	// Cookies
	for _, cookie := range resp.Cookies() {
		info.Cookies = append(info.Cookies, cookie.Name)
	}

	// CORS
	info.CORS = &CORSInfo{
		AllowOrigin:  resp.Header.Get("Access-Control-Allow-Origin"),
		AllowMethods: resp.Header.Get("Access-Control-Allow-Methods"),
		AllowHeaders: resp.Header.Get("Access-Control-Allow-Headers"),
		Credentials:  resp.Header.Get("Access-Control-Allow-Credentials") == "true",
		MaxAge:       resp.Header.Get("Access-Control-Max-Age"),
	}
	if info.CORS.AllowOrigin == "*" {
		info.CORS.IsPermissive = true
	}

	// Technology detection
	info.Technologies = detectTechnologies(resp)

	// OPTIONS for allowed methods
	optResp, err := sendProbe(target, "OPTIONS", "/", nil)
	if err == nil {
		optResp.Body.Close()
		allow := optResp.Header.Get("Allow")
		if allow != "" {
			info.Methods = strings.Split(allow, ",")
			for i := range info.Methods {
				info.Methods[i] = strings.TrimSpace(info.Methods[i])
			}
		}
	}

	return info, nil
}

func detectTechnologies(resp *http.Response) []string {
	var techs []string

	server := strings.ToLower(resp.Header.Get("Server"))
	poweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))

	// Server-based detection
	techMap := map[string]string{
		"nginx":      "Nginx",
		"apache":     "Apache",
		"cloudflare": "Cloudflare",
		"iis":        "Microsoft IIS",
		"litespeed":  "LiteSpeed",
		"caddy":      "Caddy",
		"gunicorn":   "Gunicorn (Python)",
		"uvicorn":    "Uvicorn (Python)",
		"hypercorn":  "Hypercorn (Python)",
		"puma":       "Puma (Ruby)",
		"thin":       "Thin (Ruby)",
		"jetty":      "Jetty (Java)",
		"tomcat":     "Apache Tomcat (Java)",
		"undici":     "Undici (Node.js)",
	}

	for pattern, name := range techMap {
		if strings.Contains(server, pattern) {
			techs = append(techs, name)
		}
	}

	// X-Powered-By detection
	poweredMap := map[string]string{
		"php":     "PHP",
		"asp.net": "ASP.NET",
		"express": "Express.js",
		"rails":   "Ruby on Rails",
		"django":  "Django (Python)",
		"flask":   "Flask (Python)",
		"laravel": "Laravel (PHP)",
		"next.js": "Next.js",
	}

	for pattern, name := range poweredMap {
		if strings.Contains(poweredBy, pattern) {
			techs = append(techs, name)
		}
	}

	// Cookie-based detection
	for _, cookie := range resp.Cookies() {
		name := strings.ToLower(cookie.Name)
		if strings.Contains(name, "phpsessid") {
			if !containsTech(techs, "PHP") {
				techs = append(techs, "PHP")
			}
		} else if strings.Contains(name, "jsessionid") {
			techs = append(techs, "Java")
		} else if strings.Contains(name, "csrftoken") {
			techs = append(techs, "Django (Python)")
		} else if strings.Contains(name, "_rails_session") {
			techs = append(techs, "Ruby on Rails")
		}
	}

	return techs
}

func containsTech(techs []string, tech string) bool {
	for _, t := range techs {
		if strings.EqualFold(t, tech) {
			return true
		}
	}
	return false
}

// --- Security Headers Scanner -----------------------------------------------

type SecurityInfo struct {
	Headers        map[string]string `json:"headers"`
	MissingHeaders []string          `json:"missing_headers"`
	Score          int               `json:"score"` // 0-100
	Details        []SecurityDetail  `json:"details"`
}

type SecurityDetail struct {
	Header  string `json:"header"`
	Value   string `json:"value"`
	Status  string `json:"status"` // present, missing, weak, strong
	Message string `json:"message"`
}

var securityHeaders = []struct {
	Name     string
	Required bool
	Weight   int
	Check    func(string) (string, string) // value -> (status, message)
}{
	{
		Name:     "Strict-Transport-Security",
		Required: true,
		Weight:   15,
		Check: func(v string) (string, string) {
			if v == "" {
				return "missing", "HSTS header missing — allows HTTP downgrade attacks"
			}
			if strings.Contains(v, "max-age=0") {
				return "weak", "HSTS max-age=0 disables HSTS"
			}
			maxAge := 0
			re := regexp.MustCompile(`max-age=(\d+)`)
			if matches := re.FindStringSubmatch(v); len(matches) > 1 {
				maxAge, _ = strconv.Atoi(matches[1])
			}
			if maxAge < 31536000 {
				return "weak", fmt.Sprintf("HSTS max-age=%d is less than 1 year", maxAge)
			}
			return "strong", "HSTS properly configured"
		},
	},
	{
		Name:     "Content-Security-Policy",
		Required: true,
		Weight:   15,
		Check: func(v string) (string, string) {
			if v == "" {
				return "missing", "CSP header missing — vulnerable to XSS"
			}
			if strings.Contains(v, "'unsafe-inline'") || strings.Contains(v, "'unsafe-eval'") {
				return "weak", "CSP contains unsafe-inline or unsafe-eval"
			}
			return "strong", "CSP properly configured"
		},
	},
	{
		Name:     "X-Frame-Options",
		Required: true,
		Weight:   10,
		Check: func(v string) (string, string) {
			if v == "" {
				return "missing", "X-Frame-Options missing — vulnerable to clickjacking"
			}
			return "strong", "X-Frame-Options configured"
		},
	},
	{
		Name:     "X-Content-Type-Options",
		Required: true,
		Weight:   10,
		Check: func(v string) (string, string) {
			if v == "" {
				return "missing", "X-Content-Type-Options missing — MIME sniffing possible"
			}
			if !strings.EqualFold(v, "nosniff") {
				return "weak", "X-Content-Type-Options should be 'nosniff'"
			}
			return "strong", "X-Content-Type-Options properly set"
		},
	},
	{
		Name:     "X-XSS-Protection",
		Required: false,
		Weight:   5,
		Check: func(v string) (string, string) {
			if v == "" {
				return "info", "X-XSS-Protection not set (deprecated, CSP is preferred)"
			}
			if v == "0" {
				return "info", "X-XSS-Protection disabled (OK if CSP is set)"
			}
			return "strong", "X-XSS-Protection enabled"
		},
	},
	{
		Name:     "Referrer-Policy",
		Required: true,
		Weight:   10,
		Check: func(v string) (string, string) {
			if v == "" {
				return "missing", "Referrer-Policy missing — may leak sensitive URLs"
			}
			if v == "unsafe-url" {
				return "weak", "Referrer-Policy is 'unsafe-url' — leaks full URLs"
			}
			return "strong", "Referrer-Policy configured"
		},
	},
	{
		Name:     "Permissions-Policy",
		Required: true,
		Weight:   10,
		Check: func(v string) (string, string) {
			if v == "" {
				return "missing", "Permissions-Policy missing — browsers may allow unwanted features"
			}
			return "strong", "Permissions-Policy configured"
		},
	},
	{
		Name:     "Cross-Origin-Opener-Policy",
		Required: false,
		Weight:   5,
		Check: func(v string) (string, string) {
			if v == "" {
				return "info", "COOP not set"
			}
			return "strong", "COOP configured"
		},
	},
	{
		Name:     "Cross-Origin-Resource-Policy",
		Required: false,
		Weight:   5,
		Check: func(v string) (string, string) {
			if v == "" {
				return "info", "CORP not set"
			}
			return "strong", "CORP configured"
		},
	},
	{
		Name:     "Cross-Origin-Embedder-Policy",
		Required: false,
		Weight:   5,
		Check: func(v string) (string, string) {
			if v == "" {
				return "info", "COEP not set"
			}
			return "strong", "COEP configured"
		},
	},
}

// ScanSecurity checks security headers
func ScanSecurity(target string) (*SecurityInfo, error) {
	resp, err := sendProbe(target, "GET", "/", nil)
	if err != nil {
		return nil, fmt.Errorf("probe failed: %w", err)
	}
	defer resp.Body.Close()

	info := &SecurityInfo{
		Headers:        make(map[string]string),
		MissingHeaders: make([]string, 0),
		Details:        make([]SecurityDetail, 0),
	}

	totalWeight := 0
	achievedWeight := 0

	for _, sh := range securityHeaders {
		totalWeight += sh.Weight
		value := resp.Header.Get(sh.Name)

		status, message := "info", ""
		if sh.Check != nil {
			status, message = sh.Check(value)
		}

		detail := SecurityDetail{
			Header:  sh.Name,
			Value:   value,
			Status:  status,
			Message: message,
		}
		info.Details = append(info.Details, detail)

		if value != "" {
			info.Headers[sh.Name] = value
		}

		switch status {
		case "strong":
			achievedWeight += sh.Weight
		case "weak":
			achievedWeight += sh.Weight / 2
		case "missing":
			if sh.Required {
				info.MissingHeaders = append(info.MissingHeaders, sh.Name)
			}
		}
	}

	if totalWeight > 0 {
		info.Score = int(float64(achievedWeight) / float64(totalWeight) * 100)
	}

	return info, nil
}

// --- Full Scanner -----------------------------------------------------------

func Scan(target string, port int) (*ScanResult, error) {
	start := time.Now()

	result := &ScanResult{
		Target:   target,
		ScanTime: start,
	}

	// TLS scan
	tlsInfo, err := ScanTLS(target, port)
	if err == nil {
		result.TLS = tlsInfo
	}

	// HTTP scan
	httpTarget := fmt.Sprintf("http://%s", net.JoinHostPort(target, strconv.Itoa(port)))
	httpInfo, err := ScanHTTP(httpTarget)
	if err == nil {
		result.HTTP = httpInfo
	}

	// WAF scan
	wafInfo, err := ScanWAF(httpTarget)
	if err == nil {
		result.WAF = wafInfo
	}

	// Security scan
	secInfo, err := ScanSecurity(httpTarget)
	if err == nil {
		result.Security = secInfo
	}

	// Calculate risk score
	result.Vulns = calculateVulns(result)
	result.RiskScore = calculateRiskScore(result)

	result.Duration = time.Since(start)
	return result, nil
}

func calculateVulns(r *ScanResult) []Vuln {
	var vulns []Vuln

	// TLS vulnerabilities
	if r.TLS != nil {
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsExpired {
			vulns = append(vulns, Vuln{
				ID: "TLS-001", Severity: "critical",
				Title:       "Expired SSL/TLS Certificate",
				Description: fmt.Sprintf("Certificate expired on %s", r.TLS.Certificate.NotAfter.Format("2006-01-02")),
				Remediation: "Renew the certificate immediately",
			})
		}
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsSelfSigned {
			vulns = append(vulns, Vuln{
				ID: "TLS-002", Severity: "high",
				Title:       "Self-Signed Certificate",
				Description: "Certificate is self-signed, not trusted by browsers",
				Remediation: "Use a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.)",
			})
		}
		for _, v := range r.TLS.Vulnerabilities {
			vulns = append(vulns, Vuln{
				ID: "TLS-003", Severity: "high",
				Title:       v,
				Description: v,
				Remediation: "Disable weak cipher suites and protocols",
			})
		}
		if r.TLS.Version == "TLS 1.0" || r.TLS.Version == "TLS 1.1" {
			vulns = append(vulns, Vuln{
				ID: "TLS-004", Severity: "high",
				Title:       "Deprecated TLS Version",
				Description: fmt.Sprintf("Server supports %s which has known vulnerabilities", r.TLS.Version),
				Remediation: "Disable TLS 1.0 and TLS 1.1, use TLS 1.2+",
			})
		}
	}

	// Security header vulnerabilities
	if r.Security != nil {
		for _, h := range r.Security.MissingHeaders {
			vulns = append(vulns, Vuln{
				ID:          "SEC-" + strings.ReplaceAll(strings.ToLower(h), "-", ""),
				Severity:    "medium",
				Title:       fmt.Sprintf("Missing %s header", h),
				Description: fmt.Sprintf("The %s security header is not set", h),
				Remediation: fmt.Sprintf("Add '%s' header to HTTP responses", h),
			})
		}
	}

	// CORS vulnerabilities
	if r.HTTP != nil && r.HTTP.CORS != nil && r.HTTP.CORS.IsPermissive {
		vulns = append(vulns, Vuln{
			ID: "CORS-001", Severity: "medium",
			Title:       "Permissive CORS Policy",
			Description: fmt.Sprintf("Access-Control-Allow-Origin: %s", r.HTTP.CORS.AllowOrigin),
			Remediation: "Restrict CORS to specific trusted origins",
		})
	}

	// WAF absence
	if r.WAF != nil && !r.WAF.Detected {
		vulns = append(vulns, Vuln{
			ID: "WAF-001", Severity: "info",
			Title:       "No WAF Detected",
			Description: "No Web Application Firewall detected in front of the server",
			Remediation: "Consider deploying a WAF (Cloudflare, AWS WAF, ModSecurity, etc.)",
		})
	}

	return vulns
}

func calculateRiskScore(r *ScanResult) int {
	score := 100 // start at 100 (safe), subtract for issues

	if r.TLS != nil {
		if !r.TLS.IsSecure {
			score -= 20
		}
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsExpired {
			score -= 30
		}
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsSelfSigned {
			score -= 15
		}
		if r.TLS.Version == "TLS 1.0" || r.TLS.Version == "TLS 1.1" {
			score -= 15
		}
	}

	if r.Security != nil {
		score -= (100 - r.Security.Score) / 5
	}

	for _, v := range r.Vulns {
		switch v.Severity {
		case "critical":
			score -= 25
		case "high":
			score -= 15
		case "medium":
			score -= 8
		case "low":
			score -= 3
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// --- Helpers ----------------------------------------------------------------

func sendProbe(target, method, path string, headers http.Header) (*http.Response, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	u.Path = path

	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, err
	}

	if headers != nil {
		for k, vs := range headers {
			for _, v := range vs {
				req.Header.Set(k, v)
			}
		}
	}
	req.Header.Set("User-Agent", "stress-strike-scanner/1.0")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client.Do(req)
}

// SortBysort.Slice helper for Vulns
type BySeverity []Vuln

func (v BySeverity) Len() int { return len(v) }
func (v BySeverity) Less(i, j int) bool {
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	return severityOrder[v[i].Severity] < severityOrder[v[j].Severity]
}
func (v BySeverity) Swap(i, j int) { v[i], v[j] = v[j], v[i] }

func init() {
	sort.Sort(BySeverity(nil))
}
