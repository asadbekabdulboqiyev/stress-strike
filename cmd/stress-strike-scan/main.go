package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

func main() {
	target := flag.String("target", "", "Target host to scan (e.g. example.com)")
	port := flag.Int("port", 443, "Target port")
	outputJSON := flag.String("output-json", "", "Export results to JSON file")
	scanAll := flag.Bool("all", false, "Run all scans (TLS + HTTP + WAF + Security)")
	tlsOnly := flag.Bool("tls", false, "TLS scan only")
	httpOnly := flag.Bool("http", false, "HTTP fingerprint only")
	wafOnly := flag.Bool("waf", false, "WAF detection only")
	securityOnly := flag.Bool("security", false, "Security headers only")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
╔═══════════════════════════════════════════════════════════════╗
║  stress-strike scan — TLS/WAF Deep Scanner + Fingerprinting  ║
║                                                               ║
║  Scan servers for:                                            ║
║  • TLS cipher suites, cert chain, version vulnerabilities     ║
║  • WAF fingerprinting (Cloudflare, Akamai, AWS WAF, etc.)    ║
║  • HTTP technology detection (server, frameworks, languages)  ║
║  • Security headers audit (HSTS, CSP, CORS, etc.)           ║
║  • Vulnerability detection with risk scoring                 ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
  stress-strike-scan -target example.com [flags]

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  # Full scan
  stress-strike-scan -target example.com -all

  # TLS scan only
  stress-strike-scan -target example.com -port 443 -tls

  # WAF detection
  stress-strike-scan -target example.com -waf

  # Security headers audit
  stress-strike-scan -target example.com -security

  # Export to JSON
  stress-strike-scan -target example.com -all -output-json scan.json
`)
	}

	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: -target flag is required")
		flag.Usage()
		os.Exit(1)
	}

	// Default to all if no specific flag
	if !*tlsOnly && !*httpOnly && !*wafOnly && !*securityOnly {
		*scanAll = true
	}

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  stress-strike scan — Deep Security Scanner                  ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Target: %s:%d\n", *target, *port)
	fmt.Println()

	start := time.Now()

	result := &scanner.ScanResult{
		Target:   *target,
		ScanTime: start,
	}

	// TLS Scan
	if *scanAll || *tlsOnly {
		fmt.Println("  [1/4] TLS Scan...")
		tlsInfo, err := scanner.ScanTLS(*target, *port)
		if err != nil {
			fmt.Printf("    ⚠ TLS scan error: %v\n", err)
		} else {
			result.TLS = tlsInfo
			printTLSInfo(tlsInfo)
		}
	}

	// HTTP Fingerprint
	httpTarget := fmt.Sprintf("http://%s:%d", *target, *port)
	if *scanAll || *httpOnly {
		fmt.Println("  [2/4] HTTP Fingerprint...")
		httpInfo, err := scanner.ScanHTTP(httpTarget)
		if err != nil {
			fmt.Printf("    ⚠ HTTP scan error: %v\n", err)
		} else {
			result.HTTP = httpInfo
			printHTTPInfo(httpInfo)
		}
	}

	// WAF Detection
	if *scanAll || *wafOnly {
		fmt.Println("  [3/4] WAF Detection...")
		wafInfo, err := scanner.ScanWAF(httpTarget)
		if err != nil {
			fmt.Printf("    ⚠ WAF scan error: %v\n", err)
		} else {
			result.WAF = wafInfo
			printWAFInfo(wafInfo)
		}
	}

	// Security Headers
	if *scanAll || *securityOnly {
		fmt.Println("  [4/4] Security Headers...")
		secInfo, err := scanner.ScanSecurity(httpTarget)
		if err != nil {
			fmt.Printf("    ⚠ Security scan error: %v\n", err)
		} else {
			result.Security = secInfo
			printSecurityInfo(secInfo)
		}
	}

	result.Duration = time.Since(start)

	// Vulnerabilities
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  VULNERABILITIES & RISK SCORE")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	result.Vulns = calculateVulns(result)
	result.RiskScore = calculateRiskScore(result)

	for _, v := range result.Vulns {
		severityIcon := map[string]string{
			"critical": "🔴",
			"high":     "🟠",
			"medium":   "🟡",
			"low":      "🔵",
			"info":     "⚪",
		}
		fmt.Printf("  %s [%s] %s\n", severityIcon[v.Severity], strings.ToUpper(v.Severity), v.Title)
		fmt.Printf("     %s\n", v.Description)
		if v.Remediation != "" {
			fmt.Printf("     Fix: %s\n", v.Remediation)
		}
		fmt.Println()
	}

	// Risk Score
	riskColor := "🟢"
	if result.RiskScore < 70 {
		riskColor = "🟡"
	}
	if result.RiskScore < 40 {
		riskColor = "🟠"
	}
	if result.RiskScore < 20 {
		riskColor = "🔴"
	}

	fmt.Printf("  %s Risk Score: %d/100\n", riskColor, result.RiskScore)
	fmt.Printf("  Scan Duration: %s\n", result.Duration.Round(time.Millisecond))
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// Export JSON
	if *outputJSON != "" {
		f, err := os.Create(*outputJSON)
		if err != nil {
			fmt.Printf("  ⚠ Failed to create JSON: %v\n", err)
		} else {
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			enc.Encode(result)
			fmt.Printf("\n  JSON report: %s\n", *outputJSON)
		}
	}
}

func printTLSInfo(t *scanner.TLSInfo) {
	fmt.Printf("    Version: %s\n", t.Version)
	fmt.Printf("    Cipher Suite: %s\n", t.CipherSuite)
	fmt.Printf("    Secure: %v\n", t.IsSecure)
	fmt.Printf("    Forward Secrecy: %v\n", t.ForwardSecrecy)
	fmt.Printf("    HTTP/2: %v\n", t.HTTP2Supported)
	if t.Certificate != nil {
		fmt.Printf("    Certificate Subject: %s\n", t.Certificate.Subject)
		fmt.Printf("    Certificate Issuer: %s\n", t.Certificate.Issuer)
		fmt.Printf("    Key Type: %s %d-bit\n", t.Certificate.KeyType, t.Certificate.KeySize)
		fmt.Printf("    Expires: %s (expired=%v)\n", t.Certificate.NotAfter.Format("2006-01-02"), t.Certificate.IsExpired)
	}
	if len(t.SupportedVersions) > 0 {
		fmt.Printf("    Supported: %s\n", strings.Join(t.SupportedVersions, ", "))
	}
	fmt.Println()
}

func printHTTPInfo(h *scanner.HTTPInfo) {
	fmt.Printf("    Server: %s\n", h.Server)
	fmt.Printf("    X-Powered-By: %s\n", h.XPoweredBy)
	fmt.Printf("    HTTP Version: %s\n", h.HTTPVersion)
	if len(h.Technologies) > 0 {
		fmt.Printf("    Technologies: %s\n", strings.Join(h.Technologies, ", "))
	}
	if len(h.Methods) > 0 {
		fmt.Printf("    Allowed Methods: %s\n", strings.Join(h.Methods, ", "))
	}
	if h.CORS != nil && h.CORS.AllowOrigin != "" {
		fmt.Printf("    CORS Origin: %s\n", h.CORS.AllowOrigin)
	}
	fmt.Println()
}

func printWAFInfo(w *scanner.WAFInfo) {
	if w.Detected {
		fmt.Printf("    Detected: ✅ %s (%s)\n", w.Name, w.Vendor)
		fmt.Printf("    Confidence: %d%%\n", w.Confidence)
		if len(w.Indicators) > 0 {
			fmt.Printf("    Indicators: %s\n", strings.Join(w.Indicators[:min(5, len(w.Indicators))], ", "))
		}
	} else {
		fmt.Println("    Detected: ❌ No WAF found")
	}
	fmt.Println()
}

func printSecurityInfo(s *scanner.SecurityInfo) {
	fmt.Printf("    Score: %d/100\n", s.Score)
	for _, d := range s.Details {
		icon := "✅"
		switch d.Status {
		case "missing":
			icon = "❌"
		case "weak":
			icon = "⚠️ "
		case "info":
			icon = "ℹ️ "
		}
		val := d.Value
		if val == "" {
			val = "(not set)"
		}
		fmt.Printf("    %s %s: %s\n", icon, d.Header, val)
	}
	if len(s.MissingHeaders) > 0 {
		fmt.Printf("    Missing: %s\n", strings.Join(s.MissingHeaders, ", "))
	}
	fmt.Println()
}

func calculateVulns(r *scanner.ScanResult) []scanner.Vuln {
	var vulns []scanner.Vuln

	if r.TLS != nil {
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsExpired {
			vulns = append(vulns, scanner.Vuln{
				ID: "TLS-001", Severity: "critical",
				Title:       "Expired SSL/TLS Certificate",
				Description: "Certificate expired on " + r.TLS.Certificate.NotAfter.Format("2006-01-02"),
				Remediation: "Renew the certificate immediately",
			})
		}
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsSelfSigned {
			vulns = append(vulns, scanner.Vuln{
				ID: "TLS-002", Severity: "high",
				Title:       "Self-Signed Certificate",
				Description: "Certificate is self-signed, not trusted by browsers",
				Remediation: "Use a certificate from a trusted CA",
			})
		}
		if r.TLS.Version == "TLS 1.0" || r.TLS.Version == "TLS 1.1" {
			vulns = append(vulns, scanner.Vuln{
				ID: "TLS-003", Severity: "high",
				Title:       "Deprecated TLS Version",
				Description: "Server supports " + r.TLS.Version + " which has known vulnerabilities",
				Remediation: "Disable TLS 1.0 and 1.1, use TLS 1.2+",
			})
		}
	}

	if r.Security != nil {
		for _, h := range r.Security.MissingHeaders {
			vulns = append(vulns, scanner.Vuln{
				ID:          "SEC-" + strings.ReplaceAll(strings.ToUpper(h), "-", ""),
				Severity:    "medium",
				Title:       "Missing " + h + " header",
				Description: "The " + h + " security header is not set",
				Remediation: "Add '" + h + "' header to HTTP responses",
			})
		}
	}

	if r.HTTP != nil && r.HTTP.CORS != nil && r.HTTP.CORS.IsPermissive {
		vulns = append(vulns, scanner.Vuln{
			ID: "CORS-001", Severity: "medium",
			Title:       "Permissive CORS Policy",
			Description: "Access-Control-Allow-Origin: " + r.HTTP.CORS.AllowOrigin,
			Remediation: "Restrict CORS to specific trusted origins",
		})
	}

	return vulns
}

func calculateRiskScore(r *scanner.ScanResult) int {
	score := 100

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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
