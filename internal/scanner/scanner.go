package scanner

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner/auth"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner/core"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner/crawl"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner/http"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner/owasp"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner/security"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner/tls"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner/waf"
)

// ScanResult is the top-level output of a complete scan (re-exported from core).
type ScanResult = core.ScanResult

// Vuln is a single finding from a scan (re-exported from core).
type Vuln = core.Vuln

// TLSInfo contains the results of a TLS scan (re-exported from core).
type TLSInfo = core.TLSInfo

// CertInfo describes a single TLS certificate (re-exported from core).
type CertInfo = core.CertInfo

// CipherInfo describes a single TLS cipher suite (re-exported from core).
type CipherInfo = core.CipherInfo

// WAFInfo contains the results of a WAF detection scan (re-exported from core).
type WAFInfo = core.WAFInfo

// HTTPInfo contains the results of an HTTP scan (re-exported from core).
type HTTPInfo = core.HTTPInfo

// CORSInfo describes CORS policy findings (re-exported from core).
type CORSInfo = core.CORSInfo

// SecurityInfo contains the results of a security-header scan (re-exported from core).
type SecurityInfo = core.SecurityInfo

// SecurityDetail describes a single security-header check result (re-exported from core).
type SecurityDetail = core.SecurityDetail

// BySeverity sorts Vuln by severity (re-exported from core).
type BySeverity = core.BySeverity

// AuthType selects how a scan session authenticates against a target
// (re-exported from the auth subpackage).
type AuthType = auth.AuthType

const (
	AuthNone    AuthType = 0 // no authentication
	AuthForm    AuthType = 1 // POST credentials to a login URL, keep session cookies
	AuthCookie  AuthType = 2 // inject a raw Cookie header on every request (static override)
	AuthHeader  AuthType = 3 // inject a static header (e.g. Authorization: Bearer x)
	AuthBrowser AuthType = 4 // headless Chromium: OAuth / deep login flows in browser
)

// AuthConfig configures an authenticated scanning session
// (re-exported from the auth subpackage).
type AuthConfig = auth.AuthConfig

// AuthSession is an authenticated scanning session
// (re-exported from the auth subpackage).
type AuthSession = auth.AuthSession

// NewAuthSession creates an authenticated scanning session from the given
// config. Returns nil when no auth type is configured. Never logs credentials.
func NewAuthSession(cfg AuthConfig, timeout time.Duration) (*AuthSession, error) {
	return auth.NewAuthSession(cfg, timeout)
}

// Endpoint / CrawlResult / CrawlOptions / Crawler are the attack-surface
// crawl primitives (re-exported from the crawl subpackage).
type (
	Endpoint     = crawl.Endpoint
	CrawlResult  = crawl.CrawlResult
	CrawlOptions = crawl.CrawlOptions
)

// Crawler spiders a target to discover endpoints and forms.
type Crawler = crawl.Crawler

// NewCrawler returns a new crawler for the given start URL and options.
func NewCrawler(startURL string, opts CrawlOptions) *Crawler {
	return crawl.NewCrawler(startURL, opts)
}

// OWASP re-exports (facade) — implementation lives in the owasp subpackage.
type (
	OWASPChecker  = owasp.OWASPChecker
	OWASPReport   = owasp.OWASPReport
	OWASPCategory = owasp.OWASPCategory
)

// NewOWASPChecker returns a new OWASP Top 10 checker for the given target.
func NewOWASPChecker(target string) *OWASPChecker {
	return owasp.NewOWASPChecker(target)
}

// Scan performs a full scan on target:port (TLS, HTTP, WAF, Security).
func Scan(target string, port int) (*ScanResult, error) {
	start := time.Now()

	result := &ScanResult{
		Target:   target,
		ScanTime: start,
	}

	// TLS scan
	tlsInfo, err := tls.ScanTLS(target, port)
	if err == nil {
		result.TLS = tlsInfo
	}

	// HTTP scan
	httpTarget := fmt.Sprintf("http://%s", target)
	httpInfo, err := http.ScanHTTP(httpTarget)
	if err == nil {
		result.HTTP = httpInfo
	}

	// WAF scan
	wafInfo, err := waf.ScanWAF(httpTarget)
	if err == nil {
		result.WAF = wafInfo
	}

	// Security scan
	secInfo, err := security.ScanSecurity(httpTarget)
	if err == nil {
		result.Security = secInfo
	}

	// Calculate risk score
	result.Vulns = calculateVulns(result)
	result.RiskScore = calculateRiskScore(result)

	result.Duration = time.Since(start)
	return result, nil
}

// ScanTLS re-exports tls.ScanTLS for backward compatibility.
func ScanTLS(host string, port int) (*TLSInfo, error) {
	return tls.ScanTLS(host, port)
}

// ScanWAF re-exports waf.ScanWAF for backward compatibility.
func ScanWAF(target string) (*WAFInfo, error) {
	return waf.ScanWAF(target)
}

// ScanHTTP re-exports http.ScanHTTP for backward compatibility.
func ScanHTTP(target string) (*HTTPInfo, error) {
	return http.ScanHTTP(target)
}

// ScanSecurity re-exports security.ScanSecurity for backward compatibility.
func ScanSecurity(target string) (*SecurityInfo, error) {
	return security.ScanSecurity(target)
}

func calculateVulns(r *ScanResult) []Vuln {
	var vulns []Vuln

	// TLS vulnerabilities
	if r.TLS != nil {
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsExpired {
			vulns = append(vulns, Vuln{
				ID:          "TLS-001",
				Severity:    "critical",
				Title:       "Expired SSL/TLS Certificate",
				Description: fmt.Sprintf("Certificate expired on %s", r.TLS.Certificate.NotAfter.Format("2006-01-02")),
				Remediation: "Renew the certificate immediately",
			})
		}
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsSelfSigned {
			vulns = append(vulns, Vuln{
				ID:          "TLS-002",
				Severity:    "high",
				Title:       "Self-Signed Certificate",
				Description: "Certificate is self-signed, not trusted by browsers",
				Remediation: "Use a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.)",
			})
		}
		for _, v := range r.TLS.Vulnerabilities {
			vulns = append(vulns, Vuln{
				ID:          "TLS-003",
				Severity:    "high",
				Title:       v,
				Description: v,
				Remediation: "Disable weak cipher suites and protocols",
			})
		}
		if r.TLS.Version == "TLS 1.0" || r.TLS.Version == "TLS 1.1" {
			vulns = append(vulns, Vuln{
				ID:          "TLS-004",
				Severity:    "high",
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
			ID:          "CORS-001",
			Severity:    "medium",
			Title:       "Permissive CORS Policy",
			Description: fmt.Sprintf("Access-Control-Allow-Origin: %s", r.HTTP.CORS.AllowOrigin),
			Remediation: "Restrict CORS to specific trusted origins",
		})
	}

	// WAF absence
	if r.WAF != nil && !r.WAF.Detected {
		vulns = append(vulns, Vuln{
			ID:          "WAF-001",
			Severity:    "info",
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

func init() {
	sort.Sort(BySeverity(nil))
}
