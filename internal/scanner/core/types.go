package core

import "time"

// ScanResult is the top-level output of a complete scan.
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

// Vuln is a single finding from a scan.
type Vuln struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"` // critical, high, medium, low, info
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// TLSInfo contains the results of a TLS scan.
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

// CertInfo describes a single TLS certificate.
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

// CipherInfo describes a single TLS cipher suite.
type CipherInfo struct {
	Name  string `json:"name"`
	ID    uint16 `json:"id"`
	Grade string `json:"grade"` // A, B, C, D, F
	FS    bool   `json:"forward_secrecy"`
	AEAD  bool   `json:"aead"`
}

// WAFInfo contains the results of a WAF detection scan.
type WAFInfo struct {
	Detected   bool              `json:"detected"`
	Name       string            `json:"name"`
	Vendor     string            `json:"vendor"`
	Version    string            `json:"version"`
	Confidence float64           `json:"confidence"` // 0-100
	Headers    map[string]string `json:"headers"`
	Indicators []string          `json:"indicators"`
}

// HTTPInfo contains the results of an HTTP scan.
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

// CORSInfo describes CORS policy findings.
type CORSInfo struct {
	AllowOrigin  string `json:"allow_origin"`
	AllowMethods string `json:"allow_methods"`
	AllowHeaders string `json:"allow_headers"`
	Credentials  bool   `json:"credentials"`
	MaxAge       string `json:"max_age"`
	IsPermissive bool   `json:"is_permissive"`
}

// SecurityInfo contains the results of a security-header scan.
type SecurityInfo struct {
	Headers        map[string]string `json:"headers"`
	MissingHeaders []string          `json:"missing_headers"`
	Score          int               `json:"score"` // 0-100
	Details        []SecurityDetail  `json:"details"`
}

// SecurityDetail describes a single security-header check result.
type SecurityDetail struct {
	Header  string `json:"header"`
	Value   string `json:"value"`
	Status  string `json:"status"` // present, missing, weak, strong
	Message string `json:"message"`
}

// BySeverity sorts Vuln by severity (critical → info).
type BySeverity []Vuln

func (v BySeverity) Len() int { return len(v) }
func (v BySeverity) Less(i, j int) bool {
	order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	return order[v[i].Severity] < order[v[j].Severity]
}
func (v BySeverity) Swap(i, j int) { v[i], v[j] = v[j], v[i] }
