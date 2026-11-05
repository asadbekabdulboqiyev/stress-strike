// Package security implements security-header scanning for the stress-strike scanner.
package security

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner/core"
)

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

var SecurityHeaders = []struct {
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
				fmt.Sscanf(matches[1], "%d", &maxAge)
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

// ScanSecurity checks security headers against the target URL.
func ScanSecurity(target string) (*core.SecurityInfo, error) {
	resp, err := core.SendProbe(target, "GET", "/", nil)
	if err != nil {
		return nil, fmt.Errorf("probe failed: %w", err)
	}
	defer resp.Body.Close()

	info := &core.SecurityInfo{
		Headers:        make(map[string]string),
		MissingHeaders: make([]string, 0),
		Details:        make([]core.SecurityDetail, 0),
	}

	totalWeight := 0
	achievedWeight := 0

	for _, sh := range SecurityHeaders {
		totalWeight += sh.Weight
		value := resp.Header.Get(sh.Name)

		status, message := "info", ""
		if sh.Check != nil {
			status, message = sh.Check(value)
		}

		detail := core.SecurityDetail{
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
