// Package http implements HTTP fingerprinting for the stress-strike scanner.
package http

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner/core"
)

// HTTPInfo contains the results of an HTTP scan.
type HTTPInfo struct {
	Server       string            `json:"server"`
	XPoweredBy   string            `json:"x_powered_by"`
	Technologies []string          `json:"technologies"`
	CORS         *core.CORSInfo    `json:"cors"`
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

// ScanHTTP performs HTTP fingerprinting against the target URL.
func ScanHTTP(target string) (*core.HTTPInfo, error) {
	info := &core.HTTPInfo{
		Technologies: make([]string, 0),
		Headers:      make(map[string]string),
		Cookies:      make([]string, 0),
		Methods:      make([]string, 0),
	}

	resp, err := core.SendProbe(target, "GET", "/", nil)
	if err != nil {
		return info, fmt.Errorf("probe failed: %w", err)
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		if len(values) > 0 {
			info.Headers[key] = values[0]
		}
	}

	info.Server = resp.Header.Get("Server")
	info.XPoweredBy = resp.Header.Get("X-Powered-By")
	info.HTTPVersion = resp.Proto

	for _, cookie := range resp.Cookies() {
		info.Cookies = append(info.Cookies, cookie.Name)
	}

	info.CORS = &core.CORSInfo{
		AllowOrigin:  resp.Header.Get("Access-Control-Allow-Origin"),
		AllowMethods: resp.Header.Get("Access-Control-Allow-Methods"),
		AllowHeaders: resp.Header.Get("Access-Control-Allow-Headers"),
		Credentials:  resp.Header.Get("Access-Control-Allow-Credentials") == "true",
		MaxAge:       resp.Header.Get("Access-Control-Max-Age"),
	}
	if info.CORS.AllowOrigin == "*" {
		info.CORS.IsPermissive = true
	}

	info.Technologies = DetectTechnologies(resp)

	optResp, err := core.SendProbe(target, "OPTIONS", "/", nil)
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

func DetectTechnologies(resp *http.Response) []string {
	var techs []string

	server := strings.ToLower(resp.Header.Get("Server"))
	poweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))

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

	for _, cookie := range resp.Cookies() {
		name := strings.ToLower(cookie.Name)
		if strings.Contains(name, "phpsessid") {
			if !ContainsTech(techs, "PHP") {
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

func ContainsTech(techs []string, tech string) bool {
	for _, t := range techs {
		if strings.EqualFold(t, tech) {
			return true
		}
	}
	return false
}
