// Package core provides low-level scanner primitives. transport.go adds a
// single, fingerprint-aware HTTP client constructor so every scanner
// subpackage (Guard, crawler, vuln_scanner, dirbust, sslscan, pentest helpers)
// presents a consistent TLS ClientHello instead of Go's distinctive hello.
package core

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/fingerprint"
)

// NewHTTPClient builds an *http.Client that, when profile is non-empty,
// performs the TLS handshake with uTLS presenting the given ClientHello
// fingerprint (chrome_133, firefox, safari, ...). It also attaches the
// matching browser User-Agent and Client Hint headers so the TLS fingerprint
// and the HTTP headers tell the same story.
//
// timeout bounds each request; insecure skips server certificate verification
// (used against self-signed lab targets, never production).
func NewHTTPClient(profile fingerprint.Profile, timeout time.Duration, insecure bool) *http.Client {
	if profile == fingerprint.Default {
		profile = DefaultFingerprint
	}

	tr := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}, // #nosec G402 -- caller opts in for authorized scanner targets
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Only install the uTLS dialer when a real fingerprint profile is active.
	// The empty/default profile keeps Go's stock TLS hello (no masquerading).
	if profile != fingerprint.Default {
		tr.DialTLSContext = fingerprint.NewDialer(fingerprint.Options{
			Fingerprint:        profile,
			InsecureSkipVerify: insecure, // #nosec G402 -- caller opts in for authorized scanner targets
			NextProtos:         []string{"h2", "http/1.1"},
		})
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Headers cannot be stored on *http.Client; callers apply them per-request
	// via ApplyHeaders, or wrap client.Transport with DefaultHeaderHook.
	return client
}

// DefaultHeaderHook is a RoundTripper wrapper that stamps the profile's
// User-Agent and Client Hints onto every request. Wrap a client's Transport
// with it when headers cannot be set at call time.
type DefaultHeaderHook struct {
	Base    http.RoundTripper
	Profile fingerprint.Profile
}

func (h DefaultHeaderHook) RoundTrip(req *http.Request) (*http.Response, error) {
	base := h.Base
	if base == nil {
		base = http.DefaultTransport
	}
	ApplyHeaders(req, h.Profile)
	return base.RoundTrip(req)
}

// ApplyHeaders stamps the profile's UA and Client Hints onto req. Call before
// client.Do(req).
func ApplyHeaders(req *http.Request, profile fingerprint.Profile) {
	if req.Header.Get("User-Agent") == "" {
		if ua := fingerprint.UAFor(profile); ua != "" {
			req.Header.Set("User-Agent", ua)
		}
	}
	for k, v := range fingerprint.HeadersFor(profile) {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
}

// SameHost reports whether two URLs identify the same host, ignoring scheme,
// port and path. It is the shared host-identity primitive used by the crawl and
// passive-check code paths so both agree on what "same host" means without
// duplicating the comparison at every call site.
func SameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Host, b.Host)
}
