package core

import (
	"net/http"
	"net/url"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/fingerprint"
)

// DefaultFingerprint is the TLS ClientHello profile every scanner subpackage
// uses unless a caller overrides it. The zero value (Default) means "use Go's
// stock hello". The CLI sets it via scanner.SetFingerprint -- for example
// --tls-fingerprint chrome_133 -- so the scanner presents a browser hello.
var DefaultFingerprint fingerprint.Profile

// SetFingerprint changes the default TLS ClientHello profile for all scanners
// built through NewHTTPClient / SendProbe. It is safe to call before any scan
// starts; it is not safe to call concurrently with in-flight probes.
func SetFingerprint(p fingerprint.Profile) {
	DefaultFingerprint = p
}

// SendProbe sends a single HTTP request and returns the response.
// It is used by all scanner subpackages (tls, waf, http, security).
func SendProbe(target, method, path string, headers http.Header) (*http.Response, error) {
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
	ApplyHeaders(req, DefaultFingerprint)

	client := NewHTTPClient(DefaultFingerprint, 10*time.Second, false)

	return client.Do(req)
}
