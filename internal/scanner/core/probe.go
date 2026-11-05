package core

import (
	"net/http"
	"net/url"
	"time"
)

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
	req.Header.Set("User-Agent", "stress-strike-scanner/1.0")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client.Do(req)
}
