package engine

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"
)

const maxRedirects = 10

var errRedirectLimitReached = errors.New("stopped after 10 redirects")

func newClient(timeout time.Duration, keepAlive bool, maxConnsPerHost int) *http.Client {
	if maxConnsPerHost < 256 {
		maxConnsPerHost = 256
	}
	if maxConnsPerHost > 20000 {
		maxConnsPerHost = 20000
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxConnsPerHost * 2,
		MaxIdleConnsPerHost:   maxConnsPerHost,
		MaxConnsPerHost:       maxConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableKeepAlives:     !keepAlive,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errRedirectLimitReached
			}
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
