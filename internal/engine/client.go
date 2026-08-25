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

// checkRedirect caps redirect chains and refuses to leave the original host.
var checkRedirect = func(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errRedirectLimitReached
	}
	if len(via) > 0 && req.URL.Host != via[0].URL.Host {
		return http.ErrUseLastResponse
	}
	return nil
}

// newTransport builds the shared connection transport. One instance is reused
// by every HTTP client (including per-user cookie-jar clients), so pooled
// sockets, TLS sessions and HTTP/2 state stay shared.
func newTransport(keepAlive bool, maxConnsPerHost int) *http.Transport {
	if maxConnsPerHost < 256 {
		maxConnsPerHost = 256
	}
	if maxConnsPerHost > 20000 {
		maxConnsPerHost = 20000
	}
	return &http.Transport{
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
		ReadBufferSize:        16 << 10, // fewer syscalls on large responses
		DisableKeepAlives:     !keepAlive,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Reuse TLS sessions across connections: resumed handshakes skip
			// most of the round trips, cutting per-connection CPU and latency
			// under heavy churn. Security posture is unchanged (TLS >= 1.2).
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
		},
	}
}

// clientForJar returns an http.Client bound to jar (nil jar = no cookies).
// The heavy transport is always shared; only the lightweight Client wrapper
// differs per virtual user.
func (e *Engine) clientForJar(jar http.CookieJar, timeout time.Duration) *http.Client {
	if jar == nil {
		return e.client
	}
	return &http.Client{
		Transport:     e.transport,
		Jar:           jar,
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
	}
}
