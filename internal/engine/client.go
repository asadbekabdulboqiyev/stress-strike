package engine

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/fingerprint"
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

// baseTransport shares the common transport configuration. When tlsFP names a
// fingerprint, outgoing connections present that ClientHello instead of Go's
// default one, so the engine can mimic a real browser or platform at the TLS
// layer (measurable via JA3).
func baseTransport(keepAlive bool, tlsFP fingerprint.Profile) *http.Transport {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   1,
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
	if tlsFP != "" {
		// Go's transport can only recover the negotiated ALPN protocol from a
		// real *tls.Conn, never from a custom DialTLSContext result. uTLS
		// connections are not *tls.Conn, so HTTP/2 would silently fall back to
		// HTTP/1.1 over an h2-negotiated socket and fail. Presenting a browser
		// fingerprint therefore pins the connection to HTTP/1.1 — a fair trade,
		// since most browsers open plenty of HTTP/1.1 connections anyway.
		tr.ForceAttemptHTTP2 = false
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
		tr.DialTLSContext = fingerprint.NewDialer(fingerprint.Options{
			Fingerprint: tlsFP,
			// Keep session resumption working when masquerading: uTLS keeps
			// its own cache, so repeated connections skip most of the
			// handshake just like the standard stack.
			SessionCache: utls.NewLRUClientSessionCache(0),
			NextProtos:   []string{"http/1.1"},
		})
	}
	return tr
}

// newTransport builds the shared connection transport. One instance is reused
// by every HTTP client (including per-user cookie-jar clients), so pooled
// sockets, TLS sessions and HTTP/2 state stay shared.
func newTransport(keepAlive bool, maxConnsPerHost int, tlsFP fingerprint.Profile) *http.Transport {
	if maxConnsPerHost < 256 {
		maxConnsPerHost = 256
	}
	if maxConnsPerHost > 20000 {
		maxConnsPerHost = 20000
	}
	tr := baseTransport(keepAlive, tlsFP)
	tr.MaxIdleConns = maxConnsPerHost * 2
	tr.MaxIdleConnsPerHost = maxConnsPerHost
	tr.MaxConnsPerHost = maxConnsPerHost
	return tr
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
