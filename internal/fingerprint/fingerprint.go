// Package fingerprint lets the engine masquerade its TLS ClientHello as a
// known web client (Chrome, Firefox, Safari, ...). It is built on top of
// github.com/refraction-networking/utls, which re-implements client-side TLS
// so the ClientHello spec (ciphers, extensions, curves, GREASE, ordering) can
// be chosen freely instead of using Go's distinctive hello.
//
// JA3 computation is done locally from the raw ClientHello record so the
// dialect can be verified and documented without any external service.
package fingerprint

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Profile is a named TLS fingerprint preset. The empty string means "leave the
// Go stack untouched".
type Profile string

const (
	// Default disables fingerprinting and uses crypto/tls as usual.
	Default Profile = ""

	// Golang is the plain Go ClientHello (useful as a baseline in tests).
	Golang Profile = "golang"

	Chrome           Profile = "chrome"
	Chrome120        Profile = "chrome_120"
	Chrome133        Profile = "chrome_133"
	Firefox          Profile = "firefox"
	Firefox102       Profile = "firefox_102"
	Safari           Profile = "safari"
	Edge             Profile = "edge"
	IOS              Profile = "ios"
	AndroidOkHttp    Profile = "android_okhttp"
	Randomized       Profile = "randomized"
	RandomizedALPN   Profile = "randomized_alpn"
	RandomizedNoALPN Profile = "randomized_noalpn"
)

var profileIDs = map[Profile]utls.ClientHelloID{
	Golang:           utls.HelloGolang,
	Chrome:           utls.HelloChrome_Auto,
	Chrome120:        utls.HelloChrome_120,
	Chrome133:        utls.HelloChrome_133,
	Firefox:          utls.HelloFirefox_Auto,
	Firefox102:       utls.HelloFirefox_102,
	Safari:           utls.HelloSafari_Auto,
	Edge:             utls.HelloEdge_Auto,
	IOS:              utls.HelloIOS_Auto,
	AndroidOkHttp:    utls.HelloAndroid_11_OkHttp,
	Randomized:       utls.HelloRandomized,
	RandomizedALPN:   utls.HelloRandomizedALPN,
	RandomizedNoALPN: utls.HelloRandomizedNoALPN,
}

// Names returns every valid profile name, including the empty default.
func Names() []string {
	out := []string{string(Default)}
	for p := range profileIDs {
		out = append(out, string(p))
	}
	sort.Strings(out)
	return out
}

// Valid reports whether p is a known fingerprint profile ("" is valid).
func (p Profile) Valid() bool {
	if p == Default {
		return true
	}
	_, ok := profileIDs[p]
	return ok
}

// Options configures NewDialer.
type Options struct {
	// Fingerprint is the ClientHello profile to present.
	Fingerprint Profile
	// Dialer performs the TCP part of the dial. Zero value means a 10s /
	// 30s keep-alive dialer.
	Dialer net.Dialer
	// HandshakeTimeout bounds the whole TCP+TLS dial. Zero means 10s.
	HandshakeTimeout time.Duration
	// InsecureSkipVerify disables server certificate verification. The
	// production engine keeps this off; tests against self-signed servers
	// flip it.
	InsecureSkipVerify bool
	// SessionCache, when set, enables TLS session resumption across dials.
	// Session resumption against rebuilt presets requires the preset to ship
	// a PreSharedKey extension; leave SessionResume false to skip it.
	SessionCache utls.ClientSessionCache
	// SessionResume, when true, enables TLS session resumption. Requires
	// SessionCache. Off by default because browser presets rebuilt via
	// UTLSIdToSpec do not carry a usable PSK extension, and uTLS panics on
	// the mismatch.
	SessionResume bool
	// NextProtos overrides the ALPN list. Defaults to ["h2","http/1.1"].
	NextProtos []string
}

func (o Options) resolved() Options {
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 10 * time.Second
	}
	if o.Dialer.Timeout == 0 {
		o.Dialer.Timeout = 10 * time.Second
	}
	if o.Dialer.KeepAlive == 0 {
		o.Dialer.KeepAlive = 30 * time.Second
	}
	if len(o.NextProtos) == 0 {
		o.NextProtos = []string{"h2", "http/1.1"}
	}
	return o
}

// NewDialer returns a DialTLSContext-compatible dialer that presents the
// configured ClientHello fingerprint. The returned connection performs the
// real TLS handshake with uTLS, so the caller gets a fully usable net.Conn.
func NewDialer(opts Options) func(ctx context.Context, network, addr string) (net.Conn, error) {
	opts = opts.resolved()
	id, ok := profileIDs[opts.Fingerprint]
	if !ok {
		// Default profile means dialing is never routed here; reaching this
		// branch is a programming error, so make it loud rather than silent.
		panic("fingerprint: unknown profile " + string(opts.Fingerprint))
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := opts.Dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host := hostname(addr)
		cfg := &utls.Config{
			ServerName:         host,
			MinVersion:         utls.VersionTLS12,
			InsecureSkipVerify: opts.InsecureSkipVerify,
			NextProtos:         opts.NextProtos,
		}
		if opts.SessionResume && opts.SessionCache != nil {
			cfg.ClientSessionCache = opts.SessionCache
		} else {
			cfg.SessionTicketsDisabled = true
		}
		// Presets hard-code the browser's ALPN list (typically h2, http/1.1).
		// Go's http.Transport can't recover the negotiated protocol from a
		// uTLS conn, so h2-negotiated sockets break. Rebuild the preset spec
		// from the ID and pin ALPN to the caller's list (HTTP/1.1 for the
		// engine). JA3 ignores ALPN contents, so the fingerprint is unchanged.
		u := utls.UClient(raw, cfg, id)
		if spec, specErr := utls.UTLSIdToSpec(id); specErr == nil {
			replaced := false
			for i := range spec.Extensions {
				if alpn, ok := spec.Extensions[i].(*utls.ALPNExtension); ok {
					alpn.AlpnProtocols = opts.NextProtos
					replaced = true
				}
			}
			if !replaced {
				spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: opts.NextProtos})
			}
			u = utls.UClient(raw, cfg, utls.HelloCustom)
			if err := u.ApplyPreset(&spec); err != nil {
				_ = raw.Close()
				return nil, err
			}
		}
		hctx, cancel := context.WithTimeout(ctx, opts.HandshakeTimeout)
		defer cancel()
		if err := u.HandshakeContext(hctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return u, nil
	}
}

// hostname extracts the host part of a host:port address, degrading to the
// input when split fails (no SNI will then be sent).
func hostname(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
}
