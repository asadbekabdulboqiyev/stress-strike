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
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
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
				raw.Close()
				return nil, err
			}
		}
		hctx, cancel := context.WithTimeout(ctx, opts.HandshakeTimeout)
		defer cancel()
		if err := u.HandshakeContext(hctx); err != nil {
			raw.Close()
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

// JA3FromRecord computes the JA3 string and its MD5 hash from a raw TLS
// record that contains a ClientHello handshake message (as sent by a client).
func JA3FromRecord(record []byte) (string, string, error) {
	const recordHeader, handshakeHeader = 5, 4
	if len(record) < recordHeader {
		return "", "", fmt.Errorf("record too short")
	}
	if record[0] != 0x16 { // handshake record type
		return "", "", fmt.Errorf("not a handshake record (type 0x%02x)", record[0])
	}
	recordLen := int(record[3])<<8 | int(record[4])
	if len(record) < recordHeader+handshakeHeader {
		return "", "", fmt.Errorf("record truncated")
	}
	hs := record[recordHeader:]
	if recordLen+recordHeader > len(record) {
		return "", "", fmt.Errorf("record header says %d bytes, have %d", recordLen, len(record)-recordHeader)
	}
	if hs[0] != 0x01 { // clientHello
		return "", "", fmt.Errorf("not a ClientHello (0x%02x)", hs[0])
	}
	bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if bodyLen != recordLen-handshakeHeader {
		return "", "", fmt.Errorf("message/record length mismatch")
	}
	h := hs[handshakeHeader:]
	if len(h) < bodyLen {
		return "", "", fmt.Errorf("handshake body truncated")
	}
	h = h[:bodyLen]
	off := 2 // legacy version
	if len(h) < off+32 {
		return "", "", fmt.Errorf("random missing")
	}
	version := int(h[off-2])<<8 | int(h[off-1])
	off += 32
	if off >= len(h) {
		return "", "", fmt.Errorf("session id length missing")
	}
	sidLen := int(h[off])
	off++
	if off+sidLen > len(h) {
		return "", "", fmt.Errorf("session id out of range")
	}
	off += sidLen
	if off+2 > len(h) {
		return "", "", fmt.Errorf("cipher suites length missing")
	}
	csLen := int(h[off])<<8 | int(h[off+1])
	off += 2
	if off+csLen > len(h) {
		return "", "", fmt.Errorf("cipher suites out of range")
	}
	ciphers := h[off : off+csLen]
	off += csLen
	if off >= len(h) {
		return "", "", fmt.Errorf("compression length missing")
	}
	compLen := int(h[off])
	off++
	if off+compLen > len(h) {
		return "", "", fmt.Errorf("compression methods out of range")
	}
	off += compLen

	var extTypes []int
	var groups []int
	var points []int

	if off+2 <= len(h) {
		extLen := int(h[off])<<8 | int(h[off+1])
		off += 2
		if off+extLen > len(h) {
			return "", "", fmt.Errorf("extensions out of range")
		}
		for i := 0; i+4 <= extLen; {
			typ := int(h[off+i])<<8 | int(h[off+i+1])
			elo := int(h[off+i+2])<<8 | int(h[off+i+3])
			extTypes = append(extTypes, typ)
			if i+4+elo > extLen {
				return "", "", fmt.Errorf("extension %d body out of range", typ)
			}
			data := h[off+i+4 : off+i+4+elo]
			switch typ {
			case 0x000a: // supported_groups
				for j := 0; j+2 <= len(data); j += 2 {
					groups = append(groups, int(data[j])<<8|int(data[j+1]))
				}
			case 0x000b: // ec_point_formats: first byte is the count
				for _, f := range data[1:] {
					points = append(points, int(f))
				}
			}
			i += 4 + elo
		}
	}

	ja3 := strings.Join([]string{
		strconv.Itoa(version),
		joinU16(ciphers),
		joinInts(extTypes),
		joinInts(groups),
		joinInts(points),
	}, ",")
	sum := md5.Sum([]byte(ja3))
	return ja3, hex.EncodeToString(sum[:]), nil
}

func joinU16(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(b[i])<<8 | int(b[i+1])))
	}
	return sb.String()
}

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, "-")
}
