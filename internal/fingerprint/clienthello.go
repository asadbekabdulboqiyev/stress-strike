package fingerprint

// clienthello.go — one parser for TLS ClientHello records, shared by the JA3
// and JA4 derivations.
//
// Both fingerprints are computed from the same bytes, so the offset walk lives
// here exactly once. A single parser also means a malformed record is rejected
// identically by both functions instead of one of them silently accepting a
// truncated extension block.

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// clientHello is the subset of a ClientHello that JA3 and JA4 need.
type clientHello struct {
	// legacyVersion is the 2-byte version field in the ClientHello body.
	legacyVersion int

	// ciphers holds every cipher suite exactly as offered (GREASE included);
	// JA3 keeps them verbatim, JA4 filters GREASE out.
	ciphers []uint16

	// extTypes holds every extension type in offer order.
	extTypes []uint16

	// groups and points are the JA3 elliptic-curve fields.
	groups []uint16
	points []uint8

	// supportedVersions comes from extension 43 when present.
	supportedVersions []uint16

	// alpn is the offered ALPN protocol list (extension 16).
	alpn []string

	// sigAlgs is the signature_algorithms list (extension 13), offer order.
	sigAlgs []uint16

	// hasSNI reports whether a server_name extension was sent, and sniIsIP
	// whether its value is an IP literal rather than a hostname.
	hasSNI  bool
	sniIsIP bool
}

// parseClientHello walks a raw TLS record containing a ClientHello.
func parseClientHello(record []byte) (*clientHello, error) {
	const recordHeader, handshakeHeader = 5, 4
	if len(record) < recordHeader {
		return nil, fmt.Errorf("record too short")
	}
	if record[0] != 0x16 { // handshake record type
		return nil, fmt.Errorf("not a handshake record (type 0x%02x)", record[0])
	}
	recordLen := int(record[3])<<8 | int(record[4])
	if len(record) < recordHeader+handshakeHeader {
		return nil, fmt.Errorf("record truncated")
	}
	hs := record[recordHeader:]
	if recordLen+recordHeader > len(record) {
		return nil, fmt.Errorf("record header says %d bytes, have %d", recordLen, len(record)-recordHeader)
	}
	if hs[0] != 0x01 { // clientHello
		return nil, fmt.Errorf("not a ClientHello (0x%02x)", hs[0])
	}
	bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if bodyLen != recordLen-handshakeHeader {
		return nil, fmt.Errorf("message/record length mismatch")
	}
	h := hs[handshakeHeader:]
	if len(h) < bodyLen {
		return nil, fmt.Errorf("handshake body truncated")
	}
	h = h[:bodyLen]

	ch := &clientHello{}
	off := 2 // legacy version
	if len(h) < off+32 {
		return nil, fmt.Errorf("random missing")
	}
	ch.legacyVersion = int(h[off-2])<<8 | int(h[off-1])
	off += 32
	if off >= len(h) {
		return nil, fmt.Errorf("session id length missing")
	}
	sidLen := int(h[off])
	off++
	if off+sidLen > len(h) {
		return nil, fmt.Errorf("session id out of range")
	}
	off += sidLen
	if off+2 > len(h) {
		return nil, fmt.Errorf("cipher suites length missing")
	}
	csLen := int(h[off])<<8 | int(h[off+1])
	off += 2
	if off+csLen > len(h) || csLen%2 != 0 {
		return nil, fmt.Errorf("cipher suites out of range")
	}
	for i := off; i < off+csLen; i += 2 {
		ch.ciphers = append(ch.ciphers, uint16(h[i])<<8|uint16(h[i+1]))
	}
	off += csLen
	if off >= len(h) {
		return nil, fmt.Errorf("compression length missing")
	}
	compLen := int(h[off])
	off++
	if off+compLen > len(h) {
		return nil, fmt.Errorf("compression methods out of range")
	}
	off += compLen

	if off+2 > len(h) {
		return ch, nil // no extensions block: valid for very old hellos
	}
	extLen := int(h[off])<<8 | int(h[off+1])
	off += 2
	if off+extLen > len(h) {
		return nil, fmt.Errorf("extensions out of range")
	}
	for i := 0; i+4 <= extLen; {
		typ := uint16(h[off+i])<<8 | uint16(h[off+i+1])
		elo := int(h[off+i+2])<<8 | int(h[off+i+3])
		ch.extTypes = append(ch.extTypes, typ)
		if i+4+elo > extLen {
			return nil, fmt.Errorf("extension %d body out of range", typ)
		}
		data := h[off+i+4 : off+i+4+elo]
		switch typ {
		case 0x0000: // server_name
			ch.hasSNI = true
			// ServerNameList: uint16 list length, then entries of
			// (type uint8, length uint16, value).
			if len(data) >= 5 && data[2] == 0x00 {
				n := int(data[3])<<8 | int(data[4])
				if 5+n <= len(data) {
					host := string(data[5 : 5+n])
					ch.sniIsIP = net.ParseIP(host) != nil
				}
			}
		case 0x000a: // supported_groups
			ch.groups = parseU16List(data)
		case 0x000b: // ec_point_formats: first byte is the count
			if len(data) > 1 {
				for _, f := range data[1:] {
					ch.points = append(ch.points, f)
				}
			}
		case 0x000d: // signature_algorithms
			ch.sigAlgs = parseU16List(data)
		case 0x0010: // ALPN
			if len(data) >= 2 {
				n := int(data[0])<<8 | int(data[1])
				for j := 2; j+2 <= len(data) && j < 2+n; {
					l := int(data[j])
					j++
					if j+l > len(data) {
						break
					}
					ch.alpn = append(ch.alpn, string(data[j:j+l]))
					j += l
				}
			}
		case 0x002b: // supported_versions
			if len(data) >= 1 {
				n := int(data[0])
				for j := 1; j+2 <= len(data) && j < 1+n; j += 2 {
					ch.supportedVersions = append(ch.supportedVersions, uint16(data[j])<<8|uint16(data[j+1]))
				}
			}
		}
		i += 4 + elo
	}
	return ch, nil
}

// parseU16List decodes a TLS vector of uint16 values. RFC 8446 encodes these
// with a 2-byte length prefix; a few hand-rolled encoders (and the golden-test
// fixture) omit the prefix and put the values directly in the extension body.
// The prefix form is used whenever it is self-consistent; otherwise the whole
// body is read as a value list so such hellos still fingerprint the same way.
func parseU16List(data []byte) []uint16 {
	start := 0
	if len(data) >= 2 {
		if n := int(data[0])<<8 | int(data[1]); n == len(data)-2 {
			start = 2
		}
	}
	var out []uint16
	for j := start; j+2 <= len(data); j += 2 {
		out = append(out, uint16(data[j])<<8|uint16(data[j+1]))
	}
	return out
}

// JA3FromRecord computes the JA3 string and its MD5 hash from a raw TLS
// record that contains a ClientHello handshake message (as sent by a client).
func JA3FromRecord(record []byte) (string, string, error) {
	ch, err := parseClientHello(record)
	if err != nil {
		return "", "", err
	}
	ja3 := strings.Join([]string{
		strconv.Itoa(ch.legacyVersion),
		joinU16s(ch.ciphers),
		joinU16s(ch.extTypes),
		joinU16s(ch.groups),
		joinBytes(ch.points),
	}, ",")
	sum := md5.Sum([]byte(ja3))
	return ja3, hex.EncodeToString(sum[:]), nil
}

// JA4FromRecord computes the JA4 fingerprint (a_b_c) from a raw TLS record
// containing a ClientHello, per the FoxIO JA4 specification:
//
//	JA4_a = protocol | version | sni | cipher_count | extension_count | alpn
//	JA4_b = first 12 hex chars of sha256(sorted ciphers)
//	JA4_c = first 12 hex chars of sha256(sorted extensions w/o SNI+ALPN + sigalgs)
//
// GREASE values are excluded everywhere, as the specification requires.
func JA4FromRecord(record []byte) (string, error) {
	ch, err := parseClientHello(record)
	if err != nil {
		return "", err
	}
	return ch.ja4(), nil
}

func (ch *clientHello) ja4() string {
	ciphers := filterGREASE(ch.ciphers)
	exts := filterGREASE(ch.extTypes)

	version := ja4Version(ch.effectiveVersion())
	sni := "n"
	if ch.hasSNI {
		sni = "d"
		if ch.sniIsIP {
			sni = "i"
		}
	}

	a := fmt.Sprintf("t%s%s%02d%02d%s",
		version,
		sni,
		len(ciphers),
		len(exts),
		ja4ALPN(ch.alpn),
	)

	cipherList := make([]string, 0, len(ciphers))
	for _, c := range ciphers {
		cipherList = append(cipherList, fmt.Sprintf("%04x", c))
	}
	sort.Strings(cipherList)
	b := shortSHA256(strings.Join(cipherList, ","))

	// SNI (0x0000) and ALPN (0x0010) are already encoded in JA4_a, so the
	// specification excludes them from the JA4_c extension hash.
	extList := make([]string, 0, len(exts))
	for _, e := range exts {
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		extList = append(extList, fmt.Sprintf("%04x", e))
	}
	sort.Strings(extList)
	sigList := make([]string, 0, len(ch.sigAlgs))
	for _, s := range ch.sigAlgs {
		sigList = append(sigList, fmt.Sprintf("%04x", s))
	}
	c := shortSHA256(strings.Join(extList, ",") + "_" + strings.Join(sigList, ","))

	return a + "_" + b + "_" + c
}

// effectiveVersion prefers the highest supported_versions entry, falling back
// to the legacy version field for hellos older than RFC 8446.
func (ch *clientHello) effectiveVersion() int {
	best := ch.legacyVersion
	for _, v := range ch.supportedVersions {
		if v > 0x0300 && int(v) > best {
			best = int(v)
		}
	}
	return best
}

func ja4Version(v int) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	}
	return "00"
}

// ja4ALPN renders the first ALPN protocol as its first and last character:
// "h2" -> "h2", "http/1.1" -> "h1", absent -> "00".
func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	p := alpn[0]
	if len(p) == 1 {
		return p + p
	}
	return string(p[0]) + string(p[len(p)-1])
}

// isGREASE reports whether v is one of the reserved GREASE code points
// (0x0a0a, 0x1a1a, ... 0xfafa).
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func shortSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func joinU16s(v []uint16) string {
	if len(v) == 0 {
		return ""
	}
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.Itoa(int(x))
	}
	return strings.Join(parts, "-")
}

func joinBytes(v []uint8) string {
	if len(v) == 0 {
		return ""
	}
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.Itoa(int(x))
	}
	return strings.Join(parts, "-")
}
