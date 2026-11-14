package bounty

// canonical.go — the deterministic JSON encoding used for package digests.
//
// Two verifiers must derive the same bytes for the same manifest, so the
// digest is computed over an encoding with:
//
//   - object members in ascending byte order (recursively),
//   - minimal RFC 8259 string escaping (", \, and C0 controls only),
//   - integers only: a float64 has no single textual rendering, so any
//     fractional or exponent notation is rejected rather than normalised.
//
// This mirrors the conventions of internal/attest. That package's encoder is
// unexported, so the same rules are reimplemented here over encoding/json's
// generic value model. The manifest contains only strings, integers, booleans
// and arrays, which is why the generic model is sufficient.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// canonicalizeJSON re-encodes raw JSON canonically. It rejects floats and
// trailing data so a hostile document cannot have two readings.
func canonicalizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("bounty: canonicalize: %w", err)
	}
	if dec.More() {
		return nil, errors.New("bounty: canonicalize: trailing JSON data")
	}

	var buf bytes.Buffer
	if err := writeCanonicalValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonicalValue renders one generic JSON value canonically.
func writeCanonicalValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, x)
	case json.Number:
		if !isCanonicalInteger(string(x)) {
			return fmt.Errorf("bounty: canonicalize: %q is not an integer", string(x))
		}
		buf.WriteString(string(x))
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonicalValue(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("bounty: canonicalize: unsupported JSON value %T", v)
	}
	return nil
}

// isCanonicalInteger reports whether s is a base-10 integer literal with no
// sign for zero, no leading zeros, no fraction and no exponent.
func isCanonicalInteger(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' {
		s = s[1:]
		if s == "" {
			return false
		}
	}
	if s == "0" {
		return true
	}
	if s[0] < '1' || s[0] > '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// writeCanonicalString writes s with the minimal escaping allowed by RFC 8259.
// Non-ASCII text is emitted verbatim; only ", \, and C0 controls are escaped.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			buf.WriteString(`\"`)
		case c == '\\':
			buf.WriteString(`\\`)
		case c == '\n':
			buf.WriteString(`\n`)
		case c == '\r':
			buf.WriteString(`\r`)
		case c == '\t':
			buf.WriteString(`\t`)
		case c == '\b':
			buf.WriteString(`\b`)
		case c == '\f':
			buf.WriteString(`\f`)
		case c < 0x20:
			buf.WriteString(`\u00`)
			buf.WriteByte(hexDigits[c>>4])
			buf.WriteByte(hexDigits[c&0x0f])
		default:
			buf.WriteByte(c)
		}
	}
	buf.WriteByte('"')
}
