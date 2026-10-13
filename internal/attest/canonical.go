package attest

// canonical.go — the deterministic, float-free encoding that everything else
// in the protocol hangs off.
//
// # Why a hand-written encoder
//
// The entire trust story reduces to one requirement: two parties holding the
// same logical value must derive the *same bytes*, because those bytes are
// what gets hashed and signed. Standard JSON is not canonical — object members
// may appear in any order, numbers may be written 1, 1.0 or 1e0, and escaping
// is optional — so encoding the domain types with encoding/json and signing
// the output would let an attacker (or a different Go version, or a different
// language) produce a byte string that verifies as something it is not.
//
// This file therefore encodes values through a tiny restricted model:
//
//   - object : keys emitted in ascending byte order, no duplicate keys;
//   - array  : declared order preserved;
//   - string : minimal RFC 8259 escaping (", \, and C0 controls only);
//   - number : integers only, in decimal, no sign for zero, no exponents;
//   - bool   : true / false.
//
// # Floats are banned
//
// A float64 has no single textual rendering: 0.1, 0.10 and 1e-1 all parse to
// the same value but hash differently, and the shortest-round-trip formatter
// that produces "0.1" is a language implementation detail. Decimal quantities
// in this protocol (requests per second) are therefore carried as exact
// decimal *strings* with a fixed scale — see Decimal.
//
// # Integer arithmetic
//
// Every derived number in the protocol (requests per second, parts-per-million
// pacing accuracy, intended-schedule offsets, dropped samples) is computed
// with MulDivFloor / MulDivRound below, which use a 128-bit intermediate and
// return an error instead of overflowing. A verifier that recomputes a value
// therefore reaches bit-identical results to the producer on every platform,
// and a hostile input can never make a conversion wrap silently.

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strconv"
	"unicode/utf8"
)

// -----------------------------------------------------------------------------
// Restricted value model
// -----------------------------------------------------------------------------

// cval is a node of the restricted canonical value model.
type cval interface {
	writeCanonical(*bytes.Buffer)
}

// cObject is a JSON object. Member order is normalised at write time, which is
// what makes insertion order irrelevant to the digest.
type cObject map[string]cval

// cArray is a JSON array in declared order.
type cArray []cval

// cString is a JSON string. Values are validated (UTF-8) when the cval tree is
// built, so writeCanonical cannot fail.
type cString string

// cInt is a signed JSON integer.
type cInt int64

// cUint is an unsigned JSON integer (counts, which may legitimately exceed the
// signed range in a long soak run).
type cUint uint64

// cBool is a JSON boolean.
type cBool bool

func (o cObject) writeCanonical(b *bytes.Buffer) {
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		appendJSONString(b, k)
		b.WriteByte(':')
		o[k].writeCanonical(b)
	}
	b.WriteByte('}')
}

func (a cArray) writeCanonical(b *bytes.Buffer) {
	b.WriteByte('[')
	for i, v := range a {
		if i > 0 {
			b.WriteByte(',')
		}
		v.writeCanonical(b)
	}
	b.WriteByte(']')
}

func (s cString) writeCanonical(b *bytes.Buffer) { appendJSONString(b, string(s)) }

func (n cInt) writeCanonical(b *bytes.Buffer) {
	b.WriteString(strconv.FormatInt(int64(n), 10))
}

func (n cUint) writeCanonical(b *bytes.Buffer) {
	b.WriteString(strconv.FormatUint(uint64(n), 10))
}

func (v cBool) writeCanonical(b *bytes.Buffer) {
	if v {
		b.WriteString("true")
		return
	}
	b.WriteString("false")
}

// appendJSONString writes s as a JSON string literal using the minimal
// escaping allowed by RFC 8259 §7: only the quotation mark, the reverse solidus
// and the C0 control characters are escaped, everything else (including
// non-ASCII text and U+2028/U+2029) is emitted verbatim as UTF-8. A canonical
// encoder must pick exactly one escaping for every input; this is that pick,
// and it is documented here because an independent implementation must match
// it byte for byte.
func appendJSONString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c < 0x20:
			b.WriteString(`\u00`)
			const hexDigits = "0123456789abcdef"
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}

// cstr validates and wraps a string. Invalid UTF-8 is rejected: Go's JSON
// decoder silently replaces malformed sequences with U+FFFD, which would make
// a round trip through json.Decoder produce different bytes than were signed.
func cstr(s string) (cString, error) {
	if !utf8.ValidString(s) {
		return "", errors.New("string is not valid UTF-8")
	}
	return cString(s), nil
}

// encode renders a cval tree to canonical bytes. It cannot fail: every
// validation happens while the tree is built.
func encode(v cval) []byte {
	var b bytes.Buffer
	v.writeCanonical(&b)
	return b.Bytes()
}

// -----------------------------------------------------------------------------
// Exact decimal quantities
// -----------------------------------------------------------------------------

// decimalScale is the number of fractional digits in every Decimal.
const decimalScale = 3

// Decimal is an exact, non-negative decimal quantity rendered as a JSON string
// with exactly three fractional digits: "1000.000", "0.000", "1234.567".
//
// Three digits are enough to express requests per second (a millirequest is
// already far below the resolution of any real measurement) and to compare
// rates without a float ever entering the protocol. Because the value travels
// as a string, the canonical digest covers the exact digits that were signed:
// there is no "1" vs "1.000" ambiguity.
//
// Decimal values are compared as strings. Two Decimals are equal if and only
// if their bytes are equal, so producers must use DecimalFromMilli,
// DecimalFromRatio or NewDecimalMilliScale and never format a float with %f.
type Decimal string

// DecimalFromMilli renders a value already scaled by 10^3 ("milli units") as a
// Decimal. It is the exact constructor: DecimalFromMilli(1_000_000) is
// "1000.000". Negative values are rejected — no quantity in the protocol is
// allowed to be negative.
func DecimalFromMilli(milli int64) (Decimal, error) {
	if milli < 0 {
		return "", fmt.Errorf("decimal: value %d is negative", milli)
	}
	return Decimal(fmt.Sprintf("%d.%03d", milli/1000, milli%1000)), nil
}

// NewDecimalMilliScale renders a value scaled by 10^3 as a Decimal. It is a
// spelling of DecimalFromMilli for readers who prefer the scaled-unit name.
func NewDecimalMilliScale(milli int64) (Decimal, error) { return DecimalFromMilli(milli) }

// DecimalFromRatio renders num/den rounded half away from zero to three
// fractional digits (num/den * 1000 milli units). It errors — never wraps —
// when den is zero or the result does not fit in the scaled 64-bit range.
func DecimalFromRatio(num, den uint64) (Decimal, error) {
	milli, err := MulDivRound(num, 1000, den)
	if err != nil {
		return "", fmt.Errorf("decimal ratio %d/%d: %w", num, den, err)
	}
	if milli > uint64(1<<62) {
		return "", fmt.Errorf("decimal ratio %d/%d overflows the scaled range", num, den)
	}
	return DecimalFromMilli(int64(milli))
}

// Milli parses the Decimal back into scaled units (value × 10^3). The input
// must be in canonical form: no sign, no exponent, no leading zeros beyond a
// single "0", and exactly three fractional digits.
func (d Decimal) Milli() (int64, error) {
	s := string(d)
	dot := -1
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '.':
			if dot >= 0 {
				return 0, fmt.Errorf("decimal %q: more than one decimal point", s)
			}
			dot = i
		case c >= '0' && c <= '9':
			// digit: handled below
		default:
			return 0, fmt.Errorf("decimal %q: invalid character %q", s, c)
		}
	}
	if dot < 0 {
		return 0, fmt.Errorf("decimal %q: missing decimal point", s)
	}
	whole, frac := s[:dot], s[dot+1:]
	if len(frac) != decimalScale {
		return 0, fmt.Errorf("decimal %q: want %d fractional digits, got %d", s, decimalScale, len(frac))
	}
	if len(whole) == 0 || len(frac) == 0 {
		return 0, fmt.Errorf("decimal %q: malformed", s)
	}
	if len(whole) > 1 && whole[0] == '0' {
		return 0, fmt.Errorf("decimal %q: leading zeros are not canonical", s)
	}
	v, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decimal %q: %w", s, err)
	}
	f, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decimal %q: %w", s, err)
	}
	if v > (1<<62)/1000 {
		return 0, fmt.Errorf("decimal %q: out of range", s)
	}
	return v*1000 + f, nil
}

// Valid reports whether d is a canonical Decimal.
func (d Decimal) Valid() bool {
	_, err := d.Milli()
	return err == nil
}

// String returns the canonical rendering.
func (d Decimal) String() string { return string(d) }

// -----------------------------------------------------------------------------
// Overflow-checked integer arithmetic
// -----------------------------------------------------------------------------

// MulDivFloor returns floor(a*b/d) using a 128-bit intermediate product. It
// returns an error (never panics, never wraps) when d is zero or when the
// quotient does not fit in a uint64.
//
// Every derived quantity in the protocol is computed with this function, so a
// producer and a verifier agree bit for bit on values that a float would round
// differently on different platforms.
func MulDivFloor(a, b, d uint64) (uint64, error) {
	if d == 0 {
		return 0, errors.New("muldiv: division by zero")
	}
	hi, lo := bits.Mul64(a, b)
	if hi >= d {
		return 0, fmt.Errorf("muldiv: %d*%d/%d overflows 64 bits", a, b, d)
	}
	q, _ := bits.Div64(hi, lo, d)
	return q, nil
}

// MulDivRound returns a*b/d rounded half away from zero. Like MulDivFloor it
// is total: it reports an error instead of wrapping or panicking.
func MulDivRound(a, b, d uint64) (uint64, error) {
	if d == 0 {
		return 0, errors.New("muldiv: division by zero")
	}
	hi, lo := bits.Mul64(a, b)
	lo, carry := bits.Add64(lo, d/2, 0)
	hi += carry
	if hi >= d {
		return 0, fmt.Errorf("muldiv: %d*%d/%d overflows 64 bits", a, b, d)
	}
	q, _ := bits.Div64(hi, lo, d)
	return q, nil
}
