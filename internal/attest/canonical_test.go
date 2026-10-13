package attest

// canonical_test.go — the deterministic, float-free encoder.

import (
	"bytes"
	"strings"
	"testing"
)

func TestCanonicalKeyOrderIsDeterministic(t *testing.T) {
	a := cObject{"b": cInt(2), "a": cInt(1), "c": cInt(3)}
	b := cObject{"c": cInt(3), "a": cInt(1), "b": cInt(2)}
	ea, eb := encode(a), encode(b)
	if !bytes.Equal(ea, eb) {
		t.Fatalf("insertion order changed the encoding:\n  %s\n  %s", ea, eb)
	}
	if want := `{"a":1,"b":2,"c":3}`; string(ea) != want {
		t.Fatalf("encoding = %s, want %s", ea, want)
	}
}

func TestCanonicalArrayPreservesOrder(t *testing.T) {
	arr := cArray{cInt(3), cInt(1), cInt(2)}
	if got, want := string(encode(arr)), "[3,1,2]"; got != want {
		t.Fatalf("array = %s, want %s", got, want)
	}
}

func TestCanonicalScalarForms(t *testing.T) {
	cases := []struct {
		v    cval
		want string
	}{
		{cInt(0), "0"},
		{cInt(-42), "-42"},
		{cInt(1_000_000), "1000000"},
		{cUint(18446744073709551615), "18446744073709551615"},
		{cBool(true), "true"},
		{cBool(false), "false"},
		{cString(""), `""`},
	}
	for _, tc := range cases {
		if got := string(encode(tc.v)); got != tc.want {
			t.Fatalf("encode(%T) = %s, want %s", tc.v, got, tc.want)
		}
	}
}

// TestCanonicalNeverUsesExponents pins the "no float" property: an integer is
// always rendered in plain decimal, never in scientific notation.
func TestCanonicalNeverUsesExponents(t *testing.T) {
	got := string(encode(cInt(1e15)))
	if strings.ContainsAny(got, "eE.") {
		t.Fatalf("integer encoding contains a float marker: %s", got)
	}
	if got != "1000000000000000" {
		t.Fatalf("encoding = %s", got)
	}
}

func TestCanonicalStringEscaping(t *testing.T) {
	got := string(encode(cString("a\"b\\c\nd\te\x01f")))
	want := `"a\"b\\c\nd\te\u0001f"`
	if got != want {
		t.Fatalf("escaping = %s, want %s", got, want)
	}
	// Non-ASCII text is emitted verbatim as UTF-8, not escaped.
	if got := string(encode(cString("привет"))); got != `"привет"` {
		t.Fatalf("non-ASCII escaping = %s", got)
	}
}

func TestCstrRejectsInvalidUTF8(t *testing.T) {
	if _, err := cstr(string([]byte{0xff, 0xfe})); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
}

func TestDecimalFromMilliAndBack(t *testing.T) {
	cases := []struct {
		milli int64
		want  Decimal
	}{
		{0, "0.000"},
		{1, "0.001"},
		{6500, "6.500"},
		{1_000_000, "1000.000"},
		{1234, "1.234"},
	}
	for _, tc := range cases {
		d, err := DecimalFromMilli(tc.milli)
		if err != nil {
			t.Fatalf("DecimalFromMilli(%d): %v", tc.milli, err)
		}
		if d != tc.want {
			t.Fatalf("DecimalFromMilli(%d) = %q, want %q", tc.milli, d, tc.want)
		}
		if !d.Valid() {
			t.Fatalf("%q is not valid", d)
		}
		back, err := d.Milli()
		if err != nil {
			t.Fatalf("Milli(%q): %v", d, err)
		}
		if back != tc.milli {
			t.Fatalf("Milli(%q) = %d, want %d", d, back, tc.milli)
		}
	}
	if _, err := DecimalFromMilli(-1); err == nil {
		t.Fatal("negative milli accepted")
	}
}

func TestDecimalFromRatio(t *testing.T) {
	cases := []struct {
		num, den uint64
		want     Decimal
	}{
		{1, 3, "0.333"},
		{2, 3, "0.667"},
		{1, 8, "0.125"},
		{1000, 1, "1000.000"},
	}
	for _, tc := range cases {
		d, err := DecimalFromRatio(tc.num, tc.den)
		if err != nil {
			t.Fatalf("DecimalFromRatio(%d,%d): %v", tc.num, tc.den, err)
		}
		if d != tc.want {
			t.Fatalf("DecimalFromRatio(%d,%d) = %q, want %q", tc.num, tc.den, d, tc.want)
		}
	}
	if _, err := DecimalFromRatio(1, 0); err == nil {
		t.Fatal("division by zero accepted")
	}
}

func TestDecimalRejectsNonCanonicalForms(t *testing.T) {
	bad := []string{
		"1000", "1000.0", "1000.0000", "0100.000", ".000", "1000.",
		"-1.000", "1e3.000", "abc", "1000.000.000", " 1.000",
	}
	for _, s := range bad {
		if Decimal(s).Valid() {
			t.Fatalf("%q accepted as a canonical decimal", s)
		}
	}
}

func TestMulDivFloorAndRound(t *testing.T) {
	cases := []struct {
		a, b, d uint64
		floor   uint64
		round   uint64
	}{
		{6, 7, 2, 21, 21},
		{1, 1, 2, 0, 1},
		{5, 1, 2, 2, 3},
		{10, 10, 4, 25, 25},
		{1, 1, 3, 0, 0},
	}
	for _, tc := range cases {
		f, err := MulDivFloor(tc.a, tc.b, tc.d)
		if err != nil {
			t.Fatalf("MulDivFloor(%d,%d,%d): %v", tc.a, tc.b, tc.d, err)
		}
		if f != tc.floor {
			t.Fatalf("MulDivFloor(%d,%d,%d) = %d, want %d", tc.a, tc.b, tc.d, f, tc.floor)
		}
		r, err := MulDivRound(tc.a, tc.b, tc.d)
		if err != nil {
			t.Fatalf("MulDivRound(%d,%d,%d): %v", tc.a, tc.b, tc.d, err)
		}
		if r != tc.round {
			t.Fatalf("MulDivRound(%d,%d,%d) = %d, want %d", tc.a, tc.b, tc.d, r, tc.round)
		}
	}
}

func TestMulDivFailsClosed(t *testing.T) {
	if _, err := MulDivFloor(1, 1, 0); err == nil {
		t.Fatal("floor: division by zero accepted")
	}
	if _, err := MulDivRound(1, 1, 0); err == nil {
		t.Fatal("round: division by zero accepted")
	}
	// (1<<63)*2 overflows 64 bits.
	if _, err := MulDivFloor(1<<63, 2, 1); err == nil {
		t.Fatal("overflow accepted by MulDivFloor")
	}
	if _, err := MulDivRound(1<<63, 2, 1); err == nil {
		t.Fatal("overflow accepted by MulDivRound")
	}
}
