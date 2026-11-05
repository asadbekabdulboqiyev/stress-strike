package main

import (
	"strings"
	"testing"
)

func TestParseAuthorizedKeysEmpty(t *testing.T) {
	pins, err := parseAuthorizedKeys("")
	if err != nil {
		t.Fatalf("parseAuthorizedKeys(\"\") unexpected error: %v", err)
	}
	if pins != nil {
		t.Errorf("parseAuthorizedKeys(\"\") = %v, want nil", pins)
	}
}

func TestParseAuthorizedKeysSingle(t *testing.T) {
	a64 := strings.Repeat("a", 64)
	pins, err := parseAuthorizedKeys("worker1=" + a64)
	if err != nil {
		t.Fatalf("parseAuthorizedKeys single unexpected error: %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("len(pins) = %d, want 1", len(pins))
	}
	if v, ok := pins["worker1"]; !ok || v != a64 {
		t.Errorf("pins[worker1] = %q, want %q", v, a64)
	}
}

func TestParseAuthorizedKeysMultiple(t *testing.T) {
	a64 := strings.Repeat("a", 64)
	b64 := strings.Repeat("b", 64)
	c64 := strings.Repeat("c", 64)
	pins, err := parseAuthorizedKeys("w1=" + a64 + ", w2=" + b64 + ", w3=" + c64)
	if err != nil {
		t.Fatalf("parseAuthorizedKeys multiple unexpected error: %v", err)
	}
	if len(pins) != 3 {
		t.Fatalf("len(pins) = %d, want 3", len(pins))
	}
	if v, ok := pins["w2"]; !ok || v != b64 {
		t.Errorf("pins[w2] = %q, want %q", v, b64)
	}
}

func TestParseAuthorizedKeysInvalidFormat(t *testing.T) {
	_, err := parseAuthorizedKeys("invalid")
	if err == nil {
		t.Error("expected error for invalid entry")
	}
}

func TestParseAuthorizedKeysEmptyKey(t *testing.T) {
	_, err := parseAuthorizedKeys("w1=")
	if err == nil {
		t.Error("expected error for empty key")
	}
}

func TestParseAuthorizedKeysDuplicate(t *testing.T) {
	a64 := strings.Repeat("a", 64)
	b64 := strings.Repeat("b", 64)
	_, err := parseAuthorizedKeys("w1=" + a64 + ",w1=" + b64)
	if err == nil {
		t.Error("expected error for duplicate worker id")
	}
}
