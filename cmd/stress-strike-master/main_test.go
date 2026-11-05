package main

import (
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
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

func TestErrorRate(t *testing.T) {
	if got := errorRate(0, 0); got != 0 {
		t.Errorf("errorRate(0,0) = %f, want 0", got)
	}
	if got := errorRate(100, 0); got != 0 {
		t.Errorf("errorRate(100,0) = %f, want 0", got)
	}
	if got := errorRate(100, 5); got != 5.0 {
		t.Errorf("errorRate(100,5) = %f, want 5.0", got)
	}
	if got := errorRate(100, 100); got != 100.0 {
		t.Errorf("errorRate(100,100) = %f, want 100.0", got)
	}
	if got := errorRate(-1, 5); got != 0 {
		t.Errorf("errorRate(-1,5) = %f, want 0", got)
	}
}

func TestMax64(t *testing.T) {
	if got := max64(10, 20); got != 20 {
		t.Errorf("max64(10,20) = %d, want 20", got)
	}
	if got := max64(20, 10); got != 20 {
		t.Errorf("max64(20,10) = %d, want 20", got)
	}
	if got := max64(5, 5); got != 5 {
		t.Errorf("max64(5,5) = %d, want 5", got)
	}
	if got := max64(-5, -10); got != -5 {
		t.Errorf("max64(-5,-10) = %d, want -5", got)
	}
}

func TestSplitComma(t *testing.T) {
	got := splitComma("a,b,c")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitComma = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("splitComma[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	got = splitComma("single")
	if len(got) != 1 || got[0] != "single" {
		t.Errorf("splitComma(single) = %v, want [single]", got)
	}
	got = splitComma("")
	if len(got) != 1 || got[0] != "" {
		t.Errorf("splitComma(\"\") = %v, want [\"\"]", got)
	}
}

func TestTrimSpace(t *testing.T) {
	if got := trimSpace("  hello  "); got != "hello" {
		t.Errorf("trimSpace(  hello  ) = %q, want hello", got)
	}
	if got := trimSpace("\t\ttab\t"); got != "tab" {
		t.Errorf("trimSpace(tab) = %q, want tab", got)
	}
	if got := trimSpace("   "); got != "" {
		t.Errorf("trimSpace(   ) = %q, want empty", got)
	}
	if got := trimSpace(""); got != "" {
		t.Errorf("trimSpace(\"\") = %q, want empty", got)
	}
	if got := trimSpace("no spaces"); got != "no spaces" {
		t.Errorf("trimSpace(no spaces) = %q, want no spaces", got)
	}
}

func TestSplitAndTrim(t *testing.T) {
	got := splitAndTrim(" a , b , c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitAndTrim = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("splitAndTrim[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	got = splitAndTrim("  ,  ,  ")
	if len(got) != 0 {
		t.Errorf("splitAndTrim(only spaces) = %v, want empty", got)
	}
}

func TestFormatCount(t *testing.T) {
	if got := formatCount(0); got != "0" {
		t.Errorf("formatCount(0) = %q, want 0", got)
	}
	if got := formatCount(999); got != "999" {
		t.Errorf("formatCount(999) = %q, want 999", got)
	}
	if got := formatCount(1500); got != "1.5K" {
		t.Errorf("formatCount(1500) = %q, want 1.5K", got)
	}
	if got := formatCount(1_000_000); got != "1.0M" {
		t.Errorf("formatCount(1000000) = %q, want 1.0M", got)
	}
	if got := formatCount(2_500_000); got != "2.5M" {
		t.Errorf("formatCount(2500000) = %q, want 2.5M", got)
	}
}

func TestFormatRPS(t *testing.T) {
	if got := formatRPS(0); got != "0" {
		t.Errorf("formatRPS(0) = %q, want 0", got)
	}
	if got := formatRPS(50); got != "50" {
		t.Errorf("formatRPS(50) = %q, want 50", got)
	}
	if got := formatRPS(1500); got != "1.5K" {
		t.Errorf("formatRPS(1500) = %q, want 1.5K", got)
	}
	if got := formatRPS(10000); got != "10.0K" {
		t.Errorf("formatRPS(10000) = %q, want 10.0K", got)
	}
}

func TestSlaEmpty(t *testing.T) {
	if !slaEmpty(nil) {
		t.Error("slaEmpty(nil) should be true")
	}
	if !slaEmpty(&config.SLA{}) {
		t.Error("slaEmpty(empty SLA) should be true")
	}
	if slaEmpty(&config.SLA{MaxP99Ms: 100}) {
		t.Error("slaEmpty(SLA with MaxP99Ms) should be false")
	}
	if slaEmpty(&config.SLA{MaxAvgMs: 50}) {
		t.Error("slaEmpty(SLA with MaxAvgMs) should be false")
	}
	if slaEmpty(&config.SLA{MaxErrorRatePct: 1}) {
		t.Error("slaEmpty(SLA with MaxErrorRatePct) should be false")
	}
	if slaEmpty(&config.SLA{MinRPS: 10}) {
		t.Error("slaEmpty(SLA with MinRPS) should be false")
	}
}
