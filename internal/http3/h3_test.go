package http3

import (
	"testing"
	"time"
)

func TestProbeResultFields(t *testing.T) {
	res := &ProbeResult{
		Host:        "example.com",
		Port:        443,
		AltSvcH3:    true,
		H3Reachable: true,
		H3Latency:   12 * time.Millisecond,
		Negotiated:  "h3",
		Error:       "",
	}
	if res.Host != "example.com" {
		t.Errorf("host = %q, want example.com", res.Host)
	}
	if res.Port != 443 {
		t.Errorf("port = %d, want 443", res.Port)
	}
	if !res.AltSvcH3 {
		t.Error("alt_svc_h3 should be true")
	}
	if !res.H3Reachable {
		t.Error("h3_reachable should be true")
	}
	if res.Negotiated != "h3" {
		t.Errorf("negotiated = %q, want h3", res.Negotiated)
	}
}

func TestIsAltSvcH3(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{`alt-svc: h3=":443"; ma=86400`, true},
		{`alt-svc: h3-29=":443"; ma=86400`, true},
		{`alt-svc: h3=":443"; ma=86400, h3-29=":443"; ma=86400`, true},
		{`alt-svc: h3-27=":443"; ma=86400`, false},
		{`cache-control: max-age=3600`, false},
		{`content-type: text/html`, false},
		{``, false},
	}
	for _, c := range cases {
		got := isAltSvcH3(c.line)
		if got != c.want {
			t.Errorf("isAltSvcH3(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestLower(t *testing.T) {
	if lower("ALT-SVC") != "alt-svc" {
		t.Error("lower failed")
	}
	if lower("Alt-Svc") != "alt-svc" {
		t.Error("lower failed")
	}
	if lower("alt-svc") != "alt-svc" {
		t.Error("lower failed")
	}
}

func TestContains(t *testing.T) {
	if !contains("hello world", "world") {
		t.Error("contains should find world")
	}
	if contains("hello world", "xyz") {
		t.Error("contains should not find xyz")
	}
	if !contains("", "") {
		t.Error("contains empty in empty should be true")
	}
}

func TestSplitLines(t *testing.T) {
	lines := splitLines("a\nb\nc")
	if len(lines) != 3 || lines[0] != "a" || lines[1] != "b" || lines[2] != "c" {
		t.Errorf("splitLines = %v, want [a b c]", lines)
	}
	lines = splitLines("single")
	if len(lines) != 1 || lines[0] != "single" {
		t.Errorf("splitLines = %v, want [single]", lines)
	}
}
