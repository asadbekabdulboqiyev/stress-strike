package main

import (
	"testing"
)

func TestParseRate(t *testing.T) {
	cases := []struct {
		input string
		want  float64
		ok    bool
	}{
		{"1x", 1.0, true},
		{"5x", 5.0, true},
		{"10x", 10.0, true},
		{"100x", 100.0, true},
		{"0.5x", 0.5, true},
		{"invalid", 0, false},
		{"", 0, false},
		{"abc", 0, false},
	}
	for _, c := range cases {
		got, err := parseRate(c.input)
		if c.ok {
			if err != nil {
				t.Errorf("parseRate(%q) unexpected error: %v", c.input, err)
				continue
			}
			if got != c.want {
				t.Errorf("parseRate(%q) = %v, want %v", c.input, got, c.want)
			}
		} else {
			if err == nil {
				t.Errorf("parseRate(%q) expected error, got %v", c.input, got)
			}
		}
	}
}
