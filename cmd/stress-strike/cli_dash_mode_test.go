package main

import (
	"testing"
)

// --- dash_mode.go helpers --------------------------------------------------

func TestGetS(t *testing.T) {
	m := map[string]interface{}{
		"name":  "alice",
		"count": 5,
		"flag":  true,
	}
	if got := getS(m, "name"); got != "alice" {
		t.Errorf("getS(name) = %q, want alice", got)
	}
	if got := getS(m, "missing"); got != "" {
		t.Errorf("getS(missing) = %q, want empty", got)
	}
	if got := getS(m, "count"); got != "" {
		t.Errorf("getS(count) = %q, want empty (not a string)", got)
	}
	if got := getS(m, "flag"); got != "" {
		t.Errorf("getS(flag) = %q, want empty (bool not string)", got)
	}
	if got := getS(nil, "any"); got != "" {
		t.Errorf("getS(nil) = %q, want empty", got)
	}
}

func TestGetI(t *testing.T) {
	m := map[string]interface{}{
		"count": 5,
		"ratio": 3.14,
		"name":  "alice",
		"flag":  true,
	}
	if got := getI(m, "count"); got != 5 {
		t.Errorf("getI(count) = %d, want 5", got)
	}
	if got := getI(m, "ratio"); got != 3 {
		t.Errorf("getI(ratio) = %d, want 3", got)
	}
	if got := getI(m, "missing"); got != 0 {
		t.Errorf("getI(missing) = %d, want 0", got)
	}
	if got := getI(m, "name"); got != 0 {
		t.Errorf("getI(name) = %d, want 0 (string not int)", got)
	}
	if got := getI(nil, "any"); got != 0 {
		t.Errorf("getI(nil) = %d, want 0", got)
	}
}
