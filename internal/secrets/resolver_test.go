package secrets

import (
	"os"
	"testing"
)

func TestResolve(t *testing.T) {
	os.Setenv("SS_TEST_VAR", "hello")
	os.Setenv("EMPTY_VAR", "")
	if got := Resolve("${SS_TEST_VAR}"); got != "hello" {
		t.Fatalf("resolve = %q", got)
	}
	if got := Resolve("${SS_TEST_VAR}/world"); got != "hello/world" {
		t.Fatalf("resolve2 = %q", got)
	}
	if got := Resolve("${MISSING:-fallback}"); got != "fallback" {
		t.Fatalf("resolve3 = %q", got)
	}
	if got := Resolve("${EMPTY_VAR:-fallback}"); got != "fallback" {
		t.Fatalf("resolve4 = %q", got)
	}
	if got := Resolve("${SS_TEST_VAR:-fallback}"); got != "hello" {
		t.Fatalf("resolve5 = %q", got)
	}
}
