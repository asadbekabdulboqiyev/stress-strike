package main

import (
	"strings"
	"testing"
)

func TestFlagStringsStringAndSet(t *testing.T) {
	var fs flagStrings
	if fs.String() != "" {
		t.Errorf("String() = %q, want empty", fs.String())
	}

	if err := fs.Set("a"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("b"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("c"); err != nil {
		t.Fatal(err)
	}

	got := fs.String()
	want := "a,b,c"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if len(fs) != 3 {
		t.Errorf("len(fs) = %d, want 3", len(fs))
	}
	if !strings.Contains(got, "b") {
		t.Errorf("String() = %q does not contain b", got)
	}
}
