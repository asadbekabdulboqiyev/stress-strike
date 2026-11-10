package main

// version_test.go — the `--version` entry point Dockerfile.master runs at build
// time to prove the image ships a stamped binary rather than a dev build.

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestIsVersionArg(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-version", "-v"} {
		if !isVersionArg(arg) {
			t.Errorf("isVersionArg(%q) = false, want true", arg)
		}
	}
	for _, arg := range []string{"", "healthcheck", "--verbose", "v", "-version=1"} {
		if isVersionArg(arg) {
			t.Errorf("isVersionArg(%q) = true, want false", arg)
		}
	}
}

func TestVersionFlagPrintsAndExitsZero(t *testing.T) {
	prev := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	code := runMasterMain(t, "--version")
	os.Stdout = prev
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	if code != 0 {
		t.Fatalf("--version exit = %d, want 0", code)
	}
	if !strings.Contains(string(out), "stress-strike-master v"+version) {
		t.Errorf("stdout = %q, want the stamped version", out)
	}
}
