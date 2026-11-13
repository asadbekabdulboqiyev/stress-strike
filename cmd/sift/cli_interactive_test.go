package main

import (
	"bufio"
	"io"
	"os"
	"strings"
	"testing"
)

// --- interactive.go helpers ------------------------------------------------

func TestIsInteractiveTerminal(t *testing.T) {
	// Just verify it returns a bool without panicking (value depends on whether
	// the test is run in a terminal).
	_ = isInteractiveTerminal()
	_ = stdinIsTerminal()
}

func TestStdoutIsColorable(t *testing.T) {
	// NO_COLOR disables color.
	t.Setenv("NO_COLOR", "1")
	if got := stdoutIsColorable(); got {
		t.Error("stdoutIsColorable() = true with NO_COLOR, want false")
	}

	// Without NO_COLOR, stdout in test env is not a char device → false.
	t.Setenv("NO_COLOR", "")
	if got := stdoutIsColorable(); got {
		t.Error("stdoutIsColorable() = true, want false (non-TTY test env)")
	}
}

func TestOpenBrowser(t *testing.T) {
	// openBrowser attempts to launch a browser; _ = cmd.Start() ignores errors.
	// On macOS it runs "open <url>"; on Linux "xdg-open"; on Windows "cmd /c start".
	// We just verify it doesn't panic.
	openBrowser("http://127.0.0.1:8080/")
}

func TestBanner(t *testing.T) {
	// Capture stdout.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	banner()

	w.Close()
	os.Stdout = old

	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), "Sift") {
		t.Errorf("banner missing program name: %q", string(out))
	}
	if !strings.Contains(string(out), buildVersion) {
		t.Errorf("banner missing version: %q", string(out))
	}
}

func TestReadLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("hello world\n"))
	if got := readLine(r, "enter"); got != "hello world" {
		t.Errorf("readLine = %q, want hello world", got)
	}

	// Empty reader (EOF).
	r = bufio.NewReader(strings.NewReader(""))
	if got := readLine(r, "enter"); got != "" {
		t.Errorf("readLine(empty) = %q, want empty", got)
	}
}

func TestReadInt(t *testing.T) {
	// Valid number.
	r := bufio.NewReader(strings.NewReader("42\n"))
	if got := readInt(r, "count", 0); got != 42 {
		t.Errorf("readInt = %d, want 42", got)
	}

	// Empty line → default.
	r = bufio.NewReader(strings.NewReader("\n"))
	if got := readInt(r, "count", 7); got != 7 {
		t.Errorf("readInt(empty) = %d, want 7", got)
	}

	// Invalid then valid.
	r = bufio.NewReader(strings.NewReader("abc\n99\n"))
	if got := readInt(r, "count", 0); got != 99 {
		t.Errorf("readInt(invalid then valid) = %d, want 99", got)
	}
}
