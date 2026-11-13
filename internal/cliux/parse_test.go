package cliux

// parse_test.go — coverage for Parse, BoxHelp and sep.
//
// Parse terminates through ExitProcess on --help and on a parse error, so the
// tests swap the hook for a sentinel panic, exactly like the CLI harness does.

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

type parseExit int

// withExitHook installs a panicking ExitProcess for the duration of fn.
func withExitHook(t *testing.T, fn func()) (code int) {
	t.Helper()
	prev := ExitProcess
	ExitProcess = func(c int) { panic(parseExit(c)) }
	defer func() { ExitProcess = prev }()
	defer func() {
		if r := recover(); r != nil {
			if sig, ok := r.(parseExit); ok {
				code = int(sig)
				return
			}
			panic(r)
		}
	}()
	fn()
	return 0
}

func TestParseSuccess(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	users := fs.Int("users", 1, "virtual users")
	helpCalled := false
	code := withExitHook(t, func() {
		Parse(fs, []string{"-users", "7"}, func() { helpCalled = true }, Options{Command: "x"})
	})
	if code != 0 || helpCalled {
		t.Fatalf("Parse success: code=%d help=%v", code, helpCalled)
	}
	if *users != 7 {
		t.Errorf("users = %d, want 7", *users)
	}
}

func TestParseHelpExitsZero(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.String("url", "", "target")
	helpCalled := false
	code := withExitHook(t, func() {
		Parse(fs, []string{"--help"}, func() { helpCalled = true }, Options{Command: "x"})
	})
	if code != 0 {
		t.Fatalf("Parse --help exit = %d, want 0", code)
	}
	if !helpCalled {
		t.Error("Parse --help did not call onHelp")
	}
}

func TestParseErrorExitsTwo(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.Int("users", 1, "virtual users")
	code := withExitHook(t, func() {
		Parse(fs, []string{"-users", "lots"}, func() {}, Options{
			Command:  "x",
			Examples: []string{"x --users 10"},
		})
	})
	if code != 2 {
		t.Fatalf("Parse error exit = %d, want 2", code)
	}
}

func TestBoxHelp(t *testing.T) {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	fs.String("listen", ":0", "listen address")
	fs.Bool("verbose", false, "verbose output")

	var buf bytes.Buffer
	BoxHelp(&buf, "Sift worker — test node",
		[]string{"Sift worker --listen :50052"},
		[]string{"# start", "Sift worker"},
		fs)
	out := buf.String()
	for _, want := range []string{
		"Sift worker — test node",
		" USAGE",
		"Sift worker --listen :50052",
		" FLAGS",
		"--listen string  listen address (default \":0\")",
		"--verbose",
		" EXAMPLES",
		"# start",
		"═══════",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("BoxHelp missing %q:\n%s", want, out)
		}
	}
}

func TestBoxHelpWithoutExamples(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	var buf bytes.Buffer
	BoxHelp(&buf, "title", []string{"usage"}, nil, fs)
	out := buf.String()
	if strings.Contains(out, "EXAMPLES") {
		t.Errorf("BoxHelp with no examples rendered EXAMPLES:\n%s", out)
	}
	if !strings.Contains(out, "title") {
		t.Errorf("BoxHelp missing the title:\n%s", out)
	}
}

func TestSepWritesRule(t *testing.T) {
	var buf bytes.Buffer
	sep(&buf)
	if !strings.Contains(buf.String(), "═") {
		t.Errorf("sep = %q, want a horizontal rule", buf.String())
	}
}
