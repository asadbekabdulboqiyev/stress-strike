package cliux

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "abc", 3},
		{"kitten", "sitting", 3},
		{"run", "run", 0},
		{"users", "user", 1},
		{"url", "url", 0},
		{"scan", "scn", 1},
		{"replay", "replayy", 1},
		{"abc", "xyz", 3},
	}
	for _, tt := range tests {
		if got := Levenshtein(tt.a, tt.b); got != tt.want {
			t.Errorf("Levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSuggestions(t *testing.T) {
	cands := []string{"run", "replay", "scan", "dashboard", "master", "worker", "pentest"}
	tests := []struct {
		input string
		want  []string
	}{
		{"ru", []string{"run"}},              // prefix
		{"scn", []string{"scan", "run"}},     // scan d=1, run d=2
		{"replayy", []string{"replay"}},      // distance 1
		{"pentestt", []string{"pentest"}},    // distance 1
		{"xyz", nil},                         // distance > 2, no prefix
		{"", nil},                            // empty input
		{"masterr", []string{"master"}},      // distance 1
		{"dashboard", []string{"dashboard"}}, // exact
	}
	for _, tt := range tests {
		got := Suggestions(tt.input, cands, 3)
		if len(got) != len(tt.want) {
			t.Errorf("Suggestions(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("Suggestions(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
	// Max cap respected.
	if got := Suggestions("run", cands, 1); len(got) != 1 {
		t.Errorf("max cap not respected: %v", got)
	}
}

func newTestFlagSet() (*flag.FlagSet, *string, *int) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(bytes.NewBuffer(nil))
	url := fs.String("url", "", "target URL")
	users := fs.Int("users", 10, "virtual users")
	return fs, url, users
}

func TestHandleFlagErrorMissingArgument(t *testing.T) {
	fs, _, _ := newTestFlagSet()
	// Simulate: stress-strike run --url
	if err := fs.Parse([]string{"--url"}); err == nil {
		t.Fatal("expected parse error")
	} else {
		var buf bytes.Buffer
		code := HandleFlagError(&buf, Options{Command: "run", FlagSet: fs, Err: err, Examples: []string{"stress-strike run --url https://x --users 10"}})
		if code != 2 {
			t.Errorf("exit code = %d, want 2", code)
		}
		out := buf.String()
		if !strings.Contains(out, "--url requires a value") {
			t.Errorf("missing value message not found: %q", out)
		}
		if !strings.Contains(out, "Example:") || !strings.Contains(out, "stress-strike run --url https://x") {
			t.Errorf("example missing: %q", out)
		}
		if !strings.Contains(out, "stress-strike run --help") {
			t.Errorf("help hint missing: %q", out)
		}
	}
}

func TestHandleFlagErrorUnknownFlag(t *testing.T) {
	fs, _, _ := newTestFlagSet()
	if err := fs.Parse([]string{"--userss", "5"}); err == nil {
		t.Fatal("expected parse error")
	} else {
		var buf bytes.Buffer
		HandleFlagError(&buf, Options{Command: "run", FlagSet: fs, Err: err})
		out := buf.String()
		if !strings.Contains(out, "Unknown flag --userss") {
			t.Errorf("unknown flag message missing: %q", out)
		}
		if !strings.Contains(out, "Did you mean --users") {
			t.Errorf("did-you-mean missing: %q", out)
		}
	}
}

func TestHandleFlagErrorInvalidValue(t *testing.T) {
	fs, _, _ := newTestFlagSet()
	if err := fs.Parse([]string{"--users", "abc"}); err == nil {
		t.Fatal("expected parse error")
	} else {
		var buf bytes.Buffer
		HandleFlagError(&buf, Options{Command: "run", FlagSet: fs, Err: err})
		out := buf.String()
		if !strings.Contains(out, `Invalid value "abc" for flag --users`) {
			t.Errorf("invalid value message missing: %q", out)
		}
		if !strings.Contains(out, "expects an integer") {
			t.Errorf("type hint missing: %q", out)
		}
	}
}

func TestFlagNamesSorted(t *testing.T) {
	fs, _, _ := newTestFlagSet()
	got := FlagNames(fs)
	if len(got) != 2 || got[0] != "url" || got[1] != "users" {
		t.Errorf("FlagNames = %v, want [url users]", got)
	}
}

func TestPrintFlagList(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("url", "", "target URL (quick mode)")
	fs.Int("users", 10, "concurrent virtual users")
	fs.Bool("quiet", false, "disable live progress")
	var buf bytes.Buffer
	PrintFlagList(&buf, fs)
	out := buf.String()
	for _, want := range []string{"--url string", "--users int", "--quiet", "target URL (quick mode)", "(default 10)"} {
		if !strings.Contains(out, want) {
			t.Errorf("PrintFlagList missing %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "--quiet  ") && !strings.Contains(out, "--quiet   ") {
		// alignment: bool flags have no type column, but must be aligned
		t.Errorf("PrintFlagList alignment off:\n%s", out)
	}
	// No (default false) shown for bool with zero default.
	if strings.Contains(out, "default false") {
		t.Errorf("bool default false should be hidden:\n%s", out)
	}
}
