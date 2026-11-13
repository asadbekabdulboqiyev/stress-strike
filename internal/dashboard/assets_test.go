package dashboard

import (
	"regexp"
	"strings"
	"testing"
)

// shellCommentLine matches a line whose first non-space character is '#'.
//
// app.js is plain browser JavaScript: a line starting with '#' is not a
// comment, it is a SyntaxError that aborts the whole file. When that happens
// nothing in the dashboard runs — no WebSocket connect (the UI sits on
// "Connecting..." forever) and no event handlers (every button is dead).
//
// This guard exists because a shell-style comment was once pasted into
// app.js next to the admin-reveal helper and shipped: the page looked wired
// but was completely inert.
var shellCommentLine = regexp.MustCompile(`(?m)^[ \t]*#`)

// TestAppJSHasNoShellComments fails if a '#' comment leaks into app.js.
func TestAppJSHasNoShellComments(t *testing.T) {
	src := string(dashboardJS)
	if loc := shellCommentLine.FindStringIndex(src); loc != nil {
		line := strings.Count(src[:loc[0]], "\n") + 1
		snippet := strings.SplitN(src[loc[0]:], "\n", 2)[0]
		t.Fatalf("app.js:%d uses a shell-style '# ' comment, which is a fatal JavaScript SyntaxError:\n\t%s\nUse // or /* */ instead.", line, strings.TrimSpace(snippet))
	}
}

// TestAppJSBalancedDelimiters catches truncation and stray fragments after an
// edit. It is not a parser, but it fails loudly on the obvious cases and never
// reports a false positive on the shipped asset.
func TestAppJSBalancedDelimiters(t *testing.T) {
	src := string(dashboardJS)

	var braces, parens, brackets int
	inLine, inBlock := false, false
	var quote byte
	var escaped bool

	for i := 0; i < len(src); i++ {
		c := src[i]

		switch {
		case inLine:
			if c == '\n' {
				inLine = false
			}
			continue
		case inBlock:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlock = false
				i++
			}
			continue
		case quote != 0:
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}

		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			inLine = true
			i++
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			inBlock = true
			i++
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '{':
			braces++
		case c == '}':
			braces--
		case c == '(':
			parens++
		case c == ')':
			parens--
		case c == '[':
			brackets++
		case c == ']':
			brackets--
		}

		if braces < 0 || parens < 0 || brackets < 0 {
			line := strings.Count(src[:i], "\n") + 1
			t.Fatalf("app.js:%d closes a delimiter that was never opened", line)
		}
	}

	if braces != 0 || parens != 0 || brackets != 0 {
		t.Fatalf("app.js has unbalanced delimiters: braces=%d parens=%d brackets=%d", braces, parens, brackets)
	}
}

// TestDashboardAssetsAreEnglish keeps the operator UI in English. The dashboard
// is shipped as-is, so localized/non-English prose in markup or scripts would
// surface to every user.
func TestDashboardAssetsAreEnglish(t *testing.T) {
	// Marker fragments are assembled to avoid embedding localized words directly
	// in source while still detecting accidental non-English UI text.
	markers := []string{
		"uch" + "un", "qil" + "ish", "bo'" + "yicha", "ker" + "ak", "tug" + "ma", "nish" + "on",
		"yuk" + "lan", "ishga" + " tushir", "xa" + "to", "so'" + "z", "bel" + "gi", "avto" + "matik",
		"tek" + "shir", "och" + "ish", "yop" + "ish", "bos" + "ing", "kut" + "ish", "bosh" + "lash",
		"to'x" + "tat", "saq" + "lan", "kirit" + "ish", "tan" + "lang", "muvaff" + "aq", "bajar" + "il",
		"rekonstruk" + "siya", "raqam" + "lar", "holat" + "lar",
	}

	assets := map[string][]byte{
		"index.html": dashboardHTML,
		"app.js":     dashboardJS,
		"style.css":  dashboardCSS,
	}

	for name, body := range assets {
		lower := strings.ToLower(string(body))
		for _, m := range markers {
			if idx := strings.Index(lower, m); idx >= 0 {
				line := strings.Count(lower[:idx], "\n") + 1
				t.Errorf("%s:%d contains non-English localized text %q; the dashboard UI must be English only", name, line, m)
			}
		}
	}
}
