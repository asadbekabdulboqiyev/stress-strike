package dashboard

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The OWASP panel is exercised end to end in a real browser, but two classes of
// defect it has already shipped cannot be reached from a Go test: they only
// appear once the page runs. Both are asserted here against the embedded assets
// so a refactor cannot quietly bring them back.
//
//  1. owaspRender cleared the findings *wrap*. The wrap owns the subtitle and the
//     <ul id="owaspFindings"> that owaspAddFinding appends to, so clearing it
//     detached the list: findings were then written into an orphaned node and the
//     panel showed "Findings (N)" above nothing - on the first scan, and on every
//     scan after it, because nothing re-attaches the list.
//
//  2. Every string in a report comes from the scanned server, which makes it
//     untrusted. Writing it with innerHTML would turn a hostile `Server:` header
//     into live markup. The panel writes text with textContent throughout.
func TestOWASPAssets(t *testing.T) {
	js := readDashboardAsset(t, "app.js")
	html := readDashboardAsset(t, "index.html")
	block := owaspJSBlock(t, js)

	t.Run("the findings list is never detached from the document", func(t *testing.T) {
		if strings.Contains(block, "owaspClear(_owaspFindWrap)") {
			t.Error("owaspRender must not clear the findings wrap: the wrap owns the subtitle and " +
				"the <ul id=\"owaspFindings\"> the findings are appended to, so clearing it detaches " +
				"the list and the panel can never show a finding")
		}
		if !strings.Contains(block, "owaspClear(_owaspFindings)") {
			t.Error("each render must still clear the findings list itself, or findings accumulate " +
				"across scans")
		}
		if !strings.Contains(block, "_owaspSubtitle") {
			t.Error("the findings subtitle must be updated in place via _owaspSubtitle, not " +
				"recreated by emptying the wrap")
		}
	})

	t.Run("the markup the panel contract depends on is present", func(t *testing.T) {
		wrapOpen := strings.Index(html, `id="owaspFindingsWrap"`)
		subtitle := strings.Index(html, `class="owasp-subtitle"`)
		list := strings.Index(html, `id="owaspFindings"`)
		if wrapOpen < 0 || subtitle < 0 || list < 0 {
			t.Fatal("index.html no longer carries the findings wrap, its subtitle and the list: " +
				"the OWASP panel contract changed")
		}
		if !(wrapOpen < subtitle && subtitle < list) {
			t.Fatalf("expected the findings wrap, then its subtitle, then the list; got offsets "+
				"wrap=%d subtitle=%d list=%d", wrapOpen, subtitle, list)
		}
		// app.js looks the subtitle up with a child combinator
		// (#owaspFindingsWrap > .owasp-subtitle), so the subtitle has to be the
		// wrap's first child element, not merely a descendant.
		tagEnd := strings.Index(html[wrapOpen:], ">") + wrapOpen + 1
		subtitleTag := strings.LastIndex(html[:subtitle], "<")
		if subtitleTag < tagEnd {
			t.Fatalf("could not delimit the subtitle tag: wrap opens at %d, subtitle at %d",
				wrapOpen, subtitle)
		}
		if between := strings.TrimSpace(html[tagEnd:subtitleTag]); between != "" {
			t.Errorf("the subtitle must be the wrap's first child element, but %q comes before it",
				between)
		}
	})

	t.Run("server-controlled strings are never written as markup", func(t *testing.T) {
		for _, sink := range []*regexp.Regexp{
			regexp.MustCompile(`\.innerHTML\s*=`),
			regexp.MustCompile(`\.outerHTML\s*=`),
			regexp.MustCompile(`\.insertAdjacentHTML\s*\(`),
			regexp.MustCompile(`document\.write\s*\(`),
		} {
			if loc := sink.FindStringIndex(block); loc != nil {
				t.Errorf("the OWASP panel writes server-controlled text with textContent; found a "+
					"markup sink at %q", block[loc[0]:loc[1]])
			}
		}
	})

	t.Run("passive checks are on by default in the panel", func(t *testing.T) {
		// The panel advertises itself as safe by default: passive probes are
		// read-only and gated, intrusive probes are opt-in. If passive defaults
		// off, a first click shows a coverage table and an always-empty findings
		// section, because the findings list only carries the passive and
		// intrusive families.
		if !strings.Contains(html, `id="owaspPassive" checked`) {
			t.Error("the passive checks box must default to checked; passive probes are read-only " +
				"and pass the same scope gate, and without them the findings section is always empty")
		}
	})
}

func readDashboardAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read dashboard asset %s: %v", name, err)
	}
	if len(b) == 0 {
		t.Fatalf("dashboard asset %s is empty", name)
	}
	return string(b)
}

// owaspJSBlock returns the OWASP section of app.js: from the element cache down
// to the submit listener that closes it.
func owaspJSBlock(t *testing.T, js string) string {
	t.Helper()
	start := strings.Index(js, "var _owaspStatus")
	end := strings.Index(js, "addEventListener('submit', owaspRun)")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("could not locate the OWASP block in app.js: one of the markers it is delimited " +
			"by changed, so this guard no longer checks anything")
	}
	return js[start:end]
}
