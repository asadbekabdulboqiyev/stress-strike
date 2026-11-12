package dashboard

// assets_bundle_test.go — guards the split of the dashboard script.
//
// app.js grew past 3,400 lines in a single file, and every change meant
// re-reading it. It now lives in assets/, one file per feature, concatenated in
// name order into the one /app.js the page requests. These tests exist so the
// split stays a split: if a part creeps back towards a thousand lines, or the
// ordering the numeric prefixes encode is broken, the suite says so instead of
// the page booting into a half-initialised shell.

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// maxAppPartLines is the ceiling for one part. A part that crosses it is a
// signal to split the feature, not to raise the ceiling.
const maxAppPartLines = 900

func appPartPaths(t *testing.T) []string {
	t.Helper()
	paths, err := fs.Glob(dashboardAssets, "assets/*.js")
	if err != nil {
		t.Fatalf("glob assets: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no dashboard asset parts embedded")
	}
	return paths
}

func TestDashboardBundleIsBuiltFromParts(t *testing.T) {
	parts := appPartPaths(t)
	if len(parts) < 5 {
		t.Fatalf("bundle has %d parts, expected the feature split to survive", len(parts))
	}

	bundle := string(dashboardJS)
	for _, p := range parts {
		body, err := dashboardAssets.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}

		// Each part's first real line is its banner, so it is unique enough to
		// prove the part reached the bundle.
		marker := "part " + partOrdinal(p) + " of "
		if !strings.Contains(string(body), marker) {
			t.Errorf("%s does not carry the %q banner; the split is not being maintained", p, marker)
		}
		if !strings.Contains(bundle, strings.TrimSpace(partMarkerLine(body))) {
			t.Errorf("%s is embedded but missing from the concatenated bundle", p)
		}
	}
}

// partMarkerLine returns the "part N of M" line of a part's banner.
func partMarkerLine(body []byte) string {
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, " part ") && strings.Contains(line, " of ") {
			return strings.TrimSpace(strings.Trim(line, "/* "))
		}
	}
	return ""
}

// partOrdinal extracts "01" from "assets/app-01-state.js".
func partOrdinal(path string) string {
	base := path[strings.LastIndex(path, "/")+1:]
	base = strings.TrimPrefix(base, "app-")
	if i := strings.Index(base, "-"); i > 0 {
		return base[:i]
	}
	return base
}

func TestDashboardPartsStayReviewable(t *testing.T) {
	for _, p := range appPartPaths(t) {
		body, err := dashboardAssets.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		lines := strings.Count(string(body), "\n")
		if lines > maxAppPartLines {
			t.Errorf("%s is %d lines, over the %d-line ceiling for one part — split the feature "+
				"instead of letting one file grow back into a god file", p, lines, maxAppPartLines)
		}
	}
}

// TestDashboardPartsAreOrdered pins the boot contract: state and helpers are
// declared before the code that uses them. Concatenation order is name order,
// so this also proves the numeric prefixes are unique and sortable.
func TestDashboardPartsAreOrdered(t *testing.T) {
	parts := appPartPaths(t)
	sorted := append([]string(nil), parts...)
	sort.Strings(sorted)
	for i := range parts {
		if parts[i] != sorted[i] {
			t.Fatalf("fs.Glob order is not name order at %d: %q vs %q", i, parts[i], sorted[i])
		}
	}

	bundle := string(dashboardJS)
	order := []struct {
		name    string
		needle  string
		because string
	}{
		{"state", "var S = {", "the shared state object is declared first"},
		{"websocket", "function connect(", "the socket is set up before any view renders"},
		{"render", "function render(", "render reads S, so S must already exist"},
		{"boot", "function bootView(", "the shell boots last"},
	}
	prev := -1
	for _, o := range order {
		at := strings.Index(bundle, o.needle)
		if at < 0 {
			t.Fatalf("%s: %q is missing from the bundle (%s)", o.name, o.needle, o.because)
		}
		if at < prev {
			t.Fatalf("%s: %q appears before an earlier declaration, but %s", o.name, o.needle, o.because)
		}
		prev = at
	}
}

// TestAppJSIsServedFromTheBundle proves the page still gets the whole script
// from the single URL it has always used.
func TestAppJSIsServedFromTheBundle(t *testing.T) {
	s := NewServer()
	r := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /app.js = %d", rec.Code)
	}
	if got := rec.Body.String(); got != string(dashboardJS) {
		t.Fatalf("/app.js body does not match the embedded bundle (%d vs %d bytes)", len(got), len(dashboardJS))
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q, want javascript", ct)
	}
}
