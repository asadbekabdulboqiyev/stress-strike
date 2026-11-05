package version

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
)

// resetVars restores the package-level build metadata after a test mutates it,
// so test order can never leak state.
func resetVars(t *testing.T) {
	t.Helper()
	v, c, d := Version, Commit, Date
	t.Cleanup(func() {
		Version, Commit, Date = v, c, d
	})
}

// buildInfoHasVCS reports whether the test binary carries the Go VCS stamp,
// which makes the empty-Commit/Date fallback in Full observable.
func buildInfoHasVCS() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			return true
		}
	}
	return false
}

func TestFullFormatsVersionCommitAndDate(t *testing.T) {
	resetVars(t)
	Version, Commit, Date = "0.14.5", "abc1234", "2026-10-01T00:00:00Z"

	got := Full()

	const want = "0.14.5 (abc1234, 2026-10-01T00:00:00Z)"
	if got != want {
		t.Fatalf("Full() = %q, want %q", got, want)
	}
}

func TestFullTruncatesLongCommit(t *testing.T) {
	tests := []struct {
		name   string
		commit string
		want   string
	}{
		{name: "11 chars untouched", commit: "abc12345678", want: "abc12345678"},
		{name: "exactly 12 untouched", commit: "abc123456789", want: "abc123456789"},
		{name: "13 chars truncated to 12", commit: "abc1234567890", want: "abc123456789"},
		{name: "full sha truncated to 12", commit: "40863d1e7c1a4b2f9d3e1a2b3c4d5e6f", want: "40863d1e7c1a"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetVars(t)
			Version, Commit, Date = "0.14.5", tc.commit, "2026-10-01T00:00:00Z"

			got := Full()

			want := "0.14.5 (" + tc.want + ", 2026-10-01T00:00:00Z)"
			if got != want {
				t.Fatalf("Full() = %q, want %q", got, want)
			}
		})
	}
}

func TestFullOmitsMissingCommit(t *testing.T) {
	resetVars(t)
	Version, Commit, Date = "0.14.5", "", ""

	got := Full()

	// Without a VCS stamp there is no commit to show.
	if !buildInfoHasVCS() {
		if strings.Contains(got, "(") {
			t.Fatalf("Full() = %q, want no commit section", got)
		}
		if got != "0.14.5" {
			t.Fatalf("Full() = %q, want %q", got, "0.14.5")
		}
		return
	}

	// With a VCS stamp (-buildvcs=true) the documented fallback must kick in
	// instead of printing a bare version.
	if !strings.HasPrefix(got, "0.14.5 (") || !strings.HasSuffix(got, ")") {
		t.Fatalf("Full() = %q, want \"0.14.5 (<commit>, <date>)\" from the VCS stamp", got)
	}
	if strings.Contains(got, "unofficial") {
		t.Fatalf("Full() = %q, want no unofficial marker for a stamped version", got)
	}
}

// TestFullDevBuildIsMarkedUnofficial pins the degraded-ldflag behaviour
// documented in version.go: an un-injected Version is reported as unofficial.
func TestFullDevBuildIsMarkedUnofficial(t *testing.T) {
	resetVars(t)
	Version, Commit, Date = "dev", "abc1234", "2026-10-01T00:00:00Z"

	got := Full()

	const want = "dev (abc1234, 2026-10-01T00:00:00Z) [unofficial build]"
	if got != want {
		t.Fatalf("Full() = %q, want %q", got, want)
	}
}

// TestFullFallsBackToVCSStamp covers the debug.ReadBuildInfo path used when
// ldflags were not injected. The exact stamp depends on how the test binary was
// built, so the assertion is structural rather than exact.
func TestFullFallsBackToVCSStamp(t *testing.T) {
	resetVars(t)
	Version, Commit, Date = "dev", "", ""

	got := Full()

	if !strings.HasPrefix(got, "dev") {
		t.Fatalf("Full() = %q, want prefix %q", got, "dev")
	}
	if !strings.HasSuffix(got, "[unofficial build]") {
		t.Fatalf("Full() = %q, want suffix %q", got, "[unofficial build]")
	}
	if !buildInfoHasVCS() {
		if got != "dev [unofficial build]" {
			t.Fatalf("no VCS stamp in build info, Full() = %q, want %q", got, "dev [unofficial build]")
		}
		return
	}
	if !strings.Contains(got, "(") {
		t.Fatalf("build info has VCS stamp but Full() = %q lacks commit section", got)
	}
	body := strings.TrimSuffix(strings.SplitN(got, " (", 2)[1], ") [unofficial build]")
	parts := strings.Split(body, ", ")
	if len(parts) != 2 {
		t.Fatalf("Full() commit section = %q, want \"commit, date\"", body)
	}
	if len(parts[0]) > 12 {
		t.Fatalf("commit %q not truncated to 12 chars", parts[0])
	}
	if parts[1] == "" {
		t.Fatalf("Full() = %q, VCS date not injected", got)
	}
}

// TestVersionDefaultsAreUsable guards against a release build silently
// reporting an empty version (the reason this package exists).
func TestVersionDefaultsAreUsable(t *testing.T) {
	if Version == "" {
		t.Fatal("Version is empty; binary would print a blank version")
	}
	if got := Full(); !strings.HasPrefix(got, Version) {
		t.Fatalf("Full() = %q, want prefix Version=%q", got, Version)
	}
}

// TestVersionFileMatchesInjectedVersion enforces the single-source-of-truth
// rule: the checked-in VERSION file is what ldflags inject. Skipped for
// un-injected (dev) builds, which is every plain `go test` run.
func TestVersionFileMatchesInjectedVersion(t *testing.T) {
	if Version == "dev" {
		t.Skip("dev build: Version is not ldflag-injected, nothing to compare")
	}

	path := filepath.Join("..", "..", "VERSION")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if got := strings.TrimSpace(string(raw)); got != Version {
		t.Fatalf("VERSION file = %q, linked Version = %q (mismatch)", got, Version)
	}
}

// TestVersionFileIsSemver validates the file that release tooling injects.
func TestVersionFileIsSemver(t *testing.T) {
	path := filepath.Join("..", "..", "VERSION")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	semver := regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	if got := strings.TrimSpace(string(raw)); !semver.MatchString(got) {
		t.Fatalf("VERSION content %q is not semver", got)
	}
}
