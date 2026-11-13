package version

// version_consistency_test.go — keep the release gate satisfiable.
//
// The release workflow compares three things before it publishes anything: the
// pushed tag, the VERSION file, and the version declared in source. If they
// disagree the workflow fails and no binary reaches GitHub.
//
// That is not a hypothetical failure mode. v0.14.6 and v0.14.7 were both
// tagged with a VERSION file that no longer matched the version in source, so
// both releases died at the gate and the newest published release stayed at
// v0.14.5 for weeks — while the tags looked perfectly fine from the outside.
//
// These tests fail the moment the three drift apart again, on a laptop, in
// seconds — instead of in a CI run that publishes nothing.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// repoRoot returns the repository root, two levels above internal/version.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// versionFile returns the trimmed contents of the VERSION file.
func versionFile(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// declaredVersionRe matches the exact pattern the release workflow greps for.
var declaredVersionRe = regexp.MustCompile(`var (version|Version) = "(0\.[0-9]+\.[0-9]+)"`)

// TestVersionFileIsTheOnlyDeclaredVersion pins the two inputs the release
// gate reads from the tree: the VERSION file and the version literal in
// source. They must name the same release.
func TestVersionFileIsTheOnlyDeclaredVersion(t *testing.T) {
	root := repoRoot(t)
	want := versionFile(t)

	if !regexp.MustCompile(`^0\.[0-9]+\.[0-9]+$`).MatchString(want) {
		t.Fatalf("VERSION = %q, want 0.x.y", want)
	}

	found := map[string]string{} // version -> file that declared it
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", ".audit-backup":
				return filepath.SkipDir
			case "dist", "bin":
				// Only the top-level build output is skipped:
				// internal/dist is source.
				if path == filepath.Join(root, d.Name()) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range declaredVersionRe.FindAllStringSubmatch(string(raw), -1) {
			rel, _ := filepath.Rel(root, path)
			found[m[2]] = rel
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(found) == 0 {
		t.Fatal("no version literal found in source — the release gate greps for one and would fail")
	}
	got := make([]string, 0, len(found))
	for v := range found {
		got = append(got, v)
	}
	sort.Strings(got)
	if len(got) != 1 {
		t.Fatalf("source declares %v (in %v), want exactly one version", got, found)
	}
	if got[0] != want {
		t.Fatalf("VERSION file says %q but %s declares %q — the release gate compares them and fails",
			want, found[got[0]], got[0])
	}
}

// TestReadmePointsAtTheCurrentVersion keeps the install instructions and the
// version badge on the release that is actually published.
func TestReadmePointsAtTheCurrentVersion(t *testing.T) {
	root := repoRoot(t)
	ver := versionFile(t)

	raw, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	readme := string(raw)

	if badge := "Version-" + ver + "-green.svg"; !strings.Contains(readme, badge) {
		t.Errorf("README badge is not %q — the badge shows a version that is not the release", badge)
	}
	tag := "v" + ver
	if !strings.Contains(readme, tag) {
		t.Errorf("README never mentions %s — the install instructions point at a different release", tag)
	}
}

// TestPackagingManifestsPointAtTheCurrentVersion keeps the Windows Package
// Manager manifests on the same release as the VERSION file. They carry a
// download URL, so a stale one points at an asset that does not exist.
func TestPackagingManifestsPointAtTheCurrentVersion(t *testing.T) {
	root := repoRoot(t)
	ver := versionFile(t)
	tag := "v" + ver

	files := []string{
		filepath.Join(root, "packaging", "winget", "Sift.yaml"),
		filepath.Join(root, "packaging", "winget", "Sift.installer.yaml"),
	}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		body := string(raw)
		if !strings.Contains(body, tag) {
			t.Errorf("%s does not mention %s", filepath.Base(path), tag)
		}
		if strings.Contains(body, "v0.14.7") {
			t.Errorf("%s still points at v0.14.7", filepath.Base(path))
		}
	}
}
