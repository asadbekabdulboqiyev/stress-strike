package bounty

// manifest_test.go — build/load roundtrip, digest determinism and limits.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildManifestAndLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	m := buildBaseManifest(t, dir)

	if len(m.PackageDigest) != 64 {
		t.Fatalf("package digest is %d characters, want 64", len(m.PackageDigest))
	}
	if !packageIDPattern.MatchString(m.PackageID) {
		t.Fatalf("package id %q does not match the expected shape", m.PackageID)
	}
	if len(m.Artifacts) != 3 {
		t.Fatalf("got %d artifacts, want 3 (report, scope, claim)", len(m.Artifacts))
	}
	if m.Claim.Title != "Cross-tenant invoice read" || m.Claim.Severity != string(SeverityHigh) {
		t.Fatalf("claim metadata not carried: %+v", m.Claim)
	}
	for _, art := range m.Artifacts {
		if !isLowerHex(art.SHA256, 64) {
			t.Fatalf("artifact %s digest %q is not hex", art.Role, art.SHA256)
		}
		if art.Size <= 0 {
			t.Fatalf("artifact %s size %d is not positive", art.Role, art.Size)
		}
	}

	path, err := WritePackage(m, filepath.Join(dir, "pkg"))
	if err != nil {
		t.Fatalf("WritePackage: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat package: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("package mode is %o, want 600", got)
	}

	loaded, err := LoadPackage(path)
	if err != nil {
		t.Fatalf("LoadPackage: %v", err)
	}
	if loaded.PackageDigest != m.PackageDigest || loaded.PackageID != m.PackageID {
		t.Fatalf("roundtrip changed identity: %s/%s vs %s/%s", loaded.PackageID, loaded.PackageDigest, m.PackageID, m.PackageDigest)
	}
	if len(loaded.Artifacts) != len(m.Artifacts) {
		t.Fatalf("roundtrip changed artifact count: %d vs %d", len(loaded.Artifacts), len(m.Artifacts))
	}
}

func TestComputeDigestDeterministic(t *testing.T) {
	dir := t.TempDir()
	opts := basePackageOptions(t, dir)

	first, err := BuildManifest(opts)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	second, err := BuildManifest(opts)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	if first.PackageDigest != second.PackageDigest {
		t.Fatalf("same inputs produced different digests: %s vs %s", first.PackageDigest, second.PackageDigest)
	}

	// Recomputing over a manifest that already carries its identity must give
	// the same answer: the identity fields are excluded from the digest.
	recomputed, err := first.ComputeDigest()
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	if recomputed != first.PackageDigest {
		t.Fatalf("recomputed digest %s, stored %s", recomputed, first.PackageDigest)
	}

	// Any metadata change changes the digest.
	changed := opts
	changed.Program = "Acme Internal"
	third, err := BuildManifest(changed)
	if err != nil {
		t.Fatalf("changed build: %v", err)
	}
	if third.PackageDigest == first.PackageDigest {
		t.Fatal("changing the program name did not change the digest")
	}

	// So does a different timestamp.
	changed = opts
	changed.CreatedAt = fixedTime.Add(time.Second)
	fourth, err := BuildManifest(changed)
	if err != nil {
		t.Fatalf("timestamp build: %v", err)
	}
	if fourth.PackageDigest == first.PackageDigest {
		t.Fatal("changing created_at did not change the digest")
	}
}

func TestBuildManifestRejectsMissingInputs(t *testing.T) {
	dir := t.TempDir()
	base := basePackageOptions(t, dir)

	cases := []struct {
		name string
		opts PackageOptions
	}{
		{"no program", func() PackageOptions { o := base; o.Program = "  "; return o }()},
		{"no report", func() PackageOptions { o := base; o.ReportPath = ""; return o }()},
		{"no scope", func() PackageOptions { o := base; o.ScopePath = ""; return o }()},
		{"samples without bundle", func() PackageOptions { o := base; o.SamplesPath = base.ReportPath; return o }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildManifest(tc.opts); err == nil {
				t.Fatal("BuildManifest accepted invalid options")
			}
		})
	}
}

func TestBuildManifestRejectsDuplicatePaths(t *testing.T) {
	dir := t.TempDir()
	opts := basePackageOptions(t, dir)
	opts.ScopePath = opts.ReportPath // same file in two roles

	if _, err := BuildManifest(opts); err == nil {
		t.Fatal("BuildManifest accepted one file in two artifact roles")
	}
}

func TestBuildManifestRejectsUnreadableArtifact(t *testing.T) {
	dir := t.TempDir()
	opts := basePackageOptions(t, dir)
	opts.ReportPath = filepath.Join(dir, "missing.md")

	if _, err := BuildManifest(opts); err == nil {
		t.Fatal("BuildManifest accepted a missing report")
	}
}

func TestBuildManifestArtifactSizeLimit(t *testing.T) {
	dir := t.TempDir()
	opts := basePackageOptions(t, dir)

	oversized := filepath.Join(dir, "huge.bin")
	f, err := os.Create(oversized)
	if err != nil {
		t.Fatalf("create oversized file: %v", err)
	}
	if err := f.Truncate(MaxArtifactBytes + 1); err != nil {
		_ = f.Close()
		t.Fatalf("truncate oversized file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close oversized file: %v", err)
	}
	opts.ReportPath = oversized

	_, err = BuildManifest(opts)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized artifact error = %v, want a limit error", err)
	}
}

func TestManifestValidateArtifactCountLimit(t *testing.T) {
	dir := t.TempDir()
	m := buildBaseManifest(t, dir)
	m.Artifacts = nil
	for i := 0; i <= MaxArtifacts; i++ {
		m.Artifacts = append(m.Artifacts, Artifact{
			Role:   ArtifactRole("role-" + string(rune('a'+i))),
			Path:   "file-" + string(rune('a'+i)),
			Size:   1,
			SHA256: strings.Repeat("0", 64),
		})
	}
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "exceeds the limit") {
		t.Fatalf("artifact count validation = %v, want a limit error", err)
	}
}

func TestManifestValidateRejectsUnsafePaths(t *testing.T) {
	for _, path := range []string{"", "/etc/passwd", "../secret", "a/../../b", "./x", "a//b", "a\\b", "."} {
		if validArtifactPath(path) {
			t.Errorf("validArtifactPath(%q) = true, want false", path)
		}
	}
	for _, path := range []string{"report.md", "nested/report.md", "a.b.c"} {
		if !validArtifactPath(path) {
			t.Errorf("validArtifactPath(%q) = false, want true", path)
		}
	}
}

func TestPackageRelativePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/tmp/run/report.md", "report.md"},
		{"../outside/report.md", "report.md"},
		{"nested/report.md", "nested/report.md"},
		{"./report.md", "report.md"},
	}
	for _, tc := range cases {
		got, err := packageRelativePath(tc.in)
		if err != nil {
			t.Fatalf("packageRelativePath(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("packageRelativePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLoadPackageRejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	m := buildBaseManifest(t, dir)
	path, err := WritePackage(m, dir)
	if err != nil {
		t.Fatalf("WritePackage: %v", err)
	}
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read package: %v", err)
	}

	write := func(name string, raw []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	var generic map[string]any
	if err := json.Unmarshal(good, &generic); err != nil {
		t.Fatalf("unmarshal package: %v", err)
	}
	generic["unexpected"] = "field"
	withUnknown, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("marshal unknown field: %v", err)
	}

	cases := []struct {
		name string
		raw  []byte
	}{
		{"unknown-field.json", withUnknown},
		{"trailing.json", append(append([]byte{}, good...), []byte("\n{}\n")...)},
		{"truncated.json", good[:len(good)/2]},
		{"empty.json", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadPackage(write(tc.name, tc.raw)); err == nil {
				t.Fatal("LoadPackage accepted a malformed document")
			}
		})
	}

	// Oversized manifest file.
	big := filepath.Join(dir, "big.json")
	f, err := os.Create(big)
	if err != nil {
		t.Fatalf("create big manifest: %v", err)
	}
	if err := f.Truncate(maxPackageBytes + 1); err != nil {
		_ = f.Close()
		t.Fatalf("truncate big manifest: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close big manifest: %v", err)
	}
	if _, err := LoadPackage(big); err == nil {
		t.Fatal("LoadPackage accepted an oversized manifest")
	}
}

func TestManifestValidateRejectsBadDigestAndSchema(t *testing.T) {
	dir := t.TempDir()
	m := buildBaseManifest(t, dir)

	bad := m
	bad.PackageDigest = "not-a-digest"
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted a malformed package digest")
	}

	bad = m
	bad.SchemaVersion = "bounty/v2"
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted an unknown schema version")
	}

	bad = m
	bad.Artifacts[0].SHA256 = strings.Repeat("A", 64)
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted an uppercase digest")
	}

	bad = m
	bad.Claim.Severity = "urgent"
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted an unknown severity")
	}
}
