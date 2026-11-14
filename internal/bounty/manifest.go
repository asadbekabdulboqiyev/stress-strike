package bounty

// manifest.go — the bounty package manifest and its on-disk form.
//
// A package is a manifest plus the artifacts it names. The manifest never
// embeds artifact content: it records a role, a package-relative path, a size
// and a SHA-256 for each artifact, so verification is a re-hash of the files
// the operator hands to the verifier. Paths are normalised to slash-separated
// relative paths; an absolute input path is reduced to its base name because a
// package must be replayable from a directory that is not the producer's
// machine.
//
// The PackageDigest covers the canonical manifest with the package_id and
// package_digest members removed (package_id is derived from the digest, so
// including either would be circular). Any change to a role, path, size, hash,
// program name, claim metadata or attest reference changes the digest.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

const (
	// SchemaVersion identifies the manifest document shape.
	SchemaVersion = "bounty/v1"
	// PackageFilename is the fixed manifest file name inside a package
	// directory. Verification relies on this name, so it is not configurable.
	PackageFilename = "bounty-package.json"

	// MaxArtifactBytes bounds one artifact. Evidence sidecars for long runs
	// are the largest legitimate member; 256 MiB is generous for those and
	// small enough that a hostile package cannot exhaust memory.
	MaxArtifactBytes int64 = 256 << 20
	// MaxArtifacts bounds the number of roles in one package.
	MaxArtifacts = 32

	// maxPackageBytes bounds the manifest document itself.
	maxPackageBytes = 4 << 20

	// maxProgramNameBytes, maxScopeDescriptionBytes and maxClaimTitleBytes
	// bound free-text metadata so a package header cannot be used as a
	// content-smuggling channel.
	maxProgramNameBytes      = 256
	maxScopeDescriptionBytes = 4096
	maxClaimTitleBytes       = 300
	maxComponentBytes        = 256
	maxPolicyURLBytes        = 2048
)

// ArtifactRole names the function an artifact plays in a package. Roles are
// unique within a manifest: one bundle, one sidecar, one report, and so on.
type ArtifactRole string

const (
	// ArtifactBundle is the signed attestation bundle (bundle.json).
	ArtifactBundle ArtifactRole = "bundle"
	// ArtifactSamples is the attestation sample sidecar (samples.jsonl).
	ArtifactSamples ArtifactRole = "samples"
	// ArtifactReport is the human-readable vulnerability report.
	ArtifactReport ArtifactRole = "report"
	// ArtifactScope is the program's scope file: one in-scope host per line.
	ArtifactScope ArtifactRole = "scope"
	// ArtifactClaim is the typed claim document (claim.json).
	ArtifactClaim ArtifactRole = "claim"
)

// artifactRoleOrder fixes the order artifacts are listed in, so two builds
// from the same inputs produce byte-identical manifests before hashing.
var artifactRoleOrder = []ArtifactRole{
	ArtifactBundle,
	ArtifactSamples,
	ArtifactReport,
	ArtifactScope,
	ArtifactClaim,
}

// Valid reports whether r is a defined artifact role.
func (r ArtifactRole) Valid() bool {
	switch r {
	case ArtifactBundle, ArtifactSamples, ArtifactReport, ArtifactScope, ArtifactClaim:
		return true
	}
	return false
}

// Artifact is one file referenced by a package.
type Artifact struct {
	// Role names the artifact's function. Unique within a manifest.
	Role ArtifactRole `json:"role"`
	// Path is a slash-separated path relative to the package base directory.
	Path string `json:"path"`
	// Size is the artifact length in bytes at build time.
	Size int64 `json:"size"`
	// SHA256 is the lowercase hex SHA-256 of the artifact bytes.
	SHA256 string `json:"sha256"`
}

// ProgramMeta describes the bug bounty program the report was submitted to.
type ProgramMeta struct {
	// Name is the program's display name (e.g. "Acme Web").
	Name string `json:"name"`
	// Scope is a short human description of the program scope. The
	// authoritative, machine-checked scope is the scope artifact.
	Scope string `json:"scope,omitempty"`
	// PolicyURL points at the program policy, when one exists.
	PolicyURL string `json:"policy_url,omitempty"`
}

// ClaimMeta is the claim header carried inside the manifest. The full typed
// claim lives in the claim artifact; this is the subset a triager can read
// without opening a file.
type ClaimMeta struct {
	Title     string `json:"title,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Component string `json:"component,omitempty"`
	ClaimedBy string `json:"claimed_by,omitempty"`
}

// AttestRefs points at the attestation evidence a package relies on. All
// fields are optional because a package may be assembled before evidence is
// sealed, but verification fails closed when a reference is present and does
// not match.
type AttestRefs struct {
	// BundlePublicKey is the coordinator's Ed25519 public key, lowercase hex.
	BundlePublicKey string `json:"bundle_public_key,omitempty"`
	// BundleDigest is the hex SHA-256 of the canonical unsigned bundle.
	BundleDigest string `json:"bundle_digest,omitempty"`
	// SidecarDigest is the hex SHA-256 of the sample sidecar file bytes.
	SidecarDigest string `json:"sidecar_digest,omitempty"`
}

// ToolInfo identifies the producer of the manifest.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Manifest is a complete bounty package header.
type Manifest struct {
	SchemaVersion string      `json:"schema_version"`
	CreatedAt     string      `json:"created_at"`
	PackageID     string      `json:"package_id,omitempty"`
	Program       ProgramMeta `json:"program"`
	Claim         ClaimMeta   `json:"claim"`
	Artifacts     []Artifact  `json:"artifacts"`
	Attest        AttestRefs  `json:"attest"`
	Tool          ToolInfo    `json:"tool"`
	// PackageDigest is the hex SHA-256 of the canonical manifest without
	// package_id and package_digest. It is the value a triager pins.
	PackageDigest string `json:"package_digest,omitempty"`
}

// PackageOptions describes one package build. Paths are read once, hashed, and
// never copied: the caller is responsible for keeping artifacts together in
// the directory later passed to VerifyPackage.
type PackageOptions struct {
	BundlePath  string
	SamplesPath string
	ReportPath  string
	ScopePath   string
	ClaimPath   string

	Program          string
	ProgramScope     string
	ProgramPolicyURL string

	// CreatedAt fixes the manifest timestamp. Zero means "now". Tests pass a
	// fixed value to get a deterministic digest.
	CreatedAt time.Time
	// ToolName and ToolVersion default to "sift" and "dev".
	ToolName    string
	ToolVersion string
}

// BuildManifest hashes the supplied artifacts and returns a manifest whose
// PackageDigest and PackageID are filled in. report and scope are required;
// bundle, samples and claim are optional, because a report can be packaged
// before its evidence is sealed or before a typed claim is written.
//
// BuildManifest is fail-closed: an unreadable, oversized, duplicate or
// malformed artifact produces an error, never a partially valid manifest.
func BuildManifest(opts PackageOptions) (Manifest, error) {
	program := strings.TrimSpace(opts.Program)
	if program == "" {
		return Manifest{}, errors.New("bounty: program name is required")
	}
	if len(program) > maxProgramNameBytes {
		return Manifest{}, fmt.Errorf("bounty: program name exceeds %d bytes", maxProgramNameBytes)
	}
	if strings.TrimSpace(opts.ReportPath) == "" {
		return Manifest{}, errors.New("bounty: a report artifact is required")
	}
	if strings.TrimSpace(opts.ScopePath) == "" {
		return Manifest{}, errors.New("bounty: a scope artifact is required")
	}
	if opts.SamplesPath != "" && opts.BundlePath == "" {
		return Manifest{}, errors.New("bounty: samples require a bundle")
	}

	now := opts.CreatedAt
	if now.IsZero() {
		now = time.Now()
	}
	toolName := strings.TrimSpace(opts.ToolName)
	if toolName == "" {
		toolName = "sift"
	}
	toolVersion := strings.TrimSpace(opts.ToolVersion)
	if toolVersion == "" {
		toolVersion = "dev"
	}

	m := Manifest{
		SchemaVersion: SchemaVersion,
		CreatedAt:     now.UTC().Format(time.RFC3339),
		Program: ProgramMeta{
			Name:      program,
			Scope:     strings.TrimSpace(opts.ProgramScope),
			PolicyURL: strings.TrimSpace(opts.ProgramPolicyURL),
		},
		Tool: ToolInfo{Name: toolName, Version: toolVersion},
	}

	paths := map[ArtifactRole]string{
		ArtifactBundle:  opts.BundlePath,
		ArtifactSamples: opts.SamplesPath,
		ArtifactReport:  opts.ReportPath,
		ArtifactScope:   opts.ScopePath,
		ArtifactClaim:   opts.ClaimPath,
	}
	for _, role := range artifactRoleOrder {
		p := strings.TrimSpace(paths[role])
		if p == "" {
			continue
		}
		art, err := buildArtifact(role, p)
		if err != nil {
			return Manifest{}, err
		}
		m.Artifacts = append(m.Artifacts, art)
	}
	if len(m.Artifacts) == 0 {
		return Manifest{}, errors.New("bounty: a package needs at least one artifact")
	}
	if len(m.Artifacts) > MaxArtifacts {
		return Manifest{}, fmt.Errorf("bounty: %d artifacts exceeds the limit of %d", len(m.Artifacts), MaxArtifacts)
	}

	if opts.ClaimPath != "" {
		claim, err := LoadClaim(opts.ClaimPath)
		if err != nil {
			return Manifest{}, err
		}
		m.Claim = ClaimMeta{
			Title:     claim.Title,
			Severity:  string(claim.Severity),
			Component: claim.Component,
		}
	}

	if opts.BundlePath != "" {
		bundle, err := attest.LoadBundle(opts.BundlePath)
		if err != nil {
			return Manifest{}, fmt.Errorf("bounty: read bundle: %w", err)
		}
		key, err := bundle.CoordinatorKey()
		if err != nil {
			return Manifest{}, fmt.Errorf("bounty: bundle coordinator key: %w", err)
		}
		digest, err := bundle.DigestHex()
		if err != nil {
			return Manifest{}, fmt.Errorf("bounty: bundle digest: %w", err)
		}
		m.Attest.BundlePublicKey = key
		m.Attest.BundleDigest = digest
	}
	for _, art := range m.Artifacts {
		if art.Role == ArtifactSamples {
			m.Attest.SidecarDigest = art.SHA256
		}
	}

	digest, err := m.ComputeDigest()
	if err != nil {
		return Manifest{}, err
	}
	m.PackageDigest = digest
	m.PackageID = packageID(digest)

	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// ComputeDigest returns the hex digest of the canonical manifest with the
// derived identity fields removed. It does not mutate the receiver.
func (m Manifest) ComputeDigest() (string, error) {
	m.PackageID = ""
	m.PackageDigest = ""
	raw, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("bounty: marshal manifest for digest: %w", err)
	}
	canonical, err := canonicalizeJSON(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// packageID derives a stable, ULID-shaped identifier from the digest. It is
// not a ULID and carries no timestamp; it is simply a compact content address
// that sorts and displays like one.
func packageID(digest string) string {
	const prefix = "bty_"
	const width = 26
	if len(digest) < width {
		return prefix + digest
	}
	return prefix + digest[:width]
}

var packageIDPattern = regexp.MustCompile(`^bty_[0-9a-f]{26}$`)

// Validate checks every structural invariant of a manifest. It is total: a
// malformed manifest produces an error, never a panic.
func (m Manifest) Validate() error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("bounty: schema_version is %q, want %q", m.SchemaVersion, SchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err != nil {
		return fmt.Errorf("bounty: created_at %q is not RFC3339: %w", m.CreatedAt, err)
	}
	if m.PackageID != "" && !packageIDPattern.MatchString(m.PackageID) {
		return fmt.Errorf("bounty: package_id %q is not of the form bty_<26 hex chars>", m.PackageID)
	}
	if m.PackageDigest != "" && !isLowerHex(m.PackageDigest, 64) {
		return fmt.Errorf("bounty: package_digest %q is not a 64 character lowercase hex digest", m.PackageDigest)
	}
	if m.Program.Name == "" {
		return errors.New("bounty: program.name is empty")
	}
	if len(m.Program.Name) > maxProgramNameBytes {
		return fmt.Errorf("bounty: program.name exceeds %d bytes", maxProgramNameBytes)
	}
	if len(m.Program.Scope) > maxScopeDescriptionBytes {
		return fmt.Errorf("bounty: program.scope exceeds %d bytes", maxScopeDescriptionBytes)
	}
	if len(m.Program.PolicyURL) > maxPolicyURLBytes {
		return fmt.Errorf("bounty: program.policy_url exceeds %d bytes", maxPolicyURLBytes)
	}
	if len(m.Claim.Title) > maxClaimTitleBytes {
		return fmt.Errorf("bounty: claim.title exceeds %d bytes", maxClaimTitleBytes)
	}
	if len(m.Claim.Component) > maxComponentBytes {
		return fmt.Errorf("bounty: claim.component exceeds %d bytes", maxComponentBytes)
	}
	if m.Claim.Severity != "" {
		if err := Severity(m.Claim.Severity).Validate(); err != nil {
			return fmt.Errorf("bounty: claim.severity: %w", err)
		}
	}
	if m.Tool.Name == "" {
		return errors.New("bounty: tool.name is empty")
	}
	if m.Tool.Version == "" {
		return errors.New("bounty: tool.version is empty")
	}
	if len(m.Artifacts) == 0 {
		return errors.New("bounty: artifacts is empty")
	}
	if len(m.Artifacts) > MaxArtifacts {
		return fmt.Errorf("bounty: %d artifacts exceeds the limit of %d", len(m.Artifacts), MaxArtifacts)
	}

	seenRoles := make(map[ArtifactRole]struct{}, len(m.Artifacts))
	seenPaths := make(map[string]struct{}, len(m.Artifacts))
	for i, art := range m.Artifacts {
		if !art.Role.Valid() {
			return fmt.Errorf("bounty: artifact %d has unknown role %q", i, art.Role)
		}
		if _, dup := seenRoles[art.Role]; dup {
			return fmt.Errorf("bounty: duplicate artifact role %q", art.Role)
		}
		seenRoles[art.Role] = struct{}{}
		if !validArtifactPath(art.Path) {
			return fmt.Errorf("bounty: artifact %q has unsafe path %q", art.Role, art.Path)
		}
		if _, dup := seenPaths[art.Path]; dup {
			return fmt.Errorf("bounty: duplicate artifact path %q", art.Path)
		}
		seenPaths[art.Path] = struct{}{}
		if art.Size < 0 || art.Size > MaxArtifactBytes {
			return fmt.Errorf("bounty: artifact %q size %d is outside [0, %d]", art.Role, art.Size, MaxArtifactBytes)
		}
		if !isLowerHex(art.SHA256, 64) {
			return fmt.Errorf("bounty: artifact %q sha256 is not a 64 character lowercase hex digest", art.Role)
		}
	}

	if m.Attest.BundleDigest != "" && !isLowerHex(m.Attest.BundleDigest, 64) {
		return errors.New("bounty: attest.bundle_digest is not a 64 character lowercase hex digest")
	}
	if m.Attest.SidecarDigest != "" && !isLowerHex(m.Attest.SidecarDigest, 64) {
		return errors.New("bounty: attest.sidecar_digest is not a 64 character lowercase hex digest")
	}
	if m.Attest.BundlePublicKey != "" {
		if _, err := attest.ParsePublicKeyHex(m.Attest.BundlePublicKey); err != nil {
			return fmt.Errorf("bounty: attest.bundle_public_key: %w", err)
		}
	}
	return nil
}

// WritePackage writes the manifest as bounty-package.json inside dir. The
// directory is created with mode 0750 and the file with mode 0600; the file is
// written atomically enough for this use (truncate + encode) but callers that
// need crash consistency should write to a temporary directory and rename.
func WritePackage(m Manifest, dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("bounty: output directory is required")
	}
	if err := m.Validate(); err != nil {
		return "", err
	}
	cleanDir := filepath.Clean(dir)
	if err := os.MkdirAll(cleanDir, 0o750); err != nil {
		return "", fmt.Errorf("bounty: create package directory %s: %w", cleanDir, err)
	}
	path := filepath.Join(cleanDir, PackageFilename)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- path is a fixed file name inside an operator-selected directory
	if err != nil {
		return "", fmt.Errorf("bounty: create %s: %w", path, err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("bounty: write %s: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("bounty: set mode on %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("bounty: close %s: %w", path, err)
	}
	return path, nil
}

// LoadPackage reads, strictly decodes and structurally validates a manifest.
func LoadPackage(path string) (Manifest, error) {
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath) // #nosec G304 -- path is an operator-selected package file
	if err != nil {
		return Manifest{}, fmt.Errorf("bounty: read package: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return Manifest{}, fmt.Errorf("bounty: stat package: %w", err)
	}
	if info.Size() > maxPackageBytes {
		return Manifest{}, fmt.Errorf("bounty: %s exceeds the %d byte manifest limit", cleanPath, maxPackageBytes)
	}

	raw, err := io.ReadAll(io.LimitReader(f, maxPackageBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("bounty: read package: %w", err)
	}
	if len(raw) > maxPackageBytes {
		return Manifest{}, fmt.Errorf("bounty: %s exceeds the %d byte manifest limit", cleanPath, maxPackageBytes)
	}

	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("bounty: %s is not a valid package manifest: %w", cleanPath, err)
	}
	if dec.More() {
		return Manifest{}, fmt.Errorf("bounty: %s contains trailing JSON data", cleanPath)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// buildArtifact hashes one artifact and records its package-relative path.
func buildArtifact(role ArtifactRole, path string) (Artifact, error) {
	if !role.Valid() {
		return Artifact{}, fmt.Errorf("bounty: unknown artifact role %q", role)
	}
	stored, err := packageRelativePath(path)
	if err != nil {
		return Artifact{}, err
	}
	size, digest, err := hashFile(path, MaxArtifactBytes)
	if err != nil {
		return Artifact{}, fmt.Errorf("bounty: artifact %q: %w", role, err)
	}
	return Artifact{Role: role, Path: stored, Size: size, SHA256: digest}, nil
}

// packageRelativePath normalises an operator-supplied path into a
// slash-separated path relative to the package directory. Absolute paths and
// paths that climb out of their directory are reduced to their base name: the
// package must verify on a machine that does not share the producer's layout.
func packageRelativePath(path string) (string, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return "", errors.New("bounty: artifact path is empty")
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("bounty: artifact path contains a NUL byte")
	}
	slash := filepath.ToSlash(filepath.Clean(p))
	if filepath.IsAbs(p) || strings.HasPrefix(slash, "/") || strings.HasPrefix(slash, "../") || slash == ".." || slash == "." {
		base := filepath.Base(filepath.Clean(p))
		if base == "." || base == string(filepath.Separator) || base == "" {
			return "", fmt.Errorf("bounty: cannot derive a file name from %q", path)
		}
		slash = base
	}
	if !validArtifactPath(slash) {
		return "", fmt.Errorf("bounty: unsafe artifact path %q", path)
	}
	return slash, nil
}

// validArtifactPath accepts only non-empty, relative, slash-separated paths
// with no traversal segments. This is what makes joining a stored path with a
// base directory safe.
func validArtifactPath(p string) bool {
	if p == "" || len(p) > 1024 || !utf8.ValidString(p) {
		return false
	}
	if strings.ContainsRune(p, 0) || strings.ContainsRune(p, '\\') {
		return false
	}
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || p == "." {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// hashFile streams path through SHA-256, returning its size and lowercase hex
// digest. It refuses non-regular files and anything larger than limit.
func hashFile(path string, limit int64) (int64, string, error) {
	f, err := os.Open(filepath.Clean(path)) // #nosec G304 -- path is an operator-selected artifact
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	if !info.Mode().IsRegular() {
		return 0, "", fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > limit {
		return 0, "", fmt.Errorf("%s is %d bytes, exceeding the %d byte limit", path, info.Size(), limit)
	}

	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return 0, "", fmt.Errorf("read %s: %w", path, err)
	}
	if n > limit {
		return 0, "", fmt.Errorf("%s exceeds the %d byte limit while reading", path, limit)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// isLowerHex reports whether s is exactly n lowercase hexadecimal characters.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// artifactByRole returns the artifact with the given role.
func (m Manifest) artifactByRole(role ArtifactRole) (Artifact, bool) {
	for _, art := range m.Artifacts {
		if art.Role == role {
			return art, true
		}
	}
	return Artifact{}, false
}
