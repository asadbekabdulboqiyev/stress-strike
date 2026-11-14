package bounty

// verify.go — replayable package verification.
//
// Verification answers one narrow question: are these the bytes the package
// describes? It re-hashes every artifact, re-computes the manifest digest,
// optionally replays the Sift attestation verification, and checks the claimed
// target against the packaged scope file.
//
// It does not answer whether the finding is real or severe. A report can pass
// every check here and still be invalid; the verdict is about evidence
// integrity and scope, and human triage remains mandatory.
//
// The verifier fails closed: a missing artifact, a size or digest mismatch, an
// unreadable file, a digest over the manifest that does not match, or an
// attestation that does not verify all produce a "failed" verdict. Missing
// inputs (no --bundle, no --target) produce "unverified", never "verified":
// verification never claims more than it actually checked.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

// Check status and verdict values are stable strings so reports can be
// consumed by other tools without importing Go types.
const (
	StatusPass = "pass"
	StatusFail = "fail"
	StatusSkip = "skip"

	VerdictVerified   = "verified"
	VerdictUnverified = "unverified"
	VerdictFailed     = "failed"

	// maxScopeBytes bounds the scope file read during verification.
	maxScopeBytes = 8 << 20
)

// Check is one verification step.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// AttestSummary folds the Sift evidence verification into the report.
type AttestSummary struct {
	Checked       bool     `json:"checked"`
	Valid         bool     `json:"valid"`
	BundleDigest  string   `json:"bundle_digest,omitempty"`
	Coordinator   string   `json:"coordinator_key,omitempty"`
	SamplesAbsent bool     `json:"samples_absent"`
	Workers       int      `json:"workers"`
	WorkersOK     int      `json:"workers_ok"`
	SamplesTotal  int      `json:"samples_total"`
	ChecksRun     int      `json:"checks_run"`
	ChecksFailed  int      `json:"checks_failed"`
	Errors        []string `json:"errors,omitempty"`
}

// VerificationReport is the machine-readable outcome of VerifyPackage.
type VerificationReport struct {
	SchemaVersion string         `json:"schema_version"`
	CheckedAt     string         `json:"checked_at"`
	PackageID     string         `json:"package_id,omitempty"`
	PackageDigest string         `json:"package_digest,omitempty"`
	Verdict       string         `json:"verdict"`
	Checks        []Check        `json:"checks"`
	Attest        *AttestSummary `json:"attest,omitempty"`
	Reasons       []string       `json:"reasons,omitempty"`
	Notes         []string       `json:"notes,omitempty"`
}

// VerifyOptions selects the optional verification inputs. Without BundlePath
// and Target, VerifyPackage checks artifact integrity only and reports
// "unverified" because the interesting questions were not asked.
type VerifyOptions struct {
	BundlePath   string
	SamplesPath  string
	PublicKeyHex string
	Target       string

	// MaxSamplesTotal and SkipCICheck are passed through to attest.
	MaxSamplesTotal int
	SkipCICheck     bool
}

// VerifyPackage verifies m and the artifacts under baseDir.
//
// A structurally invalid manifest is reported as a failed check rather than a
// Go error: every caller must be able to print the report, and the CLI maps a
// failed verdict to exit status 1. An error is returned only when verification
// cannot be attempted at all (for example, no base directory).
func VerifyPackage(m Manifest, baseDir string, opts VerifyOptions) (VerificationReport, error) {
	if strings.TrimSpace(baseDir) == "" {
		return VerificationReport{}, errors.New("bounty: artifact base directory is required")
	}

	report := VerificationReport{
		SchemaVersion: SchemaVersion,
		CheckedAt:     time.Now().UTC().Format(time.RFC3339),
		PackageID:     m.PackageID,
		PackageDigest: m.PackageDigest,
		Notes: []string{
			"Evidence integrity is not finding validity: a verified package still requires human triage.",
			"Reward states are triage outcomes, not payments.",
		},
	}

	if err := m.Validate(); err != nil {
		report.Checks = append(report.Checks, Check{
			Name:   "manifest",
			Status: StatusFail,
			Detail: err.Error(),
		})
		report.finish()
		return report, nil
	}
	report.Checks = append(report.Checks, Check{Name: "manifest", Status: StatusPass})

	// The manifest digest is checked before any artifact so a manifest that was
	// edited after packaging is distinguished from an artifact that was.
	computed, err := m.ComputeDigest()
	if err != nil {
		report.Checks = append(report.Checks, Check{Name: "package-digest", Status: StatusFail, Detail: err.Error()})
	} else if computed != m.PackageDigest {
		report.Checks = append(report.Checks, Check{
			Name:   "package-digest",
			Status: StatusFail,
			Detail: fmt.Sprintf("manifest digest is %s, recomputed %s", m.PackageDigest, computed),
		})
	} else {
		report.Checks = append(report.Checks, Check{Name: "package-digest", Status: StatusPass})
	}

	for _, art := range m.Artifacts {
		report.Checks = append(report.Checks, verifyArtifact(baseDir, art))
	}

	report.Checks = append(report.Checks, verifyScope(m, baseDir, opts.Target))
	attestCheck, summary := verifyAttestation(m, baseDir, opts)
	report.Checks = append(report.Checks, attestCheck)
	report.Attest = summary

	report.finish()
	return report, nil
}

// verifyArtifact re-hashes one artifact and compares size and digest.
func verifyArtifact(baseDir string, art Artifact) Check {
	name := "artifact:" + string(art.Role)
	path, err := resolveArtifactPath(baseDir, art.Path)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Detail: err.Error()}
	}
	size, digest, err := hashFile(path, MaxArtifactBytes)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("%s: %v", art.Path, err)}
	}
	if size != art.Size {
		return Check{
			Name:   name,
			Status: StatusFail,
			Detail: fmt.Sprintf("%s: size is %d bytes, manifest records %d", art.Path, size, art.Size),
		}
	}
	if digest != art.SHA256 {
		return Check{
			Name:   name,
			Status: StatusFail,
			Detail: fmt.Sprintf("%s: sha256 is %s, manifest records %s", art.Path, digest, art.SHA256),
		}
	}
	return Check{Name: name, Status: StatusPass, Detail: art.Path}
}

// verifyScope checks that a scope artifact exists and, when a target is given,
// that the target is covered by it.
func verifyScope(m Manifest, baseDir, target string) Check {
	art, ok := m.artifactByRole(ArtifactScope)
	if !ok {
		return Check{
			Name:   "scope",
			Status: StatusFail,
			Detail: "the package has no scope artifact, so the claimed target cannot be checked",
		}
	}
	if strings.TrimSpace(target) == "" {
		return Check{
			Name:   "scope",
			Status: StatusSkip,
			Detail: "no --target supplied; the scope file was hashed but not interpreted",
		}
	}

	path, err := resolveArtifactPath(baseDir, art.Path)
	if err != nil {
		return Check{Name: "scope", Status: StatusFail, Detail: err.Error()}
	}
	raw, err := readFileLimited(path, maxScopeBytes)
	if err != nil {
		return Check{Name: "scope", Status: StatusFail, Detail: fmt.Sprintf("read scope: %v", err)}
	}
	covered, err := scopeContains(raw, target)
	if err != nil {
		return Check{Name: "scope", Status: StatusFail, Detail: err.Error()}
	}
	if !covered {
		return Check{
			Name:   "scope",
			Status: StatusFail,
			Detail: fmt.Sprintf("target %q is not listed in %s", target, art.Path),
		}
	}
	return Check{Name: "scope", Status: StatusPass, Detail: fmt.Sprintf("target %q is in scope", target)}
}

// verifyAttestation loads and replays the Sift attestation when the caller
// supplied any of its inputs. It returns the check and the folded summary.
func verifyAttestation(m Manifest, baseDir string, opts VerifyOptions) (Check, *AttestSummary) {
	if opts.BundlePath == "" && opts.SamplesPath == "" && opts.PublicKeyHex == "" {
		return Check{
			Name:   "attest",
			Status: StatusSkip,
			Detail: "no --bundle/--key supplied; evidence was not replayed",
		}, nil
	}
	if opts.BundlePath == "" {
		return Check{
			Name:   "attest",
			Status: StatusFail,
			Detail: "attestation inputs require --bundle",
		}, &AttestSummary{Checked: true}
	}

	summary := &AttestSummary{Checked: true}

	if opts.PublicKeyHex != "" {
		if _, err := attest.ParsePublicKeyHex(opts.PublicKeyHex); err != nil {
			return Check{Name: "attest", Status: StatusFail, Detail: fmt.Sprintf("pinned key: %v", err)}, summary
		}
	}

	cleanBundle := filepath.Clean(opts.BundlePath)
	bundle, err := attest.LoadBundle(cleanBundle)
	if err != nil {
		return Check{Name: "attest", Status: StatusFail, Detail: fmt.Sprintf("load bundle: %v", err)}, summary
	}
	bundleDigest, err := bundle.DigestHex()
	if err != nil {
		return Check{Name: "attest", Status: StatusFail, Detail: fmt.Sprintf("bundle digest: %v", err)}, summary
	}
	summary.BundleDigest = bundleDigest
	summary.Coordinator = bundle.Signature.Key

	// Pin the coordinator identity: the manifest's reference and the caller's
	// out-of-band value must both agree with the bundle that was loaded.
	if opts.PublicKeyHex != "" && !strings.EqualFold(opts.PublicKeyHex, bundle.Signature.Key) {
		return Check{
			Name:   "attest",
			Status: StatusFail,
			Detail: fmt.Sprintf("bundle key %s does not match the pinned key %s", bundle.Signature.Key, opts.PublicKeyHex),
		}, summary
	}
	if m.Attest.BundlePublicKey != "" && !strings.EqualFold(m.Attest.BundlePublicKey, bundle.Signature.Key) {
		return Check{
			Name:   "attest",
			Status: StatusFail,
			Detail: fmt.Sprintf("bundle key %s does not match the manifest reference %s", bundle.Signature.Key, m.Attest.BundlePublicKey),
		}, summary
	}
	if m.Attest.BundleDigest != "" && bundleDigest != m.Attest.BundleDigest {
		return Check{
			Name:   "attest",
			Status: StatusFail,
			Detail: fmt.Sprintf("bundle digest %s does not match the manifest reference %s", bundleDigest, m.Attest.BundleDigest),
		}, summary
	}

	// When the package ships a bundle artifact, the file handed to verify must
	// be that file: otherwise an operator could verify one bundle and publish a
	// package pointing at another.
	if art, ok := m.artifactByRole(ArtifactBundle); ok {
		_, digest, err := hashFile(cleanBundle, MaxArtifactBytes)
		if err != nil {
			return Check{Name: "attest", Status: StatusFail, Detail: fmt.Sprintf("hash --bundle: %v", err)}, summary
		}
		if digest != art.SHA256 {
			return Check{
				Name:   "attest",
				Status: StatusFail,
				Detail: fmt.Sprintf("--bundle does not match the packaged %s", art.Path),
			}, summary
		}
	}

	var samples map[string][]attest.Record
	if opts.SamplesPath != "" {
		cleanSamples := filepath.Clean(opts.SamplesPath)
		loaded, _, err := attest.LoadSamples(cleanSamples, attest.DefaultSampleLoadOptions())
		if err != nil {
			return Check{Name: "attest", Status: StatusFail, Detail: fmt.Sprintf("load samples: %v", err)}, summary
		}
		samples = loaded

		if m.Attest.SidecarDigest != "" {
			_, digest, err := hashFile(cleanSamples, MaxArtifactBytes)
			if err != nil {
				return Check{Name: "attest", Status: StatusFail, Detail: fmt.Sprintf("hash --samples: %v", err)}, summary
			}
			if digest != m.Attest.SidecarDigest {
				return Check{
					Name:   "attest",
					Status: StatusFail,
					Detail: fmt.Sprintf("--samples digest %s does not match the manifest reference %s", digest, m.Attest.SidecarDigest),
				}, summary
			}
		}
		if art, ok := m.artifactByRole(ArtifactSamples); ok {
			_, digest, err := hashFile(cleanSamples, MaxArtifactBytes)
			if err != nil {
				return Check{Name: "attest", Status: StatusFail, Detail: fmt.Sprintf("hash --samples: %v", err)}, summary
			}
			if digest != art.SHA256 {
				return Check{
					Name:   "attest",
					Status: StatusFail,
					Detail: fmt.Sprintf("--samples does not match the packaged %s", art.Path),
				}, summary
			}
		}
	} else if m.Attest.SidecarDigest != "" {
		return Check{
			Name:   "attest",
			Status: StatusFail,
			Detail: "the manifest references a sample sidecar but --samples was not supplied",
		}, summary
	}

	res := attest.VerifyWith(bundle, samples, attest.VerifyOptions{
		MaxSamplesTotal: opts.MaxSamplesTotal,
		SkipCICheck:     opts.SkipCICheck,
	})
	summary.Valid = res.Valid
	summary.SamplesAbsent = res.SamplesAbsent
	summary.Workers = res.Summary.Workers
	summary.WorkersOK = res.Summary.WorkersOK
	summary.SamplesTotal = res.Summary.SamplesTotal
	summary.ChecksRun = res.Summary.ChecksRun
	summary.ChecksFailed = res.Summary.ChecksFailed
	summary.Errors = res.ErrorLines()

	if !res.Valid {
		detail := fmt.Sprintf("%d of %d checks failed", res.Summary.ChecksFailed, res.Summary.ChecksRun)
		if first, ok := res.FirstError(); ok {
			detail += ": " + first.Error()
		}
		return Check{Name: "attest", Status: StatusFail, Detail: detail}, summary
	}
	return Check{
		Name:   "attest",
		Status: StatusPass,
		Detail: fmt.Sprintf("%d checks passed across %d workers", res.Summary.ChecksRun, res.Summary.Workers),
	}, summary
}

// finish computes the verdict and the human-readable reasons. Any failed check
// makes the package failed; otherwise an unchecked step makes it unverified.
func (r *VerificationReport) finish() {
	r.Verdict = VerdictVerified
	r.Reasons = nil
	for _, c := range r.Checks {
		switch c.Status {
		case StatusFail:
			r.Verdict = VerdictFailed
		case StatusSkip:
			if r.Verdict == VerdictVerified {
				r.Verdict = VerdictUnverified
			}
		}
	}
	for _, c := range r.Checks {
		if c.Status != StatusFail {
			continue
		}
		reason := c.Name
		if c.Detail != "" {
			reason += ": " + c.Detail
		}
		r.Reasons = append(r.Reasons, reason)
	}
}

// resolveArtifactPath joins a stored, validated relative path to baseDir and
// re-checks containment.
func resolveArtifactPath(baseDir, rel string) (string, error) {
	if !validArtifactPath(rel) {
		return "", fmt.Errorf("bounty: unsafe artifact path %q", rel)
	}
	base := filepath.Clean(baseDir)
	joined := filepath.Join(base, filepath.FromSlash(rel))
	back, err := filepath.Rel(base, joined)
	if err != nil {
		return "", fmt.Errorf("bounty: resolve artifact %q: %w", rel, err)
	}
	if back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("bounty: artifact path %q escapes the base directory", rel)
	}
	return joined, nil
}

// readFileLimited reads a regular file with an explicit byte limit.
func readFileLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path)) // #nosec G304 -- path is an operator-selected artifact
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s is %d bytes, exceeding the %d byte limit", path, info.Size(), limit)
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d byte limit while reading", path, limit)
	}
	return raw, nil
}
