package bounty

// claim.go — the typed claim document.
//
// The claim is the reporter's own structured statement: what the issue is, how
// severe they believe it is, where it lives, how to reproduce it, and what
// standard weakness classes it resembles. It is an artifact like any other, so
// its bytes are hashed into the package.
//
// The schema is intentionally small. It exists so a triage system can sort and
// filter reports without parsing free-form prose, not so it can decide whether
// a report is valid — that remains a human judgement.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// ClaimSchemaVersion identifies the claim document shape.
	ClaimSchemaVersion = "bounty-claim/v1"
	// MaxClaimBytes bounds one claim document.
	MaxClaimBytes int64 = 1 << 20

	maxClaimSteps        = 100
	maxClaimStepBytes    = 4096
	maxImpactBytes       = 8192
	maxReferences        = 32
	maxReferenceLength   = 64
	maxComponentNameSize = maxComponentBytes
)

// Severity is the reporter's claimed severity. Triagers may lower it; the
// claimed value is preserved in the package for audit.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Valid reports whether s is a defined severity.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// Validate returns an error naming the allowed severities.
func (s Severity) Validate() error {
	if s.Valid() {
		return nil
	}
	return fmt.Errorf("%q is not one of critical, high, medium, low, info", string(s))
}

// Claim is a reporter's structured description of a suspected vulnerability.
type Claim struct {
	SchemaVersion     string   `json:"schema_version"`
	Title             string   `json:"title"`
	Severity          Severity `json:"severity"`
	Component         string   `json:"component,omitempty"`
	ReproductionSteps []string `json:"reproduction_steps,omitempty"`
	Impact            string   `json:"impact,omitempty"`
	CWE               []string `json:"cwe,omitempty"`
	OWASP             []string `json:"owasp,omitempty"`
}

var (
	cwePattern   = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)
	owaspPattern = regexp.MustCompile(`^A(0[1-9]|10):20[0-9]{2}$`)
)

// ParseClaim decodes and validates a claim document. It is total: malformed
// input produces an error, never a panic.
func ParseClaim(raw []byte) (Claim, error) {
	if int64(len(raw)) > MaxClaimBytes {
		return Claim{}, fmt.Errorf("bounty: claim exceeds the %d byte limit", MaxClaimBytes)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return Claim{}, errors.New("bounty: claim document is empty")
	}

	var c Claim
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Claim{}, fmt.Errorf("bounty: claim is not valid JSON: %w", err)
	}
	if dec.More() {
		return Claim{}, errors.New("bounty: claim contains trailing JSON data")
	}
	if err := c.Validate(); err != nil {
		return Claim{}, err
	}
	return c, nil
}

// LoadClaim reads and parses a claim file under an explicit size limit.
func LoadClaim(path string) (Claim, error) {
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath) // #nosec G304 -- path is an operator-selected claim file
	if err != nil {
		return Claim{}, fmt.Errorf("bounty: read claim: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return Claim{}, fmt.Errorf("bounty: stat claim: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Claim{}, fmt.Errorf("bounty: claim %s is not a regular file", cleanPath)
	}
	if info.Size() > MaxClaimBytes {
		return Claim{}, fmt.Errorf("bounty: claim %s is %d bytes, exceeding the %d byte limit", cleanPath, info.Size(), MaxClaimBytes)
	}

	raw, err := io.ReadAll(io.LimitReader(f, MaxClaimBytes+1))
	if err != nil {
		return Claim{}, fmt.Errorf("bounty: read claim: %w", err)
	}
	if int64(len(raw)) > MaxClaimBytes {
		return Claim{}, fmt.Errorf("bounty: claim %s exceeds the %d byte limit", cleanPath, MaxClaimBytes)
	}
	return ParseClaim(raw)
}

// Validate checks every claim invariant and rejects duplicate references.
func (c Claim) Validate() error {
	if c.SchemaVersion != ClaimSchemaVersion {
		return fmt.Errorf("bounty: claim schema_version is %q, want %q", c.SchemaVersion, ClaimSchemaVersion)
	}
	if !utf8.ValidString(c.Title) {
		return errors.New("bounty: claim title is not valid UTF-8")
	}
	title := strings.TrimSpace(c.Title)
	if title == "" {
		return errors.New("bounty: claim title is empty")
	}
	if len(c.Title) > maxClaimTitleBytes {
		return fmt.Errorf("bounty: claim title exceeds %d bytes", maxClaimTitleBytes)
	}
	if err := c.Severity.Validate(); err != nil {
		return fmt.Errorf("bounty: claim severity: %w", err)
	}
	if len(c.Component) > maxComponentNameSize {
		return fmt.Errorf("bounty: claim component exceeds %d bytes", maxComponentNameSize)
	}
	if !utf8.ValidString(c.Component) {
		return errors.New("bounty: claim component is not valid UTF-8")
	}
	if len(c.ReproductionSteps) > maxClaimSteps {
		return fmt.Errorf("bounty: claim has %d reproduction steps, exceeding the limit of %d", len(c.ReproductionSteps), maxClaimSteps)
	}
	for i, step := range c.ReproductionSteps {
		if strings.TrimSpace(step) == "" {
			return fmt.Errorf("bounty: reproduction step %d is empty", i+1)
		}
		if !utf8.ValidString(step) {
			return fmt.Errorf("bounty: reproduction step %d is not valid UTF-8", i+1)
		}
		if len(step) > maxClaimStepBytes {
			return fmt.Errorf("bounty: reproduction step %d exceeds %d bytes", i+1, maxClaimStepBytes)
		}
	}
	if len(c.Impact) > maxImpactBytes {
		return fmt.Errorf("bounty: claim impact exceeds %d bytes", maxImpactBytes)
	}
	if !utf8.ValidString(c.Impact) {
		return errors.New("bounty: claim impact is not valid UTF-8")
	}
	if err := validateReferences("cwe", c.CWE, cwePattern); err != nil {
		return err
	}
	if err := validateReferences("owasp", c.OWASP, owaspPattern); err != nil {
		return err
	}
	return nil
}

// validateReferences bounds and de-duplicates a reference list.
func validateReferences(name string, refs []string, pattern *regexp.Regexp) error {
	if len(refs) > maxReferences {
		return fmt.Errorf("bounty: claim has %d %s references, exceeding the limit of %d", len(refs), name, maxReferences)
	}
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if len(ref) > maxReferenceLength || !pattern.MatchString(ref) {
			return fmt.Errorf("bounty: %s reference %q is malformed", name, ref)
		}
		if _, dup := seen[ref]; dup {
			return fmt.Errorf("bounty: duplicate %s reference %q", name, ref)
		}
		seen[ref] = struct{}{}
	}
	return nil
}

// NewClaim returns a claim with the current schema version. It is a
// convenience for tests and report generators.
func NewClaim(title string, severity Severity) Claim {
	return Claim{
		SchemaVersion: ClaimSchemaVersion,
		Title:         title,
		Severity:      severity,
	}
}
