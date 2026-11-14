package bounty

// claim_test.go — typed claim validation and bounds.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseClaimValid(t *testing.T) {
	c, err := ParseClaim([]byte(testClaimJSON))
	if err != nil {
		t.Fatalf("ParseClaim: %v", err)
	}
	if c.SchemaVersion != ClaimSchemaVersion {
		t.Fatalf("schema = %q, want %q", c.SchemaVersion, ClaimSchemaVersion)
	}
	if c.Severity != SeverityHigh {
		t.Fatalf("severity = %q, want high", c.Severity)
	}
	if len(c.ReproductionSteps) != 2 {
		t.Fatalf("got %d reproduction steps, want 2", len(c.ReproductionSteps))
	}
	if len(c.CWE) != 1 || c.CWE[0] != "CWE-639" {
		t.Fatalf("cwe = %v", c.CWE)
	}
	if len(c.OWASP) != 1 || c.OWASP[0] != "A01:2021" {
		t.Fatalf("owasp = %v", c.OWASP)
	}
}

func TestParseClaimRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ` `},
		{"bad json", `{"schema_version":`},
		{"wrong schema", `{"schema_version":"v0","title":"t","severity":"high"}`},
		{"empty title", `{"schema_version":"bounty-claim/v1","title":"  ","severity":"high"}`},
		{"bad severity", `{"schema_version":"bounty-claim/v1","title":"t","severity":"urgent"}`},
		{"bad cwe", `{"schema_version":"bounty-claim/v1","title":"t","severity":"low","cwe":["CWE-abc"]}`},
		{"duplicate cwe", `{"schema_version":"bounty-claim/v1","title":"t","severity":"low","cwe":["CWE-79","CWE-79"]}`},
		{"bad owasp", `{"schema_version":"bounty-claim/v1","title":"t","severity":"low","owasp":["A99:1999"]}`},
		{"unknown field", `{"schema_version":"bounty-claim/v1","title":"t","severity":"low","bounty":99}`},
		{"empty step", `{"schema_version":"bounty-claim/v1","title":"t","severity":"low","reproduction_steps":["ok","  "]}`},
		{"trailing data", `{"schema_version":"bounty-claim/v1","title":"t","severity":"low"} {}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseClaim([]byte(tc.raw)); err == nil {
				t.Fatal("ParseClaim accepted an invalid document")
			}
		})
	}
}

func TestParseClaimBounds(t *testing.T) {
	c := NewClaim("t", SeverityLow)
	c.ReproductionSteps = make([]string, maxClaimSteps+1)
	for i := range c.ReproductionSteps {
		c.ReproductionSteps[i] = "step"
	}
	if err := c.Validate(); err == nil {
		t.Fatal("Validate accepted too many reproduction steps")
	}

	c = NewClaim("t", SeverityLow)
	c.Impact = strings.Repeat("x", maxImpactBytes+1)
	if err := c.Validate(); err == nil {
		t.Fatal("Validate accepted an oversized impact statement")
	}

	c = NewClaim("t", SeverityLow)
	c.CWE = make([]string, maxReferences+1)
	for i := range c.CWE {
		c.CWE[i] = "CWE-" + strings.Repeat("1", i%4+1)
	}
	if err := c.Validate(); err == nil {
		t.Fatal("Validate accepted too many references")
	}
}

func TestLoadClaimRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claim.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create claim: %v", err)
	}
	if err := f.Truncate(MaxClaimBytes + 1); err != nil {
		_ = f.Close()
		t.Fatalf("truncate claim: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close claim: %v", err)
	}
	if _, err := LoadClaim(path); err == nil {
		t.Fatal("LoadClaim accepted an oversized file")
	}
	if _, err := LoadClaim(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("LoadClaim accepted a missing file")
	}
}
