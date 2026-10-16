package authz

import (
	"os"
	"path/filepath"
	"strings"
)

// ConfigHome is the directory holding stress-strike's local state: the
// authorization policy and the audit trail.
//
// STRESS_STRIKE_HOME overrides it (isolated runs, tests); otherwise it is
// ~/.stress-strike, falling back to a relative directory when the host has no
// home directory at all.
func ConfigHome() string {
	if d := strings.TrimSpace(os.Getenv("STRESS_STRIKE_HOME")); d != "" {
		return d
	}
	if d, err := os.UserHomeDir(); err == nil && d != "" {
		return filepath.Join(d, ".stress-strike")
	}
	return ".stress-strike"
}

// DefaultPolicyPath is where the authorization policy lives unless
// STRESS_STRIKE_POLICY points somewhere else.
//
// Every entry point — run, scan, pentest and the dashboard's OWASP endpoint —
// resolves it through here, so they cannot disagree about which policy is in
// force. Passing a non-existent path to LoadPolicyOrDefault yields the default
// policy; passing an empty string would happen to do the same only because
// opening "" fails with ENOENT, which is a fragile way to be safe.
func DefaultPolicyPath() string {
	if p := os.Getenv("STRESS_STRIKE_POLICY"); p != "" {
		return p
	}
	return filepath.Join(ConfigHome(), "authz.json")
}

// DefaultAuditPath is the hash-chained audit trail every entry point appends
// to. One file, so `stress-strike audit` shows web-triggered scans alongside
// CLI ones.
func DefaultAuditPath() string {
	if p := os.Getenv("STRESS_STRIKE_AUDIT_LOG"); p != "" {
		return p
	}
	return filepath.Join(ConfigHome(), "audit.jsonl")
}
