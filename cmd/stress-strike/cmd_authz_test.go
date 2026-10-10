package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
)

func testGate(t *testing.T) gateOptions {
	t.Helper()
	dir := t.TempDir()
	return gateOptions{
		policyPath: filepath.Join(dir, "authz.json"),
		auditPath:  filepath.Join(dir, "audit.jsonl"),
	}
}

// IP literals are used throughout so the tests never touch DNS.
const (
	metadataTarget = "http://169.254.169.254/latest/meta-data/"
	publicTarget   = "https://93.184.216.34/"
	privateTarget  = "http://10.11.12.13/"
)

func TestGateBlocksMetadata(t *testing.T) {
	g := testGate(t)
	out, err := evaluateAuthz(authz.OpLoadTest, []string{metadataTarget}, g)
	if err != nil {
		t.Fatal(err)
	}
	if out.Allowed {
		t.Fatalf("metadata target must be denied: %s", out.Reason)
	}
	if out.Class != "metadata" {
		t.Fatalf("class = %q, want metadata", out.Class)
	}
}

func TestGateAllowsPublic(t *testing.T) {
	g := testGate(t)
	out, err := evaluateAuthz(authz.OpLoadTest, []string{publicTarget}, g)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Allowed {
		t.Fatalf("public target denied: %s", out.Reason)
	}
}

func TestGateBlocksPrivateUnlessAllowed(t *testing.T) {
	g := testGate(t)
	out, err := evaluateAuthz(authz.OpLoadTest, []string{privateTarget}, g)
	if err != nil {
		t.Fatal(err)
	}
	if out.Allowed {
		t.Fatal("private target must be denied without --allow-private")
	}

	g.allowPrivate = true
	out, err = evaluateAuthz(authz.OpLoadTest, []string{privateTarget}, g)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Allowed {
		t.Fatalf("private target denied with --allow-private: %s", out.Reason)
	}
}

func TestGatePentestRequiresTicket(t *testing.T) {
	g := testGate(t)
	out, err := evaluateAuthz(authz.OpPentest, []string{publicTarget}, g)
	if err != nil {
		t.Fatal(err)
	}
	if out.Allowed {
		t.Fatal("pentest must require explicit authorization")
	}
}

func TestGateAuthorizedTicket(t *testing.T) {
	g := testGate(t)
	pol := authz.DefaultPolicy()
	pol.Rules = []authz.Rule{{
		Pattern:  "93.184.216.34",
		Approver: "ciso@corp",
		Ticket:   "SEC-77",
	}}
	if err := savePolicy(g.policyPath, pol); err != nil {
		t.Fatal(err)
	}

	// Without naming the ticket, a pentest is still denied.
	if out, _ := evaluateAuthz(authz.OpPentest, []string{publicTarget}, g); out.Allowed {
		t.Fatal("pentest should be denied without --authorized")
	}

	// Naming the approved ticket unlocks it.
	g.authorized = "SEC-77"
	out, err := evaluateAuthz(authz.OpPentest, []string{publicTarget}, g)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Allowed {
		t.Fatalf("authorized pentest denied: %s", out.Reason)
	}
	if out.Rule != "93.184.216.34" {
		t.Fatalf("rule = %q", out.Rule)
	}

	// A wrong ticket does not.
	g.authorized = "SEC-000"
	if out, _ := evaluateAuthz(authz.OpPentest, []string{publicTarget}, g); out.Allowed {
		t.Fatal("wrong ticket must not authorize")
	}
}

func TestGateWritesVerifiableAuditTrail(t *testing.T) {
	g := testGate(t)

	// Two decisions: one allowed, one denied.
	allow, _ := evaluateAuthz(authz.OpLoadTest, []string{publicTarget}, g)
	deny, _ := evaluateAuthz(authz.OpLoadTest, []string{metadataTarget}, g)

	recordAuthz(authz.Entry{Action: "run", Targets: allow.Targets, Class: allow.Class, Allowed: allow.Allowed, Reason: allow.Reason}, g.auditPath, "")
	recordAuthz(authz.Entry{Action: "run", Targets: deny.Targets, Class: deny.Class, Allowed: deny.Allowed, Reason: deny.Reason}, g.auditPath, "")

	n, err := authz.Verify(g.auditPath)
	if err != nil {
		t.Fatalf("audit trail not verifiable: %v", err)
	}
	if n != 2 {
		t.Fatalf("audit recorded %d entries, want 2", n)
	}

	entries, err := authz.ReadAll(g.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !entries[0].Allowed || entries[1].Allowed {
		t.Fatalf("unexpected decisions: %+v", entries)
	}
	if entries[1].Class != "metadata" {
		t.Fatalf("denied entry class = %q", entries[1].Class)
	}
	if _, err := os.Stat(g.auditPath); err != nil {
		t.Fatal(err)
	}
}

func TestGateStrictPolicyBlocksPublic(t *testing.T) {
	g := testGate(t)
	pol := authz.DefaultPolicy()
	pol.Mode = authz.ModeStrict
	if err := savePolicy(g.policyPath, pol); err != nil {
		t.Fatal(err)
	}
	out, err := evaluateAuthz(authz.OpLoadTest, []string{publicTarget}, g)
	if err != nil {
		t.Fatal(err)
	}
	if out.Allowed {
		t.Fatal("strict policy must deny an unlisted public target")
	}
}

// TestGateDefaultPathsHonorEnvironment pins the bug where an empty --policy
// meant the saved approval file was never read. With no explicit paths, the
// gate must use $STRESS_STRIKE_HOME.
func TestGateDefaultPathsHonorEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("STRESS_STRIKE_HOME", dir)

	if got, want := defaultPolicyPath(), filepath.Join(dir, "authz.json"); got != want {
		t.Fatalf("defaultPolicyPath = %q, want %q", got, want)
	}
	if got, want := defaultAuditPath(), filepath.Join(dir, "audit.jsonl"); got != want {
		t.Fatalf("defaultAuditPath = %q, want %q", got, want)
	}

	pol := authz.DefaultPolicy()
	pol.Rules = []authz.Rule{{Pattern: "93.184.216.34", Approver: "ciso@corp", Ticket: "SEC-1"}}
	if err := savePolicy(defaultPolicyPath(), pol); err != nil {
		t.Fatal(err)
	}

	// Empty gateOptions: every path is the default.
	out, err := evaluateAuthz(authz.OpPentest, []string{publicTarget}, gateOptions{authorized: "SEC-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Allowed {
		t.Fatalf("approved ticket on default paths was not honored: %s", out.Reason)
	}
}
