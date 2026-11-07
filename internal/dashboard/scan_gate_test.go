package dashboard

import (
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/rbac"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

// --- rbacAllowed ------------------------------------------------------------

func TestRbacAllowed(t *testing.T) {
	// RBAC disabled → always allowed.
	a := &Auth{rbacEnabled: false}
	if !a.rbacAllowed("anyone", nil, "tests:run") {
		t.Error("rbacAllowed(rbac disabled) = false, want true")
	}
	if !a.rbacAllowed("anyone", nil, "admin:access") {
		t.Error("rbacAllowed(rbac disabled, admin) = false, want true")
	}

	// RBAC enabled, no roles for subject → denied.
	a = &Auth{rbacEnabled: true, rbacRoles: map[string][]string{}}
	if a.rbacAllowed("alice", nil, "tests:view") {
		t.Error("rbacAllowed(no roles) = true, want false")
	}

	// RBAC enabled, subject has viewer role with tests:view permission.
	// rbacRoles maps subject→roles AND role name→permissions (double duty).
	a = &Auth{
		rbacEnabled: true,
		rbacRoles: map[string][]string{
			"alice":  {"viewer"},
			"viewer": {"tests:view"},
		},
	}
	if !a.rbacAllowed("alice", nil, "tests:view") {
		t.Error("rbacAllowed(alice, viewer, tests:view) = false, want true")
	}
	if a.rbacAllowed("alice", nil, "tests:run") {
		t.Error("rbacAllowed(alice, viewer, tests:run) = true, want false")
	}
	if a.rbacAllowed("alice", nil, "admin:access") {
		t.Error("rbacAllowed(alice, viewer, admin:access) = true, want false")
	}

	// RBAC enabled, subject has operator role with tests:run + tests:view.
	a = &Auth{
		rbacEnabled: true,
		rbacRoles: map[string][]string{
			"bob":      {"operator"},
			"operator": {"tests:run", "tests:view"},
		},
	}
	if !a.rbacAllowed("bob", nil, "tests:run") {
		t.Error("rbacAllowed(bob, operator, tests:run) = false, want true")
	}
	if !a.rbacAllowed("bob", nil, "tests:view") {
		t.Error("rbacAllowed(bob, operator, tests:view) = false, want true")
	}

	// Admin role grants everything (* permission).
	a = &Auth{
		rbacEnabled: true,
		rbacRoles: map[string][]string{
			"carol": {"admin"},
			"admin": {"*"},
		},
	}
	if !a.rbacAllowed("carol", nil, "tests:run") {
		t.Error("rbacAllowed(carol, admin, tests:run) = false, want true")
	}
	if !a.rbacAllowed("carol", nil, "admin:access") {
		t.Error("rbacAllowed(carol, admin, admin:access) = false, want true")
	}

	// OIDC roles appended: subject has no direct role but OIDC role grants perm.
	a = &Auth{
		rbacEnabled: true,
		rbacRoles: map[string][]string{
			"dave":        {},
			"oidc-viewer": {"tests:view"},
		},
	}
	if !a.rbacAllowed("dave", []string{"oidc-viewer"}, "tests:view") {
		t.Error("rbacAllowed(dave, [oidc-viewer], tests:view) = false, want true")
	}

	// Unknown subject with OIDC role that grants perm.
	if !a.rbacAllowed("eve", []string{"oidc-viewer"}, "tests:view") {
		t.Error("rbacAllowed(eve, [oidc-viewer], tests:view) = false, want true")
	}
}

// --- Scan gate functions ----------------------------------------------------

// setTestHome sets STRESS_STRIKE_HOME to a temp dir for test isolation.
func setTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("STRESS_STRIKE_HOME", home)
	return home
}

func TestDirbustGate(t *testing.T) {
	setTestHome(t)

	// Public target allowed by default (permissive mode, no policy file).
	out, err := dirbustGate("https://127.0.0.1/")
	if err != nil {
		t.Fatalf("dirbustGate(public): %v", err)
	}
	if !out.Allowed {
		t.Errorf("dirbustGate(public) Allowed = false, want true")
	}
}

func TestGraphqlGate(t *testing.T) {
	setTestHome(t)
	out, err := graphqlGate("https://127.0.0.1/graphql")
	if err != nil {
		t.Fatalf("graphqlGate: %v", err)
	}
	if !out.Allowed {
		t.Errorf("graphqlGate(public) Allowed = false, want true")
	}
}

func TestPortscanGate(t *testing.T) {
	setTestHome(t)
	out, err := portscanGate("https://127.0.0.1/")
	if err != nil {
		t.Fatalf("portscanGate: %v", err)
	}
	if !out.Allowed {
		t.Errorf("portscanGate(public) Allowed = false, want true")
	}
}

func TestSslscanGate(t *testing.T) {
	setTestHome(t)
	out, err := sslscanGate("https://127.0.0.1/")
	if err != nil {
		t.Fatalf("sslscanGate: %v", err)
	}
	if !out.Allowed {
		t.Errorf("sslscanGate(public) Allowed = false, want true")
	}
}

func TestSubdomainGate(t *testing.T) {
	setTestHome(t)
	out, err := subdomainGate("127.0.0.1")
	if err != nil {
		t.Fatalf("subdomainGate: %v", err)
	}
	if !out.Allowed {
		t.Errorf("subdomainGate(public) Allowed = false, want true")
	}
}

func TestWebsocketGate(t *testing.T) {
	setTestHome(t)
	out, err := websocketGate("wss://127.0.0.1/socket")
	if err != nil {
		t.Fatalf("websocketGate: %v", err)
	}
	if !out.Allowed {
		t.Errorf("websocketGate(public) Allowed = false, want true")
	}
}

// --- Audit functions --------------------------------------------------------

func TestScanAuditFunctions(t *testing.T) {
	setTestHome(t)

	e := authz.Entry{
		Action:  "scan",
		Targets: []string{"https://example.test/"},
		Allowed: true,
		Class:   "public",
		Reason:  "public target",
		Version: "test",
	}

	// All audit functions delegate to owaspAudit which appends to the audit log.
	if err := dirbustAudit(e); err != nil {
		t.Fatalf("dirbustAudit: %v", err)
	}
	if err := graphqlAudit(e); err != nil {
		t.Fatalf("graphqlAudit: %v", err)
	}
	if err := portscanAudit(e); err != nil {
		t.Fatalf("portscanAudit: %v", err)
	}
	if err := sslscanAudit(e); err != nil {
		t.Fatalf("sslscanAudit: %v", err)
	}
	if err := subdomainAudit(e); err != nil {
		t.Fatalf("subdomainAudit: %v", err)
	}
	if err := websocketAudit(e); err != nil {
		t.Fatalf("websocketAudit: %v", err)
	}
}

// Ensure imports are used (referenced indirectly via rbacAllowed).
var _ = rbac.Has
var _ = store.Role{}
