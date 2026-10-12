package rbac

import (
	"errors"
	"reflect"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

func role(name string, perms ...string) store.Role {
	return store.Role{Name: name, Permissions: perms}
}

// --- Has: exact matching (backward compatible) -------------------------------

func TestHasExactMatch(t *testing.T) {
	r := role(RoleEngineer, PermRun, PermView)
	if !Has(r, PermRun) {
		t.Error("engineer must have tests:run")
	}
	if !Has(r, PermView) {
		t.Error("engineer must have tests:view")
	}
	if Has(r, PermAdmin) {
		t.Error("engineer must not have admin:access")
	}
}

func TestHasEmptyPermissionsDenies(t *testing.T) {
	r := role(RoleViewer)
	if Has(r, PermView) {
		t.Error("a role with no permissions must deny everything")
	}
}

// --- Has: admin wildcard (preserved behavior) --------------------------------

func TestHasAdminGrantsEverything(t *testing.T) {
	admin := role(RoleAdmin) // no explicit permissions at all
	for _, perm := range []string{PermRun, PermView, PermAdmin, PermAuditRead, "anything:else", ""} {
		if !Has(admin, perm) {
			t.Errorf("admin must be granted %q", perm)
		}
	}
}

// --- Has: wildcard matching --------------------------------------------------

func TestHasWildcardSegment(t *testing.T) {
	r := role(RoleEngineer, "tests:*")
	for _, perm := range []string{PermRun, PermView, "tests:delete"} {
		if !Has(r, perm) {
			t.Errorf("tests:* must grant %q", perm)
		}
	}
	for _, perm := range []string{PermAdmin, PermAuditRead, "tests", "admin:tests"} {
		if Has(r, perm) {
			t.Errorf("tests:* must not grant %q", perm)
		}
	}
}

func TestHasWildcardPrefixSegment(t *testing.T) {
	r := role("auditor", "*:read")
	if !Has(r, PermAuditRead) {
		t.Error("*:read must grant audit:read")
	}
	if Has(r, "audit:write") {
		t.Error("*:read must not grant audit:write")
	}
	if Has(r, "audit") {
		t.Error("*:read must not grant the single-segment permission audit")
	}
}

func TestHasAllSegmentsWildcard(t *testing.T) {
	r := role("ops", "*:*")
	if !Has(r, PermRun) {
		t.Error("*:* must grant tests:run")
	}
	if !Has(r, PermAuditRead) {
		t.Error("*:* must grant audit:read")
	}
	if Has(r, "tests:run:deep") {
		t.Error("*:* must not grant a three-segment permission")
	}
}

func TestHasBareStarGrantsEverything(t *testing.T) {
	r := role("super", "*")
	for _, perm := range []string{PermRun, PermView, PermAdmin, PermAuditRead, "a:b:c:d", ""} {
		if !Has(r, perm) {
			t.Errorf("bare * must grant %q", perm)
		}
	}
}

// TestHasWildcardLengthMustMatch: a wildcard only substitutes one segment.
func TestHasWildcardLengthMustMatch(t *testing.T) {
	r := role("x", "tests:*")
	if Has(r, "tests:run:deep") {
		t.Error("tests:* must not match a three-segment request")
	}
	if Has(r, "tests") {
		t.Error("tests:* must not match a single-segment request")
	}
}

// TestHasNoPartialSegmentWildcard: '*' inside a segment is not a wildcard.
func TestHasNoPartialSegmentWildcard(t *testing.T) {
	r := role("x", "te*")
	if Has(r, "tests") {
		t.Error("te* must not behave as a prefix wildcard")
	}
	r = role("y", "tests:r*n")
	if Has(r, PermRun) {
		t.Error("tests:r*n must not behave as an infix wildcard")
	}
}

func TestHasMultipleGrantsAnyMatch(t *testing.T) {
	r := role("mixed", PermView, "audit:*")
	if !Has(r, PermView) {
		t.Error("explicit grant must match")
	}
	if !Has(r, PermAuditRead) {
		t.Error("wildcard grant must match")
	}
	if Has(r, PermRun) {
		t.Error("unrelated permission must not match")
	}
}

// --- Authorize ---------------------------------------------------------------

func TestAuthorize(t *testing.T) {
	engineer := role(RoleEngineer, PermRun, PermView)
	if err := Authorize(engineer, PermRun); err != nil {
		t.Errorf("Authorize(engineer, tests:run) = %v, want nil", err)
	}
	if err := Authorize(engineer, PermAdmin); !errors.Is(err, ErrDenied) {
		t.Errorf("Authorize(engineer, admin:access) = %v, want ErrDenied", err)
	}
	if err := Authorize(role(RoleAdmin), "anything:at:all"); err != nil {
		t.Errorf("Authorize(admin, ...) = %v, want nil", err)
	}
	if err := Authorize(role("wild", "tests:*"), PermView); err != nil {
		t.Errorf("Authorize(wildcard role, tests:view) = %v, want nil", err)
	}
}

// --- PermissionsFor ----------------------------------------------------------

func TestPermissionsForDedupAndSort(t *testing.T) {
	got := PermissionsFor(
		role(RoleEngineer, PermRun, PermView),
		role(RoleViewer, PermView),
		role("auditor", PermAuditRead, PermRun),
	)
	want := []string{PermAuditRead, PermRun, PermView} // sorted
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PermissionsFor = %v, want %v", got, want)
	}
}

func TestPermissionsForEmpty(t *testing.T) {
	if got := PermissionsFor(); len(got) != 0 {
		t.Errorf("PermissionsFor() = %v, want empty", got)
	}
	if got := PermissionsFor(role(RoleAdmin)); len(got) != 0 {
		t.Errorf("PermissionsFor(admin with no explicit perms) = %v, want empty", got)
	}
}

func TestPermissionsForSkipsBlankEntries(t *testing.T) {
	got := PermissionsFor(role("x", "", "  ", PermView))
	want := []string{PermView}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PermissionsFor = %v, want %v", got, want)
	}
}

// TestPermissionsForDoesNotMutateInput ensures the returned slice is a copy.
func TestPermissionsForDoesNotMutateInput(t *testing.T) {
	r := role("x", PermView)
	out := PermissionsFor(r)
	if len(out) != 1 {
		t.Fatalf("PermissionsFor = %v, want one entry", out)
	}
	out[0] = "mutated"
	if r.Permissions[0] != PermView {
		t.Error("PermissionsFor must not alias the role's permission slice")
	}
}

// --- DefaultPermissions ------------------------------------------------------

func TestDefaultPermissions(t *testing.T) {
	tests := map[string][]string{
		RoleAdmin:    {PermRun, PermView, PermAdmin, PermAuditRead},
		RoleEngineer: {PermRun, PermView},
		RoleViewer:   {PermView},
		"unknown":    {PermView},
	}
	for name, want := range tests {
		if got := DefaultPermissions(name); !reflect.DeepEqual(got, want) {
			t.Errorf("DefaultPermissions(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestDefaultPermissionsAreSelfConsistent: the defaults grant what they claim.
func TestDefaultPermissionsAreSelfConsistent(t *testing.T) {
	for _, name := range []string{RoleAdmin, RoleEngineer, RoleViewer} {
		r := role(name, DefaultPermissions(name)...)
		if !Has(r, PermView) {
			t.Errorf("default %s role must be able to view tests", name)
		}
	}
}
