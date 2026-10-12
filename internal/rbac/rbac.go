// Package rbac provides minimal role-based access control helpers.
package rbac

import (
	"errors"
	"sort"
	"strings"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

// Default roles and permissions.
const (
	RoleAdmin     = "admin"
	RoleEngineer  = "engineer"
	RoleViewer    = "viewer"
	PermRun       = "tests:run"
	PermView      = "tests:view"
	PermAdmin     = "admin:access"
	PermAuditRead = "audit:read"
)

var ErrDenied = errors.New("rbac: permission denied")

// Has reports whether the role grants perm. Admin always grants everything.
// A granted permission may use `*` as a whole segment to match any value in
// that position: `tests:*` grants `tests:run` and `tests:view`, `*:*` grants
// every two-segment permission, and a bare `*` grants everything.
func Has(r store.Role, perm string) bool {
	if r.Name == RoleAdmin {
		return true
	}
	for _, granted := range r.Permissions {
		if matchPermission(granted, perm) {
			return true
		}
	}
	return false
}

// Authorize returns nil when the role may perform perm, ErrDenied otherwise.
func Authorize(role store.Role, perm string) error {
	if Has(role, perm) {
		return nil
	}
	return ErrDenied
}

// PermissionsFor returns the deduplicated, sorted union of the explicit
// permissions carried by the given roles. Admin's implicit universal access is
// not expanded here; use Has/Authorize for the authorization decision.
func PermissionsFor(roles ...store.Role) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, role := range roles {
		for _, perm := range role.Permissions {
			perm = strings.TrimSpace(perm)
			if perm == "" {
				continue
			}
			if _, ok := seen[perm]; ok {
				continue
			}
			seen[perm] = struct{}{}
			out = append(out, perm)
		}
	}
	sort.Strings(out)
	return out
}

// matchPermission reports whether a granted permission (which may contain `*`
// segments) authorizes the requested permission, comparing segment by segment.
func matchPermission(granted, requested string) bool {
	if granted == requested {
		return true
	}
	if granted == "*" {
		return true
	}

	grantedSegs := strings.Split(granted, ":")
	requestedSegs := strings.Split(requested, ":")
	if len(grantedSegs) != len(requestedSegs) {
		return false
	}
	for i := range grantedSegs {
		if grantedSegs[i] == "*" {
			continue
		}
		if grantedSegs[i] != requestedSegs[i] {
			return false
		}
	}
	return true
}

// DefaultPermissions returns sensible defaults.
func DefaultPermissions(name string) []string {
	switch name {
	case RoleAdmin:
		return []string{PermRun, PermView, PermAdmin, PermAuditRead}
	case RoleEngineer:
		return []string{PermRun, PermView}
	case RoleViewer:
		return []string{PermView}
	default:
		return []string{PermView}
	}
}
