// Package rbac provides minimal role-based access control helpers.
package rbac

import (
	"errors"

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

// Has checks if role has permission.
func Has(r store.Role, perm string) bool {
	for _, p := range r.Permissions {
		if p == perm {
			return true
		}
	}
	// admins get all
	if r.Name == RoleAdmin {
		return true
	}
	return false
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