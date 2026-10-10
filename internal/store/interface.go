// Package store defines the persistence interfaces for the control-plane.
// These are intentionally storage-agnostic: the in-memory implementation
// satisfies the contracts for local tests; Postgres is the enterprise target.
package store

import (
	"context"
	"time"
)

// Tenant is an organizational unit.
type Tenant struct {
	ID        string
	Name      string
	Slug      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// User is a platform user.
type User struct {
	ID        string
	TenantID  string
	Email     string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Role is a role in a tenant.
type Role struct {
	ID          string
	TenantID    string
	Name        string
	Permissions []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// APIKey is a programmatic API key.
type APIKey struct {
	ID        string
	TenantID  string
	UserID    string
	KeyHash   string
	Name      string
	ExpiresAt *time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

// AuditEvent is a control-plane audit record (complements the file-based
// hash-chained audit already used by the CLI).
type AuditEvent struct {
	ID        string
	TenantID  string
	ActorID   string
	Action    string
	Resource  string
	Details   string
	CreatedAt time.Time
	RemoteIP  string
	UserAgent string
}

// TenantStore manages tenants.
type TenantStore interface {
	Create(ctx context.Context, t Tenant) (Tenant, error)
	Get(ctx context.Context, id string) (Tenant, error)
	List(ctx context.Context) ([]Tenant, error)
}

// UserStore manages users.
type UserStore interface {
	Create(ctx context.Context, u User) (User, error)
	Get(ctx context.Context, id string) (User, error)
	ListByTenant(ctx context.Context, tenantID string) ([]User, error)
}

// RoleStore manages roles.
type RoleStore interface {
	Create(ctx context.Context, r Role) (Role, error)
	Get(ctx context.Context, id string) (Role, error)
	ListByTenant(ctx context.Context, tenantID string) ([]Role, error)
}

// APIKeyStore manages API keys.
type APIKeyStore interface {
	Create(ctx context.Context, k APIKey) (APIKey, error)
	GetByHash(ctx context.Context, hash string) (APIKey, error)
	Revoke(ctx context.Context, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]APIKey, error)
}

// AuditStore persists control-plane audit events.
type AuditStore interface {
	Write(ctx context.Context, a AuditEvent) error
	ListByTenant(ctx context.Context, tenantID string, limit int) ([]AuditEvent, error)
}

// Store composes the persistence surface for the control-plane.
type Store interface {
	Tenants() TenantStore
	Users() UserStore
	Roles() RoleStore
	APIKeys() APIKeyStore
	Audits() AuditStore
}