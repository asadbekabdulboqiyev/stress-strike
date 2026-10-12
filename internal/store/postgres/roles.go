package postgres

import (
	"context"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

type roleStore struct{ db *DB }

const roleCols = `id, tenant_id, name, permissions, created_at, updated_at`

// Create inserts a role. An unknown tenant_id yields ErrNotFound.
func (rs roleStore) Create(ctx context.Context, r store.Role) (store.Role, error) {
	if r.ID == "" {
		r.ID = newID("r")
	}
	perms := r.Permissions
	if perms == nil {
		perms = []string{}
	}
	const q = `INSERT INTO roles (id, tenant_id, name, permissions, created_at, updated_at)
	           VALUES ($1, $2, $3, $4, COALESCE($5, now()), COALESCE($6, now()))
	           RETURNING ` + roleCols
	out, err := scanRole(rs.db.pool.QueryRow(ctx, q, r.ID, r.TenantID, r.Name, perms, tsOrNil(r.CreatedAt), tsOrNil(r.UpdatedAt)))
	if err != nil {
		return store.Role{}, mapErr("create role", err)
	}
	return out, nil
}

// Get returns one role by ID, or ErrNotFound.
func (rs roleStore) Get(ctx context.Context, id string) (store.Role, error) {
	const q = `SELECT ` + roleCols + ` FROM roles WHERE id = $1`
	out, err := scanRole(rs.db.pool.QueryRow(ctx, q, id))
	if err != nil {
		return store.Role{}, mapErr("get role", err)
	}
	return out, nil
}

// ListByTenant returns the tenant's roles, oldest first.
func (rs roleStore) ListByTenant(ctx context.Context, tenantID string) ([]store.Role, error) {
	const q = `SELECT ` + roleCols + ` FROM roles WHERE tenant_id = $1 ORDER BY created_at ASC, id ASC`
	rows, err := rs.db.pool.Query(ctx, q, tenantID)
	if err != nil {
		return nil, mapErr("list roles", err)
	}
	defer rows.Close()

	out := make([]store.Role, 0)
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, mapErr("list roles", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr("list roles", err)
	}
	return out, nil
}

func scanRole(r rowScanner) (store.Role, error) {
	var role store.Role
	err := r.Scan(&role.ID, &role.TenantID, &role.Name, &role.Permissions, &role.CreatedAt, &role.UpdatedAt)
	if role.Permissions == nil {
		role.Permissions = []string{}
	}
	return role, err
}
