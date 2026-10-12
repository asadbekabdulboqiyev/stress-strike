package postgres

import (
	"context"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

type tenantStore struct{ db *DB }

const tenantCols = `id, name, slug, created_at, updated_at`

// Create inserts a tenant. A zero ID is generated; zero timestamps fall back to
// the database clock. A duplicate slug yields ErrConflict.
func (ts tenantStore) Create(ctx context.Context, t store.Tenant) (store.Tenant, error) {
	if t.ID == "" {
		t.ID = newID("t")
	}
	const q = `INSERT INTO tenants (id, name, slug, created_at, updated_at)
	           VALUES ($1, $2, $3, COALESCE($4, now()), COALESCE($5, now()))
	           RETURNING ` + tenantCols
	out, err := scanTenant(ts.db.pool.QueryRow(ctx, q, t.ID, t.Name, t.Slug, tsOrNil(t.CreatedAt), tsOrNil(t.UpdatedAt)))
	if err != nil {
		return store.Tenant{}, mapErr("create tenant", err)
	}
	return out, nil
}

// Get returns one tenant by ID, or ErrNotFound.
func (ts tenantStore) Get(ctx context.Context, id string) (store.Tenant, error) {
	const q = `SELECT ` + tenantCols + ` FROM tenants WHERE id = $1`
	out, err := scanTenant(ts.db.pool.QueryRow(ctx, q, id))
	if err != nil {
		return store.Tenant{}, mapErr("get tenant", err)
	}
	return out, nil
}

// List returns every tenant, oldest first.
func (ts tenantStore) List(ctx context.Context) ([]store.Tenant, error) {
	const q = `SELECT ` + tenantCols + ` FROM tenants ORDER BY created_at ASC, id ASC`
	rows, err := ts.db.pool.Query(ctx, q)
	if err != nil {
		return nil, mapErr("list tenants", err)
	}
	defer rows.Close()

	out := make([]store.Tenant, 0)
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, mapErr("list tenants", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr("list tenants", err)
	}
	return out, nil
}

func scanTenant(r rowScanner) (store.Tenant, error) {
	var t store.Tenant
	err := r.Scan(&t.ID, &t.Name, &t.Slug, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}
