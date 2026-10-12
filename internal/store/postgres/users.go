package postgres

import (
	"context"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

type userStore struct{ db *DB }

const userCols = `id, tenant_id, email, name, created_at, updated_at`

// Create inserts a user. An unknown tenant_id yields ErrNotFound; a duplicate
// (email, tenant_id) pair yields ErrConflict.
func (us userStore) Create(ctx context.Context, u store.User) (store.User, error) {
	if u.ID == "" {
		u.ID = newID("u")
	}
	const q = `INSERT INTO users (id, tenant_id, email, name, created_at, updated_at)
	           VALUES ($1, $2, $3, $4, COALESCE($5, now()), COALESCE($6, now()))
	           RETURNING ` + userCols
	out, err := scanUser(us.db.pool.QueryRow(ctx, q, u.ID, u.TenantID, u.Email, u.Name, tsOrNil(u.CreatedAt), tsOrNil(u.UpdatedAt)))
	if err != nil {
		return store.User{}, mapErr("create user", err)
	}
	return out, nil
}

// Get returns one user by ID, or ErrNotFound.
func (us userStore) Get(ctx context.Context, id string) (store.User, error) {
	const q = `SELECT ` + userCols + ` FROM users WHERE id = $1`
	out, err := scanUser(us.db.pool.QueryRow(ctx, q, id))
	if err != nil {
		return store.User{}, mapErr("get user", err)
	}
	return out, nil
}

// ListByTenant returns the tenant's users, oldest first.
func (us userStore) ListByTenant(ctx context.Context, tenantID string) ([]store.User, error) {
	const q = `SELECT ` + userCols + ` FROM users WHERE tenant_id = $1 ORDER BY created_at ASC, id ASC`
	rows, err := us.db.pool.Query(ctx, q, tenantID)
	if err != nil {
		return nil, mapErr("list users", err)
	}
	defer rows.Close()

	out := make([]store.User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, mapErr("list users", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr("list users", err)
	}
	return out, nil
}

func scanUser(r rowScanner) (store.User, error) {
	var u store.User
	err := r.Scan(&u.ID, &u.TenantID, &u.Email, &u.Name, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}
