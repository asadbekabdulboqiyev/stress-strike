package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

type apiKeyStore struct{ db *DB }

const apiKeyCols = `id, tenant_id, user_id, key_hash, name, expires_at, revoked_at, created_at` //nolint:gosec // SQL column list, not a credential

// Create inserts an API key. key_hash is UNIQUE, so re-issuing the same hash
// yields ErrConflict; an unknown tenant/user yields ErrNotFound.
func (ks apiKeyStore) Create(ctx context.Context, k store.APIKey) (store.APIKey, error) {
	if k.ID == "" {
		k.ID = newID("k")
	}
	const q = `INSERT INTO api_keys (id, tenant_id, user_id, key_hash, name, expires_at, revoked_at, created_at)
	           VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, now()))
	           RETURNING ` + apiKeyCols
	out, err := scanAPIKey(ks.db.pool.QueryRow(ctx, q,
		k.ID, k.TenantID, k.UserID, k.KeyHash, k.Name, k.ExpiresAt, k.RevokedAt, tsOrNil(k.CreatedAt)))
	if err != nil {
		return store.APIKey{}, mapErr("create api key", err)
	}
	return out, nil
}

// GetByHash returns the key matching hash (unique index idx_keys_hash), or
// ErrNotFound. Revoked keys are still returned; callers decide whether a revoked
// key is usable.
func (ks apiKeyStore) GetByHash(ctx context.Context, hash string) (store.APIKey, error) {
	const q = `SELECT ` + apiKeyCols + ` FROM api_keys WHERE key_hash = $1`
	out, err := scanAPIKey(ks.db.pool.QueryRow(ctx, q, hash))
	if err != nil {
		return store.APIKey{}, mapErr("get api key by hash", err)
	}
	return out, nil
}

// Revoke marks a key revoked. Revoking an already-revoked key is a no-op that
// preserves the original revocation time. An unknown ID yields ErrNotFound.
func (ks apiKeyStore) Revoke(ctx context.Context, id string) error {
	const q = `UPDATE api_keys SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1`
	tag, err := ks.db.pool.Exec(ctx, q, id)
	if err != nil {
		return mapErr("revoke api key", err)
	}
	if tag.RowsAffected() == 0 {
		return mapErr("revoke api key", pgx.ErrNoRows)
	}
	return nil
}

// ListByTenant returns the tenant's keys, oldest first.
func (ks apiKeyStore) ListByTenant(ctx context.Context, tenantID string) ([]store.APIKey, error) {
	const q = `SELECT ` + apiKeyCols + ` FROM api_keys WHERE tenant_id = $1 ORDER BY created_at ASC, id ASC`
	rows, err := ks.db.pool.Query(ctx, q, tenantID)
	if err != nil {
		return nil, mapErr("list api keys", err)
	}
	defer rows.Close()

	out := make([]store.APIKey, 0)
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, mapErr("list api keys", err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr("list api keys", err)
	}
	return out, nil
}

func scanAPIKey(r rowScanner) (store.APIKey, error) {
	var k store.APIKey
	err := r.Scan(&k.ID, &k.TenantID, &k.UserID, &k.KeyHash, &k.Name, &k.ExpiresAt, &k.RevokedAt, &k.CreatedAt)
	return k, err
}
