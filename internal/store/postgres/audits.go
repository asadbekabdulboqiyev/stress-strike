package postgres

import (
	"context"
	"math"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

type auditStore struct{ db *DB }

const auditCols = `id, tenant_id, COALESCE(actor_id, ''), action, resource,
                   COALESCE(details, ''), created_at, COALESCE(remote_ip, ''), COALESCE(user_agent, '')`

// Write appends one audit event. A zero ID is generated; a zero CreatedAt falls
// back to the database clock. An unknown tenant yields ErrNotFound.
func (as auditStore) Write(ctx context.Context, a store.AuditEvent) error {
	if a.ID == "" {
		a.ID = newID("a")
	}
	const q = `INSERT INTO audit_events
	             (id, tenant_id, actor_id, action, resource, details, remote_ip, user_agent, created_at)
	           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, now()))`
	_, err := as.db.pool.Exec(ctx, q,
		a.ID, a.TenantID, nullIfEmpty(a.ActorID), a.Action, a.Resource,
		nullIfEmpty(a.Details), nullIfEmpty(a.RemoteIP), nullIfEmpty(a.UserAgent), tsOrNil(a.CreatedAt))
	return mapErr("write audit event", err)
}

// ListByTenant returns the tenant's newest events first. A limit <= 0 means "no
// limit"; the index idx_audit_tenant_created serves the ordering.
func (as auditStore) ListByTenant(ctx context.Context, tenantID string, limit int) ([]store.AuditEvent, error) {
	if limit <= 0 {
		limit = math.MaxInt32
	}
	const q = `SELECT ` + auditCols + ` FROM audit_events
	           WHERE tenant_id = $1
	           ORDER BY created_at DESC, id DESC
	           LIMIT $2`
	rows, err := as.db.pool.Query(ctx, q, tenantID, limit)
	if err != nil {
		return nil, mapErr("list audit events", err)
	}
	defer rows.Close()

	out := make([]store.AuditEvent, 0)
	for rows.Next() {
		var a store.AuditEvent
		if err := rows.Scan(&a.ID, &a.TenantID, &a.ActorID, &a.Action, &a.Resource,
			&a.Details, &a.CreatedAt, &a.RemoteIP, &a.UserAgent); err != nil {
			return nil, mapErr("list audit events", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr("list audit events", err)
	}
	return out, nil
}
