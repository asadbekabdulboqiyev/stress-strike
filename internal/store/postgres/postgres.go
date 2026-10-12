// Package postgres implements the control-plane store.Store on PostgreSQL using
// pgx.
//
// It is the enterprise persistence target; internal/store/memstore remains the
// in-memory implementation used by tests and local development. Every statement
// is parameterized — values are never interpolated into SQL — and every method
// honours the caller's context so a stalled server cannot wedge a caller.
//
// Error mapping: pgx.ErrNoRows becomes ErrNotFound, unique violations become
// ErrConflict and foreign-key violations become ErrNotFound (see errors.go).
package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

// Pool hygiene. MaxConns is deliberately left at pgx's CPU-derived default so a
// DSN can size the pool; the rest bound connection churn and stale sessions.
const (
	defaultMinConns      = 1
	healthCheckPeriod    = 30 * time.Second
	maxConnLifetime      = time.Hour
	maxConnIdleTime      = 30 * time.Minute
	pingTimeout          = 5 * time.Second
	migrationLockTimeout = 5 * time.Second
)

// DB is a PostgreSQL-backed store.Store. It is safe for concurrent use: all
// methods delegate to the underlying connection pool.
type DB struct {
	pool *pgxpool.Pool
}

// The sub-store types must satisfy their storage-agnostic contracts, and DB the
// composed one. A failure here is a build error, not a runtime surprise.
var (
	_ store.Store       = (*DB)(nil)
	_ store.TenantStore = tenantStore{}
	_ store.UserStore   = userStore{}
	_ store.RoleStore   = roleStore{}
	_ store.APIKeyStore = apiKeyStore{}
	_ store.AuditStore  = auditStore{}
)

// Open parses dsn, builds a connection pool and verifies connectivity with a
// bounded ping so misconfiguration fails at startup rather than on first use.
// The caller owns the returned *DB and must Close it.
func Open(ctx context.Context, dsn string) (*DB, error) {
	if dsn == "" {
		return nil, errors.New("postgres: empty DSN")
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse dsn: %w", err)
	}
	cfg.MinConns = defaultMinConns
	cfg.MaxConnLifetime = maxConnLifetime
	cfg.MaxConnIdleTime = maxConnIdleTime
	cfg.HealthCheckPeriod = healthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	return &DB{pool: pool}, nil
}

// Pool exposes the underlying pgx pool for advanced callers such as health
// probes and integration harnesses.
func (db *DB) Pool() *pgxpool.Pool { return db.pool }

// Close releases every pooled connection. It is safe to call more than once.
func (db *DB) Close() error {
	if db == nil || db.pool == nil {
		return nil
	}
	db.pool.Close()
	return nil
}

// Ping checks connectivity with a bounded timeout.
func (db *DB) Ping(ctx context.Context) error {
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	return mapErr("ping", db.pool.Ping(pingCtx))
}

// Tenants returns the tenant sub-store.
func (db *DB) Tenants() store.TenantStore { return tenantStore{db} }

// Users returns the user sub-store.
func (db *DB) Users() store.UserStore { return userStore{db} }

// Roles returns the role sub-store.
func (db *DB) Roles() store.RoleStore { return roleStore{db} }

// APIKeys returns the API-key sub-store.
func (db *DB) APIKeys() store.APIKeyStore { return apiKeyStore{db} }

// Audits returns the audit-event sub-store.
func (db *DB) Audits() store.AuditStore { return auditStore{db} }

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// newID returns a random identifier with the given prefix, used only when a
// caller supplies an empty ID. Random rather than time-based so concurrent
// inserts cannot collide.
func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is effectively fatal, but a usable (if
		// non-random) identifier is better than an empty primary key.
		return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

// tsOrNil lets Postgres apply its own now() default when the caller did not
// supply a timestamp.
func tsOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// nullIfEmpty stores Go's empty string as SQL NULL for nullable columns.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
