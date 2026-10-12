package postgres

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// schemaSQL is the canonical DDL. It mirrors migrations/0001_init.sql; see
// schema.sql for the statement list.
//
//go:embed schema.sql
var schemaSQL string

// migration is one ordered, idempotent schema step.
type migration struct {
	version string
	sql     string
}

// migrations must remain append-only: a released version string is never
// edited, otherwise environments that already recorded it would diverge.
var migrations = []migration{
	{version: "0001_init", sql: schemaSQL},
}

// advisoryLockKey is an arbitrary-but-fixed 64-bit key, chosen so that this
// runner's lock cannot collide with unrelated applications sharing the
// database. The value spells "STRSTRK1" in ASCII.
const advisoryLockKey int64 = 0x5354525354524B31

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);`

// Migrate applies every pending migration exactly once.
//
// It is safe to call concurrently from multiple processes: a session-scoped
// pg_advisory_lock serialises runners, the applied set is read from
// schema_migrations, and each migration runs inside its own transaction so a
// failure leaves no half-applied version recorded. The call is idempotent —
// re-running with no pending migrations is a no-op.
func (db *DB) Migrate(ctx context.Context) error {
	// A session-scoped advisory lock lives on a single connection, so hold one
	// dedicated pooled connection for the whole migration.
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres: migrate: acquire conn: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return fmt.Errorf("postgres: migrate: advisory lock: %w", err)
	}
	defer func() {
		// Best effort: a cancelled caller context must not leave the lock held
		// on a connection that is returned to the pool.
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrationLockTimeout)
		defer cancel()
		_, _ = conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, advisoryLockKey)
	}()

	if _, err := conn.Exec(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("postgres: migrate: create schema_migrations: %w", err)
	}

	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		if err := db.applyMigration(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

func appliedVersions(ctx context.Context, conn *pgxpool.Conn) (map[string]bool, error) {
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("postgres: migrate: read schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("postgres: migrate: scan schema_migrations: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: migrate: iterate schema_migrations: %w", err)
	}
	return applied, nil
}

// applyMigration runs one migration and records its version atomically. The
// DDL is sent with no bind parameters, so pgx uses the simple query protocol,
// which allows the multi-statement script.
func (db *DB) applyMigration(ctx context.Context, m migration) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: migrate %s: begin: %w", m.version, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, m.sql); err != nil {
		return fmt.Errorf("postgres: migrate %s: apply: %w", m.version, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING`,
		m.version,
	); err != nil {
		return fmt.Errorf("postgres: migrate %s: record: %w", m.version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: migrate %s: commit: %w", m.version, err)
	}
	return nil
}
