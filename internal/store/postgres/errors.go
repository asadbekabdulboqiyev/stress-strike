package postgres

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store/memstore"
)

// ErrNotFound is returned by lookups when no matching row exists, by Revoke for
// an unknown key, and by writes whose parent row is missing (a foreign-key
// violation).
//
// Package store declares no not-found sentinel and internal/store/interface.go
// is frozen, while internal/store/memstore defines the canonical one. ErrNotFound
// therefore reports Is for both sentinels, so a caller can test whichever it
// already depends on:
//
//	errors.Is(err, postgres.ErrNotFound)
//	errors.Is(err, memstore.ErrNotFound)
//	errors.Is(err, pgx.ErrNoRows)
var ErrNotFound error = notFoundError{}

type notFoundError struct{}

func (notFoundError) Error() string { return "postgres: not found" }

func (notFoundError) Is(target error) bool {
	return target == memstore.ErrNotFound || target == pgx.ErrNoRows
}

// ErrConflict is returned when a write violates a uniqueness constraint, e.g. a
// duplicate tenant slug, a duplicate (email, tenant_id) pair, or a duplicate key
// hash. The underlying *pgconn.PgError stays reachable via errors.As.
var ErrConflict = errors.New("postgres: conflict")

// PostgreSQL SQLSTATE codes we translate into sentinels.
const (
	sqlStateUniqueViolation     = "23505"
	sqlStateForeignKeyViolation = "23503"
)

// mapErr normalises driver errors onto package sentinels while preserving the
// original error in the chain.
func mapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("postgres: %s: %w", op, ErrNotFound)
	case isPgCode(err, sqlStateUniqueViolation):
		return fmt.Errorf("postgres: %s: %w", op, ErrConflict)
	case isPgCode(err, sqlStateForeignKeyViolation):
		// The referenced parent row (tenant/user) does not exist.
		return fmt.Errorf("postgres: %s: %w", op, ErrNotFound)
	default:
		return fmt.Errorf("postgres: %s: %w", op, err)
	}
}

func isPgCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
