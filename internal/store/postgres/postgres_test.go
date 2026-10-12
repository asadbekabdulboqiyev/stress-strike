package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

// defaultTestDSN targets the local PostgreSQL 16 instance that listens on the
// unix socket in /tmp (user asadbek, database postgres). Override with
// STRESS_STRIKE_TEST_PG_DSN.
const defaultTestDSN = "postgres:///postgres?host=/tmp"

func testDSN() string {
	if dsn := os.Getenv("STRESS_STRIKE_TEST_PG_DSN"); dsn != "" {
		return dsn
	}
	return defaultTestDSN
}

// newTestDB opens the database, applies migrations and registers a cleanup.
// It skips (rather than fails) only when Postgres is genuinely unreachable, so
// the suite still runs on machines without a local server.
func newTestDB(t *testing.T) *DB {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db, err := Open(ctx, testDSN())
	if err != nil {
		t.Skipf("postgres unreachable at %q: %v", testDSN(), err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// uniqueSuffix keeps rows from concurrent test runs from colliding.
func uniqueSuffix(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), t.Name())
}

// createTenant inserts a tenant and schedules deletion; ON DELETE CASCADE
// removes the tenant's users, roles, keys and audit events with it.
func createTenant(t *testing.T, db *DB) store.Tenant {
	t.Helper()
	ctx := context.Background()

	tn, err := db.Tenants().Create(ctx, store.Tenant{
		Name: "acme",
		Slug: "acme-" + uniqueSuffix(t),
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tn.ID); err != nil {
			t.Logf("cleanup tenant %s: %v", tn.ID, err)
		}
	})
	return tn
}

func TestMigrateIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// newTestDB already migrated once; a second and third run must be no-ops.
	for i := 2; i <= 3; i++ {
		if err := db.Migrate(ctx); err != nil {
			t.Fatalf("Migrate run %d: %v", i, err)
		}
	}

	var count int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = $1`, "0001_init").Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count != 1 {
		t.Fatalf("schema_migrations rows for 0001_init = %d, want 1", count)
	}
}

func TestTenantCreateGetList(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	tn := createTenant(t, db)

	if tn.ID == "" {
		t.Fatal("tenant ID was not generated")
	}
	if tn.CreatedAt.IsZero() || tn.UpdatedAt.IsZero() {
		t.Fatal("timestamps were not populated by the database")
	}

	got, err := db.Tenants().Get(ctx, tn.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Slug != tn.Slug || got.Name != tn.Name {
		t.Fatalf("Get returned %+v, want slug %q name %q", got, tn.Slug, tn.Name)
	}

	list, err := db.Tenants().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !containsTenant(list, tn.ID) {
		t.Fatalf("List did not contain tenant %s", tn.ID)
	}
}

func TestTenantSlugConflict(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	tn := createTenant(t, db)

	_, err := db.Tenants().Create(ctx, store.Tenant{Name: "dup", Slug: tn.Slug})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate slug error = %v, want ErrConflict", err)
	}
}

func TestValuesAreParameterized(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	hostile := `bob'); DROP TABLE tenants; --`
	tn, err := db.Tenants().Create(ctx, store.Tenant{Name: hostile, Slug: "inj-" + uniqueSuffix(t)})
	if err != nil {
		t.Fatalf("create tenant with hostile values: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tn.ID)
	})

	got, err := db.Tenants().Get(ctx, tn.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != hostile {
		t.Fatalf("name round-trip = %q, want %q", got.Name, hostile)
	}
	// The table must still exist.
	if _, err := db.Tenants().List(ctx); err != nil {
		t.Fatalf("tenants table unusable after hostile write: %v", err)
	}
}

func TestUserCreateGetList(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	tn := createTenant(t, db)

	u, err := db.Users().Create(ctx, store.User{TenantID: tn.ID, Email: "a@example.com", Name: "Ann"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	got, err := db.Users().Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Email != "a@example.com" || got.TenantID != tn.ID {
		t.Fatalf("Get returned %+v", got)
	}

	list, err := db.Users().ListByTenant(ctx, tn.ID)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(list) != 1 || list[0].ID != u.ID {
		t.Fatalf("ListByTenant = %+v, want exactly user %s", list, u.ID)
	}

	if _, err := db.Users().Create(ctx, store.User{TenantID: tn.ID, Email: "a@example.com", Name: "Ann2"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate email/tenant error = %v, want ErrConflict", err)
	}
}

func TestRoleCreateGetList(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	tn := createTenant(t, db)

	r, err := db.Roles().Create(ctx, store.Role{
		TenantID:    tn.ID,
		Name:        "admin",
		Permissions: []string{"tenant:read", "tenant:write"},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if len(r.Permissions) != 2 {
		t.Fatalf("permissions not persisted: %+v", r.Permissions)
	}

	got, err := db.Roles().Get(ctx, r.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if strings.Join(got.Permissions, ",") != "tenant:read,tenant:write" {
		t.Fatalf("permissions round-trip = %+v", got.Permissions)
	}

	list, err := db.Roles().ListByTenant(ctx, tn.ID)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(list) != 1 || list[0].ID != r.ID {
		t.Fatalf("ListByTenant = %+v", list)
	}
}

func TestAPIKeyCreateGetByHashRevoke(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	tn := createTenant(t, db)

	u, err := db.Users().Create(ctx, store.User{TenantID: tn.ID, Email: "k@example.com", Name: "Key Owner"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	expires := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond)
	key, err := db.APIKeys().Create(ctx, store.APIKey{
		TenantID:  tn.ID,
		UserID:    u.ID,
		KeyHash:   "hash-" + uniqueSuffix(t),
		Name:      "ci",
		ExpiresAt: &expires,
	})
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	got, err := db.APIKeys().GetByHash(ctx, key.KeyHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.ID != key.ID || got.RevokedAt != nil {
		t.Fatalf("GetByHash returned %+v", got)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("expires_at round-trip = %v, want %v", got.ExpiresAt, expires)
	}

	list, err := db.APIKeys().ListByTenant(ctx, tn.ID)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(list) != 1 || list[0].ID != key.ID {
		t.Fatalf("ListByTenant = %+v", list)
	}

	if err := db.APIKeys().Revoke(ctx, key.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revoked, err := db.APIKeys().GetByHash(ctx, key.KeyHash)
	if err != nil {
		t.Fatalf("GetByHash after revoke: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("revoked_at is nil after Revoke")
	}

	// Idempotent: a second revoke keeps the original timestamp.
	first := *revoked.RevokedAt
	if err := db.APIKeys().Revoke(ctx, key.ID); err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
	again, err := db.APIKeys().GetByHash(ctx, key.KeyHash)
	if err != nil {
		t.Fatalf("GetByHash after second revoke: %v", err)
	}
	if again.RevokedAt == nil || !again.RevokedAt.Equal(first) {
		t.Fatalf("revoked_at changed on second revoke: %v -> %v", first, again.RevokedAt)
	}
}

func TestAuditWriteListAndLimit(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	tn := createTenant(t, db)

	base := time.Now().UTC().Truncate(time.Microsecond)
	actions := []string{"login", "create", "delete"}
	for i, action := range actions {
		err := db.Audits().Write(ctx, store.AuditEvent{
			TenantID:  tn.ID,
			Action:    action,
			Resource:  "tenant:" + tn.ID,
			Details:   "step " + action,
			RemoteIP:  "203.0.113.7",
			UserAgent: "stress-strike/test",
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatalf("Write %s: %v", action, err)
		}
	}

	all, err := db.Audits().ListByTenant(ctx, tn.ID, 0)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListByTenant(unlimited) = %d events, want 3", len(all))
	}
	// Newest first.
	if all[0].Action != "delete" || all[2].Action != "login" {
		t.Fatalf("order = %s,%s,%s, want delete,create,login", all[0].Action, all[1].Action, all[2].Action)
	}
	if all[0].RemoteIP != "203.0.113.7" || all[0].UserAgent != "stress-strike/test" {
		t.Fatalf("actor metadata not persisted: %+v", all[0])
	}

	limited, err := db.Audits().ListByTenant(ctx, tn.ID, 2)
	if err != nil {
		t.Fatalf("ListByTenant(limit): %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("ListByTenant(limit=2) = %d events, want 2", len(limited))
	}

	// An event with an empty actor is stored as NULL and read back as "". It is
	// stamped explicitly newest so the limit=1 assertion is deterministic.
	if err := db.Audits().Write(ctx, store.AuditEvent{
		TenantID:  tn.ID,
		Action:    "anonymous",
		Resource:  "scope",
		CreatedAt: base.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Write anonymous: %v", err)
	}
	anon, err := db.Audits().ListByTenant(ctx, tn.ID, 1)
	if err != nil {
		t.Fatalf("ListByTenant after anonymous: %v", err)
	}
	if len(anon) != 1 || anon[0].Action != "anonymous" || anon[0].ActorID != "" || anon[0].Details != "" {
		t.Fatalf("newest event = %+v, want the anonymous event with empty actor/details", anon)
	}
}

func TestNotFoundMapping(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	missing := "does-not-exist-" + uniqueSuffix(t)

	if _, err := db.Tenants().Get(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("Tenants().Get(missing) = %v, want ErrNotFound", err)
	}
	if _, err := db.Users().Get(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("Users().Get(missing) = %v, want ErrNotFound", err)
	}
	if _, err := db.Roles().Get(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("Roles().Get(missing) = %v, want ErrNotFound", err)
	}
	if _, err := db.APIKeys().GetByHash(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("APIKeys().GetByHash(missing) = %v, want ErrNotFound", err)
	}
	if err := db.APIKeys().Revoke(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("APIKeys().Revoke(missing) = %v, want ErrNotFound", err)
	}
}

func TestCreateWithUnknownTenantIsNotFound(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	_, err := db.Users().Create(ctx, store.User{TenantID: "ghost-" + uniqueSuffix(t), Email: "x@example.com"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("create user for unknown tenant = %v, want ErrNotFound", err)
	}
}

func containsTenant(list []store.Tenant, id string) bool {
	for _, tn := range list {
		if tn.ID == id {
			return true
		}
	}
	return false
}
