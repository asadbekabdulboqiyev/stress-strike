package memstore_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/store/memstore"
)

// newStore builds an isolated in-memory store per test so tests never share
// state (subtests run sequentially, but isolation keeps failures debuggable).
func newStore() *memstore.Store { return memstore.New() }

// mustCreateTenant fails the test if the tenant cannot be created.
func mustCreateTenant(t *testing.T, s *memstore.Store, id, name string) store.Tenant {
	t.Helper()
	tn, err := s.Tenants().Create(context.Background(), store.Tenant{ID: id, Name: name, Slug: name})
	if err != nil {
		t.Fatalf("Create tenant %q: unexpected error: %v", id, err)
	}
	return tn
}

// TestStoreSatisfiesInterfaces pins the compile-time contract that memstore is
// a drop-in for the control-plane store surface.
func TestStoreSatisfiesInterfaces(t *testing.T) {
	var s store.Store = newStore()
	if s.Tenants() == nil || s.Users() == nil || s.Roles() == nil || s.APIKeys() == nil || s.Audits() == nil {
		t.Fatalf("New() returned a Store with a nil sub-store")
	}
}

func TestNewReturnsEmptyStore(t *testing.T) {
	s := newStore()

	tenants, err := s.Tenants().List(context.Background())
	if err != nil {
		t.Fatalf("List tenants on fresh store: unexpected error: %v", err)
	}
	if len(tenants) != 0 {
		t.Fatalf("List tenants on fresh store: got %d, want 0", len(tenants))
	}
}

func TestTenantCreateAndGet(t *testing.T) {
	// Arrange
	s := newStore()
	before := time.Now().UTC()

	// Act
	got, err := s.Tenants().Create(context.Background(), store.Tenant{ID: "t-acme", Name: "Acme", Slug: "acme"})

	// Assert
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	if got.ID != "t-acme" || got.Name != "Acme" || got.Slug != "acme" {
		t.Fatalf("Create returned %+v, want ID/Name/Slug preserved", got)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("Create left timestamps unset: created=%v updated=%v", got.CreatedAt, got.UpdatedAt)
	}
	if got.CreatedAt.Before(before.Add(-time.Second)) || got.CreatedAt.After(time.Now().UTC().Add(time.Second)) {
		t.Fatalf("CreatedAt %v is not near now (%v)", got.CreatedAt, before)
	}
	if got.CreatedAt.Location() != time.UTC {
		t.Fatalf("CreatedAt location = %v, want UTC", got.CreatedAt.Location())
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Fatalf("new tenant CreatedAt %v != UpdatedAt %v", got.CreatedAt, got.UpdatedAt)
	}

	stored, err := s.Tenants().Get(context.Background(), "t-acme")
	if err != nil {
		t.Fatalf("Get after Create: unexpected error: %v", err)
	}
	if stored.ID != "t-acme" || stored.Name != "Acme" || !stored.CreatedAt.Equal(got.CreatedAt) {
		t.Fatalf("Get returned %+v, want %+v", stored, got)
	}
}

func TestTenantCreateGeneratesID(t *testing.T) {
	s := newStore()

	got, err := s.Tenants().Create(context.Background(), store.Tenant{Name: "No ID"})
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	if got.ID == "" {
		t.Fatal("Create with empty ID did not generate one")
	}
	if got.ID[:2] != "t-" {
		t.Fatalf("generated tenant ID = %q, want prefix %q", got.ID, "t-")
	}
	if _, err := s.Tenants().Get(context.Background(), got.ID); err != nil {
		t.Fatalf("Get by generated ID %q: unexpected error: %v", got.ID, err)
	}
}

func TestTenantGetMissing(t *testing.T) {
	s := newStore()

	_, err := s.Tenants().Get(context.Background(), "nope")
	if !errors.Is(err, memstore.ErrNotFound) {
		t.Fatalf("Get(missing) error = %v, want memstore.ErrNotFound", err)
	}
}

// TestTenantCreateSameIDOverwrites documents current behaviour: there is no
// uniqueness error and no Delete on the interface, so re-create upserts.
func TestTenantCreateSameIDOverwrites(t *testing.T) {
	s := newStore()
	first := mustCreateTenant(t, s, "t-dup", "First")
	time.Sleep(2 * time.Millisecond)

	second, err := s.Tenants().Create(context.Background(), store.Tenant{ID: "t-dup", Name: "Second"})
	if err != nil {
		t.Fatalf("Create duplicate: unexpected error: %v", err)
	}
	if second.Name != "Second" {
		t.Fatalf("Create duplicate returned Name %q, want %q", second.Name, "Second")
	}

	tenants, err := s.Tenants().List(context.Background())
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(tenants) != 1 {
		t.Fatalf("List after duplicate create: got %d tenants, want 1", len(tenants))
	}
	if !tenants[0].CreatedAt.After(first.CreatedAt) {
		t.Fatalf("overwrite did not refresh CreatedAt: first=%v now=%v", first.CreatedAt, tenants[0].CreatedAt)
	}
}

func TestTenantListSortedAscending(t *testing.T) {
	s := newStore()
	for i := 0; i < 5; i++ {
		mustCreateTenant(t, s, fmt.Sprintf("t-%d", i), fmt.Sprintf("tenant-%d", i))
	}

	tenants, err := s.Tenants().List(context.Background())
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(tenants) != 5 {
		t.Fatalf("List: got %d tenants, want 5", len(tenants))
	}
	for i := 1; i < len(tenants); i++ {
		if tenants[i].CreatedAt.Before(tenants[i-1].CreatedAt) {
			t.Fatalf("List not ascending at %d: %v before %v", i, tenants[i].CreatedAt, tenants[i-1].CreatedAt)
		}
	}
	seen := make(map[string]bool, len(tenants))
	for _, tn := range tenants {
		seen[tn.ID] = true
	}
	for i := 0; i < 5; i++ {
		if !seen[fmt.Sprintf("t-%d", i)] {
			t.Fatalf("List missing tenant t-%d: %+v", i, tenants)
		}
	}
}

func TestUserCreateGetAndTenantIsolation(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	mustCreateTenant(t, s, "t-a", "A")
	mustCreateTenant(t, s, "t-b", "B")

	alice, err := s.Users().Create(ctx, store.User{TenantID: "t-a", Email: "alice@a.example"})
	if err != nil {
		t.Fatalf("Create user alice: unexpected error: %v", err)
	}
	if alice.ID == "" || alice.ID[:2] != "u-" {
		t.Fatalf("generated user ID = %q, want u- prefix", alice.ID)
	}
	if alice.CreatedAt.IsZero() || !alice.CreatedAt.Equal(alice.UpdatedAt) {
		t.Fatalf("user timestamps unset/mismatched: created=%v updated=%v", alice.CreatedAt, alice.UpdatedAt)
	}

	if _, err := s.Users().Create(ctx, store.User{ID: "u-bob", TenantID: "t-b", Email: "bob@b.example"}); err != nil {
		t.Fatalf("Create user bob: unexpected error: %v", err)
	}

	got, err := s.Users().Get(ctx, alice.ID)
	if err != nil {
		t.Fatalf("Get alice: unexpected error: %v", err)
	}
	if got.Email != "alice@a.example" || got.TenantID != "t-a" {
		t.Fatalf("Get alice = %+v, want alice@a.example in t-a", got)
	}

	if _, err := s.Users().Get(ctx, "u-missing"); !errors.Is(err, memstore.ErrNotFound) {
		t.Fatalf("Get(missing user) error = %v, want memstore.ErrNotFound", err)
	}

	aUsers, err := s.Users().ListByTenant(ctx, "t-a")
	if err != nil {
		t.Fatalf("ListByTenant t-a: unexpected error: %v", err)
	}
	if len(aUsers) != 1 || aUsers[0].ID != alice.ID {
		t.Fatalf("ListByTenant t-a = %+v, want only alice", aUsers)
	}

	bUsers, err := s.Users().ListByTenant(ctx, "t-b")
	if err != nil {
		t.Fatalf("ListByTenant t-b: unexpected error: %v", err)
	}
	if len(bUsers) != 1 || bUsers[0].ID != "u-bob" {
		t.Fatalf("ListByTenant t-b = %+v, want only bob", bUsers)
	}

	none, err := s.Users().ListByTenant(ctx, "t-unknown")
	if err != nil {
		t.Fatalf("ListByTenant unknown: unexpected error: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("ListByTenant unknown = %+v, want empty", none)
	}
}

func TestUserListByTenantSortedAscending(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, err := s.Users().Create(ctx, store.User{ID: fmt.Sprintf("u-%d", i), TenantID: "t-1"}); err != nil {
			t.Fatalf("Create user %d: %v", i, err)
		}
	}

	users, err := s.Users().ListByTenant(ctx, "t-1")
	if err != nil {
		t.Fatalf("ListByTenant: unexpected error: %v", err)
	}
	if len(users) != 4 {
		t.Fatalf("ListByTenant: got %d users, want 4", len(users))
	}
	for i := 1; i < len(users); i++ {
		if users[i].CreatedAt.Before(users[i-1].CreatedAt) {
			t.Fatalf("users not ascending at %d", i)
		}
	}
}

func TestRoleCreateGetAndTenantIsolation(t *testing.T) {
	s := newStore()
	ctx := context.Background()

	admin, err := s.Roles().Create(ctx, store.Role{TenantID: "t-a", Name: "admin", Permissions: []string{"read", "write"}})
	if err != nil {
		t.Fatalf("Create role: unexpected error: %v", err)
	}
	if admin.ID == "" || admin.ID[:2] != "r-" {
		t.Fatalf("generated role ID = %q, want r- prefix", admin.ID)
	}
	if admin.CreatedAt.IsZero() || !admin.CreatedAt.Equal(admin.UpdatedAt) {
		t.Fatalf("role timestamps unset/mismatched: created=%v updated=%v", admin.CreatedAt, admin.UpdatedAt)
	}

	if _, err := s.Roles().Create(ctx, store.Role{ID: "r-viewer", TenantID: "t-b", Name: "viewer"}); err != nil {
		t.Fatalf("Create second role: %v", err)
	}

	got, err := s.Roles().Get(ctx, admin.ID)
	if err != nil {
		t.Fatalf("Get role: unexpected error: %v", err)
	}
	if got.Name != "admin" || len(got.Permissions) != 2 || got.Permissions[1] != "write" {
		t.Fatalf("Get role = %+v, want admin with [read write]", got)
	}

	if _, err := s.Roles().Get(ctx, "r-missing"); !errors.Is(err, memstore.ErrNotFound) {
		t.Fatalf("Get(missing role) error = %v, want memstore.ErrNotFound", err)
	}

	aRoles, err := s.Roles().ListByTenant(ctx, "t-a")
	if err != nil {
		t.Fatalf("ListByTenant t-a: %v", err)
	}
	if len(aRoles) != 1 || aRoles[0].ID != admin.ID {
		t.Fatalf("ListByTenant t-a = %+v, want only admin", aRoles)
	}
	bRoles, err := s.Roles().ListByTenant(ctx, "t-b")
	if err != nil {
		t.Fatalf("ListByTenant t-b: %v", err)
	}
	if len(bRoles) != 1 || bRoles[0].ID != "r-viewer" {
		t.Fatalf("ListByTenant t-b = %+v, want only viewer", bRoles)
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	s := newStore()
	ctx := context.Background()

	key, err := s.APIKeys().Create(ctx, store.APIKey{TenantID: "t-a", UserID: "u-1", KeyHash: "sha256:deadbeef", Name: "ci"})
	if err != nil {
		t.Fatalf("Create key: unexpected error: %v", err)
	}
	if key.ID == "" || key.ID[:2] != "k-" {
		t.Fatalf("generated key ID = %q, want k- prefix", key.ID)
	}
	if key.CreatedAt.IsZero() {
		t.Fatal("Create key did not set CreatedAt")
	}
	if key.RevokedAt != nil {
		t.Fatalf("fresh key RevokedAt = %v, want nil", key.RevokedAt)
	}

	byHash, err := s.APIKeys().GetByHash(ctx, "sha256:deadbeef")
	if err != nil {
		t.Fatalf("GetByHash: unexpected error: %v", err)
	}
	if byHash.ID != key.ID {
		t.Fatalf("GetByHash returned id %q, want %q", byHash.ID, key.ID)
	}

	if _, err := s.APIKeys().GetByHash(ctx, "sha256:unknown"); !errors.Is(err, memstore.ErrNotFound) {
		t.Fatalf("GetByHash(unknown) error = %v, want memstore.ErrNotFound", err)
	}

	if err := s.APIKeys().Revoke(ctx, key.ID); err != nil {
		t.Fatalf("Revoke: unexpected error: %v", err)
	}
	revoked, err := s.APIKeys().GetByHash(ctx, "sha256:deadbeef")
	if err != nil {
		t.Fatalf("GetByHash after revoke: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("Revoke did not set RevokedAt")
	}
	if revoked.RevokedAt.Location() != time.UTC {
		t.Fatalf("RevokedAt location = %v, want UTC", revoked.RevokedAt.Location())
	}

	if err := s.APIKeys().Revoke(ctx, "k-missing"); !errors.Is(err, memstore.ErrNotFound) {
		t.Fatalf("Revoke(missing) error = %v, want memstore.ErrNotFound", err)
	}

	if _, err := s.APIKeys().Create(ctx, store.APIKey{ID: "k-b", TenantID: "t-b", KeyHash: "sha256:cafe"}); err != nil {
		t.Fatalf("Create second key: %v", err)
	}
	aKeys, err := s.APIKeys().ListByTenant(ctx, "t-a")
	if err != nil {
		t.Fatalf("ListByTenant t-a: %v", err)
	}
	if len(aKeys) != 1 || aKeys[0].ID != key.ID {
		t.Fatalf("ListByTenant t-a = %+v, want only the first key", aKeys)
	}
	bKeys, err := s.APIKeys().ListByTenant(ctx, "t-b")
	if err != nil {
		t.Fatalf("ListByTenant t-b: %v", err)
	}
	if len(bKeys) != 1 || bKeys[0].ID != "k-b" {
		t.Fatalf("ListByTenant t-b = %+v, want only k-b", bKeys)
	}
}

func TestAPIKeyListEmptyTenant(t *testing.T) {
	s := newStore()
	keys, err := s.APIKeys().ListByTenant(context.Background(), "t-none")
	if err != nil {
		t.Fatalf("ListByTenant empty: unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("ListByTenant empty = %+v, want empty", keys)
	}
}

// TestAPIKeyListByTenantSortedAscending exercises the sort comparator with more
// than one key in a tenant.
func TestAPIKeyListByTenantSortedAscending(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, err := s.APIKeys().Create(ctx, store.APIKey{ID: fmt.Sprintf("k-%d", i), TenantID: "t-1", KeyHash: fmt.Sprintf("h-%d", i)}); err != nil {
			t.Fatalf("Create key %d: %v", i, err)
		}
	}

	keys, err := s.APIKeys().ListByTenant(ctx, "t-1")
	if err != nil {
		t.Fatalf("ListByTenant: unexpected error: %v", err)
	}
	if len(keys) != 4 {
		t.Fatalf("ListByTenant: got %d keys, want 4", len(keys))
	}
	for i := 1; i < len(keys); i++ {
		if keys[i].CreatedAt.Before(keys[i-1].CreatedAt) {
			t.Fatalf("keys not ascending at %d", i)
		}
	}
}

// TestRoleListByTenantSortedAscending exercises the sort comparator with more
// than one role in a tenant.
func TestRoleListByTenantSortedAscending(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, err := s.Roles().Create(ctx, store.Role{ID: fmt.Sprintf("r-%d", i), TenantID: "t-1", Name: fmt.Sprintf("role-%d", i)}); err != nil {
			t.Fatalf("Create role %d: %v", i, err)
		}
	}

	roles, err := s.Roles().ListByTenant(ctx, "t-1")
	if err != nil {
		t.Fatalf("ListByTenant: unexpected error: %v", err)
	}
	if len(roles) != 4 {
		t.Fatalf("ListByTenant: got %d roles, want 4", len(roles))
	}
	for i := 1; i < len(roles); i++ {
		if roles[i].CreatedAt.Before(roles[i-1].CreatedAt) {
			t.Fatalf("roles not ascending at %d", i)
		}
	}
}

func TestAuditWriteGeneratesIDAndTimestamp(t *testing.T) {
	s := newStore()

	if err := s.Audits().Write(context.Background(), store.AuditEvent{TenantID: "t-a", Action: "login"}); err != nil {
		t.Fatalf("Write: unexpected error: %v", err)
	}

	events, err := s.Audits().ListByTenant(context.Background(), "t-a", 0)
	if err != nil {
		t.Fatalf("ListByTenant: unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("ListByTenant: got %d events, want 1", len(events))
	}
	if events[0].ID == "" || events[0].ID[:2] != "a-" {
		t.Fatalf("generated audit ID = %q, want a- prefix", events[0].ID)
	}
	if events[0].CreatedAt.IsZero() {
		t.Fatal("Write did not set CreatedAt")
	}
	if events[0].Action != "login" {
		t.Fatalf("Action = %q, want login", events[0].Action)
	}
}

func TestAuditWritePreservesExplicitFields(t *testing.T) {
	s := newStore()
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	err := s.Audits().Write(context.Background(), store.AuditEvent{ID: "a-fixed", TenantID: "t-a", Action: "logout", CreatedAt: when})
	if err != nil {
		t.Fatalf("Write: unexpected error: %v", err)
	}

	events, err := s.Audits().ListByTenant(context.Background(), "t-a", 0)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].ID != "a-fixed" || !events[0].CreatedAt.Equal(when) {
		t.Fatalf("Write did not preserve explicit ID/CreatedAt: %+v", events[0])
	}
}

func TestAuditListOrderingFilteringAndLimit(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	// Oldest first: e0 .. e4, plus one event for another tenant.
	for i := 0; i < 5; i++ {
		ev := store.AuditEvent{
			ID:        fmt.Sprintf("a-%d", i),
			TenantID:  "t-a",
			Action:    fmt.Sprintf("action-%d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}
		if err := s.Audits().Write(ctx, ev); err != nil {
			t.Fatalf("Write event %d: %v", i, err)
		}
	}
	if err := s.Audits().Write(ctx, store.AuditEvent{ID: "a-other", TenantID: "t-b", CreatedAt: base}); err != nil {
		t.Fatalf("Write other-tenant event: %v", err)
	}

	all, err := s.Audits().ListByTenant(ctx, "t-a", 0)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("ListByTenant: got %d, want 5 (tenant isolation)", len(all))
	}
	for i := 0; i < len(all); i++ {
		want := fmt.Sprintf("a-%d", 4-i)
		if all[i].ID != want {
			t.Fatalf("ListByTenant[%d] = %q, want %q (newest first)", i, all[i].ID, want)
		}
	}

	limited, err := s.Audits().ListByTenant(ctx, "t-a", 2)
	if err != nil {
		t.Fatalf("ListByTenant limit=2: %v", err)
	}
	if len(limited) != 2 || limited[0].ID != "a-4" || limited[1].ID != "a-3" {
		t.Fatalf("ListByTenant limit=2 = %+v, want [a-4 a-3]", limited)
	}

	over, err := s.Audits().ListByTenant(ctx, "t-a", 99)
	if err != nil {
		t.Fatalf("ListByTenant limit=99: %v", err)
	}
	if len(over) != 5 {
		t.Fatalf("ListByTenant limit=99: got %d, want 5", len(over))
	}

	none, err := s.Audits().ListByTenant(ctx, "t-unknown", 10)
	if err != nil {
		t.Fatalf("ListByTenant unknown: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("ListByTenant unknown = %+v, want empty", none)
	}
}

// TestGeneratedIDsAreUnique guards randID against collisions: a duplicate ID
// would silently overwrite an existing row because Create upserts.
func TestGeneratedIDsAreUnique(t *testing.T) {
	const n = 200
	s := newStore()
	ctx := context.Background()

	for i := 0; i < n; i++ {
		if _, err := s.Tenants().Create(ctx, store.Tenant{Name: fmt.Sprintf("tenant-%d", i)}); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}

	tenants, err := s.Tenants().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(tenants) != n {
		t.Fatalf("generated IDs collided: got %d tenants, want %d", len(tenants), n)
	}
	seen := make(map[string]struct{}, n)
	for _, tn := range tenants {
		if _, dup := seen[tn.ID]; dup {
			t.Fatalf("duplicate generated ID %q", tn.ID)
		}
		seen[tn.ID] = struct{}{}
	}
}

// TestConcurrentAccess exercises the mutex under -race: concurrent writes and
// reads across every sub-store must not race or lose writes.
func TestConcurrentAccess(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	const workers = 50

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			tenantID := fmt.Sprintf("t-%d", i)
			if _, err := s.Tenants().Create(ctx, store.Tenant{ID: tenantID, Name: tenantID}); err != nil {
				t.Errorf("concurrent tenant create %d: %v", i, err)
				return
			}
			user, err := s.Users().Create(ctx, store.User{TenantID: tenantID, Email: fmt.Sprintf("u%d@example.test", i)})
			if err != nil {
				t.Errorf("concurrent user create %d: %v", i, err)
				return
			}
			if _, err := s.Roles().Create(ctx, store.Role{TenantID: tenantID, Name: "reader"}); err != nil {
				t.Errorf("concurrent role create %d: %v", i, err)
				return
			}
			key, err := s.APIKeys().Create(ctx, store.APIKey{TenantID: tenantID, KeyHash: fmt.Sprintf("hash-%d", i)})
			if err != nil {
				t.Errorf("concurrent key create %d: %v", i, err)
				return
			}
			if err := s.Audits().Write(ctx, store.AuditEvent{TenantID: tenantID, ActorID: user.ID, Action: "create"}); err != nil {
				t.Errorf("concurrent audit write %d: %v", i, err)
				return
			}
			if _, err := s.Tenants().Get(ctx, tenantID); err != nil {
				t.Errorf("concurrent tenant get %d: %v", i, err)
			}
			if _, err := s.Users().ListByTenant(ctx, tenantID); err != nil {
				t.Errorf("concurrent user list %d: %v", i, err)
			}
			if _, err := s.Roles().ListByTenant(ctx, tenantID); err != nil {
				t.Errorf("concurrent role list %d: %v", i, err)
			}
			if _, err := s.APIKeys().GetByHash(ctx, key.KeyHash); err != nil {
				t.Errorf("concurrent key lookup %d: %v", i, err)
			}
			if err := s.APIKeys().Revoke(ctx, key.ID); err != nil {
				t.Errorf("concurrent key revoke %d: %v", i, err)
			}
			if _, err := s.Audits().ListByTenant(ctx, tenantID, 10); err != nil {
				t.Errorf("concurrent audit list %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	tenants, err := s.Tenants().List(ctx)
	if err != nil {
		t.Fatalf("List after concurrent writes: %v", err)
	}
	if len(tenants) != workers {
		t.Fatalf("after concurrent writes got %d tenants, want %d", len(tenants), workers)
	}
}

// TestStoreIgnoresCancelledContext documents that the in-memory store does no
// I/O and therefore does not honour context cancellation.
func TestStoreIgnoresCancelledContext(t *testing.T) {
	s := newStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Tenants().Create(ctx, store.Tenant{ID: "t-cancel"}); err != nil {
		t.Fatalf("Create with cancelled ctx: unexpected error: %v", err)
	}
	if _, err := s.Tenants().Get(ctx, "t-cancel"); err != nil {
		t.Fatalf("Get with cancelled ctx: unexpected error: %v", err)
	}
}
