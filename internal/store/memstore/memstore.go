// Package memstore provides an in-memory Store implementation for tests and
// local development.
package memstore

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

var (
	ErrNotFound = errors.New("memstore: not found")
	ErrExists   = errors.New("memstore: already exists")
)

type Store struct {
	mu      sync.Mutex
	tenants map[string]store.Tenant
	users   map[string]store.User
	roles   map[string]store.Role
	keys    map[string]store.APIKey
	audits  []store.AuditEvent
}

func New() *Store {
	return &Store{
		tenants: make(map[string]store.Tenant),
		users:   make(map[string]store.User),
		roles:   make(map[string]store.Role),
		keys:    make(map[string]store.APIKey),
	}
}

func (s *Store) Tenants() store.TenantStore { return &tenantStore{s} }
func (s *Store) Users() store.UserStore     { return &userStore{s} }
func (s *Store) Roles() store.RoleStore     { return &roleStore{s} }
func (s *Store) APIKeys() store.APIKeyStore { return &keyStore{s} }
func (s *Store) Audits() store.AuditStore   { return &auditStore{s} }

type tenantStore struct{ s *Store }
type userStore struct{ s *Store }
type roleStore struct{ s *Store }
type keyStore struct{ s *Store }
type auditStore struct{ s *Store }

func (ts *tenantStore) Create(ctx context.Context, t store.Tenant) (store.Tenant, error) {
	ts.s.mu.Lock()
	defer ts.s.mu.Unlock()
	if _, ok := ts.s.tenants[t.ID]; ok && t.ID != "" {
		// allow empty to be generated? but keep simple
	}
	if t.ID == "" {
		t.ID = randID("t")
	}
	now := time.Now().UTC()
	t.CreatedAt = now
	t.UpdatedAt = now
	ts.s.tenants[t.ID] = t
	return t, nil
}

func (ts *tenantStore) Get(ctx context.Context, id string) (store.Tenant, error) {
	ts.s.mu.Lock()
	defer ts.s.mu.Unlock()
	t, ok := ts.s.tenants[id]
	if !ok {
		return store.Tenant{}, ErrNotFound
	}
	return t, nil
}

func (ts *tenantStore) List(ctx context.Context) ([]store.Tenant, error) {
	ts.s.mu.Lock()
	defer ts.s.mu.Unlock()
	out := make([]store.Tenant, 0, len(ts.s.tenants))
	for _, t := range ts.s.tenants {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (us *userStore) Create(ctx context.Context, u store.User) (store.User, error) {
	us.s.mu.Lock()
	defer us.s.mu.Unlock()
	if u.ID == "" {
		u.ID = randID("u")
	}
	now := time.Now().UTC()
	u.CreatedAt = now
	u.UpdatedAt = now
	us.s.users[u.ID] = u
	return u, nil
}

func (us *userStore) Get(ctx context.Context, id string) (store.User, error) {
	us.s.mu.Lock()
	defer us.s.mu.Unlock()
	u, ok := us.s.users[id]
	if !ok {
		return store.User{}, ErrNotFound
	}
	return u, nil
}

func (us *userStore) ListByTenant(ctx context.Context, tenantID string) ([]store.User, error) {
	us.s.mu.Lock()
	defer us.s.mu.Unlock()
	var out []store.User
	for _, u := range us.s.users {
		if u.TenantID == tenantID {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (rs *roleStore) Create(ctx context.Context, r store.Role) (store.Role, error) {
	rs.s.mu.Lock()
	defer rs.s.mu.Unlock()
	if r.ID == "" {
		r.ID = randID("r")
	}
	now := time.Now().UTC()
	r.CreatedAt = now
	r.UpdatedAt = now
	rs.s.roles[r.ID] = r
	return r, nil
}

func (rs *roleStore) Get(ctx context.Context, id string) (store.Role, error) {
	rs.s.mu.Lock()
	defer rs.s.mu.Unlock()
	r, ok := rs.s.roles[id]
	if !ok {
		return store.Role{}, ErrNotFound
	}
	return r, nil
}

func (rs *roleStore) ListByTenant(ctx context.Context, tenantID string) ([]store.Role, error) {
	rs.s.mu.Lock()
	defer rs.s.mu.Unlock()
	var out []store.Role
	for _, r := range rs.s.roles {
		if r.TenantID == tenantID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (ks *keyStore) Create(ctx context.Context, k store.APIKey) (store.APIKey, error) {
	ks.s.mu.Lock()
	defer ks.s.mu.Unlock()
	if k.ID == "" {
		k.ID = randID("k")
	}
	k.CreatedAt = time.Now().UTC()
	ks.s.keys[k.ID] = k
	return k, nil
}

func (ks *keyStore) GetByHash(ctx context.Context, hash string) (store.APIKey, error) {
	ks.s.mu.Lock()
	defer ks.s.mu.Unlock()
	for _, k := range ks.s.keys {
		if k.KeyHash == hash {
			return k, nil
		}
	}
	return store.APIKey{}, ErrNotFound
}

func (ks *keyStore) Revoke(ctx context.Context, id string) error {
	ks.s.mu.Lock()
	defer ks.s.mu.Unlock()
	k, ok := ks.s.keys[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	k.RevokedAt = &now
	ks.s.keys[id] = k
	return nil
}

func (ks *keyStore) ListByTenant(ctx context.Context, tenantID string) ([]store.APIKey, error) {
	ks.s.mu.Lock()
	defer ks.s.mu.Unlock()
	var out []store.APIKey
	for _, k := range ks.s.keys {
		if k.TenantID == tenantID {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (as *auditStore) Write(ctx context.Context, a store.AuditEvent) error {
	as.s.mu.Lock()
	defer as.s.mu.Unlock()
	if a.ID == "" {
		a.ID = randID("a")
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	as.s.audits = append(as.s.audits, a)
	return nil
}

func (as *auditStore) ListByTenant(ctx context.Context, tenantID string, limit int) ([]store.AuditEvent, error) {
	as.s.mu.Lock()
	defer as.s.mu.Unlock()
	var out []store.AuditEvent
	for _, a := range as.s.audits {
		if a.TenantID == tenantID {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func randID(prefix string) string {
	return prefix + "-" + time.Now().UTC().Format("20060102150405.000000000")
}