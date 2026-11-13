package auditdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/store"
	"github.com/asadbekabdulboqiyev/sift/internal/store/memstore"
)

func sampleEntry() authz.Entry {
	return authz.Entry{
		Seq:     7,
		Time:    time.Date(2026, 10, 1, 12, 30, 0, 0, time.UTC),
		Actor:   "cli-user",
		Action:  "scan",
		Targets: []string{"https://a.example", "https://b.example"},
		IPs:     []string{"10.0.0.1"},
		Class:   "authorized",
		Allowed: true,
		Rule:    "allowlist",
		Reason:  "target in allowlist",
		Version: "0.14.5",
		Argv:    []string{"scan", "--target", "https://a.example"},
	}
}

func TestToEventMapsAllowedEntry(t *testing.T) {
	// Arrange
	adapter := Adapter{}
	entry := sampleEntry()

	// Act
	got := adapter.ToEvent(entry, "t-acme", "u-42", "203.0.113.9", "Sift/0.14.5")

	// Assert
	if got.TenantID != "t-acme" {
		t.Fatalf("TenantID = %q, want %q", got.TenantID, "t-acme")
	}
	if got.ActorID != "u-42" {
		t.Fatalf("ActorID = %q, want %q", got.ActorID, "u-42")
	}
	if want := "scan:allow"; got.Action != want {
		t.Fatalf("Action = %q, want %q", got.Action, want)
	}
	if want := "https://a.example,https://b.example"; got.Resource != want {
		t.Fatalf("Resource = %q, want %q", got.Resource, want)
	}
	if !got.CreatedAt.Equal(entry.Time) {
		t.Fatalf("CreatedAt = %v, want entry.Time %v", got.CreatedAt, entry.Time)
	}
	if got.RemoteIP != "203.0.113.9" {
		t.Fatalf("RemoteIP = %q, want %q", got.RemoteIP, "203.0.113.9")
	}
	if got.UserAgent != "Sift/0.14.5" {
		t.Fatalf("UserAgent = %q, want %q", got.UserAgent, "Sift/0.14.5")
	}
	if got.ID != "" {
		t.Fatalf("ID = %q, want empty (assigned by the store)", got.ID)
	}
}

func TestToEventMapsDeniedEntry(t *testing.T) {
	entry := sampleEntry()
	entry.Allowed = false

	got := Adapter{}.ToEvent(entry, "t-acme", "u-42", "", "")

	if want := "scan:deny"; got.Action != want {
		t.Fatalf("Action = %q, want %q", got.Action, want)
	}
}

func TestToEventHandlesNoTargets(t *testing.T) {
	entry := sampleEntry()
	entry.Targets = nil

	got := Adapter{}.ToEvent(entry, "t-acme", "u-42", "", "")

	if got.Resource != "" {
		t.Fatalf("Resource = %q, want empty for targetless entry", got.Resource)
	}
}

func TestVerdict(t *testing.T) {
	tests := []struct {
		allowed bool
		want    string
	}{
		{allowed: true, want: "allow"},
		{allowed: false, want: "deny"},
	}
	for _, tc := range tests {
		if got := verdict(tc.allowed); got != tc.want {
			t.Fatalf("verdict(%v) = %q, want %q", tc.allowed, got, tc.want)
		}
	}
}

func TestJoinTargets(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{name: "nil", in: nil, want: ""},
		{name: "empty slice", in: []string{}, want: ""},
		{name: "single", in: []string{"https://a.example"}, want: "https://a.example"},
		{name: "two", in: []string{"a", "b"}, want: "a,b"},
		{name: "many with empty element", in: []string{"a", "", "c"}, want: "a,,c"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinTargets(tc.in); got != tc.want {
				t.Fatalf("joinTargets(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestWritePersistsThroughStore(t *testing.T) {
	// Arrange
	s := memstore.New()
	entry := sampleEntry()

	// Act
	err := Adapter{}.Write(context.Background(), s, entry, "t-acme", "u-42", "203.0.113.9", "cli")

	// Assert
	if err != nil {
		t.Fatalf("Write: unexpected error: %v", err)
	}
	events, err := s.Audits().ListByTenant(context.Background(), "t-acme", 0)
	if err != nil {
		t.Fatalf("ListByTenant: unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(events))
	}
	ev := events[0]
	if ev.Action != "scan:allow" {
		t.Fatalf("persisted Action = %q, want scan:allow", ev.Action)
	}
	if ev.Resource != "https://a.example,https://b.example" {
		t.Fatalf("persisted Resource = %q", ev.Resource)
	}
	if ev.ID == "" {
		t.Fatal("store did not assign an ID")
	}
	if !ev.CreatedAt.Equal(entry.Time) {
		t.Fatalf("persisted CreatedAt = %v, want %v", ev.CreatedAt, entry.Time)
	}
	if ev.ActorID != "u-42" || ev.TenantID != "t-acme" {
		t.Fatalf("persisted actor/tenant = %q/%q", ev.ActorID, ev.TenantID)
	}
}

func TestRecordBestEffortSwallowsWriteError(t *testing.T) {
	// Arrange
	entry := sampleEntry()
	s := &failingStore{}

	// Act: must not panic or block on the error.
	Adapter{}.RecordBestEffort(context.Background(), s, entry, "t-acme", "u-42", "", "")

	// Assert
	if s.writes != 1 {
		t.Fatalf("audit Write called %d times, want 1", s.writes)
	}
}

func TestRecordBestEffortWritesThrough(t *testing.T) {
	s := memstore.New()

	Adapter{}.RecordBestEffort(context.Background(), s, sampleEntry(), "t-acme", "u-42", "", "")

	events, err := s.Audits().ListByTenant(context.Background(), "t-acme", 10)
	if err != nil {
		t.Fatalf("ListByTenant: unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(events))
	}
}

// TestExampleIsCallable covers the exported package-level helper, which is part
// of the published API surface.
func TestExampleIsCallable(t *testing.T) {
	s := memstore.New()

	Example(context.Background(), s, sampleEntry())

	events, err := s.Audits().ListByTenant(context.Background(), "t1", 10)
	if err != nil {
		t.Fatalf("ListByTenant: unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(events))
	}
	if events[0].ActorID != "u1" || events[0].UserAgent != "cli" {
		t.Fatalf("Example recorded %+v, want actor u1 / ua cli", events[0])
	}
}

// failingStore is a store.Store whose audit write always fails; it proves
// RecordBestEffort is genuinely best-effort.
type failingStore struct{ writes int }

func (f *failingStore) Tenants() store.TenantStore { return nil }
func (f *failingStore) Users() store.UserStore     { return nil }
func (f *failingStore) Roles() store.RoleStore     { return nil }
func (f *failingStore) APIKeys() store.APIKeyStore { return nil }
func (f *failingStore) Audits() store.AuditStore   { return failingAuditStore{f} }

type failingAuditStore struct{ parent *failingStore }

func (f failingAuditStore) Write(context.Context, store.AuditEvent) error {
	f.parent.writes++
	return errors.New("auditdb: write failed")
}

func (f failingAuditStore) ListByTenant(context.Context, string, int) ([]store.AuditEvent, error) {
	return nil, errors.New("auditdb: read failed")
}
