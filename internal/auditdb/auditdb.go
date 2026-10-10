// Package auditdb adapts the file-based authz audit to a Postgres-backed store.
// The CLI continues to use the hash-chained file audit for tamper-evidence;
// this adapter is provided for the control-plane (multi-tenant) path.
package auditdb

import (
	"context"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/store"
)

// Adapter maps authz.Entry to store.AuditEvent.
type Adapter struct{}

// ToEvent converts an authz entry to a control-plane audit event.
func (a Adapter) ToEvent(e authz.Entry, tenantID, actorID string, remoteIP, userAgent string) store.AuditEvent {
	details := struct {
		Rule    string   `json:"rule"`
		Reason  string   `json:"reason"`
		IPs     []string `json:"ips"`
		Class   string   `json:"class"`
		Version string   `json:"version"`
		Argv    []string `json:"argv"`
	}{
		Rule:    e.Rule,
		Reason:  e.Reason,
		IPs:     e.IPs,
		Class:   e.Class,
		Version: e.Version,
		Argv:    e.Argv,
	}
	// JSON details kept minimal; callers can serialize.
	_ = details
	return store.AuditEvent{
		TenantID:  tenantID,
		ActorID:   actorID,
		Action:    e.Action + ":" + verdict(e.Allowed),
		Resource:  joinTargets(e.Targets),
		CreatedAt: e.Time,
		RemoteIP:  remoteIP,
		UserAgent: userAgent,
	}
}

func verdict(ok bool) string {
	if ok {
		return "allow"
	}
	return "deny"
}

func joinTargets(ts []string) string {
	if len(ts) == 0 {
		return ""
	}
	out := ts[0]
	for _, s := range ts[1:] {
		out += "," + s
	}
	return out
}

// Write writes an authz entry through the provided store.
func (a Adapter) Write(ctx context.Context, s store.Store, e authz.Entry, tenantID, actorID, remoteIP, userAgent string) error {
	ev := a.ToEvent(e, tenantID, actorID, remoteIP, userAgent)
	return s.Audits().Write(ctx, ev)
}

// RecordBestEffort writes without blocking on error.
func (a Adapter) RecordBestEffort(ctx context.Context, s store.Store, e authz.Entry, tenantID, actorID, remoteIP, userAgent string) {
	_ = a.Write(ctx, s, e, tenantID, actorID, remoteIP, userAgent)
}

// Stub to ensure it compiles when caller passes a concrete store.
// Keep minimal and avoid adding heavy deps.

func Example(ctx context.Context, s store.Store, e authz.Entry) {
	Adapter{}.RecordBestEffort(ctx, s, e, "t1", "u1", "127.0.0.1", "cli")
}