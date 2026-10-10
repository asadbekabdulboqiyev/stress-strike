// Package tenant provides helpers for multi-tenancy (tenant context and
// utilities).
package tenant

import "context"

type ctxKey struct{}

var key = ctxKey{}

// FromContext returns the tenant ID stored in ctx. Empty string means no tenant.
func FromContext(ctx context.Context) string {
	if v := ctx.Value(key); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// WithContext stores tenantID in ctx.
func WithContext(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, key, tenantID)
}