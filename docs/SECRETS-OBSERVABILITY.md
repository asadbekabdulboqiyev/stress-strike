# Phase 4/5: Secrets Management & Observability (minimal, in-scope)

## 4) Secrets Management
Goal: `${ENV}` interpolation for secrets/config. Support pluggable backends later (Vault/AWS SM/Azure KV) without breaking existing behavior.

### Design
- `internal/secrets/resolver.go` — interface + env resolver
- `Resolve(s string) string` — expands `${VAR}`/`${VAR:-default}`
- Wired into config loading where credentials/tokens/URLs may be substituted
- Never log resolved secret values

### Implementation (minimal)
Keep to env expansion first (most common). Add helpers and tests.

## 5) Observability
Minimal, non-invasive:
- Prometheus exporter (`internal/metrics/exporter/prom.go`) — `/metrics` handler
- OTel trace hooks (`internal/otel/otel.go`) — no-op by default; enabled via env
- Grafana dashboard JSON stub (`observability/grafana/dashboard.json`) if useful
- SIEM webhook notifier helper (`internal/siem/webhook.go`) — best-effort

Keep scope to what's useful for enterprise ops.
