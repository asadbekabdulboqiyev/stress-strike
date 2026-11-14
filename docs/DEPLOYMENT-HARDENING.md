# Deployment Hardening & External Infrastructure Guide

This document provides practical guidance for deploying Sift securely in external environments. It addresses TLS termination/HTTPS, reverse proxy/CDN exposure, database hardening, and security re-scan (A01–A10 style) procedures.

> **Scope:** Sift is a self-hosted toolkit. Operators are responsible for deployment security, network controls, authorization boundaries, and compliance obligations in their environment.

## 1. TLS Termination / HTTPS

### 1.1 Recommended architecture
- Terminate TLS at a trusted reverse proxy/load balancer/ingress (Caddy, nginx, cloud LB, ingress controller).
- Keep Sift services (dashboard/master/worker) on private/internal networks when possible.
- Expose only required ports (typically 443/tcp for HTTPS; 80/tcp for ACME HTTP-01 redirects/challenges if used).
- Do **not** expose unauthenticated dashboard control endpoints publicly.

### 1.2 Provided deployment assets (in-repo)
- `deploy/reverse-proxy/Caddyfile` — Caddy reverse proxy with automatic HTTPS (Let's Encrypt) and security headers.
- `deploy/reverse-proxy/nginx.conf` — nginx TLS termination template (WebSocket-aware) for use with certbot/manual certs.
- `deploy/docker-compose.secure.yml` — compose overlay that places Caddy in front of the dashboard and removes direct dashboard host port publishing.
- `deploy/reverse-proxy/Caddyfile.local` + `deploy/docker-compose.secure.local.yml` — localhost validation overlay (no public DNS/ACME) for testing proxy wiring.
- `deploy/charts/sift/templates/ingress.yaml` + `deploy/charts/sift/values.yaml` (`ingress.*`) — optional Kubernetes Ingress template for TLS-terminated HTTP exposure.

### 1.3 Docker Compose (HTTPS via Caddy)
1. Set your DNS record (e.g. `dashboard.example.com`) to the host public IP.
2. Open inbound `80/tcp` and `443/tcp` (firewall/security group) and restrict admin ports.
3. Edit `deploy/reverse-proxy/Caddyfile` and replace `dashboard.example.com`.
4. Start:
   ```bash
   docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.secure.yml up -d --build
   ```
5. Verify certificate issuance and HTTPS access:
   ```bash
   curl -I https://dashboard.example.com/healthz
   ```
6. Keep dashboard credentials/tokens configured and rotate secrets regularly.

### 1.3.1 Local validation (no public DNS)
```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.secure.yml \
  -f deploy/docker-compose.secure.local.yml up -d --build
curl -I http://127.0.0.1:8088/
```


**Notes**
- If the dashboard must bind non-loopback inside containers, use explicit auth configuration (tokens/credentials) per Sift dashboard behavior; do not rely on `-insecure` for public exposure.
- Restrict gRPC control ports (`50051`) to trusted networks/hosts only.

### 1.4 Kubernetes (Ingress TLS termination)
- Enable and configure `ingress` in Helm values (host, service, TLS secret, annotations for cert-manager/controller).
- Use cert-manager or your platform's certificate management for automated issuance/renewal.
- Enforce TLS-only redirects and modern TLS policies at the ingress/controller layer.
- Add network policies to limit pod-to-pod and ingress/egress traffic as appropriate.

Example values snippet:
```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: dashboard.example.com
      paths:
        - path: /
          pathType: Prefix
          serviceName: sift-dashboard
          servicePort: 8888
  tls:
    - secretName: sift-dashboard-tls
      hosts:
        - dashboard.example.com
```

## 2. Reverse Proxy / CDN Exposure

### 2.1 Reverse proxy hardening checklist
- [ ] HTTPS enforced (HTTP -> HTTPS redirect)
- [ ] Strong TLS configuration (TLS 1.2/1.3 per policy) and automatic renewal
- [ ] Security headers set (HSTS, X-Content-Type-Options, frame/referrer/permissions policies as appropriate)
- [ ] Request/body size limits aligned with app behavior (dashboard uploads are bounded; verify limits)
- [ ] Timeouts configured (including WebSocket/long-lived connections)
- [ ] Access controls applied (IP allowlists, VPN, SSO/auth proxy) for admin/dashboard surfaces
- [ ] Trusted proxy headers handled correctly (X-Forwarded-*), and client IP trust boundaries defined
- [ ] Logging/monitoring enabled (access logs, error rates, TLS/cert expiry alerts)

### 2.2 CDN/WAF considerations
- If placing a CDN/WAF in front:
  - Restrict origin access so only CDN/proxy egress IPs can reach origin (where supported).
  - Preserve/forward required headers and WebSocket upgrade behavior.
  - Configure caching carefully for authenticated/dynamic dashboard and API responses (prefer bypass/no-store for sensitive/control endpoints).
  - Enable WAF/rate-limiting/bot protections appropriate to your threat model.
  - Validate that security scanners/pentest traffic is authorized and not violating provider terms.

### 2.3 Network segmentation
- Expose only the reverse proxy publicly; keep dashboard/master/worker/DB on private subnets.
- Use firewall/security groups and Kubernetes NetworkPolicies.
- Limit egress from sensitive components where feasible.

## 3. Database Hardening (Postgres-backed deployments)

Sift includes a Postgres-backed store implementation (`internal/store/postgres`) and migrations (`migrations/`). Apply standard database hardening in production:

### 3.1 Transport and access
- [ ] Require TLS for client connections (`sslmode=verify-full` where possible)
- [ ] Use private networking; do not expose Postgres directly to the public internet
- [ ] Restrict inbound DB access by security group/firewall/IP allowlist
- [ ] Use separate credentials per service/environment (no shared superuser credentials)

### 3.2 Authentication and authorization
- [ ] Least-privilege DB roles (app role limited to required schemas/tables/operations)
- [ ] Rotate credentials/secrets; store in secret manager/K8s Secrets (not in git)
- [ ] Disable/avoid trust auth; prefer SCRAM authentication
- [ ] Separate migration/admin credentials from runtime app credentials where operationally feasible

### 3.3 Configuration and operations
- [ ] Enable backups + restore testing (PITR if required)
- [ ] Enable encryption at rest (disk/volume/provider-managed or native as applicable)
- [ ] Configure logging/auditing appropriate to policy (connections, DDL, slow queries, auth failures)
- [ ] Patch/upgrade Postgres regularly and monitor for CVEs
- [ ] Apply connection limits/timeouts and resource controls to prevent exhaustion
- [ ] Validate migrations in staging before production rollout

### 3.4 Application-level notes
- Use parameterized queries and least privilege (already expected in code paths); review DSN handling and secret injection in deployment manifests.
- Ensure `DATABASE_URL`/DSNs are injected via secrets and not committed to source control.

## 4. Service and Container Hardening (baseline)

### 4.1 Containers (already partially applied in repo assets)
- Run as non-root (distroless/alpine images and chart settings already favor this)
- Read-only root filesystem where possible; mount explicit writable tmp/report volumes
- Drop Linux capabilities (`ALL`) and set `no-new-privileges`; use seccomp `RuntimeDefault`
- Set CPU/memory limits and health probes
- Pin image tags/digests for production rollouts; scan images (Trivy/Grype) in CI and before release

### 4.2 OS/service (systemd/VM)
- Use dedicated service users, minimal file permissions, and `ProtectSystem`/sandboxing options (see `deploy/systemd/sift-worker.service`)
- Restrict inbound ports with host firewall (ufw/nftables/security groups)
- Keep OS/packages patched; enable centralized logs/metrics/alerts

## 5. Public Deploy Checklist (external actions)

These steps require your infrastructure/accounts and cannot be completed from source code alone:

- [ ] Provision target environment (VM/K8s/containers) and private networking
- [ ] Configure DNS records for public endpoints
- [ ] Provision and validate TLS certificates (ACME/cert-manager/cloud certs)
- [ ] Configure reverse proxy/ingress/CDN/WAF and origin restrictions
- [ ] Configure firewall/security groups and network policies
- [ ] Inject secrets (tokens, DB DSNs, keys) via secret manager/K8s secrets
- [ ] Enable observability (logs, metrics, alerts, uptime/cert expiry)
- [ ] Run staging verification before production cutover
- [ ] Perform authorized security re-scan (see Section 6)

## 6. A01–A10 Re-scan Procedure (authorized)

> **Authorization required:** Only scan systems you own or are explicitly authorized to test. Follow your legal/policy/process requirements and record approvals/audit evidence.

Sift provides security scanning/pentest workflows (e.g. `sift scan`, individual scanners, `sift pentest`) that can help identify common web security issues (headers/TLS/config exposure/OWASP-mapped checks depending on scope and target behavior). Use them as part of a broader assessment, not as a complete guarantee.

### 6.1 Pre-scan
- Define scope (domains, IPs, paths, environments) and obtain written authorization/tickets as required.
- Confirm rate limits/safe windows to avoid service disruption.
- Ensure WAF/CDN/proxy rules will not block/alter results unexpectedly (or account for them).
- Capture baseline (version deployed, commit/tag, config profile).

### 6.2 Local verification (example, owned/local target)
```bash
# Start local demo target (authorized/local)
./bin/sift demo-store --addr 127.0.0.1:8090

# Run scans against local target (adjust flags/authorization options per your policy)
./bin/sift scan https://127.0.0.1:8090
./bin/sift pentest --target http://127.0.0.1:8090
```
(Exact command options may vary by build/config and authorization gates; use `--help` for the installed version.)

### 6.3 Public/staging re-scan (after deploy)
- Re-run authorized scans against the deployed HTTPS endpoint (through CDN/proxy as exposed).
- Validate TLS configuration, security headers, redirect behavior, auth controls, and exposed services/ports.
- Re-test after each remediation; track findings, evidence, and closure status.
- Supplement with external/manual assessments as needed for coverage beyond automated checks.

### 6.4 Evidence and reporting
- Store reports/artifacts securely; avoid leaking secrets/tokens in shared outputs.
- Use verifiable evidence workflows where applicable (`sift verify`, bounty/attestation artifacts) for integrity of captured evidence.
- Document residual risks and compensating controls.

## 7. Known external dependencies / limitations
- Real HTTPS certificates, DNS, CDN/WAF, cloud firewalls, and managed databases require external provider access and credentials.
- A01–A10 re-scans against public production targets require an actually deployed, reachable, and authorized environment.
- Compliance certifications (e.g. SOC 2/ISO 27001) are organizational/process outcomes, not automatic results of tooling.
