# Sift — Fitting Product Directions

This folder holds design documents for product directions that fit Sift's
authorized, evidence-honest, defensive posture. Each document is a design
proposal; implementation status is tracked separately below.

| Document | Scope | Status |
| --- | --- | --- |
| [digital-twin-capacity-simulation.md](digital-twin-capacity-simulation.md) | Evidence-based capacity/risk "what-if" simulation from Sift runs, replays and attested samples. | MVP in progress (`internal/twin`, `Sift simulate`) |
| [ebpf-kernel-xray.md](ebpf-kernel-xray.md) | Opt-in, Linux-first host observability agent correlating external Sift signals with in-host evidence. | MVP in progress (`internal/hostxray`, `Sift xray`) |
| [verifiable-bug-bounty-triage.md](verifiable-bug-bounty-triage.md) | Staged, verifiable evidence packaging and triage workflow on top of VPMP/attest. | MVP in progress (`internal/bounty`, `Sift bounty`) |

## Explicitly not pursued (as proposed)

- **Adversarial Ghost** (self-learning WAF-evasion / RL attack automation) and
  **Ghost Protocol** (P2P volunteer traffic distribution) are not implemented:
  they enable abuse and are incompatible with authorized-testing guarantees.
  Defensive alternatives (authorized coverage testing, operator-controlled
  distributed workers with audit and attestation) remain in scope.

## Design principles

1. Estimates, not guarantees: any prediction ships with confidence and
   uncertainty, and states its assumptions.
2. Evidence integrity is not finding validity: cryptographic packaging proves
   what was submitted, not that a finding is real; human triage stays in the
   loop.
3. Opt-in, least privilege, redaction by default for anything host-level.
4. No new runtime dependencies where the standard library is sufficient.
