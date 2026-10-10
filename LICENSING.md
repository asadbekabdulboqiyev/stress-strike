# Licensing

stress-strike is **open core**. The project has two tiers:

| Tier | License | What it covers |
|---|---|---|
| **Core** (this repository) | [Apache License 2.0](LICENSE) | The CLI, load engine, protocol clients, scenario engine, replay, scanner/pentest, VeriGate, dashboard, reports, and the public Go library in `api/` |
| **Enterprise** (separate, commercial) | Commercial license | Features built for organisations that must pass procurement and InfoSec review |

---

## 1. Core — Apache-2.0

Everything currently in this repository is licensed under the **Apache License,
Version 2.0**. You may use, modify, embed, self-host, and redistribute it,
including commercially and inside closed-source products, subject to the terms
in [`LICENSE`](LICENSE) and the attributions in [`NOTICE`](NOTICE).

The full text of the core license is in [`LICENSE`](LICENSE).

## 2. Enterprise tier — commercial

The following capabilities are reserved for a commercial license. They are
**not** part of this repository and are not covered by Apache-2.0:

- Single sign-on (OIDC / SAML) and role-based access control
- The multi-tenant control plane (teams, projects, per-tenant isolation)
- Persistent run history and the audit log of who ran what, against which
  target, when, and under whose approval
- The managed distributed fleet (autoscaling, hosted coordinator)

These are the features that turn an excellent open-source tool into something a
bank, hospital, or government buyer can put through procurement. Keeping them
commercially licensed is what funds the core. Nothing in the core loses
functionality because of this split — the core stays a complete, usable tool.

To discuss a commercial license, contact the maintainer (see [`README.md`](README.md)).

## 3. Relicensing note (prior releases)

Earlier releases of stress-strike were published under
**AGPL-3.0**. A license already granted cannot be revoked: **anyone who received
a copy of an AGPL-3.0 release keeps the rights AGPL-3.0 granted them, for that
version, forever.** Relicensing applies going forward only — to this release and
later ones. If you need the terms that applied to an older version, use the
`LICENSE` file at the matching git tag.

This project has a single copyright holder (`git shortlog -sne` shows one
author), so relicensing does not require a contributor agreement from anyone
else. To keep it that way, see §4.

## 4. Contributions

To keep the open-core model legally sound, every contribution must be
accompanied by a sign-off that you have the right to submit it and that it may be
distributed under **both** the Apache-2.0 core license and the commercial
license (a dual-license grant). This is what lets the project keep a single
licensing story without ever having to hunt down contributors.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the exact procedure (Developer
Certificate of Origin).

## 4.1 Why a CLA-style sign-off, and why now

If a contributor's code enters the tree without an explicit grant that covers
future relicensing, that contributor's code can permanently block the dual
license. The sign-off requirement is added **now**, while the project still has
a single author, precisely to avoid that trap later.

## 5. Third-party components

The binaries bundle third-party Go modules under their own licenses
(Apache-2.0, BSD-3-Clause, BSD-2-Clause, MIT). The full attribution list is in
[`NOTICE`](NOTICE). Those licenses apply to those components only; they do not
relicense the core.

## 6. Trademarks

"stress-strike" and the project logo are not covered by the Apache-2.0 grant.
Forks may use the source under Apache-2.0, but must not present themselves as
the official project or imply endorsement by the maintainer.
