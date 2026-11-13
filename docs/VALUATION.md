# stress-strike — valuation dossier

**Purpose.** What this asset is, what it cost to build, what the market pays for
comparable capability, and what it is realistically worth — as a code asset, as
an OEM licence, and as a running product.

**Status of the numbers.** Everything below is dated 13 November 2026. Vendor
prices were checked against published 2026 sources and are quoted as market
anchors, not offers. The valuation ranges are estimates with the reasoning
shown, not a financial opinion. Currency is USD throughout.

---

## 1. What the asset actually is

A security assessment platform in Go, shipped as six binaries plus a dashboard,
with a distributed execution model and a verifiable-output story.

### 1.1 Measured inventory

| Metric | Value |
|---|---|
| Production Go | 61,375 lines across 204 files (protobuf-generated code excluded) |
| Test Go | 59,438 lines across 204 files |
| Total Go | 124,042 lines, 410 files |
| Packages | 57 |
| Test functions | 1,986 |
| Fuzz targets | 5 (HTTP stream, HAR, JWT, Set-Cookie, CSP) |
| Benchmarks | 16 |
| Statement coverage | 79.1% overall |
| Direct dependencies | 17 |
| Dashboard routes | 37 dispatch arms, 32 distinct endpoints (33 arms under `/api`; `certificate/generate` is an alias of `certificate/issue`) |
| Dashboard frontend | 7,402 lines (13 embedded JS parts + CSS + templates) |
| Documentation | 6,033 lines across README and `docs/*.md` (generated HTML not double-counted) |
| Commits / release tags | 193 / 24 |
| Elapsed build time | 92 days (13 Aug → 13 Nov 2026) |
| Binaries | 6, 7–25 MB each, CGO-free, `-trimpath` |
| Licence | Apache-2.0 (with NOTICE and a dual-use legal note) |

### 1.2 Capability inventory

**Load and performance engine.** HTTP/1.1, HTTP/2, HTTP/3 (quic-go), gRPC,
WebSocket; TLS ClientHello fingerprinting through uTLS (chrome/firefox/safari
profiles) with matching header sets, so a scan does not announce itself as Go;
distributed master/worker execution over gRPC with registration, backoff and
readiness endpoints; real-browser load measurement through CDP with JS-error
collection.

**Assessment scanners.** Passive analysis (headers, CSP, cookies, source maps,
secrets); intrusive checks behind an explicit allowlist and an opt-in gate;
OWASP Top 10 mapping; TLS/SSL inspection; WAF fingerprinting; port scan;
subdomain enumeration; directory brute-force; JWT analysis; GraphQL and
WebSocket probes; CVE matching against NVD; JS-rendered crawler.

**Reporting.** PDF, HTML and Markdown professional reports; one shared scoring
ladder (weights, six grade bands, verdict sentences) used by both the CLI and
the dashboard; compliance mapping for OWASP, PCI DSS v4.0 and ISO 27001:2022;
baseline comparison; SLA evaluation.

**Verifiable output.** Ed25519-signed assessment certificates (`ss-cert/v1`)
with a certificate history chain; attestation bundles with sample data;
`internal/verigate` — a verification service; an audit DB; an honesty gate that
refuses to certify a scan as CLEAN when findings exist.

**Platform.** 36-route dashboard dispatcher (32 under `/api`) plus SPA; admin lock; authz tickets; RBAC;
multi-tenant; OIDC; Postgres and in-memory stores; Prometheus, OpenTelemetry and
SIEM exporters; Kubernetes/Helm/operator/CRDs, Compose, systemd, fleet
bootstrap; six CI/CD workflows; SBOM (SPDX + CycloneDX) and cosign signatures on
every release asset; winget, Homebrew-grade install scripts and a `ss` command.

### 1.3 What is genuinely differentiated

1. **One artefact that does load, pentest and proof.** Competitors split these
   across k6/Locust, a DAST scanner and a document template. Here a load test
   and a pentest produce the same signed, verifiable certificate with a
   reproducible score.
2. **Honest scoring as a design constraint.** The score, grade and verdict live
   in one file, are pinned by boundary tests from both entry points, and the
   product refuses to print CLEAN when findings exist. That is a sales argument
   against every scanner whose grade is decoration.
3. **Verifiable evidence, not a PDF claim.** Ed25519 certificate, attestation
   bundle, verification endpoint, chained history. Auditors and clients can
   check a report instead of trusting it.
4. **Distributed by default.** Master/worker over gRPC, K8s operator, HPA,
   fleet bootstrap — the shape enterprises ask for before they will run a
   scanner continuously.
5. **Protocol and spec work.** `vpmp/v1` is written down as an RFC-style spec
   (`docs/VPMP-RFC.md`), which is what makes an OEM or standards conversation
   possible.

### 1.4 What it is not

- No paying customers, no logo list, no case study.
- One effective maintainer. Three author identities in git, one human.
- No SOC 2, no ISO 27001 certification, no pen-test-of-the-pen-tester report.
- No hosted SaaS, no billing, no self-serve signup.
- The coverage floor is real: `internal/dist/proto` sits at 17% (generated
  code), and `cmd/stress-strike-worker` at 46%.
- `gopacket` is effectively unmaintained; the exposure is bounded by a size
  guard and by not fuzzing third-party parsing, but the dependency is a liability.
- Dual-use: an offensive tool. Some buyers cannot touch it without legal review.

---

## 2. What it cost to build

Two honest numbers, because AI-assisted build cost and replacement cost are not
the same thing.

### 2.1 Replacement cost (commission it without AI assistance)

At 20–40 net new tested lines per engineer-hour for high-assurance Go, 123,207
lines is 3,100–6,200 engineer-hours. Cross-checked bottom-up:

| Component | Person-days | Share |
|---|---|---|
| Load/performance engine, distributed master/worker | 110–170 | 22% |
| Scanner families (passive, intrusive, TLS, WAF, ports, subdomains, dirbust, JWT, GraphQL, WS, CVE, crawler) | 160–240 | 30% |
| Reporting, scoring, compliance mapping | 55–85 | 11% |
| Certificates, attestation, verification service, audit | 65–95 | 13% |
| Dashboard API + SPA | 60–90 | 12% |
| Platform: K8s/Helm/operator, CI, SBOM/cosign, installers, observability, stores | 50–80 | 10% |
| Docs, protocol spec, legal/dual-use material | 25–40 | 5% |
| **Total** | **525–800** | 100% |

525–800 person-days is 4,200–6,400 engineer-hours. At a blended $80–$120/hour
(European contractor to US senior), that is **$340,000–$770,000**. At an Indian
or Eastern-European outsourced rate of $35–$55/hour it is **$145,000–$350,000**.

### 2.2 What was actually spent

The repository shows 178 commits over 91 calendar days. A single engineer
working daily with AI assistance at 150–250 net lines/hour lands at 500–800
hours — **$75,000–$160,000** at a senior blended rate including review time.
That gap between 2.1 and 2.2 is the point: the replacement cost is what a buyer
avoids paying, and the build cost is what the seller actually risked.

---

## 3. What the market pays for comparable capability

Published 2026 anchors (verify before quoting to a buyer):

| Product | Model | Price |
|---|---|---|
| Burp Suite Professional | per user / year | **$499** |
| Burp Suite DAST (ex-Enterprise) | per website + scan hours | entry ~**$6,000/yr**, large estates past $200,000 |
| Invicti | per target / year | entry ~**$7,000**, median contract **$21,596**, 50 FQDNs ~$37,000 |
| Intruder.io | base + per target | Cloud ~**$299/month** (5 targets), Pro ~$499/month, 100 targets ~$10,923/yr |
| Human pentest, one web app | per engagement | **$5,000–$25,000** (market range) |
| Load testing SaaS | per VU-hour or plan | $50–$500/month typical |

Translation for this asset:

- The **scanning** capability sits in the $6,000–$22,000/yr bracket per
  customer, i.e. it competes with Burp DAST entry tier and Invicti's median.
- The **certificate + attestation + compliance mapping** capability sits next to
  audit-evidence tooling, which is priced per framework and per year, and is
  what turns a scanner into something a compliance budget pays for.
- The **load engine** replaces a separate k6/Locust subscription, worth a few
  hundred to a few thousand dollars a year per team.

That is a $6,000–$25,000/yr product per mid-size customer **if it has a
support organisation behind it**. Without one, it is a code asset.

---

## 4. Valuation

Four lenses, then a recommended asking range.

### 4.1 Cost basis (floor)

`0.3–0.8 × replacement cost` is the normal band for pre-revenue software assets
where the buyer must still build the go-to-market. With replacement cost of
$340k–$770k, the floor is **$100k–$400k** for a buyer who values the code at
what it saves them.

### 4.2 Income basis (what it could earn)

Recommended price card if productised:

| Tier | Scope | Price / year |
|---|---|---|
| Team (self-hosted) | 5 targets, load + pentest, certificates | **$1,800–$3,600** |
| Pro | 25 targets, compliance mapping, PDF/HTML reports, CI integration | **$6,000–$12,000** |
| Enterprise | unlimited, OIDC/SSO, multi-tenant, SIEM, K8s operator, support SLA | **$18,000–$40,000** |
| Per-assessment | one certificate-graded pentest, pay as you go | **$250–$600** |
| OEM / white-label | source licence, per-seat or royalty | **$40k–$120k upfront**, 10–20% royalty |

Scenario revenue in year 2 of real selling:

| Scenario | Customers | Avg ACV | ARR |
|---|---|---|---|
| Conservative | 20 | $4,000 | **$80,000** |
| Base | 60 | $6,000 | **$360,000** |
| Optimistic | 200 | $5,000 | **$1,000,000** |

At 3–5× ARR (small, single-maintainer, unproven retention) the base scenario is
worth **$1.1M–$1.8M** — but only after the customers exist. Today it is worth
zero on this lens, which is exactly why the cost basis dominates.

### 4.3 Market basis (what a strategic buyer pays)

Buyers and what they would pay:

| Buyer | Motive | Range |
|---|---|---|
| Pentest / MSSP firm | replaces a $30k–$80k/yr internal tooling build, adds a certificate product to their service line | **$120k–$280k** + 3–6 month handover or retention at $8k–$15k/month |
| DAST vendor | bolts on load testing + verifiable certificates | **$150k–$400k**, often as acquihire |
| Compliance/GRC vendor | wants signed evidence and OWASP/PCI/ISO mapping | **$150k–$350k** |
| Individual practitioner / small team | self-hosted tool, no support expectation | **$20k–$60k** |
| Open-source sponsor / foundation | takes stewardship, seller keeps advisory role | $0 cash + sponsorship $2k–$6k/month |

### 4.4 IP basis (spec and protocol value)

`vpmp/v1` + `ss-cert/v1` + the scoring/honesty rules are the parts that survive
a rewrite of the code:

- As a standalone spec package with the reference implementation: **$15k–$40k**.
- If a third party adopts `vpmp/v1`: materially more, because adoption is what
  makes a protocol valuable — but that is a 12–24 month bet, not a price today.

### 4.5 Recommended ranges

| Deal shape | Asking | Walk-away |
|---|---|---|
| **As-is asset sale** (code, docs, brand, releases; no customers, no support) | **$120k–$180k** | $75k |
| **Strategic sale with handover** (3 months of the maintainer's time, migration help) | **$180k–$300k** | $140k |
| **OEM source licence** (non-exclusive, one vendor, one vertical) | **$40k–$90k upfront** + 10–20% royalty, 24-month floor | $30k |
| **Exclusive licence by vertical** (e.g. only MSSPs in one country) | **$60k–$120k/yr** | $45k/yr |
| **SaaS, after 10 paying customers** | 3–5× ARR | — |
| **Single practitioner licence** (no support) | **$1,500–$3,000** one-off, or $600–$1,200/yr | — |

Point estimate for the asset **today, as it stands**: **$110k–$150k**, with the
$120k–$180k asking range above it because the first number is what it clears at,
not what it lists at.

---

## 5. Risk discounts and premiums

Applied to the cost basis, these are why the number lands near 25–35% of
replacement cost rather than 60%.

| Factor | Direction | Weight |
|---|---|---|
| No paying customers, no retention data | −25 to −40% | largest single discount |
| Single maintainer (bus factor 1) | −10 to −20% | buyer must fund a second engineer |
| Offensive dual-use, no legal opinion on file | −5 to −15% | blocks regulated buyers |
| No SOC 2 / ISO 27001, no third-party pentest of the tool | −5 to −10% | enterprise procurement gate |
| `gopacket` unmaintained; 17 direct deps to track | −3 to −8% | bounded by the capture guard |
| No trademark, no domain, no brand recognition | −3 to −5% | pure code then |
| 78.7% coverage, 5 fuzz targets, 6 CI workflows | +5 to +10% | unusual for a solo project |
| Signed releases, SBOM, reproducible flags | +3 to +5% | supply-chain story is real |
| Honesty gate + verifiable certificates | +5 to +10% | the differentiating story |
| Distributed execution, K8s operator, protocol spec | +5 to +8% | enterprise shape already built |
| Documentation volume and quality (7.7k lines) | +3 to +5% | reduces handover cost |

Net of the table, the defensible multiplier on replacement cost is **0.25–0.40**,
which is where $110k–$150k sits.

---

## 6. What would move the price

In order of return per unit of effort:

1. **Three paying design partners at $3k–$6k.** Pre-revenue to $15k ARR
   typically triples an asset price, because it converts a cost story into a
   revenue story. Highest-leverage item on this list by a wide margin.
2. **A second maintainer with commit rights for 3+ months.** Removes the
   largest single discount. Costs $10k–$20k, adds $20k–$60k of value.
3. **A named benchmark report** — this tool vs OWASP ZAP and Nuclei on the same
   five targets, published with methodology. Buyers believe measured claims.
4. **SOC 2 Type I** (3–6 months, $8k–$25k). Unlocks the enterprise tier and the
   GRC-vendor buyer.
5. **A hosted demo with a real certificate the buyer can verify.** The
   verification flow is the product's best argument and it is currently
   invisible until someone runs it.
6. **A third-party pentest of the tool itself**, published. Cheap credibility
   for a security product that sells honesty.
7. **Trademark + domain.** $1k–$3k, and it removes an objection in every
   negotiation.

---

## 7. Deal structures worth offering

- **Asset sale with a 90-day handover**, price split 60% at close / 40% at day
  90, with the seller on call for integration. Keeps the bus-factor objection
  priced rather than argued.
- **OEM licence with a floor**: $45k upfront, 15% royalty, $30k/yr minimum for
  24 months, source escrow. Common shape for a security vendor buying capability
  without buying a company.
- **Vertical exclusivity**: sell the right to resell to MSSPs in one country for
  12 months. Simpler to sign than an asset sale and leaves the core asset intact.
- **Acquihire-shaped**: code at a nominal price plus a 6-month contract at
  $10k–$15k/month. Usually the highest total for a solo builder.
- **Avoid**: pure revenue-share with no floor, and any deal that transfers the
  certificates' signing keys without a written custody plan.

---

## 8. Due-diligence pack a buyer will ask for

Have these ready before the first serious conversation:

1. `VERSION`, tag list, and the six green workflows — proof the release pipeline
   is real, including the fuzz job and the signed assets.
2. Test and coverage reports: 1,973 tests, 78.7% statements, the five fuzz
   targets with their corpus.
3. Dependency inventory with licences (17 direct, Apache-2.0 core) and the
   `gopacket` risk note.
4. SBOM (SPDX + CycloneDX) and cosign verification instructions for the current
   release.
5. A CodeQL/gosec report on the current commit.
6. The dual-use legal note (`docs/LEGAL-DUAL-USE.md`) and the authorization
   model (`docs/AUTHORIZATION.md`) — this is what makes an offensive tool
   sellable at all.
7. Architecture and data-flow description: what leaves the machine, what is
   stored, where the signing keys live.
8. A recorded demo: scan → findings → certificate → independent verification.

---

## 9. Summary table

| Question | Answer |
|---|---|
| Replacement cost | $340k–$770k (Western rates), $145k–$350k (outsourced) |
| Actual build spend | 500–800 hours, $75k–$160k |
| As-is asset value today | **$110k–$150k**, ask $120k–$180k |
| Strategic sale with handover | **$180k–$300k** |
| OEM licence | **$40k–$90k** upfront + 10–20% royalty |
| Productised ACV | $1.8k team / $6k–$12k pro / $18k–$40k enterprise |
| Value after 10 paying customers | 3–5× ARR |
| Biggest value lever | three paying design partners |
| Biggest discount | single maintainer + zero revenue |

---

*Prepared as an engineering-grounded estimate. Market prices cited are 2026
published anchors and change; re-check them before any negotiation. This is not
financial or legal advice.*
