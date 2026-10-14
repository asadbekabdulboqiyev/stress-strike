# VeriBench — Investor & Competition Pitch

> **Verifiable load-test results.** Turn a performance claim into evidence a
> third party can check.
>
> Structure below maps 1:1 onto a 12-slide deck. Each `## Slide N` is one slide.
> Numbers are labelled **ESTIMATE** or with a source. Nothing here is a legal or
> audit opinion.

---

## Slide 1 — Title

**VeriBench**
*Verifiable performance measurement for the people who have to trust the numbers.*

Format identifier: `vpmp/v1` · Built on the `stress-strike` load-testing engine.

One line: **Today, a load-test report is a promise. VeriBench makes it a
receipt.**

---

## Slide 2 — Problem

Performance numbers decide money:

- Enterprises size infrastructure and sign SLAs on load-test results.
- Agencies win contracts on claimed throughput and p99 latency.
- Regulators, insurers, and acquirers increasingly ask for performance evidence.

But those numbers **cannot be checked by the person relying on them**.

Three consequences, all observed in practice:

1. **Unverifiable**: a `p99 = 41 ms` summary with no path to audit the raw data.
2. **Flattering by construction**: coordinated omission inflates reported
   percentiles on saturated systems — the worse the system performs, the better
   the numbers look.
3. **Unattributable and fabricable**: no binding to who ran what, when; and a
   dishonest generator can emit synthetic samples with no way to tell.

**The buyer bears all the risk and holds none of the proof.**

---

## Slide 3 — Solution

**VeriBench emits a measurement bundle that anyone can verify offline.**

Three pillars (named identically in all VeriBench docs):

1. **Attested Measurement (VPMP v1)** — an Ed25519-signed manifest, with the
   raw per-request sample stream locked behind a Merkle root. Change one byte →
   verification fails.
2. **Honest Latency** — coordinated-omission correction applied to the raw
   stream, plus a **bootstrap 95% confidence interval** on the reported
   percentiles. The correction inputs are themselves signed and auditable.
3. **Adversarial-in-the-loop** — VeriGate adaptive difficulty makes the target
   an **independent witness**: the target's observed arrival count must
   corroborate the generator's claimed load.

Three commands: `keygen` → `run --emit-bundle` → `verify` (exit 0 = PASS,
exit 1 = FAIL, CI-gateable).

---

## Slide 4 — Why now

- **Performance claims are moving from engineering folklore into contracts and
  compliance.** SLAs-as-code, error budgets, and vendor acceptance tests all
  need evidence, not screenshots.
- **Regulated-industry pressure on operational resilience** (financial services
  operational-resilience regimes, DORA-style requirements) pushes firms toward
  documented, repeatable performance evidence.
- **Trust infrastructure is now cheap.** Ed25519 signing and Merkle proofs cost
  microseconds; the engineering cost of an evidence envelope is negligible
  next to the value of the decision it supports.
- **AI-generated reports are eroding credibility.** Once anyone can produce a
  beautiful, plausible performance chart in seconds, *provable* provenance
  becomes the differentiator.
- **The measurement bug is finally well understood.** Gil Tene's coordinated
  omission is common knowledge in the performance community — so "we corrected
  for it, and here is the auditable proof" is a claim buyers can evaluate.

---

## Slide 5 — Product (the three columns)

| **1. Attested Measurement (VPMP v1)** | **2. Honest Latency** | **3. Adversarial-in-the-loop** |
|---|---|---|
| Ed25519-signed manifest · Merkle-locked raw sample stream · commit-then-reveal configuration binding · offline `verify` with exit codes | Coordinated-omission correction over the raw stream · auditable `co_extra_ns` per request · nearest-rank percentiles · seeded bootstrap 95% CI · `p99 = 41 ms [39–44 ms]` | VeriGate adaptive difficulty (PoW challenge, rate limits) · target-side arrival counting as an independent witness · claim-vs-witness corroboration counters |
| **Answers:** *"Is this result intact, attributable, and consistent with its own raw data?"* | **Answers:** *"Is this latency number honest, and how sure are we?"* | **Answers:** *"Did the load actually reach the target?"* |
| Ships in: CLI + bundle format `vpmp/v1` | Ships in: engine + manifest `method` block | Ships in: VeriGate middleware + witness counters |

**MVP status:** Pillar 1 protocol + Pillar 2 correction logic implemented in the
engine today; the `bundle`/`verify` CLI surface is **implemented and shipping**
(see Slide 10). Pillar 3 machinery (VeriGate) ships in the product today; its
witness-corroboration wiring into the bundle is **[ROADMAP] v1.1**.

---

## Slide 6 — Market & sizing

**All figures below are ESTIMATES** compiled from commonly cited analyst
segments. They are **not verified in this document** and must be re-checked
against the named source before any external use. Treat them as order-of-magnitude
planning inputs, not facts.

| Layer | Figure | Basis | Label |
|---|---|---|---|
| Global software testing / QA market | ~USD 55–65B (mid-2020s) | Commonly cited analyst range (Grand View Research / MarketsandMarkets-class estimates) | **ESTIMATE — unverified** |
| Performance & load-testing tooling segment | ~USD 1.5–2.5B | Bottom-up subset of the above (tooling + managed execution) | **ESTIMATE — unverified** |
| Vendor-reported cloud load-test pricing anchors | k6 Cloud / BlazeMeter / LoadRunner Cloud list tiers | Published vendor pricing pages | **VENDOR-REPORTED** |
| **TAM** | ≈ USD 2.4B/year | Performance/load-testing tooling + adjacent APM verification budget | **ESTIMATE** |
| **SAM** | ≈ USD 480M/year | Tooling spend in *enterprise + regulated* segments where verification has contractual value (~20% of TAM) | **ESTIMATE** |
| **SOM (3 years)** | ≈ USD 2.4M ARR | **Bottom-up (primary):** 120 accounts × USD 20k average annual contract | **ESTIMATE — internal model** |

**Sizing method.** We lead with the bottom-up SOM because it is falsifiable
against a pricing model rather than a market-share assertion: `120 accounts ×
USD 20k`. The top-down TAM/SAM are a sanity check that the bottom-up number is
not absurd. If the bottom-up arithmetic is wrong, the pitch is wrong — so this
is the number to challenge in Q&A.

---

## Slide 7 — Competition

Real, shipping products. Comparison is on *verifiability*, not on throughput or
feature count — where several competitors are strong.

| Capability | **VeriBench** | k6 Cloud (Grafana) | BlazeMeter (Perforce) | LoadRunner Cloud (OpenText) | Grafana Cloud k6 |
|---|---|---|---|---|---|
| Distributed load generation | Yes (master/worker fleet) | Yes (cloud) | Yes (cloud) | Yes (cloud) | Yes (cloud) |
| Scripting / protocol breadth | Good | Excellent | Excellent | Excellent (deep enterprise protocols) | Excellent |
| Managed execution & dashboards | Self-host + SaaS | Excellent | Excellent | Excellent | Excellent |
| **Signed, portable evidence artifact** | **Yes — Ed25519-signed bundle** | No | No | No (proprietary analysis) | No |
| **Tamper-evidence on raw per-request data** | **Yes — Merkle root** | No | No | No | No |
| **Offline third-party verification (exit-code gate)** | **Yes — `verify`** | No | No | No | No |
| **Auditable coordinated-omission correction** | **Yes — signed `co_extra_ns` per request** | Tool-dependent, not auditable/declared | Not disclosed | Not disclosed | Tool-dependent |
| **Confidence intervals on reported percentiles** | **Yes — bootstrap 95% CI** | No (point estimates) | No | No | No (TSDB aggregates) |
| **Target as independent witness of delivered load** | **Yes — VeriGate adaptive difficulty** | No | No | No | No |
| **Key-to-identity binding (PKI/CA)** | Not yet — **[ROADMAP]** | n/a | n/a | n/a | n/a |
| **Per-request correspondence proof (nonce/ZK)** | Not yet — **[ROADMAP]** | n/a | n/a | n/a | n/a |

**Honest read.** Competitors beat us on polish, protocol coverage, and managed
convenience *today*. Our wedge is a capability none of them offer: a result that
a disinterested party can verify without trusting anyone. That is a different
axis, not a better version of the same axis.

Also relevant: open-source **Locust**, **Apache JMeter**, and **Gatling** —
excellent, widely used, and in the same trust model as the commercial tools
(results are self-reported, no evidence envelope). They are the realistic
"we'll just build it ourselves" alternative, and the reason our moat must be the
protocol plus the certificate-of-verification workflow, not the load generator
alone.

---

## Slide 8 — Business model

Four revenue lines, ordered by expected contribution:

1. **SaaS — verification workflows.** Free (self-serve, open protocol) ·
   **Team USD 99/mo** · **Business USD 499/mo** (CI gates, team keys,
   certificate issuance, retention). *Prices are designed, not yet validated.*
2. **Enterprise self-hosted licence.** Air-gapped/on-prem deployment for
   regulated and public-sector buyers where results cannot leave the perimeter.
   **USD 25k–75k/year** plus support. *Designed range.*
3. **Certificate-as-a-Service (the asymmetric bet).** Per **verified report**:
   issue a certificate binding `key_id`, `scenario_hash`, and the bundle's
   Merkle root, anchored to a transparency log. **USD 0.50–2.00 per certified
   bundle**, or a bundled annual issuance allowance at the Business/Enterprise
   tier. Buyers want the *third-party stamp*, not just the tool. *Designed
   pricing.*
4. **Audit & assurance integrations.** Sell into audit/GRC and MSP workflows:
   the evidence artifact becomes an attachment in existing audit tooling.
   Referral/rev-share and API consumption. *Designed.*

**Why the certificate line matters:** the tool is open and the protocol is
public (that is what makes verification credible), so the durable business is
being the neutral party that *issues and anchors* the attestation — the same
shape as certificate authorities and timestamping services.

---

## Slide 9 — Go-to-market

1. **Developer wedge (open protocol).** Ship `vpmp/v1` openly, with a
   reference `verify` implementation and a CI action. Adoption of the *verifier*
   is what creates demand for the *signer*.
2. **Beachhead: performance/QA consultancies and agencies.** They carry the
   reputational risk of unverifiable numbers, and they differentiate on
   "our results are provable". Land them, they drag clients in.
3. **Regulated enterprise expansion.** Operational-resilience and vendor-risk
   programmes in financial services, healthcare, and public sector — where
   "the regulator asked for evidence" is a buying trigger, not a nice-to-have.
4. **Distribution through existing channels.** Grafana/JMeter/Locust users are
   not the enemy: `verify` should be consumable *from* any pipeline, so
   VeriBench can be adopted as the evidence layer beside an incumbent generator.
5. **Standards & community.** Publish the spec, submit the format for review, and
   push for interop so that "vpmp/v1 verified" becomes a known phrase in RFPs.

---

## Slide 10 — Traction / MVP status (honest)

**Working today** (in the `stress-strike` engine, v0.14.3):

- Distributed master/worker load generation; live telemetry aggregation.
- **Pillar 2 partially live:** coordinated-omission correction exists in the
  engine and is exposed as `--coordinated-omission` for paced runs, with tests.
- **Pillar 3 machinery live:** VeriGate rate limiting + PoW challenge + IP
  blocking, with concurrency/race tests, demonstrated live by
  `scripts/demo-store-sla.sh`.
- **Pillar 1 live:** the `vpmp/v1` bundle format, `keygen` / `verify` / `run --emit-bundle`
  CLI surface, Merkle-locked raw samples, Ed25519 seal, and the full
  verification algorithm (`verify` exit 0/1) are implemented and shipping.
  Bundle-level CI computation and claim-recomputation gate are in the `verify`
  binary.
- Tamper-evident, hash-chained **audit log** for authorization decisions
  (`audit verify`) — the same tamper-evidence discipline applied to a different
  artifact, already shipped.
- CLI, packaging (Homebrew/Scoop/Winget), K8s manifests, CI/CD.

- **Independent verification, not a promise:** a self-contained offline page
  (`docs/VERIFIER.html`) re-checks bundles in the browser using the browser's own
  SHA-256 and Ed25519, and `scripts/verify-html-parity.sh` asserts it reaches the
  same verdict as the Go verifier on a genuine bundle and four tampered ones
  (`make verifier`: 23 unit tests + drift guard + parity, all wired into CI).

**Next on the roadmap:**

- **[ROADMAP] v1.1:** challenge–response nonce corroboration and transparency-log
  anchoring of Merkle roots.

**We are explicitly not claiming:** that fabrication is solved, that the signer's
identity is established, or that any customer has paid. No revenue to date.

---

## Slide 11 — Team

> **[FILL IN BEFORE THE PITCH — do not present placeholders as facts.]**

| Role | Needed profile | Status |
|---|---|---|
| Founder / CEO | Enterprise sales into performance/QA or vendor-risk buyers | **FILL IN** |
| Founding engineer — protocol | Applied cryptography (signatures, Merkle/transparency logs) + Go | **FILL IN** |
| Founding engineer — measurement/engine | Distributed load generation, latency measurement & statistics | **FILL IN** |
| Advisor — audit/assurance | GRC/audit background to open the certificate channel | **FILL IN** |

**Evidence of execution:** a production-grade Go load-testing engine with
distributed mode, TLS fingerprinting, VeriGate protection, an authorization gate
with an immutable audit trail, cross-platform packaging, and K8s deployment
manifests — built and tested, not a slide.

*(Do not invent names, logos, or credentials. This section is intentionally
unpopulated.)*

---

## Slide 12 — Ask

> **[PLACEHOLDER — confirm round size and use-of-funds with the founder before
> presenting.]**

**Raising:** *(amount to be confirmed; indicative: a pre-seed round to reach
v1.1 with 5 design partners).*

**Use of funds (indicative):**

| Allocation | Purpose |
|---|---|
| ~45% Engineering | Ship `vpmp/v1` bundle + `verify`, then challenge–response + transparency-log anchoring (v1.1) |
| ~25% Design partners | Convert 5 performance consultancies / regulated enterprises into signed pilots |
| ~15% Standards & security | Public spec, reference verifier, crypto review, key-custody (HSM/TEE) design |
| ~15% GTM & certificate channel | Pricing validation, audit/GRC partnership development |

**What we will prove with it (milestones, not vibes):**

1. A third party verifies a bundle produced by a different organisation, using
   only our public spec, offline, in under 5 seconds.
2. Five signed pilots, at least one where the buyer's auditor is the verifier.
3. One anchored certificate issued to a party other than the operator.

---

## Appendix A — Objection handling

- **"I can already see the numbers in Grafana."** You can see *a party's*
  numbers. VeriBench gives you numbers you can re-derive from raw data you can
  verify. Different problem.
- **"The generator is open source — why pay?"** The protocol and verifier being
  open is the *point*; the paid product is the workflow, retention, support, and
  the neutral certificate issuance.
- **"Isn't signing enough?"** No. §7.2 of `docs/INVENTION.md` states why a
  signature is not proof the traffic happened — that is Pillar 3's job, and it
  is a roadmap item, not a solved claim.
- **"Do you beat k6 on throughput?"** Irrelevant. We are not competing on load
  generation capacity; we are the evidence layer, and we aim to sit beside
  whatever generator you already use.

## Appendix B — Claims register (what is a claim vs. an estimate)

| Statement | Type | Verified here? |
|---|---|---|
| Ed25519/Merkle verification detects single-byte tampering | **Technical claim** | Mechanically demonstrated by `scripts/demo-verified.sh` |
| CO correction + 95% CI are implemented in the engine | **Status claim** | CO correction: yes (code + tests). Bundle-level CI: **not shipped** |
| VeriGate adaptive difficulty works (rate limit, PoW, block) | **Status claim** | Yes — VeriGate tests + `demo-store-sla.sh` |
| `keygen` / `verify` / `--emit-bundle` exist today | **Yes** | Shipped in v0.14.3; `scripts/demo-verified.sh` demonstrates the full cycle |
| Market size figures | **ESTIMATE** | No — re-verify against named analyst sources |
| Pricing tiers and ranges | **Designed pricing** | No — not validated with buyers |
| SOM = USD 2.4M ARR (120 × USD 20k) | **ESTIMATE / internal model** | No — falsifiable bottom-up arithmetic |
| Any customer, revenue, or pilot | **None** | No traction claimed |
