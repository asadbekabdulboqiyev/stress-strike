# VeriBench — Invention Disclosure: Verifiable Performance Measurement

**Format identifier:** `vpmp/v1`
**Product name:** VeriBench
**Status of this document:** invention disclosure + protocol specification
**Scope note:** this document states honestly what the MVP proves and what it
does not. Sections marked **[MVP]** are in scope today; **[ROADMAP]** are
designed but not yet implemented.

---

## 1. Problem

Performance and load-test results are used as *evidence* for consequential
decisions — capacity purchases, vendor acceptance, SLA compliance, regulatory
and insurance attestations — yet the evidence itself is unverifiable.

Four distinct failure modes are routinely conflated:

1. **Unverifiable reporting.** A result is a summary (`p99 = 41 ms`, `RPS =
   52,000`) with no path to independently reproduce or audit it. The consumer of
   the report must trust the producer.
2. **Measurement that systematically flatters the system.** Coordinated
   omission (Tene, 2013): when the SUT saturates, a closed-loop generator stops
   sending, so the *slowest* requests are never sampled. Reported percentiles
   improve precisely as the system degrades.
3. **Absent provenance.** No binding between a report and *who* produced it,
   *what* was targeted, *when*, and *under what configuration*. A file is a
   file; nothing ties it to a source of truth.
4. **Undetectable fabrication.** A load generator can emit entirely synthetic
   samples. Signature schemes do not help here — signing a lie yields a
   well-signed lie.

Existing tooling addresses throughput and orchestration well, and integrity not
at all.

---

## 2. Prior art and its shortcomings

| Solution | What it does well | Where it falls short for evidentiary use |
|---|---|---|
| **k6 / k6 Cloud** (Grafana) | Excellent scripting ergonomics, thresholds-as-code, mature CI integration, cloud execution. | Results are trusted as produced. No cryptographic provenance, no third-party verification path, no tamper-evidence. Cloud runs are vendor-attested only. |
| **Locust** (open source) | Simple Python load definitions, distributed workers via `--master/--worker`, widely understood. | Reports are self-reported by the operator. No signing, no commitment scheme, no claim↔evidence recomputation. |
| **Apache JMeter / Gatling** | Deep protocol coverage and long enterprise history. | Same trust model: a JTL/HTML report is accepted at face value; no provenance or integrity envelope. |
| **BlazeMeter** (Perforce) | Managed execution, reporting, integrations; commercial support. | Verification remains vendor-internal. Consumer of a report cannot re-derive claimed statistics from raw per-request data, nor detect post-hoc edits. |
| **LoadRunner Cloud** (OpenText) | Enterprise scale, protocol breadth, ALM/reporting ecosystem. | Proprietary analysis; no portable, independently verifiable evidence artifact. High cost and lock-in. |
| **Grafana Cloud k6** | Observability-adjacent, good dashboards, TSDB integration. | Measurement and verification are the same party. No artifact a third party can validate offline. |
| **Distributed load testing in general** (master/worker fleets) | Removes single-host CPU/socket limits; realistic multi-origin load. | The aggregator *must* trust every worker's telemetry. A slow or lying worker corrupts the aggregate silently; nothing contradicts its numbers. |
| **Coordinated-omission correction** (as implemented in HdrHistogram/`wrk2`-style tools, and partly in this repo) | Corrects paced-run latency inflation. | Rarely exposed as a *verifiable* claim; typically an internal correction with no CI, no declared method, and no auditable raw stream. |

**The gap:** no mainstream tool produces a result that a *disinterested third
party* can check for integrity, provenance, and claims-consistency — and none
addresses fabrication by external corroboration.

---

## 3. Invention summary

VeriBench introduces a **measurement protocol** (`vpmp/v1`) with three pillars.
The pillars are named identically across all VeriBench documents.

| # | Pillar | Mechanism | Addresses |
|---|---|---|---|
| 1 | **Attested Measurement (VPMP v1)** | Ed25519-signed manifest bound by a Merkle root to the raw per-request sample stream; commit-then-reveal binding to run configuration | failure modes 1, 3 |
| 2 | **Honest Latency** | Coordinated-omission correction applied to the raw sample stream + bootstrap 95% confidence intervals declared in the manifest | failure mode 2 |
| 3 | **Adversarial-in-the-loop** | VeriGate adaptive difficulty used as an independent witness: the *target* counts arrivals while the generator ramps difficulty, and the two accounts must agree | failure mode 4 |

The novel object is the **measurement bundle**: a two-file, offline-verifiable
artifact whose integrity, provenance, and claimed statistics can all be
re-derived by a party that trusts neither the tool vendors nor the operator.

---

## 4. Protocol: VPMP v1 (commit → reveal → verify)

### 4.1 Roles

- **Signer / operator** — holds the Ed25519 private key; runs the measurement.
- **Verifier** — any third party; holds only the bundle and the samples file.
- **Target (witness)** — the system under test; in Pillar 3 it also emits an
  arrival count (and, in v2, per-epoch nonces).

### 4.2 Phase A — COMMIT

Performed **before** load generation begins.

1. `keygen` creates an Ed25519 keypair. The private key is written with mode
   `0600` and never leaves the operator's host. The **key identifier** is
   `key_id = SHA-256(public_key)` (hex), a 32-byte public key.
2. The run configuration is canonicalised
   (`json-sort-keys-compact-utf8`: keys sorted, no insignificant whitespace,
   UTF-8) and hashed:
   `scenario_hash = SHA-256(canonical_config)`.
3. `scenario_hash`, `target.url_origin`, `run.started_at`, the declared
   `method` block (CO on/off, percentile method, CI parameters) and the tool
   identity are fixed into the manifest. **This is the sealed envelope:** the
   operator has committed to what was tested and how, before any result exists.
4. All randomised parameters used later (bootstrap PRNG seed, bundle id
   entropy) are derived from a declared, reproducible seed so the verifier can
   re-run the same procedure.

### 4.3 Phase B — REVEAL

Performed during and after load generation.

1. Every request produces exactly one **sample** record (see §5.2). Samples are
   streamed to the samples file and never rewritten.
2. If Pillar 2 is active, the generator records, per request, the
   `co_extra_ns` — the schedule skew between the intended send time and the
   actual send time — making the correction auditable rather than a black box.
3. Merkle leaves are computed over the canonical bytes of each sample line;
   the root is `samples.merkle.root`.
4. The summary `claims` block is computed **from the same sample stream** using
   the declared method (nearest-rank percentiles over *honest* latency, i.e.
   `lat_ns + co_extra_ns`; counts and error rate over all samples).
5. The manifest is signed: `signature.value_b64 = Ed25519_sign(SK, canonical(manifest \ signature))`.
6. The bundle (`bundle.json` + `bundle.samples.jsonl`) is emitted. Nothing is
   sealed away or discarded; the reveal is complete.

### 4.4 Phase C — VERIFY

Performed by the verifier, offline, with no network access (§6).

---

## 5. Bundle scheme (`vpmp/v1`)

### 5.1 `bundle.json` (manifest)

```json
{
  "format": "vpmp/v1",
  "bundle_id": "vb-1f7c9a3d5e21",
  "created_at": "2026-10-13T10:15:04Z",
  "tool": { "name": "VeriBench", "binary": "stress-strike", "version": "0.14.3", "protocol": "vpmp/v1" },
  "signer": {
    "alg": "Ed25519",
    "key_id": "<hex SHA-256 of public key>",
    "public_key_b64": "<base64, 32 bytes>"
  },
  "target": { "url_origin": "http://127.0.0.1:8090", "tls_fingerprint": null },
  "scenario_hash": {
    "alg": "sha256",
    "value": "<hex>",
    "canonicalization": "json-sort-keys-compact-utf8"
  },
  "run": {
    "started_at": "2026-10-13T10:14:50Z",
    "ended_at": "2026-10-13T10:15:00Z",
    "duration_seconds": 10,
    "profile": "constant-rps",
    "target_rps": 1000
  },
  "method": {
    "coordinated_omission": true,
    "percentile_method": "nearest-rank",
    "latency_unit": "nanoseconds",
    "rate_unit": "milli-requests-per-second",
    "error_rate_unit": "parts-per-million",
    "percentile_unit": "parts-per-million",
    "float_encoding": "forbidden",
    "confidence_interval": {
      "method": "bootstrap",
      "level_ppm": 950000,
      "resamples": 1000,
      "seed_declared": true
    }
  },
  "claims": {
    "total_requests": 2000,
    "errors": 4,
    "error_rate_ppm": 2000,
    "rps_milli": 200000,
    "p50_ns": 3100000,
    "p95_ns": 12400000,
    "p99_ns": 41000000,
    "p99_ns_ci95": [39200000, 44100000],
    "co_corrected_samples": 37
  },
  "samples": {
    "path": "veribench-bundle.samples.jsonl",
    "count": 2000,
    "encoding": "jsonl",
    "leaf_canonicalization": "json-sort-keys-compact-utf8",
    "merkle": {
      "alg": "sha256",
      "leaf": "sha256(0x00 || be64(index) || canonical_record)",
      "node": "sha256(0x01 || left || right)",
      "padding": "repeat-last-leaf-to-power-of-two",
      "empty_root": "sha256(\"\")",
      "root": "<hex>"
    }
  },
  "signature": {
    "alg": "Ed25519",
    "value_b64": "<base64, 64 bytes>",
    "signed_payload": "manifest minus the signature object, canonicalised json-sort-keys-compact-utf8"
  },
  "extensions": { "challenge_response": null, "audit_anchor": null }
}
```

Field notes:

- **`signer.public_key_b64` is embedded.** Verification therefore needs no
  key server and no network. Trust in the key itself is out of scope for v1
  (see §7.2); v1 proves *integrity and attribution*, not *identity*.
- **`claims.p99_ns` is the CO-corrected p99** (honest latency =
  `lat_ns + co_extra_ns`), not the raw measured p99. This is declared explicitly
  by `method.coordinated_omission`. For humans this renders as
  `p99 = 41.0 ms [39.2–44.1 ms]`; on the wire it is `41000000` and
  `[39200000, 44100000]` nanoseconds, integers only.
- **Every number in the manifest is an integer.** `rps_milli: 200000` is
  200.000 req/s; `error_rate_ppm: 2000` is 0.2%. See §5.3 for why floats are
  banned.
- **`extensions`** is the reserved space for Pillar 3 evidence
  (`challenge_response`) and for transparency-log anchoring
  (`audit_anchor`). Both are `null` in the MVP.

### 5.2 `bundle.samples.jsonl` (raw evidence)

One canonical JSON object per line, in emission order:

```json
{"co_extra_ns":0,"epoch_nonce":null,"lat_ns":2984000,"ok":true,"seq":0,"status":200,"step":"quick-test","t_end_ns":1791905123456789,"t_start_ns":1791905120472789}
```

| Field | Meaning | Required in v1 |
|---|---|---|
| `seq` | 0-based, strictly increasing | yes |
| `step` | scenario step name | yes |
| `t_start_ns`, `t_end_ns` | request start/end, monotonic ns clock | yes |
| `lat_ns` | measured latency = `t_end_ns - t_start_ns` | yes |
| `co_extra_ns` | coordinated-omission schedule skew added back (0 if none) | yes |
| `status` | HTTP status (or transport error code, 0) | yes |
| `ok` | `true` if the sample counts as success | yes |
| `epoch_nonce` | target-issued per-epoch nonce (Pillar 3, v2) | reserved, `null` in v1 |

### 5.3 Canonicalisation (mandatory, normative)

Both the signing payload and Merkle leaf input use the same rule:

> `canonical(x) = json.dumps(x, sort_keys=True, separators=(",", ":"))`
> encoded as UTF-8.

The protocol deliberately uses a **restricted subset of JSON** so that
canonicalisation is unambiguous across languages and versions:

- **Object members** are emitted in ascending byte order of the key; duplicate
  keys are forbidden.
- **Arrays** preserve declared order.
- **Strings** use minimal RFC 8259 escaping (`"`, `\`, and C0 controls only);
  UTF-8, no BOM.
- **Numbers are integers only. Floats are forbidden anywhere in the protocol.**
  A `float64` has no single textual rendering — `0.1`, `0.10` and `1e-1` all
  parse to the same value but serialise differently — so a producer and a
  verifier written in different languages could disagree on the bytes that were
  signed. Integers cannot disagree. Consequently latency is carried in integer
  **nanoseconds**, percentiles and error rates in integer
  **parts-per-million**, and rates in integer **milli-units**; all units are
  declared explicitly in `method`.
- **Booleans** are `true` / `false`; `null` is permitted.
- No trailing newline is part of a leaf or of the signing payload. Newlines
  separate lines in the samples file only.

### 5.4 Merkle construction (normative)

```
LeafHash(i, record_i) = SHA-256( 0x00 || be64(i) || canonical_bytes(record_i) )
node(l, r)            = SHA-256( 0x01 || l || r )
empty leaf list       = SHA-256("")
padding               = the leaf list is padded to a power of two by repeating the last leaf
```

Three deliberate properties:

1. **Domain separators** (`0x00` leaf, `0x01` node) prevent second-preimage
   confusion between a leaf hash and an internal node hash.
2. **Leaves bind their index.** A bare leaf hash admits a well-known ambiguity:
   the three-leaf list `[a, b, c]` and the four-leaf list `[a, b, c, c]` can be
   made to collide (the same defect class as CVE-2012-2459 in Bitcoin's block
   malleability). Binding `be64(i)` into each leaf hash removes it: the padded
   duplicate of leaf 2 is hashed as index 3 and therefore differs.
3. **Power-of-two padding by repetition** makes the tree shape deterministic, so
   an independent implementation reproduces the root exactly. A verifier using a
   different padding rule (e.g. promoting odd nodes unchanged) will compute a
   different root and is non-conforming to `vpmp/v1`.

This definition is frozen and mirrors the in-repository implementation
(`internal/attest/merkle.go`); an independent verifier must match it byte for
byte.

---

## 6. Verification algorithm (normative)

Input: `bundle.json`, `bundle.samples.jsonl`. Output: `PASS` (exit 0) or
`FAIL` (exit 1), with a per-check report. All checks run offline.

1. **Format.** `manifest.format == "vpmp/v1"`. Else FAIL.
2. **Key binding.** `key_id == SHA-256(decoded public_key_b64)`. Else FAIL.
3. **Signature.** Recompute `canonical(manifest with "signature" removed)`;
   `Ed25519_verify(public_key, payload, signature.value_b64)`. Else FAIL
   (*INTEGRITY FAIL: signature*).
4. **Sample count.** Number of non-empty lines == `samples.count`. Else FAIL.
5. **Merkle root.** Recompute every leaf per §5.4 (including the index binding
   and the power-of-two padding), rebuild the tree per §5.4, compare to
   `samples.merkle.root`. Else FAIL (*INTEGRITY FAIL: merkle*).
6. **Claims recomputation.** From the sample stream, recompute using the
   declared method: `total_requests`, `errors`, `error_rate_ppm` (errors /
   total, in parts-per-million), `rps_milli` (total × 1000 /
   `run.duration_seconds`, rounded half-up), `p50_ns` / `p95_ns` / `p99_ns`
   (nearest-rank percentiles over **honest latency** `lat_ns + co_extra_ns`),
   `p99_ns_ci95` (seeded bootstrap at `method.confidence_interval.level_ppm`),
   and `co_corrected_samples` (count of `co_extra_ns > 0`). Compare to
   `claims`. **Every field is an integer and every field must match exactly** —
   there is no tolerance to argue about. Else FAIL (*CLAIM MISMATCH*).
7. **Internal consistency.** For every sample: `seq` strictly increasing from
   0; `t_end_ns >= t_start_ns`; `lat_ns == t_end_ns - t_start_ns`;
   `t_start_ns`/`t_end_ns` inside `[run.started_at, run.ended_at]` with a
   declared 2-second clock-format slack; `ok == (status < 400)`. Else FAIL
   (*CONSISTENCY FAIL*).
8. **Verdict.** All of the above pass → PASS. Any failure → FAIL, exit 1,
   naming the first failing check.

Because checks 3 and 5 are cryptographic and check 6 is arithmetic, a bundle
cannot be edited *after* signing without failing 3, and cannot have its raw
data altered without failing 5. A dishonest operator who wants to publish fake
numbers must therefore sign them at creation time — which is precisely the
attack Pillar 3 exists to detect.

---

## 7. Security analysis

### 7.1 What VPMP v1 **does** prove

- **Integrity / tamper-evidence.** Any modification to the manifest breaks
  check 3; any modification to a sample breaks check 5; any modification to
  both in a coordinated way requires the private key.
- **Attribution.** The bundle was signed by the holder of the private key whose
  fingerprint is `key_id`, embedded in the bundle.
- **Non-repudiation against the operator.** The operator cannot later disown a
  signed bundle, nor alter it, without detection.
- **Claim↔evidence binding.** The published summary numbers are *forced* to
  equal what the raw sample stream actually says. "Lying in the summary" is
  reduced to "lying in the raw data", which is a strictly harder, more
  auditable act.
- **Measurement-honesty of the reported distribution.** Because the correction
  inputs (`co_extra_ns`) are part of the signed, Merkle-locked raw stream, the
  coordinated-omission correction is auditable: a verifier sees exactly how
  much latency was added back and where. A tool that silently smooths its
  percentiles cannot produce this artifact.
- **Reproducibility of derived statistics.** The bootstrap CI and the
  percentiles are recomputable from the raw stream under a declared, seeded
  method — no black-box post-processing.

### 7.2 What VPMP v1 **does NOT** prove — stated plainly

- **It does not prove the traffic happened.** A malicious worker can fabricate
  internally-consistent samples and sign them. Checks 3 and 5 will *pass*.
  **A valid signature is not proof that packets were sent.** This is the single
  most important limitation of the MVP, stated without hedging. VPMP v1 proves
  *integrity and provenance*, not *correspondence to external reality*.
- **It does not establish the identity of the signer.** The public key is
  embedded; nothing in v1 binds it to a legal entity, a domain, or a
  certificate. Key-to-identity binding requires an external PKI/CA step, or
  key pinning by the verifier out of band.
- **It does not corroborate server-side latency.** Client-side honest latency
  and the server's own view of the same requests can differ (queuing in
  intermediate proxies, clock skew). v1 measures the client's view.
- **It does not detect host-level interference.** A throttled CPU, a shaped
  network link, or a co-tenant stealing cycles (the "noisy neighbour" problem)
  can be real and invisible to any client-side evidence.
- **It does not protect against a compromised signing host.** If the private
  key and the sample generator are both attacker-controlled, the attacker
  controls the evidence. Mitigation is a TEE/HSM key-holding design, not
  cryptography in the bundle format.
- **The confidence interval is conditional on the sample stream.** A bootstrap
  CI quantifies sampling uncertainty *given the observed samples*. It cannot
  repair a systematically wrong sampling process (that is Pillar 2's
  correction), and it is not a claim about the future.

### 7.3 Pillar 3 — what it establishes, and its own limits

VeriGate's adaptive difficulty provides an **independent witness**:

- the generator's claimed request count / arrival cadence, versus
- the target's own observed arrival count and challenge-solve rate.

Agreement across two parties with opposed interests (the party being tested has
no incentive to corroborate a fake test) is materially stronger than a
self-signed statement. It converts "we promise we sent the load" into "the
target also saw the load".

**MVP honesty:** this is *evidence-based suspicion and corroboration*, not
proof. If the attacker controls both the generator and the target (a
colluding pair), the two accounts can be fabricated together. Pillar 3 raises
the cost of the cheat and gives a verifier a second, independent signal; it
does not make fabrication mathematically impossible. The MVP does **not** fully
solve the "worker never measured anything" case — see §8.

---

## 8. Limitations and future work

| Phase | Mechanism | What it adds |
|---|---|---|
| **[MVP]** | Signed manifest + Merkle-locked samples + CO-corrected honest latency + bootstrap CI + VeriGate corroboration counters | Integrity, provenance, claim binding, honest distributions, external witness signal |
| **[ROADMAP] v1.1** | **Challenge–response corroboration.** The target (or a co-located VeriGate probe) issues an unpredictable `epoch_nonce` per epoch (e.g. per second); the generator must echo it in each sample's `epoch_nonce`. A generator that never contacted the target cannot produce the nonces, and the verifier checks the nonce chain against the target's signed epoch digest. | Upgrades "did traffic reach the target" from *unprovable* to *provable with high probability* — closes the §7.2 headline gap for non-colluding attestors. |
| **[ROADMAP] v1.2** | **Per-request unpredictable nonce** (nonce embedded in a response header the generator must record), plus a signed target-side arrival digest. Removes the epoch-window replay surface of v1.1. | Strong, per-request correspondence evidence. |
| **[ROADMAP] v2** | **Zero-knowledge distribution proof.** The generator proves the committed Merkle tree is a valid sample draw from the claimed distribution without revealing individual samples (useful when samples embed sensitive URLs/tokens, and stronger against selective disclosure). | Fabrication resistance + privacy. |
| **[ROADMAP] v2** | **TEE / HSM key custody** (SGX/SEV/TPM-backed signing, or sealed key in an HSM) + optional transparency-log anchoring of the Merkle root (RFC 6962-style append-only log). | Protects against a compromised signing host; makes back-dating detectable. |
| **Known v1 gaps** | No key-to-identity binding; no server-side corroboration; sample stream is fully disclosed (no privacy mode); single signer (no threshold/multi-sig); no replay/anchoring timestamp from a third party. | Each is an explicit, bounded v2 item. |

---

## 9. Worked example of a detection

1. Test runs; bundle emitted; `verify` → `PASS`, exit 0.
2. An attacker edits one hexadecimal character of `samples.merkle.root` in
   `bundle.json` to hide a replaced samples file.
3. `verify`: check 3 (signature over the manifest) fails immediately, because
   the signed payload includes `samples.merkle.root`. Verdict `FAIL`, exit 1,
   reported as `INTEGRITY FAIL: signature`.
4. An attacker instead edits a sample line in
   `bundle.samples.jsonl` and leaves the manifest alone: check 3 passes, but
   check 5 recomputes a different Merkle root → `INTEGRITY FAIL: merkle`.
5. To pass both, the attacker would have to re-sign. Re-signing requires the
   private key, and produces a bundle attributable to `key_id` — which is
   exactly where Pillar 3's external witness becomes the operative defense.

`scripts/demo-verified.sh` performs steps 1–3 mechanically, with color-coded
`PASS`/`FAIL` and honest exit codes.

---

## 10. Claims discipline for this document

- No absolute accuracy, revenue, or market claim is made in this file.
- Every "does not prove" statement in §7.2 is deliberate, not boilerplate:
  a verifier reading only §7.1 would over-trust the artifact.
- The three pillar names (Attested Measurement (VPMP v1), Honest Latency,
  Adversarial-in-the-loop) are canonical across `INVENTION.md`, `PITCH.md`,
  `EXPLAINER.md`, `DEMO.md`, and `ONE-PAGER.md`.
- This document describes a protocol and a partially implemented product. It is
  not a certification, an audit opinion, or a legal attestation, and it must not
  be presented as any of those.
