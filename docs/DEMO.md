# VeriBench — 2-Minute Demo Script

**Goal of the demo:** in 120 seconds, show that a load-test result can be
*checked* — and that tampering with it is detected, with a machine-readable exit
code.

**One sentence to land:** *"This is the difference between a report you must
trust and evidence you can verify."*

---

## 0. Pre-flight (do this 5 minutes before you present)

```bash
cd /path/to/stress-strike
bash -n scripts/demo-verified.sh     # syntax gate
chmod +x scripts/demo-verified.sh    # if needed
NO_COLOR=1 ./scripts/demo-verified.sh   # dry run: must exit 0
```

You should see `RESULT` with `intact → PASS`, `one byte changed → FAIL`,
`byte restored → PASS`.

**What the script needs:** `bash`, `perl`, and `python3` (3.8+). No network, no
credentials, no target server required. Runtime ≈ 2 seconds.

> **Read this before you speak.** On a build that predates the CLI integration,
> the script prints an explicit `NOTE REFERENCE mode …` block and emits a
> spec-conformant bundle from its embedded reference implementation. **Say that
> out loud.** Never imply live traffic was generated when it was not — the whole
> product is about not doing that.

**Terminal setup:** a font size the back row can read, no `NO_COLOR`, and a
window at least 100 columns wide. Clear the scrollback so the output starts at
the top.

---

## 1. Run sheet (2:00)

| Time | What you press | What you say | What appears on screen |
|---|---|---|---|
| 0:00 | `clear` | "Every website claim you've ever been sold looks like this." | blank terminal |
| 0:05 | Type (don't run): `stress-strike run --url … --duration 10s` | "A load test. 52,000 requests per second, p99 of 41 milliseconds. Impressive. **How would you check it?**" | the command sits there, unexecuted |
| 0:20 | `Ctrl-C` to clear the line | "You can't. You're trusting whoever produced the number. VeriBench changes that — three ideas, thirty seconds each." | — |
| 0:25 | Show `docs/EXPLAINER.md` §2 headings, or just say it | "One: a **digital seal**. Two: the raw data locked behind one fingerprint. Three: an **outside witness** that catches a fake test." | — |
| 0:40 | `./scripts/demo-verified.sh` | "One command. Watch the verdicts." | banner + `1/5 Mode` + `2/5 keygen` |
| 0:55 | *(let it run)* | "It creates a signing key, runs the test, and emits **two files**: a signed cover sheet and one line of raw evidence per request." | `3/5 run` + bundle/samples sizes and sha256 |
| 1:10 | *(let it run)* | "Now the part that matters. A third party verifies all of it — offline, trusting nobody." | `4/5` seven `[PASS]` lines + `VERDICT: PASS` |
| 1:25 | *(let it run)* | "Now I'll cheat. **One byte.**" | `bytes differing from the original: 1` |
| 1:35 | *(let it run)* | "The signature fails. The fingerprint fails. Verdict `FAIL`, exit code `1` — so your CI pipeline blocks on it." | two `[FAIL]` lines + `VERDICT: FAIL` |
| 1:50 | *(let it run)* | "Restore the byte — it's clean again. That's the whole product." | `restore the byte` + `VERDICT: PASS` + `RESULT` block |
| 2:00 | Stop | "A result you can check is a result you can use." | — |

**If you are short on time**, run the script first and talk over it — it is
self-narrating and takes 2 seconds.

---

## 2. The exact commands

```bash
# The full demo, one command:
./scripts/demo-verified.sh

# The three-command product surface it drives (the frozen contract):
stress-strike keygen --out /tmp/veribench.key
stress-strike run    --url http://127.0.0.1:8090/ --duration 10s \
                     --emit-bundle /tmp/veribench-bundle.json
stress-strike verify --bundle  /tmp/veribench-bundle.json \
                     --samples /tmp/veribench-bundle.samples.jsonl
```

Useful variations:

```bash
DEMO_COUNT=400 ./scripts/demo-verified.sh          # more samples
NO_COLOR=1 ./scripts/demo-verified.sh              # plain output (piped logs)
VERIBENCH_KEEP=1 ./scripts/demo-verified.sh        # keep the temp bundle to inspect
STRESS_STRIKE_BIN=/usr/local/bin/stress-strike ./scripts/demo-verified.sh
```

---

## 3. Expected output (real transcript, `NO_COLOR=1`)

```
VeriBench — verifiable measurement demo
format vpmp/v1 · Ed25519 seal · Merkle-locked samples · offline verify
binary: ./stress-strike

── 1/5  Mode ──
NOTE  REFERENCE mode — this build does not yet expose the full frozen contract.
       Missing surface is at least one of:
         · stress-strike keygen --out <key>        [not in this build]
         · stress-strike verify --bundle …        [not in this build]
         · stress-strike run --emit-bundle <b>    [not in this build]
       These are specified in docs/INVENTION.md and are in integration.
       So: NO load is generated here. Instead a spec-conformant vpmp/v1
       bundle is emitted by the embedded reference implementation, and the
       VERIFICATION half of this demo runs for real.

── 2/5  keygen — create the digital seal (Ed25519) ──
b0ba50fdbda647354c52ba8bb276648eba931e1c27bcaae5f64a4510812fcdfb
private key: …/veribench-demo.SSVD8y/veribench.key (mode 0600) · never leaves this host
key_id (public fingerprint): b0ba50fdbda647354c52ba8bb276648eba931e1c27bcaae5f64a4510812fcdfb

── 3/5  run — produce the measurement bundle ──
(reference bundle: 1500 samples, synthetic — no traffic was sent)
bundle  : …/veribench-bundle.json  (1671 bytes, sha256 7dc01993bbe372c1…)
samples : …/veribench-bundle.samples.jsonl  (1500 lines, sha256 545620e1141bf049…)

── 4/5  verify — the honest bundle must PASS ──
veribench verify (vpmp/v1)
  [PASS] format identifier is vpmp/v1
  [PASS] key_id binds to the embedded public key
  [PASS] Ed25519 signature over the manifest
  [PASS] sample count matches the manifest
  [PASS] Merkle root matches the recomputed tree
  [PASS] claims match the recomputed statistics
  [PASS] per-sample internal consistency
VERDICT: PASS
PASS  verifier accepted the bundle (exit 0)

── 5/5  tamper with ONE byte, then verify again ──
altered : …/veribench-bundle.json  (1671 bytes, sha256 3f762963ed2cacc9…)
bytes differing from the original: 1
one nibble of samples.merkle.root changed; the samples file is untouched
veribench verify (vpmp/v1)
  [PASS] format identifier is vpmp/v1
  [PASS] key_id binds to the embedded public key
  [FAIL] Ed25519 signature over the manifest — manifest bytes do not match the signed payload
  [PASS] sample count matches the manifest
  [FAIL] Merkle root matches the recomputed tree — recomputed 3358d1751d1f8b17… vs manifest 0358d1751d1f8b17…
  [PASS] claims match the recomputed statistics
  [PASS] per-sample internal consistency
VERDICT: FAIL — 2 check(s) failed
PASS  tampering detected — verifier refused the bundle (exit 1)

restore the byte and re-verify
veribench verify (vpmp/v1)
  … all seven checks [PASS] …
VERDICT: PASS
PASS  restored bundle verifies again (exit 0)

RESULT
  intact bundle   → PASS (exit 0)   sha256 7dc01993bbe372c1…
  one byte changed→ FAIL (exit 1)   sha256 3f762963ed2cacc9…
  byte restored   → PASS (exit 0)   sha256 7dc01993bbe372c1…
  mode            → reference
```

On a build that exposes the contract, `── 1/5 Mode ──` instead reads:

```
LIVE — this build exposes keygen / verify / --emit-bundle.
       Running the real end-to-end contract against http://127.0.0.1:8090/
```

…and `mode → live` at the bottom. **Both modes are tested.**

---

## 4. What the script guarantees you can point at

| On-screen line | What it proves |
|---|---|
| `bytes differing from the original: 1` | The tamper is *exactly one byte* — not a crude wholesale edit. |
| `sha256 7dc01993…` before / `sha256 3f762963…` after | The files really differ; the hashes are recomputable by anyone. |
| `[FAIL] Ed25519 signature over the manifest` | Cryptographic attribution works: the manifest cannot be edited after signing. |
| `[FAIL] Merkle root matches the recomputed tree` | The raw request stream is locked behind one fingerprint. |
| `exit 1` | It is gate-able: a CI job fails the build on a bad bundle. |
| `VERDICT: PASS` (third time) | The check is deterministic — restoration restores the verdict. |
| `mode → reference` / `live` | The script never pretends a missing feature exists. |

**Bonus check to run live if asked** — tamper with the *samples* file instead:

```bash
VERIBENCH_KEEP=1 ./scripts/demo-verified.sh
# then edit one sample line and re-verify: Merkle root FAILs and
# "per-sample internal consistency" FAILs too (lat_ns != t_end_ns - t_start_ns).
```

---

## 5. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `FAIL verifier rejected an intact bundle` | Something is genuinely wrong — **do not present this**. Capture the output and file it; it is a real bug, not a demo glitch. |
| `bad TAMPERING WAS NOT DETECTED` | Same: a real integrity failure. Stop and investigate. |
| `python3 is required in REFERENCE mode` | Install `python3` (3.8+). |
| `perl is required to flip the demo byte` | Install `perl`; the flip is deliberately one byte via `perl`. |
| No colour in the output | Terminal is not a TTY, or `NO_COLOR` is set. Expected when piping to a file. |
| `binary: not found` | Harmless — the demo runs in reference mode. Set `STRESS_STRIKE_BIN` to probe a specific build. |
| `run: --emit-bundle is required` | A partially-integrated build detected `emit-bundle` in help but rejects it; set `STRESS_STRIKE_BIN` to a build without it, or finish the integration. |
| Run takes noticeably longer | `DEMO_COUNT` is large; the bootstrap CI does 1000 resamples. Use `DEMO_COUNT=400` for a snappier demo. |

---

## 6. Honesty guardrails — say these, don't say the opposite

Do say:

- "In reference mode, no load was generated — the verification is real, the
  traffic is not."
- "The signature proves *integrity and attribution*. It does **not** prove the
  packets were sent. That is Pillar 3, and it is a roadmap item — stated plainly
  in `docs/INVENTION.md` §7.2."
- "We are not claiming fabrication is solved. A colluding generator and target
  can fabricate together."
- "The market numbers in the pitch are labelled `ESTIMATE` and must be re-verified."

Do **not** say:

- "This is cryptographically impossible to fake." (False.)
- "We have customers / pilots / revenue." (No traction to date; see `PITCH.md`
  Slide 10.)
- "The three commands ship in v0.14.3." (The protocol is specified; the CLI
  surface is in integration.)

---

## 7. Q&A one-liners

- **"Why not just use k6?"** k6 is an excellent generator. This is not a
  generator race; it is about the *evidence layer* — and `verify` is designed to
  sit beside whatever generator you already run.
- **"Is this blockchain?"** No. A Merkle tree plus a signature plus, later, an
  append-only transparency log — no consensus, no tokens, no chain.
- **"What stops a lying worker?"** Nothing in the MVP, and we say so. Pillar 3's
  external witness raises the cost; per-request nonces (v1.2) close it for
  non-colluding attestors.
- **"Can a verifier recompute without our tool?"** Yes — that is the point of
  publishing the canonicalisation, Merkle, percentile, and bootstrap rules.
  `vpmp/v1` is specified in `docs/INVENTION.md` §5–6.
- **"What's the business?"** Verification workflows, enterprise self-hosted, and
  certificate-as-a-service — the neutral party that issues and anchors the
  attestation. `PITCH.md` Slide 8.
