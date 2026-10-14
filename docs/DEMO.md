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

> **Read this before you speak.** The demo script auto-detects the binary capability:
> - **LIVE** (default on v0.14.3+): runs real traffic, seals a bundle with the real
>   CLI, verifies it.
> - **REFERENCE** (only when no binary can be found *and* Go isn't available to
>   build one): prints an explicit notice and emits a spec-conformant bundle from
>   the embedded reference implementation. **Say that out loud.** Never imply live
>   traffic was generated when it was not — the whole product is about not doing
>   that.

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

## 3. Expected output (real transcript, `NO_COLOR=1`, LIVE mode)

```
VeriBench — verifiable measurement demo
format vpmp/v1 · Ed25519 seal · Merkle-locked samples · offline verify
binary: /tmp/veribench-demo.xxx/stress-strike

── 1/5  Mode ──
LIVE — this build exposes keygen / verify / --emit-bundle.
       Running the real end-to-end contract against http://127.0.0.1:8090/health
target http://127.0.0.1:8090/health answered HTTP 200

── 2/5  keygen — create the digital seal (Ed25519) ──
keypair written to …/veribench-demo.xxx/veribench.key (private key mode 0600, unencrypted)
       public key: 63989b7e96cf7e9eb4fca66bb41ed0ec7c1dcc9bb3d88eb27e34fcb946218086
private key: …/veribench-demo.xxx/veribench.key (mode 0600) · never leaves this host
key_id (public fingerprint): 63989b7e96cf7e9eb4fca66bb41ed0ec7c1dcc9bb3d88eb27e34fcb946218086

── 3/5  run — produce the measurement bundle ──
authorization: ok (class=loopback)
WARNING: stress-strike is a load testing tool. Only run it against systems you own or
have explicit written permission to test. Unauthorized load floods are illegal (DDoS).
stress-strike v0.14.3 | target: http://127.0.0.1:8090/health | profile: steady | duration: 10s

Verifiable evidence written:
  …/veribench-bundle.json
  …/veribench-bundle.samples.jsonl
  format:        vpmp/v1 — 3300 samples, worker "Asadbeks-MacBook-Air.local-xxxxx"
  coordinator:   63989b7e96cf7e9eb4fca66bb41ed0ec7c1dcc9bb3d88eb27e34fcb946218086
  p99:           1.077ms (coordinated-omission corrected, 95% CI [0.838ms, 1.586ms])
  verify it yourself (exit 0 = valid, 1 = tampered):
    stress-strike verify --bundle …/veribench-bundle.json --samples …/veribench-bundle.samples.jsonl

── 4/5  verify — the honest bundle must PASS ──
verify …/veribench-bundle.json
  format:        vpmp/v1
  bundle digest: 26890ae2b068ead2218b61945f06c9594a8a1280c5cafa3c7245cae3097fa327
  sidecar:       …/veribench-bundle.samples.jsonl (3300 records, 1 workers)

  worker Asadbeks-MacBook-Air.local-xxxxx ok      3300 records    257 proofs

PASS — bundle is valid. 15 checks passed across 1 workers (3300 records, 257 inclusion proofs verified).
PASS  verifier accepted the bundle (exit 0)

── 5/5  tamper with ONE byte, then verify again ──
altered : …/veribench-bundle.json  (1468 bytes, sha256 61917cb66cc342dd…)
bytes differing from the original: 1
one nibble of the Merkle root changed; the samples file is untouched
veribench verify (vpmp/v1)
  [PASS] format identifier is vpmp/v1
  [PASS] key_id binds to the embedded public key
  [FAIL] Ed25519 signature over the manifest — manifest bytes do not match the signed payload
  [PASS] sample count matches the manifest
  [FAIL] Merkle root matches the recomputed tree — recomputed 045180f5c990f172… vs manifest 045180f5c990f172…
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
  intact bundle   → PASS (exit 0)   sha256 40ef3ad103deb7a8…
  one byte changed→ FAIL (exit 1)   sha256 61917cb66cc342dd…
  byte restored   → PASS (exit 0)   sha256 40ef3ad103deb7a8…
  mode            → live
```

On a build without Go available, `── 1/5 Mode ──` reads:

```
NOTE  REFERENCE mode — no stress-strike binary was found or could be built.
       Missing surface is at least one of:
         · stress-strike keygen --out <key>        [unavailable]
         · stress-strike verify --bundle …        [unavailable]
         · stress-strike run --emit-bundle <b>    [unavailable]
       The real thing ships in this repo (cmd/stress-strike): set
       STRESS_STRIKE_BIN to a built binary, or install Go so this script
       can build it itself.
       So: NO load is generated here. Instead a spec-conformant vpmp/v1
       bundle is emitted by the embedded reference implementation, and the
       VERIFICATION half of this demo runs for real.
```

…and `mode → reference` at the bottom. **Both modes are tested.**

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

## 4b. Second act (30 s) — let the judge verify it themselves

The strongest moment in the demo is the one where you stop talking. Hand over
`docs/VERIFIER.html` — a single offline file — and let the judge drive it.

1. Open `docs/VERIFIER.html` (double-clicking works; nothing is uploaded and the
   page has no network access).
2. Drop in `run.json` and `run.samples.jsonl` from the run you just sealed →
   **PASS**, with the bundle digest, 15 checks run, and the recomputed
   p50/p95/p99 plus the 95% confidence interval.
3. Change **one** byte of the JSON and drop it in again → **FAIL**, and the page
   names the failing check (`bundle-signature`, `commit-root`, …).

Say: *"That page is not our verifier. It is a second implementation of the same
published rules, written from the spec, and it agrees with the Go verifier on
every case. That is what 'anyone can verify' has to mean."*

Reproduce that claim yourself in one command:

```bash
bash scripts/verify-html-parity.sh
# ok genuine / ok tampered merkle root / ok tampered p99 claim /
# ok tampered sidecar / ok sidecar absent → the two verifiers agree
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
| `binary: not found` | Harmless — the demo falls back to reference mode. Set `STRESS_STRIKE_BIN` to probe a specific build. |
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
- "The three commands (`keygen`, `run --emit-bundle`, `verify`) ship in v0.14.3."

Do **not** say:

- "This is cryptographically impossible to fake." (False.)
- "We have customers / pilots / revenue." (No traction to date; see `PITCH.md`
  Slide 10.)
- "The protocol is specified but the CLI is in integration." (False — both ship
  in v0.14.3.)

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
  `vpmp/v1` is specified in `docs/INVENTION.md` §5–6 — and we did more than
  specify it: `docs/VERIFIER.html` is an independent JavaScript implementation,
  and `scripts/verify-html-parity.sh` asserts it reaches the same verdict as the
  Go verifier on a genuine bundle and four tampered ones.
- **"What's the business?"** Verification workflows, enterprise self-hosted, and
  certificate-as-a-service — the neutral party that issues and anchors the
  attestation. `PITCH.md` Slide 8.
