# VeriBench — Explained for Everyone

> **No programming background required.** Every technical term is explained the
> moment it appears. If you can read a receipt, you can read this page.

---

## 1. The problem in one paragraph

When someone says *"our website handled 50,000 requests per second with a
99th-percentile latency of 40 milliseconds"*, how do you know that is true?

The usual answer is: **you don't.** You are trusting a report produced by a
tool you often don't control, run by a person or a vendor who has an incentive
to look good. There is no way to check the numbers. There is no way to check
that the test actually happened at all. A slide full of impressive graphs is
just a slide full of impressive graphs.

This matters because real money and real decisions ride on those numbers:
a company buys more servers, a client renews a contract, a regulator asks for
evidence, an insurer prices a risk.

**VeriBench makes load-test results checkable by a third party** — a client, an
auditor, a judge — without having to trust either the tool or the person who
ran it.

---

## 2. Three analogies that carry the whole idea

### 2.1 The sealed envelope (commit-then-reveal)

Imagine you want to prove you predicted the result of a coin toss *before* the
coin was tossed — without telling anyone your prediction early.

You write the prediction on a card, **seal it in an envelope**, and hand the
envelope to a judge. The toss happens. You open the envelope. The judge sees
that the card matches the result, and that the envelope was sealed the whole
time, so you couldn't have written the card after the toss.

The trick is the order of operations: **lock it first, reveal it later.**
Cryptographers call this **commit-then-reveal**. VeriBench uses exactly this
shape: at the start of a test the tool *commits* to a secret (publishes only a
fingerprint of it), and at the end it *reveals* the secret. If the revealed
secret doesn't produce the committed fingerprint, something was swapped.

### 2.2 The fingerprint tree (Merkle tree)

You have 2,000 photographs and you want to prove none of them was altered —
but you can't put 2,000 photos on a single sheet of paper.

Solution: fingerprint each photo. Then fingerprint each *pair* of fingerprints.
Then fingerprint each pair of *those*, and so on, like a knockout tournament,
until only one fingerprint remains. Write that single final fingerprint on the
sheet of paper.

Now anyone can check any single photo: recompute it, walk it back up the tree,
and confirm it lands on the same final fingerprint. **Change one pixel in one
photo and the final fingerprint changes completely.** So one short line of text
secures 2,000 photos at once.

This structure is called a **Merkle tree**, after Ralph Merkle. VeriBench uses
it on the individual measurements (one per request) so that the thousands of
underlying numbers are locked behind one short fingerprint. Each fingerprint also
records the photo's *position* in the pile, so nobody can silently reorder or
duplicate one — a subtle trick that would otherwise let two different piles
produce the same final fingerprint.

### 2.3 The digital seal (Ed25519 signature)

A wax seal proved a letter came from a particular office, because only that
office had the seal.

The digital version is a **signature**: you hold a **private key** (kept secret,
like the wax stamp) and publish the matching **public key** (the impression
everyone can recognise). Anyone can use the public key to check that a document
was signed by the private key — and that not one character has changed since.

**Ed25519** is simply the modern, fast, widely trusted standard for doing this.
VeriBench's key generation command is `stress-strike keygen` — it creates your
private key. That is your stamp. VeriBench never sends it anywhere.

---

## 3. What VeriBench actually produces

One test run produces a **bundled evidence pack** (a *bundle*) made of two files:

| File | Plain-English meaning |
|---|---|
| `bundle.json` | The **cover sheet**: who signed it, which target was tested, what the summary numbers are claimed to be, and the final fingerprint of all the raw data. |
| `bundle.samples.jsonl` | The **receipt roll**: one line per request — when it started, when it finished, how long it took, and what status code came back. |

The cover sheet is signed with the digital seal. The receipt roll is locked
behind the fingerprint tree. They are tied together: the cover sheet says
*"the fingerprint of the receipt roll is X"*.

Because of that tie, there is exactly one honest combination of the two files,
and it cannot be edited afterwards without detection.

---

## 4. The three pillars (what each one buys you)

VeriBench stands on three ideas. They are named exactly like this everywhere in
our documents.

### Pillar 1 — Attested Measurement (VPMP v1)

**VPMP** stands for *Verifiable Performance Measurement Protocol*. `v1` is the
version — together they form the format identifier **`vpmp/v1`**, which is
printed in every bundle so a verifier knows what it is reading. "Attested" means
*backed by cryptographic evidence*, not by promises.

This pillar is the sealed envelope + the fingerprint tree + the digital seal
working together. It makes a result:

- **Tamper-evident** — change any single byte and verification fails.
- **Attributable** — you know exactly which key produced it.
- **Recomputable** — the summary numbers must match the raw receipt roll.

### Pillar 2 — Honest Latency (coordinated-omission correction + 95% CI)

This one fixes a subtle lie that almost every load-testing tool tells.

Imagine a restaurant with a 30-minute wait. A customer is told there's no wait,
walks in, and is served in 30 minutes. Now imagine the restaurant *stops
counting* anyone who would have to wait more than a minute — it just tells them
to come back later. Suddenly the "average wait" looks wonderful. Nothing
improved; the slow cases were simply deleted from the statistics.

That is **coordinated omission**, a well-known measurement bug described by
Gil Tene. In software terms: when the server slows down, the test tool also has
to slow down (it's waiting), so it *stops sending* requests, and the slow
requests are never recorded. The resulting latency numbers are flattering and
wrong.

Correction: when a request was *supposed* to be sent at time T but was actually
sent later, we add the hidden waiting time back into that request's latency.
VeriBench reports this corrected latency as the **honest latency**.

Because a single number hides how sure we are, VeriBench also reports a **95%
confidence interval** — a range that the true value is very likely to fall
inside, computed by re-sampling the raw data many times (a *bootstrap*). A
result is `p99 = 41 ms [39–44 ms]`, not just `p99 = 41 ms`. The raw per-request
receipt roll is what makes this possible — you cannot compute a confidence
interval from a summary someone handed you.

### Pillar 3 — Adversarial-in-the-loop (VeriGate adaptive difficulty)

The first two pillars stop *dishonest editing*. This third pillar goes after a
harder cheat: **a worker that never measured anything at all**, but fabricates
plausible-looking numbers.

VeriBench turns protection into a detector. Its **VeriGate** layer
(already part of the product) raises the bar for traffic as it ramps: it can
serve a small puzzle each client must solve, and it counts every real visitor
that arrives.

So during a measurement run, VeriGate deliberately makes the target harder
("adaptive difficulty") and then compares two independent counters:

- what the load generator *claims* it sent, and
- what the target *actually saw* arrive.

If the generator reports 200,000 requests and the target only ever observed 300,
the claim is disproven by an **outside witness** — the target itself. VeriBench
never has to trust the worker's word; it corroborates against the thing being
tested, which has no reason to cooperate with a fake test.

> **Honest boundary:** this pillar catches many fabrications, but in the current
> MVP it is *evidence-based suspicion*, not *mathematical proof*. See
> `docs/INVENTION.md` §7 for exactly what it does and does not establish.

---

## 5. Why anyone should care

| Who you are | What VeriBench gives you |
|---|---|
| **Client / buyer** | You can independently check the performance claim in a vendor's report instead of taking it on faith. |
| **Vendor / agency** | You can *prove* your numbers, so honest work stops losing to inflated work. |
| **Auditor / regulator** | A machine-checkable artifact for a claim that previously had none. |
| **Engineer** | A measurement that doesn't silently flatter the system (honest latency + confidence intervals). |
| **Insurer / investor** | Numbers with a provenance trail and a named signer, not an unattributed chart. |

---

## 6. The three-step demo

Everything above reduces to three commands. This is the whole product.

```bash
# Step 1 — make your digital seal (once).
stress-strike keygen --out /tmp/veribench.key

# Step 2 — run a test and emit the evidence pack.
stress-strike run --url http://127.0.0.1:8090/ --duration 10s \
  --emit-bundle /tmp/veribench-bundle.json

# Step 3 — let anyone verify the pack, including you.
stress-strike verify \
  --bundle  /tmp/veribench-bundle.json \
  --samples /tmp/veribench-bundle.samples.jsonl
```

**What step 3 does, visibly:** it replays every check from scratch — reseal the
envelope, rebuild the fingerprint tree, check the signature, recompute the
summary numbers from the raw receipt roll. If everything matches it prints
`PASS` and exits with code `0`. If a single byte was altered it prints `FAIL`
and exits with code `1`, so a CI pipeline can block on it.

**What happens when you cheat deliberately:** the demo script
`scripts/demo-verified.sh` proves the detection is real, not decorative. It
shows `PASS`, then edits **one byte** of the bundle, then shows the verifier
refusing it with exit code `1`, then restores the file and shows `PASS` again.

> If your installed build predates the integration of these three commands, the
> script says so plainly and runs the same demo against a reference-generated
> bundle instead. It never pretends a feature exists when it doesn't.

---

## 6b. Checking it yourself — no trust, no tools, no internet

Here is the part that surprises people. To check a VeriBench pack you do **not**
need our software, an account, or an internet connection.

`docs/VERIFIER.html` is a single web page. Double-click it and it opens in your
browser like any other file. Then drag in the two files from your test:

- `veribench-bundle.json` — the sealed report
- `veribench-bundle.samples.jsonl` — the raw receipt roll

The page does the whole job in front of you, inside the browser, with nothing
sent anywhere. It recomputes the fingerprint, checks the digital seal, re-derives
the latency numbers and their confidence interval from the raw receipts, and
checks every single receipt against the fingerprint tree. You get either a green
**PASS** or a red **FAIL** — and on a FAIL it names the exact check that broke,
in plain words, so you are never left guessing which part was tampered with.

**Why the page matters more than the tool.** Anyone can write a program that says
"trust me, it's valid." This page is a *second, independent* implementation of
the same written rules, written separately, in a different language. And
`scripts/verify-html-parity.sh` proves, case by case, that it reaches the same
verdict as the Go verifier — on a genuine pack and on four tampered ones. Two
implementations agreeing is what "anyone can verify" has to mean; one
implementation agreeing with itself means nothing.

> If the page ever says it cannot check the signature, your browser is blocking
> that feature for files opened directly from disk. Serve the folder with any
> local web server and open the page over `http://localhost` — still no internet
> needed.

---

## 7. One-sentence summary

**VeriBench turns a load-test report from a claim you must trust into evidence
you can check.**
