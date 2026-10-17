# stress-strike — Presentation & Pitch Guide

**Event:** "Ixtirochilikka qadam" olympiad
**Subject:** stress-strike — a load-testing platform that grew a *consent-gated
security-scan control plane*
**Companion document:** `demo_script.md` (the press-by-press run sheet)

> **The thesis in one line:**
> *"Most security scanners optimise for the number of findings. We optimised for
> whether you can trust the list — every probe is scope-gated, every offensive
> action is consent-gated, and a category we could not test says NOT TESTED, not
> PASS."*

---

## 1. The 3-minute demo flow (what to show, in order)

Three minutes is short. Show **three things**, tell **one story**, and let the
audit log close it. Keep the terminal font large and the browser window ≥ 100
columns.

| Time | On screen | What you do | What you say (short) |
|---|---|---|---|
| **0:00–0:20** | Dashboard open, target running | Point at the panel list: OWASP, Pentest, Crawl, Fuzzer, JWT, WebSocket… | *"One dashboard, eleven security tools. But the interesting part is not the tools — it is the gate in front of them."* |
| **0:20–0:50** | Terminal | Run the **crawl** command (Step 1) | *"A crawler discovers 22 endpoints. Look at `scope`: `127.0.0.1` only. Off-site links are never followed."* |
| **0:50–1:30** | Terminal | Run the **passive OWASP** scan (Step 2) | *"Passive OWASP Top 10. Score B. But look at A03, A05, A07, A10 — **NOT TESTED**. Not PASS. We did not reach those probes, so we refuse to grade them. Coverage, not confidence."* |
| **1:30–2:10** | Terminal | Run **pentest** with no ticket → 403. Then `authorize add`, rerun with the ticket (Steps 3–4) | *"Offensive scan. No ticket: refused, 403, nothing sent. A human approves a ticket. Same request — now it finds SQL injection and command injection. The only thing that changed is consent."* |
| **2:10–2:40** | Terminal, second pane | `tail -3 audit.jsonl`, point at `prev_hash` × `hash` (Step 7) | *"Every decision — allowed or denied — is in a hash-chained log. Delete one line and the chain breaks. That is the trust story."* |
| **2:40–3:00** | Browser | Scroll to a findings list; mention it renders with `textContent` | *"Findings come from the target, so they are never injected as HTML. A hostile server cannot script the analyst."* |

**If you only have 60 seconds:** Steps 2 (NOT TESTED) → 3+4 (403 → ticket →
findings) → 7 (audit chain). Those three carry the whole pitch.

**Do not touch in the demo:** the **Dir bust** and **GraphQL** buttons, and
**Port scanner** / **SSL** results — see `demo_script.md` §7. One of them will
crash the dashboard.

---

## 2. Key talking points — what makes this innovative

### 2.1 Coverage honesty (the headline differentiator)

Most scanners print a verdict per category. If a probe failed, timed out, or was
never run, the category often still reads "PASS" or "no issues found" — which the
reader interprets as "tested and clean". stress-strike does the opposite:

- A category with **zero coverage is `NOT TESTED`**, and `NOT TESTED` is **not**
  a pass (`internal/dashboard/owasp.go:144-167`).
- Merging verdicts across paths can only **hold or downgrade** a verdict —
  never upgrade (`owaspWorstStatus`).
- An unrecognised verdict string is **not** silently treated as PASS.

**Line to land:** *"A scanner that says PASS when it tested nothing is worse than
no scanner. Ours can only be pessimistic, never optimistic."*

### 2.2 Consent gate on offensive actions

- Information gathering (crawl, fuzz, subdomain, portscan, SSL) is `OpScan`:
  allowed on public/loopback by default, but still scope-limited.
- **Offensive** scanning (pentest, intrusive probe families) requires an
  **approval entry AND the caller naming its ticket** (`owaspGate`,
  `internal/dashboard/owasp.go:389-448`). Neither alone is enough.
- The **browser is not a back door**: the dashboard runs the *same* gate as the
  CLI, before any packet leaves.

**Line to land:** *"You cannot scan offensively by accident — and you cannot scan
offensively by clicking a button someone else made look safe. Consent is a
separate, named, auditable act."*

### 2.3 Scope gate on every probe

- The scope defaults to **the host you typed** and nothing else.
- Off-site links are not followed; redirect hops are pinned to the original host.
- Dangerous classes are refused outright: cloud **metadata** (the
  credential-theft path), link-local, multicast, CGNAT, RFC1918 private (unless
  explicitly authorized).

**Line to land:** *"A scanner that wanders the internet is a liability. Ours only
touches what you named."*

### 2.4 Shared, hash-chained audit trail

- One append-only JSONL for the CLI **and** the web UI; entries are linked by
  `prev_hash` → `hash`, so removal or edits are detectable.
- Denied decisions are logged too, with the reason.

**Line to land:** *"The consent trail is shared by every entry point. Web-triggered
scans show up in `stress-strike audit` right next to shell ones."*

### 2.5 Output-side safety (XSS)

- Findings (titles, evidence) come **from the scanned target** — attacker-
  controlled by definition.
- The dashboard renders them with `textContent` only, never `innerHTML`
  (`internal/dashboard/app.js:1298`, `:1508`).

**Line to land:** *"The scanner that finds XSS is itself immune to XSS in its own
report — by construction."*

### 2.6 Engineered not to hang or DoS

- A single-scan **semaphore**: concurrent clicks get `HTTP 409`, so a browser
  cannot pin host resources.
- `budget`/`rate`/`timeout` are capped and refused (not silently clamped) so
  `budget/rate ≤ 120 s`.
- CSRF guard: cross-origin POSTs are refused; WebSocket read limits and an idle
  watchdog bound sockets.

### 2.7 Breadth with one mental model

Eleven tools (OWASP, pentest, crawl, fuzz, subdomain, portscan, dirbust, SSL,
JWT, GraphQL, WebSocket) sit behind **one** gate/scope/audit model. A security
team learns the rules once.

---

## 3. Anticipated Q&A

Prepare these answers; the jury will pick from them.

**Q: Isn't this just a wrapper around existing tools?**
> The scanners are ours (crawl, fuzz, OWASP checks, intrusive probes). The
> novelty is the *control plane*: the same authorization gate, scope allow-list
> and tamper-evident audit trail for CLI and web, and the coverage-honesty rule.
> The dashboard is not a UI bolted onto a scanner — it is the same gate with a
> different front door.

**Q: What stops someone scanning a site they don't own?**
> Two gates. First, scope: only the host you typed is contacted — off-site links
> and redirects are refused. Second, consent: offensive scans require an
> approval entry plus the exact ticket name; that decision is written to a
> hash-chained log. And on the dashboard, running on a non-loopback address
> without a token is refused outright.

**Q: "NOT TESTED" looks like a weakness — why show it?**
> It is the point. The failure mode we are eliminating is *false confidence*: a
> report that reads "A03 Injection — PASS" when no injection probe ever ran. We
> would rather hand the reader a smaller, true list than a bigger, flattering
> one. It also makes the tool's own limits auditable.

**Q: Is the result reproducible / can I verify it?**
> Yes. The companion invention in this codebase is VeriBench — a verifiable
> measurement protocol (`vpmp/v1`) that seals a load-test bundle and lets a third
> party recompute the claimed statistics. The security scans feed the same
> provenance philosophy; see `docs/INVENTION.md` and `docs/VERIGATE.md`.

**Q: What about performance / does scanning block the load tester?**
> The web scans run under their own semaphore with hard budget/timeout caps so
> a click cannot hold a goroutine for minutes. Load generation is a separate
> engine; the scan control plane is deliberately conservative.

**Q: Are the intrusive probes safe / non-destructive?**
> They are proportional and reversible by design: boolean/time SQLi use
> comparison pairs, path traversal uses read-only traversals, and write-method
> probes target a **random, provably-writable** path so a `PUT`/`DELETE` tells
> you whether the server accepts it without damaging real content. Nothing runs
> without an explicit ticket.

**Q: Why not require auth on the dashboard by default?**
> Loopback is treated as the trusted default (a local analyst). The moment you
> bind a non-loopback address, the server refuses to start without
> `-auth-token`/`-auth-api-key` — or an explicit `-insecure` acknowledgement.
> Secure-by-default where it matters, friction-free where it does not.

**Q: How do you know the findings are real?**
> Findings carry the parameter, the evidence, a confidence level and a CWE; the
> UI shows all of them. In the demo, the SQLi/command-injection findings come
> from a known-vulnerable target. And because a finding whose probe never ran is
> `NOT TESTED`, the report never over-claims.

**Q: Does it work offline?**
> The core demo (crawl, OWASP, pentest, fuzz, JWT, WebSocket) is entirely
> loopback and needs no network. Only subdomain enumeration (crt.sh) and scanning
> public hosts need egress.

**Q: What is the biggest thing left to fix?**
> (Be honest — this turns a bug into a maturity signal.) "While verifying, we
> found four endpoints that are wired but broken: two panic on a nil gate handle
> — one of which takes the process down — and two pass the full URL where the
> scanner expects a bare host, so they return false negatives. They are
> documented in `demo_script.md` §7 with root cause and fix. Finding them is
> exactly what our QA step is for."

**Q: What's next?**
> Turn the top three defects into regression tests, add a panic-recovery
> middleware as a backstop, and extend the coverage-honesty rule to the port/SSL
> tools so a "lookup failed" never reads as "no findings".

---

## 4. Slide visuals (what to put on each slide)

Keep slides sparse: one idea, one image, ≤ 12 words of text. Below is the
visual description for each.

### Slide 1 — Title
- **Background:** near-black.
- **Image:** the dashboard in the centre, dimmed; a single green padlock glyph
  over the OWASP/Pentest panels.
- **Text:** `stress-strike` / *"Security testing you can trust — and audit."*
- **Speaker note:** state the one-line thesis.

### Slide 2 — The problem
- **Visual:** two report cards side by side.
  - Left card (red): "A03 Injection — **PASS**" with a tiny footnote "(no probe
    run)". Caption: *"False confidence."*
  - Right card (green): "A03 Injection — **NOT TESTED**". Caption: *"Honest."*
- **Text:** *"PASS when nothing was tested is the bug."*

### Slide 3 — Three gates
- **Visual:** a horizontal pipeline diagram:
  `Request → [ SCOPE GATE ] → [ CONSENT GATE ] → [ AUDIT LOG ] → Scan`.
  Icons: a fence (scope), a signature (consent), a chain of blocks (audit).
- **Text:** *"Scope. Consent. Trail."*

### Slide 4 — Consent in action (screenshot pair)
- **Visual:** two terminal screenshots stacked.
  - Top: the 403 JSON `{"denied":true,"reason":"...requires an authorization ticket..."}`.
  - Bottom: the same request with `"authorized":"DEMO-2026"` returning findings
    (SQLi, command injection).
- **Text:** *"The only thing that changed is consent."*

### Slide 5 — Coverage honesty
- **Visual:** the OWASP category table as a screenshot, with the four
  `NOT TESTED` rows outlined in amber; a callout arrow to A10.
- **Text:** *"We report what we tested — not what we hoped."*

### Slide 6 — The audit chain
- **Visual:** three JSON log entries as linked blocks; draw arrows from each
  `hash` to the next `prev_hash`. One block crossed out and the chain turning
  red with a "TAMPER DETECTED" stamp.
- **Text:** *"Tamper-evident by construction."*

### Slide 7 — Output-side safety
- **Visual:** a browser rendering a findings list where a finding title reads
  `<script>alert(1)</script>` **as literal text** (because it is `textContent`),
  next to a code snippet `title.textContent = f.title`.
- **Text:** *"Finds XSS. Immune to XSS."*

### Slide 8 — Breadth behind one model
- **Visual:** a honeycomb of eleven tool tiles (OWASP, Pentest, Crawl, Fuzz,
  Subdomain, Port, Dirbust, SSL, JWT, GraphQL, WS) all sitting on a single
  horizontal bar labelled "one gate · one scope · one audit log".
- **Text:** *"Eleven tools. One contract."*

### Slide 9 — Honest status / roadmap
- **Visual:** a traffic-light table — 7 green (working), 2 amber (false
  negatives), 2 red (panic) — matching `demo_script.md` §7, with "found by QA,
  documented, fix scoped" as the caption.
- **Text:** *"We test our own claims."*
- **Speaker note:** this slide is a *strength*. Volunteering your own defects,
  with root cause and a fix, signals engineering maturity.

### Slide 10 — Close
- **Visual:** the dashboard full-width; the audit log scrolling in a side pane.
- **Text:** *"Finds the flaws. Keeps the receipts."* + repo URL + version.

---

## 5. Optional: Uzbek key phrases (for the presenter)

The audience is Uzbek-speaking; these are ready-made lines. Keep them short.

- **Opening:** *"Bu shunchaki skaner emas — bu ishonch tizimi. Har bir tekshiruv
  ruxsat darvozasidan o'tadi va audit jurnaliga yoziladi."*
- **Scope gate:** *"Faqat siz kiritgan hostga tegadi. Boshqa hech qayerga
  chiqmaydi."*
- **NOT TESTED:** *"Sinab ko'rilmagan kategoriya **PASS** emas — **NOT TESTED**.
  Ya'ni 'tekshirilmadi', 'toza' degani emas."*
- **Consent:** *"Hujumkor skan uchun chipta kerak. Chiptasiz — 403, hech narsa
  yuborilmaydi."*
- **XSS safety:** *"Topilmalar nishondan keladi, shuning uchun ular HTML sifatida
  joylanmaydi — faqat matn. XSS topadigan vosita o'zi XSS'ga chidamli."*
- **Audit:** *"Har bir qaror hash-zanjirli jurnalda. Bitta qatorni o'chirsangiz,
  zanjir uziladi."*
- **Closing:** *"Kamchiliklarni topadi. Dalillarni saqlaydi."*

---

## 6. Logistics checklist

- [ ] `bin/stress-strike-dashboard` and `bin/stress-strike` built (`make build`).
- [ ] Demo target running on `127.0.0.1:8090`.
- [ ] Dashboard running on `127.0.0.1:8888`; browser open and scrolled to top.
- [ ] Terminal: large font, wide window, scrollback cleared, `NO_COLOR` off.
- [ ] The pentest ticket (`DEMO-2026`) **not** pre-added (so the 403 lands), but
      the `authorize add` command is one paste away.
- [ ] `demo_script.md` §7 open in a second window in case the jury asks about the
      known-broken endpoints.
- [ ] A second terminal pane parked at the audit-log directory for Step 7.
- [ ] Backup: screenshots of Steps 2, 3, 4 and 7 in case of a live glitch.
