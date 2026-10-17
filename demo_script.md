# stress-strike — Live Demo Script (Security Scan Control Plane)

**For:** "Ixtirochilikka qadam" olympiad
**Audience:** jury / judges
**Presenter:** the person at the keyboard
**Version checked:** `stress-strike v0.14.3` (must match `./VERSION`)

> **One sentence to land the demo:**
> *"Every scan in this dashboard goes through the same authorization gate, the
> same scope allow-list and the same hash-chained audit log as the CLI — the
> browser is not a back door."*

This script is a **press-by-press run sheet**. Everything below has been run
against the real code and the real outputs are quoted verbatim.

---

## 0. Pre-flight (do this 5 minutes before you present)

### 0.1 Requirements

| Tool | Why | Check |
|---|---|---|
| Go 1.26+ | build the binaries | `go version` |
| `curl` | drive the JSON API from a terminal | `curl --version` |
| A browser | show the UI | any modern browser |
| Free TCP ports **8888** (dashboard) and **8090** (demo target) | the demo needs two servers | `lsof -nP -iTCP:8888 -sTCP:LISTEN` (empty = free) |

Network is **not** required for the core demo — everything is scannable on
loopback.

### 0.2 Build (once)

```bash
cd /path/to/stress-strike
make build          # builds ./bin/stress-strike-dashboard and friends
# or, minimal:
go build -o bin/stress-strike-dashboard ./cmd/stress-strike-dashboard
go build -o bin/stress-strike            ./cmd/stress-strike
```

Confirm the artifact exists:

```bash
ls -la bin/stress-strike-dashboard
```

### 0.3 Start the scannable target (the VoltStore demo)

Two options — **pick one**:

**(A) From the shell** (recommended, deterministic):

```bash
go run ./examples/demo_store -addr 127.0.0.1:8090 &      # unprotected: finds the most
# or: go run ./examples/demo_store -addr 127.0.0.1:8090 -protect   # VeriGate ON
sleep 5
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8090/   # expect 200
```

**(B) One click in the dashboard** — the dashboard ships a launcher for the
same store (VeriGate ON). Covered in Step 1 below.

> The VoltStore demo is a small e-commerce app with a search box, a login form,
> a `/product/{id}` route, an `/admin` page and intentionally weak spots. It is
> what makes the intrusive scan produce *real* findings instead of an empty
> report.

### 0.4 Start the dashboard

```bash
./bin/stress-strike-dashboard -listen 127.0.0.1:8888
```

Expected banner:

```
╔═══════════════════════════════════════════════════════════════╗
║  stress-strike dashboard — real-time load telemetry             ║
╚═══════════════════════════════════════════════════════════════╝
  Dashboard: http://127.0.0.1:8888
```

Open **http://127.0.0.1:8888** in the browser.

> **Loopback is the safe default.** The dashboard *refuses to start* on a
> non-loopback address without `-auth-token`/`-auth-api-key` (or an explicit
> `-insecure` acknowledgement). If your demo box needs `0.0.0.0`, pass a token
> — see Troubleshooting §8.

### 0.5 (Optional) Prepare the pentest authorization ticket

Intrusive pentest **always** requires an approved ticket. Create one for the
loopback target before you present (do it once, before the jury sits down):

```bash
./bin/stress-strike authorize add \
  --pattern 127.0.0.1 \
  --approver "olympiad-jury" \
  --ticket "DEMO-2026" \
  --reason "olympiad demo on loopback target"
# → added authorization: 127.0.0.1 ticket=DEMO-2026
```

The policy file lives at `$STRESS_STRIKE_HOME/authz.json`
(default `~/.stress-strike/authz.json`). The **same** policy the dashboard reads.

> **Do NOT pre-add the ticket if you want to *show* the 403 denial live.** The
> most impressive 20 seconds of the demo is: *"watch it refuse me."* Keep the
> ticket in the clipboard, paste it in Step 4.

### 0.6 Sanity-check the whole chain (30 seconds, runs offline)

```bash
D=http://127.0.0.1:8888
curl -s -o /dev/null -w "dashboard %{http_code}\n" $D/
curl -s -o /dev/null -w "target    %{http_code}\n" http://127.0.0.1:8090/
curl -s -X POST $D/api/crawl/scan -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","depth":1,"pages":5}' | head -c 200; echo
```

If the crawl returns `{"ok":true,...}` you are ready.

---

## 1. The endpoints at a glance

All endpoints are `POST`, take a JSON body, and return JSON. Scans are
**serialized** by a single semaphore: if one scan is running, the next request
gets `HTTP 409 "a scan is already running — wait for it to finish"`. Run them
**one at a time**.

| # | Endpoint | Operation class | Needs ticket? | Default scope | Demo status |
|---|---|---|---|---|---|
| 1 | `POST /api/owasp/scan` | passive scan / intrusive families | only if `intrusive:true` | host you typed | ✅ works |
| 2 | `POST /api/pentest/scan` | **offensive** | **yes** (always) | host you typed | ✅ works |
| 3 | `POST /api/crawl/scan` | info gathering | no | host you typed | ✅ works |
| 4 | `POST /api/fuzz/scan` | info gathering / intrusive | only if `intrusive:true` | host you typed | ✅ works |
| 5 | `POST /api/subdomain/scan` | info gathering | no | crt.sh + DNS | ✅ works |
| 6 | `POST /api/jwt/scan` | local analysis | no | n/a | ✅ works |
| 7 | `POST /api/websocket/scan` | info gathering | no | the URL you typed | ✅ works |
| 8 | `POST /api/portscan` | info gathering | no | host:port | ⚠️ returns JSON, **always 0 open** (see §7) |
| 9 | `POST /api/sslscan` | info gathering | no | host:port | ⚠️ returns JSON, **always fails to connect** (see §7) |
| 10 | `POST /api/dirbust` | info gathering | no | host you typed | ❌ **CRASHES the process** (see §7) |
| 11 | `POST /api/graphql/scan` | info gathering | no | endpoint you typed | ❌ **panics**, empty reply (see §7) |

**Demo the ✅ rows. Do NOT click the ❌ rows in front of the jury** — one of them
takes the whole dashboard down (documented honestly in §7).

---

## 2. Demo run sheet (the money shots)

Everything below is copy-pasteable. `D` is the dashboard.

```bash
D=http://127.0.0.1:8888
```

### Step 1 — Crawl the site (safe, visual, 3 s)

**What you say:** *"First, a katana-style spider. Watch where it is allowed to
go."*

```bash
curl -s -X POST $D/api/crawl/scan -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","depth":2,"pages":10}'
```

**Expected response (real):**

```json
{
  "ok": true,
  "target": "http://127.0.0.1:8090",
  "scope": ["127.0.0.1"],
  "pages": 10,
  "endpoints": 22,
  "duration_sec": 0.0045,
  "dryRun": false,
  "offsite": false,
  "gate": {
    "requests_sent": 10,
    "requests_refused": 0,
    "refused_out_of_scope": 0,
    "refused_intrusive": 0,
    "refused_budget": 0,
    "refused_rate": 0,
    "refused_dry_run": 0
  },
  "discovered": [
    { "url": "http://127.0.0.1:8090/",        "method": "GET",  "kind": "link" },
    { "url": "http://127.0.0.1:8090/admin",   "method": "GET",  "kind": "link" },
    { "url": "http://127.0.0.1:8090/login",   "method": "POST", "params": ["email","password"], "kind": "form" },
    { "url": "http://127.0.0.1:8090/product/1","method": "GET", "found_at": "http://127.0.0.1:8090", "kind": "link" }
  ]
}
```

**Jury should notice:** `scope: ["127.0.0.1"]` — it discovered 22 endpoints but
every one is on the host you typed. Off-site links are **not** followed
(`"offsite": false`), and redirects stay on the original host.

**Browser equivalent:** scroll to the **"Site Crawler (open pages)"** panel →
Target `http://127.0.0.1:8090`, Depth `2`, Pages `10`, Concurrency `5` →
click **Run**. The table fills with discovered URLs (GET/POST, params).

---

### Step 2 — OWASP Top 10, passive (honesty on display, 5 s)

**What you say:** *"A passive OWASP Top 10 pass. No payloads yet. Notice what it
says about the categories it could not actually test."*

```bash
curl -s -X POST $D/api/owasp/scan -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","budget":120,"rate":20}'
```

**Expected response (real, abridged):**

```json
{
  "ok": true,
  "target": "http://127.0.0.1:8090",
  "scope": ["127.0.0.1"],
  "intrusive": false,
  "tested": 6,
  "total": 10,
  "score": 83,
  "grade": "B",
  "categories": [
    { "id": "A01", "name": "Broken Access Control", "status": "PASS" },
    { "id": "A02", "name": "Cryptographic Failures", "status": "WARNING",
      "findings": ["[HIGH] HTTP does not redirect to HTTPS", "[HIGH] HSTS header missing"],
      "remediation": ["Configure HTTP to HTTPS redirect (301/308 permanent)",
                      "Add Strict-Transport-Security header with max-age >= 31536000"] },
    { "id": "A03", "name": "Injection", "status": "NOT TESTED" },
    { "id": "A04", "name": "Insecure Design", "status": "PASS" },
    { "id": "A05", "name": "Security Misconfiguration", "status": "NOT TESTED" },
    { "id": "A06", "name": "Vulnerable and Outdated Components", "status": "PASS" },
    { "id": "A07", "name": "Identification and Authentication Failures", "status": "NOT TESTED" },
    { "id": "A08", "name": "Software and Data Integrity Failures", "status": "PASS" },
    { "id": "A09", "name": "Security Logging and Monitoring Failures", "status": "PASS" },
    { "id": "A10", "name": "Server-Side Request Forgery (SSRF)", "status": "NOT TESTED" }
  ],
  "gate": { "requests_sent": 51, "requests_refused": 0 }
}
```

**Jury should notice:**
- **`"status": "NOT TESTED"` is not a pass.** `tested: 6, total: 10` — four
  categories produced **no evidence**, so the tool refuses to grade them. A
  "confidence-first" scanner would have printed PASS for all ten. This is the
  single most important thing to point at.
- A02 is `WARNING` with concrete remediation strings, not a bare verdict.

**Browser equivalent:** **"OWASP Top 10 Security Scan"** panel → Target
`http://127.0.0.1:8090` → **Run Scan**. The category table shows PASS/WARNING/
FAIL/**NOT TESTED** badges, and the Findings list appears below.

---

### Step 3 — Pentest **without** a ticket (the refusal, 2 s) ⭐

**What you say:** *"This one is offensive. I have not been authorized. Watch it
refuse me."*

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST $D/api/pentest/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","intrusive":true}'
```

**Expected response (real):**

```json
{"ok":false,"denied":true,"reason":"intrusive scanning of 127.0.0.1 requires an authorization ticket approved with `stress-strike authorize add`"}

HTTP 403
```

**Jury should notice:** the request never reached the network — it was refused
**before** any probe. `"denied": true` is a distinct field so the UI can explain
*why*, not just show "error". The refusal is also written to the audit log
(Step 6).

**Browser equivalent:** the **"Pentest (offensive scan)"** panel shows a red
refusal reason instead of results.

---

### Step 4 — Authorize, then pentest again (the payoff, 10 s) ⭐

**What you say:** *"Now a human approves a ticket. Same request, plus the
ticket."*

**4a — the approver adds the ticket** (run it live if you did not pre-create it):

```bash
./bin/stress-strike authorize add \
  --pattern 127.0.0.1 --approver "olympiad-jury" \
  --ticket "DEMO-2026" --reason "olympiad demo"
```

**4b — the same scan, now authorized, with two intrusive families:**

```bash
curl -s -X POST $D/api/pentest/scan -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","authorized":"DEMO-2026",
       "intrusive":true,"enable":["crlf","boolean-sqli"],
       "budget":150,"rate":20}'
```

**Expected response (real, abridged):**

```json
{
  "ok": true,
  "target": "http://127.0.0.1:8090",
  "scope": ["127.0.0.1"],
  "intrusive": true,
  "tested": 9,
  "total": 10,
  "score": 67,
  "grade": "D",
  "categories": [
    { "id": "A01", "status": "PASS" },
    { "id": "A02", "status": "WARNING",
      "findings": ["[HIGH] HTTP does not redirect to HTTPS", "[HIGH] HSTS header missing"] },
    { "id": "A03", "name": "Injection", "status": "WARNING",
      "findings": ["[CRITICAL] SQL Injection in parameter 'search': error/message exposed",
                   "[CRITICAL] OS Command Injection in parameter 'host'"] },
    { "id": "A04", "status": "PASS" },
    { "id": "A05", "status": "PASS" },
    { "id": "A06", "status": "PASS" },
    { "id": "A07", "status": "WARNING",
      "findings": ["[HIGH] No brute force protection: 20 failed login attempts with no lockout/rate limit",
                   "[MEDIUM] User enumeration possible: 'admin' returns different response than invalid users"] },
    { "id": "A08", "status": "PASS" },
    { "id": "A09", "status": "PASS" },
    { "id": "A10", "name": "Server-Side Request Forgery (SSRF)", "status": "NOT TESTED" }
  ],
  "gate": { "requests_sent": 150, "requests_refused": 64, "refused_budget": 64 }
}
```

**Jury should notice (three things at once):**
1. **The ticket flipped a 403 into a real scan** — the only thing that changed
   was `"authorized": "DEMO-2026"`.
2. **Real findings.** SQL injection and OS command injection in the demo target,
   with the parameter name and the CWE class.
3. **Still honest.** `A10 = NOT TESTED` because the request budget ran out
   (`refused_budget: 64`) before the SSRF probes were reached. The tool reports
   *"I did not get there"* rather than inheriting A10's PASS from Step 2.

**Browser equivalent:** **"Pentest (offensive scan)"** panel → Target
`http://127.0.0.1:8090` → Depth `standard` → tick intrusive options → **Run**.

---

### Step 5 — Fuzz (coverage-guided, 5 s)

**What you say:** *"A mutation fuzzer. Every mutation still goes through the
gate."*

```bash
curl -s -X POST $D/api/fuzz/scan -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","paths":["/"],"mutations":40,"budget":120,"rate":20}'
```

**Expected response (real):**

```json
{
  "ok": true,
  "target": "http://127.0.0.1:8090",
  "scope": ["127.0.0.1"],
  "sent": 80,
  "refused": 0,
  "interesting": 0,
  "gate": {
    "requests_sent": 82, "requests_refused": 0,
    "refused_out_of_scope": 0, "refused_intrusive": 0,
    "refused_budget": 0, "refused_rate": 0, "refused_dry_run": 0
  }
}
```

**Browser equivalent:** **"HTTP Fuzzer"** panel → Target + optional paths +
mutations → **Fuzz**.

---

### Step 6 — Compact: the remaining working endpoints (15 s total)

Run these back-to-back; each returns JSON in under a second (subdomain needs
network for crt.sh).

```bash
# JWT weakness analyzer — alg:none confusion, missing claims
curl -s -X POST $D/api/jwt/scan -H 'Content-Type: application/json' \
  -d '{"token":"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."}'
# → {"ok":true,"valid":true,"algo_confusion":true,
#    "issues":["algorithm 'none' — signature not verified","missing 'exp' claim", ...]}

# WebSocket tester
curl -s -X POST $D/api/websocket/scan -H 'Content-Type: application/json' \
  -d '{"url":"ws://127.0.0.1:8090/ws"}'
# → {"ok":true,"url":"...","connected":false,
#    "issues":["cannot connect: websocket: bad handshake","server responded 404"]}

# Subdomain enumeration (crt.sh + DNS; needs network)
curl -s -X POST $D/api/subdomain/scan -H 'Content-Type: application/json' \
  -d '{"target":"example.com"}'
# → {"ok":true,"target":"https://example.com","found":0,"resolved":0,"duration_seconds":8.0}
```

> The JWT one is a great 5-second crowd-pleaser: it decodes the header/payload
> and reports `algo:none` as an algorithm-confusion weakness.

---

### Step 7 — Show the audit trail (the trust story, 10 s) ⭐

**What you say:** *"Every one of those decisions — allowed or denied — is in a
hash-chained log. The web path cannot quietly bypass the consent trail."*

```bash
tail -3 ~/.stress-strike/audit.jsonl | python3 -m json.tool --json-lines 2>/dev/null || tail -3 ~/.stress-strike/audit.jsonl
```

**Expected entries (real):**

```json
{"seq":1,"time":"2026-...","actor":"asadbek","action":"pentest",
 "targets":["http://127.0.0.1:8090"],"ips":["127.0.0.1"],"class":"loopback",
 "allowed":true,"rule":"127.0.0.1","reason":"authorization ticket \"DEMO-2026\" (127.0.0.1)",
 "argv":["stress-strike dashboard","POST /api/pentest/scan"],
 "prev_hash":"","hash":"3e6edf..."}

{"seq":2,"time":"2026-...","actor":"asadbek","action":"scan",
 "targets":["http://10.0.0.5"],"ips":["10.0.0.5"],"class":"private",
 "allowed":false,"reason":"10.0.0.5 resolves to a private address ([10.0.0.5]); pass an authorization entry or --allow-private",
 "argv":["stress-strike dashboard","POST /api/owasp/scan"],
 "prev_hash":"3e6edf...","hash":"d31fa6..."}
```

**Jury should notice:** `prev_hash` of entry *n+1* equals `hash` of entry *n* —
remove or edit any line and the chain breaks. Both the **allowed** and the
**denied** decisions are recorded, including the reason.

---

## 3. What the jury should look for (the rubric)

Use this as a checklist while the demo runs.

| # | Property | Where it shows up | Why it matters |
|---|---|---|---|
| 1 | **Scope gate** | `"scope": ["127.0.0.1"]` on every result; crawl `"offsite": false` | The tool only touches the host you typed. A private target (`10.0.0.5`) is refused with a 403 *before* any packet is sent. |
| 2 | **Authorization before action** | Step 3 → `HTTP 403 {"denied":true}`; Step 4 → same request succeeds with a ticket | Offensive scanning is consent-gated. A ticket is required in addition to the scope allow-list — neither alone is enough. |
| 3 | **"NOT TESTED", never a false PASS** | `"status": "NOT TESTED"` for A03/A05/A07/A10 in Step 2; A10 again in Step 4 | Coverage, not confidence. A category whose probes never reached the server is **not** reported as PASS. This is the tool refusing to lie to you. |
| 4 | **textContent-only XSS safety** | `internal/dashboard/app.js`: findings are rendered with `element.textContent = ...`, never `.innerHTML` (see the comments at `app.js:1298` and `app.js:1508`) | Finding titles/evidence come **from the scanned target** — attacker-controlled. If they were injected as HTML, a malicious target could XSS the analyst viewing the report. The UI is immune by construction. |
| 5 | **CSRF / same-origin guard** | A cross-origin POST is refused: `HTTP 403 "cross-origin requests are not allowed"` | A random website cannot make your browser fire a scan at your dashboard. |
| 6 | **Hash-chained audit log** | Step 7 — `prev_hash` links each entry to the last | Tamper-evident consent trail shared by the CLI and the web UI. |
| 7 | **Bounded, non-hanging scans** | `budget`/`rate` capped so `budget/rate <= 120 s`; single-scan semaphore → `HTTP 409` if you spam | A browser click cannot pin a server goroutine for minutes or DoS the host. |

### The two sentences to say out loud

> *"A scanner that says PASS when it tested nothing is worse than no scanner.
> This one says **NOT TESTED** — and it can only hold or downgrade a verdict,
> never upgrade one."*

> *"Findings come from the target server, so we render them with `textContent`
> only — never `innerHTML`. A hostile target cannot script the analyst's browser."*

---

## 4. Browser (UI) walkthrough

The dashboard is a single scrolling page. Panels, top to bottom:

| Panel title | Input field(s) | Button |
|---|---|---|
| **OWASP Top 10 Security Scan** | `#owaspTarget` (e.g. `http://127.0.0.1:8090`) | `#btnOwaspRun` — "Run Scan" |
| **Pentest (offensive scan)** | `#pentestTarget`, `#pentestDepth` (quick/standard/deep) | `#btnPentestRun` |
| **Site Crawler (open pages)** | `#crawlTarget`, `#crawlDepth`, `#crawlPages`, `#crawlConcur` | `#btnCrawlRun` |
| **HTTP Fuzzer** | `#fuzzTarget`, `#fuzzPaths`, `#fuzzMutations`, `#fuzzIntrusive` | `#btnFuzzRun` |
| **Subdomain Enumeration** | `#subdomainTarget` | `#btnSubdomainRun` |
| **Port Scanner** | `#portscanTarget`, `#portscanPorts` | `#btnPortscanRun` |
| **Directory Brute-forcer** | `#dirbustTarget`, `#dirbustPaths` | `#btnDirbustRun` — ⚠️ **do not click** (see §7) |
| **SSL/TLS Analyzer** | `#sslscanTarget` | `#btnSslscanRun` — ⚠️ see §7 |
| **JWT Analyzer** | `#jwtToken` (textarea) | `#btnJwtRun` |
| **GraphQL Scanner** | `#graphqlTarget` | `#btnGraphQLRun` — ⚠️ **do not click** (see §7) |
| **WebSocket Tester** | `#websocketTarget` | `#btnWebSocketRun` |

**Recommended on-screen UI order:** Crawl → OWASP → Pentest (refused) →
add ticket in terminal → Pentest (authorized) → JWT → scroll to the audit log
in a terminal side-by-side.

---

## 5. Reading the JSON (field reference)

| Field | Meaning |
|---|---|
| `ok` | `true` for an executed scan; `false` only in the denial body |
| `denied` | present **only** on a 403 authorization refusal |
| `reason` | human-readable gate decision (allowed *or* denied) |
| `scope` | the allow-list actually enforced (default: the named host) |
| `gate.requests_sent` / `requests_refused` | what actually happened on the wire |
| `gate.refused_out_of_scope` | probes the guard blocked for leaving scope |
| `gate.refused_intrusive` | intrusive probes blocked because they were not authorized |
| `gate.refused_budget` / `refused_rate` / `refused_dry_run` | self-explanatory; a non-zero `refused_budget` is why a category can end up `NOT TESTED` |
| `tested` / `total` | categories with evidence / categories in the OWASP Top 10 |
| `status` | `PASS` \| `WARNING` \| `FAIL` \| `NOT TESTED` — **`NOT TESTED` is not a pass** |

**Status codes you will see**

| Code | Means |
|---|---|
| `200` | scan executed (body has `ok:true`) |
| `400` | malformed body / bad target / bad flag (e.g. unknown probe family) |
| `403` | authorization refusal (`denied:true`) **or** cross-origin POST |
| `405` | not a POST |
| `409` | another scan is already running — wait |
| `500` | policy/audit infrastructure error |

---

## 6. Endpoint bodies (copy-paste reference)

```bash
D=http://127.0.0.1:8888

# OWASP (passive)
curl -X POST $D/api/owasp/scan -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","budget":120,"rate":20}'

# OWASP (intrusive families) — needs ticket
curl -X POST $D/api/owasp/scan -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","authorized":"DEMO-2026","intrusive":true,
       "enable":["crlf","boolean-sqli","time-sqli","path-traversal","ssrf","write-methods"]}'
# valid families: crlf, boolean-sqli, time-sqli, path-traversal, ssrf, write-methods

# Pentest
curl -X POST $D/api/pentest/scan -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","authorized":"DEMO-2026","intrusive":true,"depth":2}'

# Crawl
curl -X POST $D/api/crawl/scan -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","depth":2,"pages":10,"concurrency":5}'

# Fuzz
curl -X POST $D/api/fuzz/scan -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","paths":["/"],"mutations":40,"budget":120}'

# Subdomain
curl -X POST $D/api/subdomain/scan -H 'Content-Type: application/json' \
  -d '{"target":"example.com"}'

# JWT
curl -X POST $D/api/jwt/scan -H 'Content-Type: application/json' \
  -d '{"token":"<jwt>"}'

# WebSocket
curl -X POST $D/api/websocket/scan -H 'Content-Type: application/json' \
  -d '{"url":"ws://127.0.0.1:8090/ws"}'

# Port scan   (⚠️ see §7)
curl -X POST $D/api/portscan  -H 'Content-Type: application/json' \
  -d '{"target":"127.0.0.1","ports":[8090,8888,22,443]}'

# SSL scan    (⚠️ see §7)
curl -X POST $D/api/sslscan   -H 'Content-Type: application/json' \
  -d '{"target":"example.com:443"}'

# Dir bust    (❌ CRASHES — do not run in the demo)
curl -X POST $D/api/dirbust   -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","paths":["/admin","/login"]}'

# GraphQL     (❌ panics — do not run in the demo)
curl -X POST $D/api/graphql/scan -H 'Content-Type: application/json' \
  -d '{"endpoint":"http://127.0.0.1:8090/graphql"}'
```

**Numeric bounds** (zero = default): `rate` 1–50 (default 10),
`budget` 1–2000 (default 400), `timeoutSec` 1–30 (default 10),
`paths` ≤ 25, `budget/rate` ≤ 120 s. Out-of-range values are a **400**, not a
silent clamp.

---

## 7. KNOWN ISSUES — endpoints that are wired but broken (verified)

> **Read this before the demo.** These are real defects found while verifying
> v0.14.3. They are documented here so the presenter is never blindsided, and so
> the fix is unambiguous. **Do not click these in front of the jury.**

### 7.1 `POST /api/dirbust` — CRITICAL: crashes the whole dashboard (DoS)

**Reproduce:**

```bash
curl -s -X POST http://127.0.0.1:8888/api/dirbust -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8090","paths":["/admin","/login"]}'
# → connection closed; the dashboard process is DEAD
```

**Observed:** the process panics:

```
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV ...]
github.com/asadbekabdulboqiyev/stress-strike/internal/scanner.DirBust.func1(...)
        internal/scanner/dirbust.go:102
created by ...scanner.DirBust in goroutine 134
        internal/scanner/dirbust.go:82
```

**Root cause:** the handler calls
`scanner.DirBust(ctx, target, req.Paths, nil)` with a **nil `Requester`**
(`internal/dashboard/dirbust.go:93`), but `DirBust` dereferences it at
`internal/scanner/dirbust.go:102` (`req.Check(...)`) with no nil guard.
Because the panic happens inside a **child goroutine** spawned by `DirBust`,
`net/http`'s per-request panic recovery does **not** catch it → **whole process
exits**. There is no `recover()` middleware in `internal/dashboard/server.go`.

**Impact:** any user (or any same-origin request) can kill the dashboard with
one request → denial of service.

**Fix (for the developer):** either pass a real guarded `Requester` from the
handler, or add `if req == nil { ... }` handling in `scanner.DirBust` (compare
`scanner/websocket.go:46` which does guard with `if req != nil`, and
`scanner/fuzz.go:144` which rejects nil). Adding a `recover()` middleware to the
dashboard is the defense-in-depth backstop.

---

### 7.2 `POST /api/graphql/scan` — panics; endpoint returns nothing

**Reproduce:**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST http://127.0.0.1:8888/api/graphql/scan \
  -H 'Content-Type: application/json' -d '{"endpoint":"http://127.0.0.1:8090/graphql"}'
# → empty body, HTTP 000 (connection reset). The dashboard SURVIVES.
```

**Root cause:** same nil-`Requester` bug as 7.1 — `internal/dashboard/graphql.go:90`
passes `nil` to `scanner.ScanGraphQL(...)`, which calls `req.Check` at
`internal/scanner/graphql.go:55` with no nil guard. Here the panic is on the
**handler goroutine**, so `net/http` recovers it (connection closes, process
survives) — but the endpoint is unusable.

**Fix:** same as 7.1.

---

### 7.3 `POST /api/portscan` — returns JSON but **always 0 open ports**

**Reproduce** (both ports below are demonstrably open — `curl` gets `200`
from each):

```bash
lsof -nP -iTCP:8888 -sTCP:LISTEN   # listening
lsof -nP -iTCP:8090 -sTCP:LISTEN   # listening
curl -s -X POST http://127.0.0.1:8888/api/portscan -H 'Content-Type: application/json' \
  -d '{"target":"127.0.0.1","ports":[8888,8090]}'
# → {"ok":true,"target":"https://127.0.0.1","opened":0,"closed":2,...}
```

**Root cause:** the handler normalizes the target to a full URL
(`owaspValidateTarget` turns `127.0.0.1` into `https://127.0.0.1`) and passes
**that** to `scanner.ScanPorts`, which expects a bare `host[:port]`. Inside
`ScanPorts`, `net.SplitHostPort("https://127.0.0.1")` fails → `host` becomes the
whole `"https://127.0.0.1"` string → `net.JoinHostPort(host, "8888")` =
`"https://127.0.0.1:8888"` → `DialContext` fails → every port is reported
`"closed"`. **False negatives for every port.**

**Fix:** the handler must extract `parsed.Hostname()` (and optional
`parsed.Port()`) and pass the bare host to `scanner.ScanPorts`.

---

### 7.4 `POST /api/sslscan` — returns JSON but **always fails to connect**

```bash
curl -s -X POST http://127.0.0.1:8888/api/sslscan -H 'Content-Type: application/json' \
  -d '{"target":"example.com:443"}'
# → {"ok":true,"target":"https://example.com:443","valid":false,
#    "issues":["cannot connect: dial tcp: lookup https://example.com:443: no such host"], ...}
```

**Root cause:** the same scheme-as-host bug. `scanner.ScanSSL` receives
`"https://example.com:443"`; `net.SplitHostPort` yields host
`"https://example.com"` → DNS lookup for `https://example.com` fails.
**The endpoint never produces a TLS result via the API.**

**Fix:** pass `parsed.Hostname()` + `"443"` (or `parsed.Port()`) to
`scanner.ScanSSL`.

---

### 7.5 Summary for the developer

| Endpoint | Symptom | Root cause | Severity |
|---|---|---|---|
| `/api/dirbust` | **process crash** | nil `Requester` → child-goroutine panic (`dirbust.go:102`) | **critical (DoS)** |
| `/api/graphql/scan` | empty reply | nil `Requester` → handler panic (`graphql.go:55`) | high (broken) |
| `/api/portscan` | always 0 open | full URL passed as host | high (false negatives) |
| `/api/sslscan` | always cannot-connect | full URL passed as host | high (broken) |

The dashboard routes (`internal/dashboard/server.go:391-412`) all exist and
dispatch correctly — the defects are one level down, in what the handlers pass
to the scanner package, plus a missing panic-recovery middleware.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `go: command not found` | Go not installed/on PATH | install Go 1.26+, or use a prebuilt `bin/stress-strike-dashboard` |
| `bind: address already in use` on 8888 | another dashboard is running | `lsof -nP -iTCP:8888 -sTCP:LISTEN` → `kill <pid>`, or use `-listen 127.0.0.1:8899` |
| `FATAL: dashboard is listening on a non-loopback interface with NO authentication` | you passed `-listen 0.0.0.0:8888` without auth | pass `-auth-token 'change-me'` and send `Authorization: Bearer change-me`, or keep it on `127.0.0.1` |
| `HTTP 409 a scan is already running` | you fired two scans at once | wait; scans are serialized by design. In the UI, wait for the spinner to stop |
| `HTTP 403 cross-origin requests are not allowed` | you sent an `Origin` header from another host | use the dashboard's own UI, or don't set `Origin` with curl |
| `HTTP 403 {"denied":true}` on pentest/owasp-intrusive | no ticket, or ticket not approved | `./bin/stress-strike authorize add --pattern <host> --approver <name> --ticket <id>`, then pass `"authorized":"<id>"` |
| `403 ... resolves to a private address` | target is RFC1918 (e.g. `10.`, `192.168.`, `172.16-31.`) | use `127.0.0.1`, or add an authorization rule, or set `STRESS_STRIKE_ALLOW` / policy `allow_private` |
| Empty response body from `/api/dirbust` or `/api/graphql/scan` | **known bug §7** — do not use in the demo | — |
| `/api/portscan` shows all closed | **known bug §7.3** | demo the crawl/owasp/pentest instead |
| First `go run ./examples/demo_store` is slow | Go is compiling | pre-build: `make build` (produces `bin/demo-store`) |
| Subdomain scan returns `found:0` / is slow | crt.sh needs the network, or is rate-limited | that is a real "no results", not an error; skip it if offline |
| `curl` to a public target hangs | network egress is blocked | stay on loopback (`127.0.0.1`) — the whole core demo works offline |
| Policy edits in the dashboard don't take effect | dashboard read env at startup | restart the dashboard with the same `STRESS_STRIKE_HOME`/`STRESS_STRIKE_POLICY` |

**Environment variables** (must match between the CLI and the dashboard):

| Var | Purpose |
|---|---|
| `STRESS_STRIKE_HOME` | base dir for `authz.json` + `audit.jsonl` (default `~/.stress-strike`) |
| `STRESS_STRIKE_POLICY` | explicit path to the authorization policy |
| `STRESS_STRIKE_AUDIT_LOG` | explicit path to the audit log |
| `STRESS_STRIKE_ALLOW` | extra allow rules appended to the policy at runtime |

---

## 9. Reset / clean up after the demo

```bash
# stop the servers
pkill -f stress-strike-dashboard
pkill -f demo_store

# if you created a demo ticket and want to remove it
./bin/stress-strike authorize remove --pattern 127.0.0.1
```

If you used a throwaway home for the demo, just `rm -rf` it:

```bash
STRESS_STRIKE_HOME=/tmp/ss-demo-home ./bin/stress-strike-dashboard -listen 127.0.0.1:8888
# ... later:
rm -rf /tmp/ss-demo-home
```

---

## 10. Endpoint verification (source-level)

All eleven routes are registered in `internal/dashboard/server.go` (`serveApp`,
lines 391–412) and each dispatches to a handler that writes
`Content-Type: application/json`:

| Route | Handler | File |
|---|---|---|
| `/api/owasp/scan` | `handleOWASPScan` | `internal/dashboard/owasp.go` |
| `/api/pentest/scan` | `handlePentestScan` | `internal/dashboard/pentest.go` |
| `/api/crawl/scan` | `handleCrawlScan` | `internal/dashboard/crawl.go` |
| `/api/fuzz/scan` | `handleFuzzScan` | `internal/dashboard/fuzz.go` |
| `/api/subdomain/scan` | `handleSubdomainScan` | `internal/dashboard/subdomain.go` |
| `/api/portscan` | `handlePortScan` | `internal/dashboard/portscan.go` |
| `/api/dirbust` | `handleDirBust` | `internal/dashboard/dirbust.go` |
| `/api/sslscan` | `handleSSLScan` | `internal/dashboard/sslscan.go` |
| `/api/jwt/scan` | `handleJWTScan` | `internal/dashboard/jwt.go` |
| `/api/graphql/scan` | `handleGraphQLScan` | `internal/dashboard/graphql.go` |
| `/api/websocket/scan` | `handleWebSocketScan` | `internal/dashboard/websocket.go` |

**Live verification result (v0.14.3, loopback target `127.0.0.1:8090`):**

| Endpoint | Result |
|---|---|
| `/api/owasp/scan` | ✅ JSON, `score 83 / grade B`, honest `NOT TESTED` |
| `/api/pentest/scan` | ✅ 403 without ticket; full JSON with ticket |
| `/api/crawl/scan` | ✅ JSON, 22 endpoints discovered, `scope:["127.0.0.1"]` |
| `/api/fuzz/scan` | ✅ JSON, `sent:80` |
| `/api/subdomain/scan` | ✅ JSON |
| `/api/jwt/scan` | ✅ JSON, `algo_confusion:true` |
| `/api/websocket/scan` | ✅ JSON |
| `/api/portscan` | ⚠️ JSON but always `opened:0` (§7.3) |
| `/api/sslscan` | ⚠️ JSON but always "no such host" (§7.4) |
| `/api/dirbust` | ❌ process crash (§7.1) |
| `/api/graphql/scan` | ❌ panic, empty reply (§7.2) |
