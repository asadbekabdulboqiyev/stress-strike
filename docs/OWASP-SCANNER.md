# OWASP Top 10 Scanner (2021)

This document describes stress-strike's OWASP Top 10 (2021) web-vulnerability
scanning capability: what it checks, how each check is proven, what is safe by
default, and what is deliberately refused. It is grounded in the code in
`internal/scanner/` and in the OWASP Web Security Testing Guide (WSTG).
Identifiers were verified against the guide pages cited in
[References](#references).

**This page describes the `scan` and `pentest` commands. Where a check exists
in the code today it names the file; where a check is added in the same release
as this document it is marked `new`. Anything you cannot confirm from the code
should be treated as "verify against the code".**

---

## 1. What this is, in plain language

You point the tool at a web address you are allowed to test; it sends a fixed,
small set of HTTP requests and TLS handshakes, compares the answers against
known weak patterns (a server that still offers an old TLS version, a page that
reflects your input without encoding it, a `/backup.sql` that answers `200`),
and writes a list of findings with a confidence label on each one. **It does
NOT "find all vulnerabilities" and it cannot prove your site is secure.** It
only reports what is observable from outside, over the network, without
credentials unless you supply them. It is a checklist runner, not an oracle: a
clean run means "these specific checks found nothing", not "there is nothing to
find". The most dangerous classes of bug (business-logic flaws, authorization
mistakes behind a login, supply-chain tampering) are either invisible to it or
only weakly signalled, and every automated finding still needs a human to confirm
it before anyone acts on it.

---

## 2. Coverage matrix

One table per OWASP Top 10 (2021) category. Column meanings:

- **Check id** — the stable identifier this document uses (ours, not OWASP's).
- **WSTG** — the OWASP Web Security Testing Guide test id (v4.2) that describes
  the manual technique this check approximates. See [References](#references)
  for the URLs.
- **What is sent** — the request(s) the check issues. No payload is described
  here that is not already bounded by the safety model in section 3.
- **What confirms it** — the observable evidence that turns a request into a
  finding.
- **Default** — `ON` (runs whenever the check family is selected) or
  `OFF` (opt-in: requires both `--intrusive` **and** `--enable <probe>`).
- **Confidence** — the *highest* label the check can reach on its own:
  `confirmed`, `high`, `heuristic`, or `informational` (see section 5).
- **Risk** — `none` (read-only, no state change) or `low-bounded` (a small,
  fixed, capped number of requests or one request with an altered header).

Status markers used in the rows: **exists (`file`)** = implemented today;
**`new`** = added in this release; **`owasp.go` (unreachable)** = the code
exists in `internal/scanner/owasp.go` and is exercised by
`internal/scanner/owasp_test.go`, but is **not currently called from the `scan`
or `pentest` commands**.

### A01:2021 — Broken Access Control

| Check id | WSTG | What is sent | What confirms it | Default | Confidence | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| `AC-IDOR` | [WSTG-ATHZ-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) | Two requests for the same resource with two different object identifiers (numeric ±1, or two UUIDs harvested from the crawl). Exists (`internal/scanner/vuln_scanner.go`, `scanAPISecurity`). | Both identifiers return `200` with different, non-empty object bodies. | ON | heuristic | low-bounded |
| `AC-MASSASSIGN` | [WSTG-ATHZ-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) | One request that adds an extra, non-schema field to a JSON body that the crawl showed the API accepts. Exists (`internal/scanner/vuln_scanner.go`, `scanAPISecurity`). | The response echoes the extra field as accepted state, and a follow-up read shows it persisted. | ON | heuristic | low-bounded |
| `AC-REDIRECT` | [WSTG-CLNT-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect) | One request per redirect-looking parameter with an absolute off-site URL. Exists (`internal/scanner/vuln_scanner.go`, `scanOpenRedirect`). Redirects are never followed. | The raw `3xx` `Location` header points at the injected external host. | ON | high | none |
| `AC-TRAVERSAL` | [WSTG-ATHZ-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include) | A short, fixed set of `../` sequences in one path or parameter (and their URL-encoded forms). A check for this exists in `internal/scanner/vuln_scanner.go` (`scanDirectoryTraversal`) and `internal/scanner/owasp.go`; the **bounded opt-in probe is `new`**. | The body contains a known file signature (for example `root:x:0:0:` or `[extensions]`). | **OFF** (`--intrusive --enable path-traversal`) | high | low-bounded |
| `AC-VERB` | [WSTG-INPV-03](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering) | One write-method request (a single `PUT`/`DELETE` against a discovered endpoint) to test whether method-based access control is enforced. `new`. This is the **only** check permitted to use a state-changing verb, and it is the bounded write-method probe. | The server accepts the method on a resource that should reject it (a `2xx` where the UI never offers that verb). | **OFF** (`--intrusive --enable write-methods`) | high | low-bounded |

### A02:2021 — Cryptographic Failures

| Check id | WSTG | What is sent | What confirms it | Default | Confidence | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| `CRYP-TLS` | [WSTG-CRYP-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security) | A TLS handshake across supported protocol versions and a bounded cipher inventory. Exists (`internal/scanner/scanner.go`, `ScanTLS`). | Negotiated protocol is TLS 1.0/1.1, a known-weak cipher is offered, the certificate is expired or self-signed, or forward secrecy is absent. | ON | confirmed | none |
| `CRYP-CLEARTEXT` | [WSTG-CRYP-03](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels) | One plain-HTTP request to see whether it is served without redirecting to HTTPS. Exists (`internal/scanner/scanner.go`). | The plain-HTTP request returns content instead of a redirect to `https://`. | ON | high | none |
| `CRYP-MIXED` | [WSTG-CRYP-03](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels) | Parses the already-fetched HTML of the target pages for `http://` sub-resource references. Exists (`internal/scanner/vuln_scanner.go`). | An `https://` page references a script/style/image over `http://`. | ON | high | none |
| `CRYP-CACHE` | [WSTG-ATHN-06](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses) | Reads the `Cache-Control`/`Pragma`/`Expires` headers on responses to authenticated or sensitive endpoints (login, account, API reads). `new`. | A sensitive response lacks `Cache-Control: no-store` (or `no-cache`/`private`), so it may be cached and later read from a shared browser. | ON | heuristic | none |

### A03:2021 — Injection

| Check id | WSTG | What is sent | What confirms it | Default | Confidence | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| `INJ-SQLI-ERR` | [WSTG-INPV-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) | One request per parameter with a single quote and a syntax-breaking fragment. Exists (`internal/scanner/vuln_scanner.go`, `scanSQLInjection`; also `internal/scanner/owasp.go`). | The response body matches a database error signature (for example `ORA-`, `ODBC SQL Server`, `MySQL` syntax text). Error strings only — never an extracted data value. | ON | high | none |
| `INJ-SQLI-BOOL` | [WSTG-INPV-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) | A matched pair of true/false boolean conditions in one parameter, compared against the baseline response. `new`. | A stable, repeatable difference between the true and false responses that is not explained by the baseline. | **OFF** (`--intrusive --enable boolean-sqli`) | heuristic | low-bounded |
| `INJ-SQLI-TIME` | [WSTG-INPV-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) | One time-delay condition per parameter, with a measured baseline. `new`. | A delay that reproduces on a second attempt and is far outside baseline jitter. **Reported as `heuristic` only, never as confirmed** (see section 4). | **OFF** (`--intrusive --enable time-sqli`) | heuristic | low-bounded |
| `INJ-XSS-REFL` | [WSTG-INPV-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting) | One request per parameter with a uniquely tokenised marker string. Exists (`internal/scanner/vuln_scanner.go`, `scanXSS`). | The marker appears in the response. The report distinguishes *unencoded reflection* (a candidate) from actual script execution — which this tool never claims (see section 4). | ON | heuristic | none |
| `INJ-CRLF` | [WSTG-INPV-15](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling) | One request with encoded CR/LF sequences in a parameter that influences a response header. `new`. | An injected header name appears in the response, or the response is split. Header-injection confirmation is reported as `high`; response splitting as `heuristic`. | **OFF** (`--intrusive --enable crlf`) | high | low-bounded |

### A04:2021 — Insecure Design

| Check id | WSTG | What is sent | What confirms it | Default | Confidence | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| `DESIGN-RATELIMIT` | [WSTG-BUSL-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits) | A small, budgeted burst against a login or OTP-style endpoint, within the per-host rate limit. A variant exists in `internal/scanner/owasp.go` (unreachable); the budgeted `new` form is used. | Every request in the burst returns the same non-throttled status (no `429`, no lockout, no delay). | ON | heuristic | low-bounded |

> A04 is mostly design intent, which is not observable from outside. The single
> row above is the only black-box signal this tool can offer for the category,
> and it is a weak one.

### A05:2021 — Security Misconfiguration

| Check id | WSTG | What is sent | What confirms it | Default | Confidence | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| `HDR-HSTS` | [WSTG-CONF-07](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security) | One HTTPS request; reads `Strict-Transport-Security`. Exists (`internal/scanner/scanner.go`, `securityHeaders`). | The header is absent, or lacks a useful `max-age`, or omits `includeSubDomains`. | ON | confirmed | none |
| `HDR-CSP` | WSTG-CONF-12 *(current WSTG line; not present in v4.2)* | Reads `Content-Security-Policy` on HTML responses. Exists (`internal/scanner/scanner.go`, `securityHeaders`). | The policy is absent, or contains `unsafe-inline`/`unsafe-eval`/`*`. Reported as a hardening gap, not a vulnerability. | ON | high | none |
| `HDR-FRAME` | [WSTG-CLNT-09](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking) | Reads `X-Frame-Options` and the CSP `frame-ancestors` directive. Exists (`internal/scanner/scanner.go`, `securityHeaders`). | Neither is set, so the page may be framed. | ON | confirmed | none |
| `HDR-BROWSER` | WSTG-CONF-14 *(current WSTG line; not present in v4.2)* | Reads `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection`. Exists (`internal/scanner/scanner.go`, `securityHeaders`). | Any of them is missing or weak (for example `Referrer-Policy: unsafe-url`, `X-Content-Type-Options` not `nosniff`). | ON | high | none |
| `HDR-ISOLATION` | *(no v4.2 test; see Secure Headers project)* | Reads `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`. Exists (`internal/scanner/scanner.go`, `securityHeaders`). | A cross-origin isolation header is absent. Informational hardening signal. | ON | informational | none |
| `HDR-MISCONF` | WSTG-CONF-14 *(current WSTG line; not present in v4.2)* | Aggregate view of the header set above. Exists (`internal/scanner/scanner.go`, `securityHeaders`; `internal/scanner/vuln_scanner.go`, `scanSecurityHeaders`). | One or more recommended security headers are missing or set to a known-weak value. | ON | high | none |
| `CFG-METHODS` | [WSTG-CONF-06](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods) | `OPTIONS`, plus one `TRACE`/`TRACK` probe. Exists (`internal/scanner/scanner.go`). | `TRACE`/`TRACK` is enabled, or `OPTIONS` advertises state-changing verbs. | ON | high | none |
| `CFG-CORS` | [WSTG-CLNT-07](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing) | One request with an `Origin` header. Exists (`internal/scanner/scanner.go`, `ScanHTTP`; `internal/scanner/vuln_scanner.go`, `scanCORS`). | `Access-Control-Allow-Origin` is `*` next to credentials, reflects an arbitrary origin, or is `null`. | ON | high | none |
| `CFG-VCS` | [WSTG-CONF-03](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information) | `GET` for a fixed list of `.git/`, `.svn/` and related metadata paths. Exists (`internal/scanner/vuln_scanner.go`, `scanInfoDisclosure`). | A `200` with recognisable VCS content (for example `.git/HEAD` returning `ref:`). | ON | confirmed | none |
| `CFG-ENV` | [WSTG-CONF-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information) | `GET` for a fixed list of `.env`, config, and credential-file names. Exists (`internal/scanner/vuln_scanner.go`, `scanInfoDisclosure`). | A `200` whose body looks like configuration or key material. Only the fact of exposure is reported — **file contents are never exfiltrated beyond the fixed response cap** (see section 3). | ON | confirmed | none |
| `CFG-BACKUP` | [WSTG-CONF-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information) | `GET` for a named set of backup files (for example `wp-config.php.bak`, `index.php~`). Exists (`internal/scanner/vuln_scanner.go`, `scanInfoDisclosure`). | A `200` for a backup path. | ON | high | none |
| `CFG-BACKUPEXT` | [WSTG-CONF-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information) | Same, but appends a fixed extension list (`.bak`, `.old`, `.orig`, `.zip`, `.tar.gz`, `.sql`) to each crawl-discovered path. `new`. | A `200` with a body that is clearly the original file. | ON | high | none |
| `CFG-ADMIN` | [WSTG-CONF-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces) | `GET` for a fixed list of admin, debug, and management paths (`/admin`, `/actuator`, `/swagger`, `/debug/`, `debug/vars`, `debug/pprof`, `/server-status`). Exists (`internal/scanner/vuln_scanner.go`, `scanInfoDisclosure`). | A `200` on a management path, reported as exposed surface. | ON | high | none |
| `CFG-ARTIFACT` | [WSTG-CONF-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information) | `GET` for deployment/CI artifacts (`Dockerfile`, `docker-compose.yml`, `.github/workflows/`, CI config). Exists (`internal/scanner/vuln_scanner.go`, `scanInfoDisclosure`). | A `200` on a build/deploy artifact. | ON | high | none |
| `CFG-DSSTORE` | [WSTG-CONF-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information) | `GET /<path>/.DS_Store` for crawl-discovered directories. `new`. | A `200` whose body starts with the `.DS_Store` magic bytes. | ON | confirmed | none |
| `CFG-ROBOTS` | [WSTG-INFO-03](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage) | `GET /robots.txt`. Exists (`internal/scanner/vuln_scanner.go`, `scanInfoDisclosure`). | The file is present and lists `Disallow` entries that name sensitive paths (a map of what the owner wishes to hide). | ON | informational | none |
| `CFG-SECTXT` | *(no v4.2 test; see RFC 9116)* | `GET /.well-known/security.txt`. `new`. | Reports conformance gaps (missing file, no `Contact`, expired `Expires`). Informational only. | ON | informational | none |
| `CFG-ROBOTSPEC` | *(no v4.2 test; see RFC 9309)* | Reads the already-fetched `/robots.txt` for `Sitemap:` pointers. `new`. | Reports discovered sitemaps. Informational only. | ON | informational | none |
| `CFG-HOSTHDR` | [WSTG-INPV-17](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection) | One request whose `Host` header is set to a canonical unpredictable value. `new`. | The injected host is reflected into the body or into a `Location`/link — the signal behind cache-poisoning and password-reset-poisoning. | ON | heuristic | low-bounded |
| `CFG-SRCMAP` | [WSTG-INFO-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage) | `GET` for `<script>.js.map` next to each discovered script. `new`. | A `200` returning a source map, which exposes original source. | ON | high | none |
| `CFG-BANNER` | [WSTG-INFO-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server) | Reads `Server` and `X-Powered-By`. Exists (`internal/scanner/scanner.go`; `internal/scanner/vuln_scanner.go`, `scanSecurityHeaders`). | Either header discloses a product and version. | ON | high | none |
| `CFG-COMMENT` | [WSTG-INFO-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage) | Scans the already-fetched HTML for HTML comments containing words like `password`, `todo`, `internal`, `debug`. `new`. | Such a comment is present in a served page. | ON | informational | none |
| `CFG-DIRLIST` | [WSTG-CONF-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration) | `GET` for a discovered directory without its index file. Exists (`internal/scanner/vuln_scanner.go`, `scanInfoDisclosure`). | The response is an auto-generated directory listing. | ON | high | none |

### A06:2021 — Vulnerable and Outdated Components

| Check id | WSTG | What is sent | What confirms it | Default | Confidence | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| `COMP-JSLIB` | [WSTG-INFO-08](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework) | Reads the already-fetched HTML for third-party library banner strings. Exists (`internal/scanner/vuln_scanner.go`, `scanInfoDisclosure`). | A library name plus version is visible (for example a jQuery or Bootstrap banner), from which a stale version can be inferred. | ON | heuristic | none |
| `COMP-CVE` | [WSTG-INFO-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server) | Uses the fingerprints above to query the NVD for matching CVEs. Exists (`internal/scanner/cve.go`, `internal/scanner/nvd.go`). | A product/version fingerprint maps to a known CVE. | ON | heuristic | none |

### A07:2021 — Identification and Authentication Failures

| Check id | WSTG | What is sent | What confirms it | Default | Confidence | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| `AUTH-COOKIE` | [WSTG-SESS-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes) | Reads `Set-Cookie` on the target. Exists (`internal/scanner/vuln_scanner.go`, `scanCookies`; `internal/scanner/scanner.go`). | A session cookie lacks `Secure`, lacks `HttpOnly`, uses `SameSite=None` without `Secure`, or has an excessive lifetime. | ON | confirmed | none |
| `AUTH-COOKIEPFX` | [WSTG-SESS-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes) | Reads `Set-Cookie` and checks the name prefix against the required attributes. `new`. | A cookie claims `__Host-` but is not `Secure`/`Path=/`/host-locked, or claims `__Secure-` but is not `Secure`. | ON | confirmed | none |
| `AUTH-CSRF` | [WSTG-SESS-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery) | Parses crawled HTML forms and notes POST endpoints lacking an anti-CSRF token field or a custom header. `new`; passive (no state-changing request is sent). | A state-changing-looking form is served without any obvious anti-CSRF token. Reported as `heuristic`. | ON | heuristic | none |
| `AUTH-DEFCREDS` | [WSTG-ATHN-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials) | One login attempt per entry in a small, fixed list of well-known default pairs. Exists (`internal/scanner/vuln_scanner.go`, `scanDefaultCredentials`). | A default pair is accepted. **No password guessing, no wordlists, no brute force** (see section 3). | ON | high | low-bounded |
| `AUTH-LOCKOUT` | [WSTG-ATHN-03](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism) | A small, budgeted series of failed logins for one account. A variant exists in `internal/scanner/owasp.go` (unreachable); the budgeted `new` form is used. | The account is never locked and no delay is introduced across the series. | ON | heuristic | low-bounded |
| `AUTH-JWT` | WSTG-SESS-10 *(current WSTG line; not present in v4.2)* | Reads, **passively only**, any JWT-shaped token in cookies, headers, or JSON bodies already received. `new`. | Reports structural hints only: `alg: none`, `alg: HS256` alongside an RS256-looking key, missing `exp`, or a token served over cleartext. **The token is never modified, replayed, or cracked.** | ON | informational | none |

### A08:2021 — Software and Data Integrity Failures

| Check id | WSTG | What is sent | What confirms it | Default | Confidence | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| `INTEG-SRI` | *(no v4.2 test; see Third-Party JavaScript Management guide)* | Parses the already-fetched HTML for third-party `<script>`/`<link>` tags. Exists (`internal/scanner/vuln_scanner.go`). | A cross-origin script/style is loaded without an `integrity` attribute. | ON | high | none |

> Integrity failures in the build and release pipeline are out of scope for a
> black-box HTTP scanner; the single row above is the only externally visible
> signal for this category.

### A09:2021 — Security Logging and Monitoring Failures

| Check id | WSTG | What is sent | What confirms it | Default | Confidence | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| `LOG-ERR` | [WSTG-ERRH-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling), [WSTG-ERRH-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces) | Triggers errors (a bad path, a malformed parameter) and reads the response. Exists (`internal/scanner/vuln_scanner.go`, `scanInfoDisclosure`). | The response contains a stack trace, a framework debug page, or a database error. Reported as `informational` for this category. | ON | informational | none |

> A09 is about what the **server** records and alerts on, which a black-box
> scanner cannot see. Verbose errors are a weak proxy at best: they suggest
> input/error handling problems, not the absence of logging. This row exists to
> be honest about the limit, not to claim coverage of the category.

### A10:2021 — Server-Side Request Forgery (SSRF)

| Check id | WSTG | What is sent | What confirms it | Default | Confidence | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| `SSRF-IND` | [WSTG-INPV-19](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery) | A parameter that looks like a URL is given a benign external URL; the tool observes whether the server fetches it. A broader check exists in `internal/scanner/owasp.go` (unreachable); the **bounded opt-in probe is `new`**. | The response (or a timing change) shows the server made the outbound request. **Cloud metadata addresses are never targeted** (see section 3). | **OFF** (`--intrusive --enable ssrf`) | heuristic | low-bounded |

---

## 3. Safety model

Every check above runs behind one seam, `internal/scanner/probe.go`, whose
contract is that **no probe talks to the network except through the `Requester`
interface**, and the only production implementation enforces the rules below.
`probe.go` documents an implementation named `Guard` in `guard.go`; **`guard.go`
is landing in the same release as this document (`new`)** — until it exists, treat
the guarantees below as the intended contract and verify against the code.

**A probe that cannot be bounded is not shipped.**

### Authorization is two keys, not one

An intrusive run requires *both* an approval recorded by someone else *and* the
operator naming that approval:

```sh
# The approver records the authorization (approver's action, not the operator's).
stress-strike authorize add \
  --pattern shop.example.com \
  --approver ciso@corp.example \
  --ticket SEC-4421 \
  --until 2026-11-01T00:00:00Z \
  --reason "pre-release soak, window agreed with the platform team"

# The operator runs against it, naming the ticket.
stress-strike pentest --target https://shop.example.com --authorized SEC-4421
```

- `--authorized <ticket>` must name an entry that is **active** (not expired) and
  that **matches the target** exactly. `pentest` requires an exact rule; a
  wildcard rule such as `*.example.com` or `*` never satisfies `pentest`.
- `internal/authz/policy.go` holds the policy; `internal/authz/audit.go` holds the
  log. `internal/authz.ClassMetadata` targets (cloud instance metadata such as
  `169.254.169.254`) are **denied even if a wildcard rule matches**.
- The matching rule is looked up by `Policy.AuthorizedBy`; wildcards, expiry, and
  the metadata class are all enforced there.

### Refusal has a distinct exit code

A policy refusal exits with **code 3** — distinct from `1` (the run failed) and
`2` (bad usage) — so CI can branch on it
(`cmd/stress-strike/cmd_authz.go`, `authzDeniedExitCode`). The refusal is
printed with the target and the reason, plus the exact `authorize add` command
that would grant access.

### Audit log

Every allow and deny is appended to a hash-chained, append-only log
(`internal/authz/audit.go`). The path is configurable with `--audit-log`
(default `~/.stress-strike/audit.jsonl`). Any edit breaks the chain, which is
what `stress-strike audit verify` detects (it exits `1` on tampering). A webhook
can be notified of each decision with `--notify-webhook`.

### Scope allowlist is fail-closed

- `--allow <pattern>` accepts an exact host (`api.example.com`), a subdomain
  wildcard (`*.example.com`), a `host:port`, a bare IP, a CIDR (`10.0.0.0/8`),
  and an optional path prefix.
- **An empty allowlist refuses everything.** With no `--allow` and no
  `--allow-all`, the scanner sends nothing. This is deliberate: the default is
  "probe nothing", and access is granted by naming it.
- `--allow-all` is the explicit, single, auditable opt-out for a lab you own.

### Budgeting and blast-radius limits

- **Per-host rate limiting and a total request budget.** `--rate` caps requests
  per second per host; `--budget` caps the total number of requests for the run.
  When the budget is spent, the run stops; it never silently continues.
- **Per-request timeout and response-size cap.** `--timeout` bounds each request;
  the response read is capped (`internal/scanner/probe.go`, `DefaultProbeLimit`,
  2 MiB) so a check can never be steered into downloading a large file.
- **Identifiable User-Agent.** Every probe sends
  `stress-strike-scanner/1.0 (+https://github.com/asadbekabdulboqiyev/stress-strike; authorized-assessment)`
  (`internal/scanner/probe.go`, `ScannerUserAgent`) so the target's operator can
  find the traffic in their logs. Redirects are **not** followed, because several
  checks need the raw `3xx` and its `Location` header.
- **`--dry-run`.** Answers every policy question and prints what *would* be sent,
  without sending a byte.

### Intrusive probes are off by default

The following probes never run unless **both** `--intrusive` and
`--enable <probe>` are present:

```sh
stress-strike scan --target shop.example.com --owasp \
  --intrusive --enable write-methods,time-sqli,boolean-sqli,path-traversal,ssrf,crlf
```

| Probe | Enables |
| --- | --- |
| `write-methods` | `AC-VERB` — the single bounded write-method request |
| `time-sqli` | `INJ-SQLI-TIME` — time-based SQLi indicators |
| `boolean-sqli` | `INJ-SQLI-BOOL` — boolean-based SQLi indicators |
| `path-traversal` | `AC-TRAVERSAL` — the bounded traversal probe |
| `ssrf` | `SSRF-IND` — the bounded SSRF probe |
| `crlf` | `INJ-CRLF` — CRLF / response-splitting probe |

Without `--intrusive`, or without the matching `--enable`, the probe is skipped
and the run reports it as not attempted.

### The never-do list

The scanner **never** does any of the following, by design:

- **No write, modify, or delete payloads** — with the single exception of the
  bounded write-method probe (`AC-VERB`), which exists only to detect a missing
  method check.
- **No credential brute force.** Only a small fixed list of default pairs is
  tried (`AUTH-DEFCREDS`); there is no wordlist and no lockout-bypass loop.
- **No denial-of-service or amplification.** Request rates and totals are capped;
  nothing is amplified.
- **No automated exploitation.** A finding is reported, never weaponised.
- **No third-party collaborator services.** The scanner does not hand a URL to an
  external out-of-band service; all observation is in-band.
- **No cloud metadata addresses.** `169.254.169.254` and its peers are never
  targeted (`internal/authz` metadata class).
- **No exfiltration of file contents.** Traversal/config/backup checks confirm
  *exposure* from a fixed response cap; they do not extract the file.

> **Implementation status (this release):**
> Every probe in `internal/scanner/owasp.go` — including the A01–A10 categories
> — is routed through the `Requester` seam (`internal/scanner/probe.go`), so the
> scope pattern, the rate limiter, the budget, the dry-run switch and the
> intrusive gate apply to each individual request. The single check that must
> speak a different scheme than the target (A02's HTTP-to-HTTPS test) builds its
> base URL with `makeRequestURL` for exactly that reason: it used to own a
> private `http.Client` and therefore sent one request per scan that the gate
> never saw. Intrusive categories (A03/A05/A07/A10) run only inside
> `runIntrusive`; with the gate closed the `Requester` refuses each one and the
> category comes back with no evidence — which is reported as `NOT TESTED`.

---

## 4. Detection limits and reporting rules

Every check has a limit. This table is the honest boundary of what each family
can and cannot prove.

| Family | Can show | Cannot show | Why |
| --- | --- | --- | --- |
| Transport / TLS | Weak protocol, weak cipher, expired or untrusted certificate, cleartext HTTP | That application data is safely encrypted end-to-end | The scanner sees the handshake, not the data handling behind it |
| Security headers | A recommended header is missing or weak | That the app is exploitable because of it | A missing header is a hardening gap; exploitation depends on the app |
| Cookies | Missing `Secure`/`HttpOnly`/`SameSite`, bad prefix use | Session fixation, token theft, or session logic bugs | Those need a login flow and a human |
| CORS | A permissive `Access-Control-Allow-*` policy | Whether an attacker can actually read sensitive data with it | Depends on credentials and endpoint semantics |
| SQLi (error/time/boolean) | A signal consistent with injection | Injection is definitely present | Error strings can be triggered by noise; timing is noisy |
| XSS (reflected) | That input is reflected | That it executes as script in a browser | Execution depends on context and encoding the scanner does not run |
| Open redirect | A `Location` pointing off-site | Whether a user is realistically induced to follow it | Social, not technical |
| Path traversal | A signature file was returned | The full extent of readable files | The probe is deliberately shallow |
| SSRF | The server made one outbound request | Reachability of internal networks, or impact | Bounded to a benign external URL |
| Exposure (VCS/env/backup/admin) | That a path returns content | Sensitivity or exploitability of that content | The scanner does not read beyond the cap |
| Outdated components | A version banner | That the version is actually vulnerable | Version-to-CVE mapping is approximate |
| Verb tampering | A method was accepted | That it leads to an escalation | Needs an authenticated, authorized context |

Three reporting rules apply to every run, and the report is written to respect
them:

- **Unencoded reflection is reported as a candidate, never as an exploited
  XSS.** The finding says "input was reflected without encoding"; it never says
  "XSS was executed".
- **Timing differences are reported as `heuristic`, never as confirmed.** A time
  delta is a hint; the report says so.
- **A missing security header is a hardening gap, not a vulnerability.** It is
  labelled as a gap, and it is not scored as a vulnerability on its own.

### Limits that belong to the whole scanner

- **No JavaScript rendering.** Nothing executes scripts or waits for XHR, so
  content that only appears after client-side rendering is invisible to every
  check in the table above.
- **Authenticated areas are only as tested as the session you hand it.** Without
  `--auth-cookie` / `--auth-header` or a configured login flow, everything behind
  a login answers with a redirect or a `401` and produces no evidence — which is
  reported as `NOT TESTED`, not as a pass.
- **`INJ-CRLF` probes the URL, not the request headers.** Go's `net/http`
  refuses CR/LF inside a header value, so the header-carrier variant cannot be
  sent at all; only the `%0d%0a` URL carrier is tested, and the header carrier is
  not claimed.
- **`.dockerignore` is not checked.** The exposure checks cover `.git`, `.env`,
  editor backups and similar; a missing `.dockerignore` is deliberately outside
  the set.

---

## 5. Confidence model

The report labels every finding with one of four levels. The label is a claim
about *evidence*, not about *severity*.

| Level | Evidence required | What you do next | Example bytes in the finding |
| --- | --- | --- | --- |
| `confirmed` | Reproduced independently: two requests, or a deterministic response, agreeing. Matches a signature that cannot be a false positive by accident. | Fix it. | Request head plus the exact matched response fragment (redacted), for example the `Location:` line or the `Server:` banner. |
| `high` | One strong signal, single method, no independent reproduction. | Verify once by hand, then fix. | The request that produced it and the response fragment that matched, redacted to the relevant header/line. |
| `heuristic` | A pattern that *correlates* with the issue (reflection, timing, a missing token). | Treat as a lead, not a result. Reproduce manually before acting or filing. | The request, the observed difference, and the reason it is only a hint. |
| `informational` | A hardening observation or a conformance note (missing `security.txt`, a comment containing "todo"). | Schedule it; it is not urgent. | The observation, with the source (which header/path/comment). |

Every finding records, in addition to the label:

- the **request** sent (method, URL, the specific parameter used);
- the **decisive response bytes**, redacted — enough to reproduce the decision
  without dumping a whole page or any secret;
- a short **false-positive rationale** — what else could produce the same signal
  and how the operator should rule it out.

**Honest note about the code.** The four levels above are the model this
document specifies and the report aims for. Today the false-positive verifier in
`internal/scanner/verify.go` implements **three** levels — `confirmed`,
`probable`, `possible` (`ConfConfirmed`, `ConfProbable`, `ConfPossible`) with
badges `[VERIFIED]`, `[PROBABLE]`, `[UNVERIFIED]`. The mapping is
`confirmed`↔`[VERIFIED]`, `high`↔`probable`↔`[PROBABLE]`,
`heuristic`↔`possible`↔`[UNVERIFIED]`, and `informational` carries no badge.
Also note that `cmd/stress-strike/cmd_pentest.go` (`pentestDeepScan`) computes a
real per-finding confidence but then writes `Confidence: string(scanner.ConfPossible)`
for every emitted finding — so the badge in the pentest report may not reflect
the verifier's verdict. **Verify against the code** before relying on a badge.

---

## 6. Usage

The flags below are wired and covered by tests. `stress-strike scan` is a thin
subcommand that re-execs the standalone `stress-strike-scan` binary with the
same arguments (`cmd/stress-strike/cmd_sub.go`), so both spellings run the same
program. Verify against the code before scripting against it.

### Interface

```text
stress-strike scan --target <host> \
  [--port 443] [--all|--tls|--http|--waf|--security] [--owasp] \
  [--path /,/login] [--rate 10] [--budget 2000] [--timeout 10] \
  [--allow <pattern>] [--allow-all] \
  [--intrusive --enable write-methods|time-sqli|boolean-sqli|path-traversal|ssrf|crlf] \
  [--dry-run] [--authorized <ticket>] [--policy <file>] [--audit-log <file>] \
  [--output-json <file>] [--verbose]

stress-strike pentest --target https://example.com \
  [--passive] [--intrusive] [--enable <probe>] \
  [--rate 10] [--budget 2000] \
  [--allow <pattern>] [--allow-all] [--dry-run] \
  [--authorized <ticket>]
```

### A safe default run

Read-only checks only; nothing intrusive is attempted; the scope is named
explicitly:

```sh
stress-strike scan --target shop.example.com --owasp \
  --path /,/login,/account \
  --rate 10 --budget 2000 --timeout 10 \
  --allow shop.example.com \
  --output-json owasp-report.json
```

Everything in the matrix marked `ON` runs; everything marked `OFF` is skipped
and shown as "not attempted". With no `--allow` and no `--allow-all`, this run
refuses to send anything and exits `3`.

### An opt-in intrusive run

Intrusive probes require authorization *and* the explicit probe name:

```sh
stress-strike scan --target staging.example.com --owasp \
  --allow staging.example.com \
  --intrusive --enable path-traversal,ssrf \
  --rate 5 --budget 500 \
  --authorized SEC-4421
```

A dry run first, to see exactly what would be sent:

```sh
stress-strike scan --target staging.example.com --owasp \
  --intrusive --enable time-sqli --dry-run \
  --allow staging.example.com --authorized SEC-4421
```

### From the web dashboard

The same checker is reachable from the browser. Start the dashboard
(`stress-strike dashboard`), scroll to **OWASP Top 10 Security Scan**, enter a
target URL, and press **Run scan**; the panel POSTs to `/api/owasp/scan`
(`internal/dashboard/owasp.go`).

The browser path is not a weaker one:

- **Scope still defaults to the host you typed.** Sending `allowAll: true` is an
  explicit widening, not the default, and it is visible in the response's
  `scope` field.
- **Intrusive probes are still off by default.** Turning them on makes the
  request an offensive operation (`OpPentest`), so it needs a ticket granted by
  `stress-strike authorize add` — including when you ask for a single family
  through `enable`. Asking for a family *is* asking for an intrusive scan.
- **Every decision, allow or deny, is appended to the same audit log the CLI
  writes** (`authz.DefaultAuditPath()`), so `stress-strike audit` shows
  browser-triggered scans beside shell ones. If that write fails for an allowed
  scan, the scan is refused — a scan that cannot be recorded does not run.
- **One scan at a time.** A second click while one is in flight gets `409`.
- **A refused scan answers `403`** with `{"ok":false,"denied":true,"reason":"…"}`
  carrying the policy's own reason. That is an authorization answer, not a
  session timeout, and the UI shows it as such instead of locking the page.

The web caps are deliberately tighter than the CLI's, so one click cannot pin the
server process:

| Knob | Default | Maximum |
| --- | --- | --- |
| `rate` (requests/s) | 10 | 50 |
| `budget` (requests) | 400 | 2000 |
| `timeoutSec` (per probe) | 10 | 30 |
| `budget / rate` | — | 120 s (refused above) |
| POST body | — | 32 KB |
| `paths` per request | — | 25 |

Unknown JSON fields are rejected rather than ignored, so a typo fails loudly
instead of scanning with a default you did not ask for. Findings and evidence
come from the target server, so the panel writes every one of them with
`textContent` — never as HTML.

### Reading the results

- **JSON** (`--output-json`) is for machines: each finding carries a check id, a
  WSTG id, a `confidence` label, the request, the redacted evidence, and the
  false-positive rationale.
- **HTML/PDF** (from `pentest --format html|pdf|professional`) is for people: a
  findings list grouped by severity, plus the OWASP category matrix
  (`cmd/stress-strike/cmd_pentest.go`, `owaspFullCategories`).
- The terminal output uses the confidence badge
  (`[VERIFIED]` / `[PROBABLE]` / `[UNVERIFIED]`).

### What to do with a `heuristic` finding

A `heuristic` finding is a lead, not a result. Open the request it recorded,
reproduce it once by hand, and check the false-positive rationale — if the
signal has another explanation (a CDN normalising headers, a WAF returning a
generic page, baseline jitter in a timing test), close it as a false positive.
Only a `confirmed` finding should be acted on without manual reproduction.

---

## 7. Legal and ethical use

Only scan systems you own or have **written permission** to test. Unauthorized
scanning is, at minimum, a breach of the target's terms and, in many
jurisdictions, a criminal offence — regardless of intent. stress-strike makes
this a workflow rather than a promise: every offensive run goes through the
`stress-strike authorize` approval described in section 3 before a packet is
sent, every decision is recorded in the tamper-evident audit log, and a refusal
is returned as exit code `3`. The tool is a checklist runner that helps you find
some classes of problem faster; the responsibility for the finding, the
permission to look, and the decision to act all remain yours.

---

## Static analysis

`internal/scanner/checks_passive.go` and `internal/scanner/intrusive.go` hold
long string literals whose whole purpose is to be long: OWASP / WSTG / MDN / RFC
reference URLs, check identifiers, OWASP category labels, the
`ss-canary.invalid` Host-header canary, and the `root:x:0:0:` signature that
exists to *detect* an exposed `/etc/passwd`.

gosec's `G101` (hardcoded credentials) flags every one of them: it screens
high-entropy string literals and it flags declaration names that look
credential-shaped. All 54 were reviewed line by line and none is a credential;
they are recorded in `.gosec-baseline.json` as frozen false positives, which is
that file's documented path for a deliberate, reviewed exception.

Re-check locally with the gosec version CI pins:

```sh
gosec -no-fail -fmt sarif -out gosec.sarif ./...
bash scripts/gosec-ratchet.sh
rm gosec.sarif
```

The ratchet fails on any error-level finding that is **not** in the baseline, so
a genuinely new credential still fails the build. Nothing in this scanner uses
`#nosec`.

## References

WSTG links below are the OWASP Web Security Testing Guide, v4.2 stable (the
per-page URLs resolve to `wstg.owasp.org/v4.2/...`). All URLs were verified as
reachable at the time this document was written.

WSTG test ids cited:

| Id | Title | Source |
| --- | --- | --- |
| WSTG-INFO-02 | Fingerprint Web Server | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server> |
| WSTG-INFO-03 | Review Webserver Metafiles for Information Leakage | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage> |
| WSTG-INFO-05 | Review Webpage Content for Information Leakage | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage> |
| WSTG-INFO-08 | Fingerprint Web Application Framework | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework> |
| WSTG-CONF-02 | Test Application Platform Configuration | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration> |
| WSTG-CONF-03 | Test File Extensions Handling for Sensitive Information | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information> |
| WSTG-CONF-04 | Review Old Backup and Unreferenced Files for Sensitive Information | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information> |
| WSTG-CONF-05 | Enumerate Infrastructure and Application Admin Interfaces | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces> |
| WSTG-CONF-06 | Test HTTP Methods | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods> |
| WSTG-CONF-07 | Test HTTP Strict Transport Security | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security> |
| WSTG-ATHN-02 | Testing for Default Credentials | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials> |
| WSTG-ATHN-03 | Testing for Weak Lock Out Mechanism | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism> |
| WSTG-ATHN-06 | Testing for Browser Cache Weaknesses | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses> |
| WSTG-ATHZ-01 | Testing Directory Traversal File Include | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include> |
| WSTG-ATHZ-04 | Testing for Insecure Direct Object References | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References> |
| WSTG-SESS-02 | Testing for Cookies Attributes | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes> |
| WSTG-SESS-05 | Testing for Cross Site Request Forgery | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery> |
| WSTG-INPV-01 | Testing for Reflected Cross Site Scripting | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting> |
| WSTG-INPV-03 | Testing for HTTP Verb Tampering | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering> |
| WSTG-INPV-05 | Testing for SQL Injection | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection> |
| WSTG-INPV-15 | Testing for HTTP Splitting Smuggling | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling> |
| WSTG-INPV-17 | Testing for Host Header Injection | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection> |
| WSTG-INPV-19 | Testing for Server-Side Request Forgery | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery> |
| WSTG-ERRH-01 | Testing for Improper Error Handling | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling> |
| WSTG-ERRH-02 | Testing for Stack Traces | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces> |
| WSTG-CRYP-01 | Testing for Weak Transport Layer Security | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security> |
| WSTG-CRYP-03 | Testing for Sensitive Information Sent via Unencrypted Channels | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels> |
| WSTG-BUSL-05 | Test Number of Times a Function Can Be Used Limits | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits> |
| WSTG-CLNT-04 | Testing for Client-side URL Redirect | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect> |
| WSTG-CLNT-07 | Testing Cross Origin Resource Sharing | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing> |
| WSTG-CLNT-09 | Testing for Clickjacking | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking> |

Two ids are named in the matrix but are **not** part of WSTG v4.2; they belong to
the current WSTG line and have no individually verifiable v4.2 page, so they are
listed here without a test-page link:

- **WSTG-CONF-12** — Test for Content Security Policy (referenced by `HDR-CSP`).
- **WSTG-CONF-14** — Test Other HTTP Security Header Misconfigurations
  (referenced by `HDR-BROWSER`).
- **WSTG-SESS-10** — Testing JSON Web Tokens (referenced by `AUTH-JWT`).

OWASP Top 10 (2021) category pages:

| Category | Source |
| --- | --- |
| A01:2021 Broken Access Control | <https://owasp.org/Top10/A01_2021-Broken_Access_Control/> |
| A02:2021 Cryptographic Failures | <https://owasp.org/Top10/A02_2021-Cryptographic_Failures/> |
| A03:2021 Injection | <https://owasp.org/Top10/A03_2021-Injection/> |
| A04:2021 Insecure Design | <https://owasp.org/Top10/A04_2021-Insecure_Design/> |
| A05:2021 Security Misconfiguration | <https://owasp.org/Top10/A05_2021-Security_Misconfiguration/> |
| A06:2021 Vulnerable and Outdated Components | <https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/> |
| A07:2021 Identification and Authentication Failures | <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/> |
| A08:2021 Software and Data Integrity Failures | <https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/> |
| A09:2021 Security Logging and Monitoring Failures | <https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/> |
| A10:2021 Server-Side Request Forgery (SSRF) | <https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/> |

OWASP Cheat Sheets referenced by the checks (used where WSTG has no matching
v4.2 test):

| Topic | Source |
| --- | --- |
| HTTP headers (incl. CORS response headers) | <https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html> |
| Content Security Policy | <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html> |
| HTTP Strict Transport Security | <https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html> |
| Clickjacking Defense | <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> |
| Session Management | <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html> |
| JSON Web Token | <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> |
| Web Cache Security | <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> |
| SQL Injection Prevention | <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> |
| Cross Site Scripting Prevention | <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> |
| Server-Side Request Forgery Prevention | <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> |
| Unvalidated Redirects and Forwards | <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html> |
| Insecure Direct Object Reference Prevention | <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> |
| Cross-Site Request Forgery Prevention | <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> |
| Third Party JavaScript Management (SRI) | <https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html> |
| Error Handling | <https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html> |
| Transport Layer Security | <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html> |
| Authorization | <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> |
| Mass Assignment | <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html> |
| Vulnerable Dependency Management | <https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html> |

Project / RFC references:

| Topic | Source |
| --- | --- |
| OWASP Secure Headers Project (COOP/COEP/CORP, `X-XSS-Protection`) | <https://owasp.org/www-project-secure-headers/> |
| API Security Top 10 2023 — API1 Broken Object Level Authorization | <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> |
| WSTG project home | <https://owasp.org/www-project-web-security-testing-guide/> |
| RFC 9116 — A File Format to Aid in Security Vulnerability Disclosure (`security.txt`) | <https://www.rfc-editor.org/rfc/rfc9116> |
| RFC 9309 — Robots Exclusion Protocol | <https://www.rfc-editor.org/rfc/rfc9309> |
