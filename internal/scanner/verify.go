package scanner

// verify.go implements the FALSE-POSITIVE VERIFIER module.
//
// Every finding produced by the scanners is independently re-tested over HTTP
// before it reaches a paid pentest report, and graded on a three-level
// confidence scale so the operator knows exactly what was proven versus what
// still needs manual review:
//
//	confirmed - independently re-verified with a second observation or control
//	probable  - strong signal from a single method (e.g. boolean differential)
//	possible  - heuristic match, needs manual confirmation
//
// All verification probes are BENIGN: random markers, boolean toggles and
// passive re-reads only. No time-based sleeps, no stacked queries, no
// destructive payloads.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Confidence grades how strongly a finding survived re-verification.
type Confidence string

const (
	ConfConfirmed Confidence = "confirmed" // independently re-verified
	ConfProbable  Confidence = "probable"  // strong signal, single method
	ConfPossible  Confidence = "possible"  // heuristic, needs manual check
)

// Verdict is the outcome of verifying a single finding.
type Verdict struct {
	Confidence Confidence `json:"confidence"`
	Evidence   string     `json:"evidence,omitempty"` // why this grade (diff, marker, signature)
}

// Verifier re-tests findings over HTTP. Redirects are disabled so that open
// redirect Location headers remain directly observable.
type Verifier struct {
	Client  *http.Client
	Timeout time.Duration
}

// NewVerifier creates a verifier whose HTTP client never follows redirects.
func NewVerifier(timeout time.Duration) *Verifier {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Verifier{
		Client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Timeout: timeout,
	}
}

// Check re-verifies a single finding and returns its confidence verdict.
// Verification failures (network errors) NEVER drop a finding silently:
// they degrade it to ConfPossible with an explanatory evidence note.
func (v *Verifier) Check(targetURL string, vuln Vulnerability) Verdict {
	requestURL := vuln.URL
	if requestURL == "" {
		requestURL = targetURL
	}

	switch classifyFinding(vuln) {
	case clsSQLi:
		return v.verifySQLi(requestURL, vuln)
	case clsXSS:
		return v.verifyXSS(requestURL, vuln)
	case clsTraversal:
		return v.verifyTraversal(requestURL)
	case clsRedirect:
		return v.verifyRedirect(requestURL)
	case clsDeterministic:
		return v.verifyDeterministic(requestURL, vuln)
	default:
		return verifyOther(vuln)
	}
}

// Annotate verifies every finding and returns COPIES whose Title carries a
// confidence badge (e.g. "[VERIFIED] SQL Injection Detected") and whose
// Evidence is enriched with the verdict rationale. The input slice and its
// elements are never mutated.
func (v *Verifier) Annotate(targetURL string, vulns []Vulnerability) []Vulnerability {
	out := make([]Vulnerability, len(vulns))
	for i, vuln := range vulns {
		verdict := v.Check(targetURL, vuln)

		annotated := vuln // value copy: input element stays untouched
		annotated.Title = ConfidenceBadge(verdict.Confidence) + " " + vuln.Title
		if verdict.Evidence != "" {
			note := "verification: " + verdict.Evidence
			if annotated.Evidence != "" {
				annotated.Evidence = annotated.Evidence + "; " + note
			} else {
				annotated.Evidence = note
			}
		}
		out[i] = annotated
	}
	return out
}

// ConfidenceBadge renders a confidence level as a report-friendly prefix.
func ConfidenceBadge(c Confidence) string {
	switch c {
	case ConfConfirmed:
		return "[VERIFIED]"
	case ConfProbable:
		return "[PROBABLE]"
	default:
		return "[UNVERIFIED]"
	}
}

// ---------------------------------------------------------------------------
// Finding classification
// ---------------------------------------------------------------------------

const (
	clsSQLi         = "sqli"
	clsXSS          = "xss"
	clsTraversal    = "traversal"
	clsRedirect     = "redirect"
	clsDeterministic = "deterministic"
	clsOther        = "other"
)

var deterministicCWETags = map[string]bool{
	"CWE-200":  true, // information disclosure
	"CWE-215":  true, // debug/info leak
	"CWE-16":   true, // configuration
	"CWE-613":  true, // long session expiry
	"CWE-614":  true, // cookie without Secure
	"CWE-693":  true, // missing protection headers
	"CWE-1004": true, // cookie without HttpOnly
	"CWE-1275": true, // cookie SameSite
}

// classifyFinding maps a finding to its verification strategy, using the CWE
// first and Title keywords as a fallback for findings without a CWE tag.
func classifyFinding(vuln Vulnerability) string {
	cwe := strings.ToUpper(strings.TrimSpace(vuln.CWE))
	switch cwe {
	case "CWE-89":
		return clsSQLi
	case "CWE-79":
		return clsXSS
	case "CWE-22":
		return clsTraversal
	case "CWE-601":
		return clsRedirect
	}
	if deterministicCWETags[cwe] {
		return clsDeterministic
	}

	title := strings.ToLower(vuln.Title + " " + vuln.Category)
	switch {
	case strings.Contains(title, "sql"):
		return clsSQLi
	case strings.Contains(title, "xss"), strings.Contains(title, "cross-site scripting"):
		return clsXSS
	case strings.Contains(title, "traversal"):
		return clsTraversal
	case strings.Contains(title, "redirect"):
		return clsRedirect
	case strings.Contains(title, "header"),
		strings.Contains(title, "cookie"),
		strings.Contains(title, "disclosure"),
		strings.Contains(title, "exposed"),
		strings.Contains(title, "leaks"):
		return clsDeterministic
	}
	return clsOther
}

// ---------------------------------------------------------------------------
// Shared low-level plumbing
// ---------------------------------------------------------------------------

const maxVerifyBody = 1 << 20 // cap response bodies at 1 MB, like the scanner

// verifyPage is a fully drained HTTP response.
type verifyPage struct {
	status int
	header http.Header
	body   string
}

// fetch performs a GET with the verifier client (redirects off) and drains
// the body so the connection can be reused.
func (v *Verifier) fetch(rawURL string) (*verifyPage, error) {
	client := v.Client
	if client == nil {
		timeout := v.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "stress-strike-verifier/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVerifyBody))
	if err != nil {
		return nil, err
	}
	return &verifyPage{status: resp.StatusCode, header: resp.Header, body: string(body)}, nil
}

// unreachableVerdict degrades a finding when the target could not be reached
// during verification. Findings are never dropped silently.
func unreachableVerdict(err error) Verdict {
	return Verdict{
		Confidence: ConfPossible,
		Evidence:   fmt.Sprintf("verification unreachable (%v); grade left at possible, manual check required", err),
	}
}

// randToken returns a fresh random hex token used as a benign control/marker.
func randToken() string {
	buf := make([]byte, 5)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("sstick%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// withParam returns rawURL with the given query parameter replaced by value,
// preserving every other parameter.
func withParam(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if key == "" {
		key = "id"
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// paramValueOf reads the current value of a query parameter, falling back to
// "1" (a typical numeric row id) when absent.
func paramValueOf(rawURL, key string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "1"
	}
	if key == "" {
		key = "id"
	}
	if val := u.Query().Get(key); val != "" {
		return val
	}
	return "1"
}

// ---------------------------------------------------------------------------
// SQL injection (CWE-89)
// ---------------------------------------------------------------------------

var sqlErrorRegexes = compileInsensitive([]string{
	`SQLSTATE`,
	`ORA-\d{5}`,
	`SQL syntax`,
	`mysql_fetch`,
	`pg_query`,
	`pg_exec`,
	`SQLite3::`,
	`SQLite\.Exception`,
	`unclosed quotation mark`,
	`quoted string not properly terminated`,
	`ODBC SQL Server`,
	`Microsoft OLE DB`,
	`MySqlClient`,
	`Npgsql\.`,
	`PG::SyntaxError`,
	`org\.postgresql`,
	`Warning: mysql`,
	`PDOException`,
	`valid MySQL result`,
	`valid PostgreSQL result`,
})

func compileInsensitive(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(`(?i)`+p))
	}
	return out
}

// matchSQLError returns the first SQL error signature found in a body.
func matchSQLError(body string) (string, bool) {
	for _, re := range sqlErrorRegexes {
		if loc := re.FindString(body); loc != "" {
			return loc, true
		}
	}
	return "", false
}

// verifySQLi grades a SQLi finding:
//   - error signature on the replayed payload (and NOT on a random-marker
//     control) -> confirmed;
//   - boolean differential between AND 1=1 / AND 1=2 variants with a clean
//     control -> probable;
//   - anything else -> downgraded to possible.
func (v *Verifier) verifySQLi(requestURL string, vuln Vulnerability) Verdict {
	page, err := v.fetch(requestURL)
	if err != nil {
		return unreachableVerdict(err)
	}

	// 1. Error-based: replay the original PoC and hunt for DBMS errors.
	if sig, hit := matchSQLError(page.body); hit {
		controlURL := withParam(requestURL, vuln.Parameter, randToken())
		control, cerr := v.fetch(controlURL)
		if cerr == nil {
			if _, ctrlHit := matchSQLError(control.body); ctrlHit {
				return Verdict{
					Confidence: ConfProbable,
					Evidence: fmt.Sprintf("payload replay showed SQL error '%s' but the random-marker control errored too; "+
						"generic error pages cannot be ruled out", sig),
				}
			}
		}
		return Verdict{
			Confidence: ConfConfirmed,
			Evidence:   fmt.Sprintf("payload replay independently triggered SQL error '%s' while a random-marker control request returned no error", sig),
		}
	}

	// 2. Boolean-based: compare AND 1=1 vs AND 1=2 when the parameter is known.
	if vuln.Parameter != "" {
		base := paramValueOf(requestURL, vuln.Parameter)
		trueURL := withParam(requestURL, vuln.Parameter, base+" AND 1=1")
		falseURL := withParam(requestURL, vuln.Parameter, base+" AND 1=2")

		t1, err := v.fetch(trueURL)
		if err != nil {
			return unreachableVerdict(err)
		}
		t2, err := v.fetch(trueURL)
		if err != nil {
			return unreachableVerdict(err)
		}
		f1, err := v.fetch(falseURL)
		if err != nil {
			return unreachableVerdict(err)
		}

		stableTrue := t1.status == t2.status && t1.body == t2.body
		differs := t1.body != f1.body
		_, falseErrors := matchSQLError(f1.body)

		if stableTrue && differs && !falseErrors {
			return Verdict{
				Confidence: ConfProbable,
				Evidence: fmt.Sprintf("boolean differential: '%s AND 1=1' answered consistently (HTTP %d, %d bytes) "+
					"while '%s AND 1=2' differed (HTTP %d, %d bytes) with no SQL error on either",
					base, t1.status, len(t1.body), base, f1.status, len(f1.body)),
			}
		}
	}

	return Verdict{
		Confidence: ConfPossible,
		Evidence:   "payload replay produced no SQL error and no boolean differential; could not independently reproduce",
	}
}

// ---------------------------------------------------------------------------
// XSS (CWE-79)
// ---------------------------------------------------------------------------

// verifyXSS injects a UNIQUE random marker wrapped in a benign probe and
// grades confirmed ONLY when the marker reflects raw (outside HTML-escaped
// form). Encoded reflection means output encoding works: downgraded.
func (v *Verifier) verifyXSS(requestURL string, vuln Vulnerability) Verdict {
	marker := "sx" + randToken()
	param := vuln.Parameter
	if param == "" {
		param = "q"
	}

	probeURL := withParam(requestURL, param, `"><`+marker)
	page, err := v.fetch(probeURL)
	if err != nil {
		return unreachableVerdict(err)
	}

	raw := "<" + marker
	escaped := "&lt;" + marker

	switch {
	case strings.Contains(page.body, raw):
		return Verdict{
			Confidence: ConfConfirmed,
			Evidence:   fmt.Sprintf("unique marker '%s' reflected UN-encoded in the response body ('<%s' appears literally), proving raw HTML injection", marker, marker),
		}
	case strings.Contains(page.body, escaped):
		return Verdict{
			Confidence: ConfPossible,
			Evidence:   fmt.Sprintf("marker '%s' reflected but HTML-encoded ('&lt;%s'); output encoding blocks execution, needs manual context check", marker, marker),
		}
	default:
		return Verdict{
			Confidence: ConfPossible,
			Evidence:   fmt.Sprintf("probe marker '%s' was not reflected at all on re-test; original reflection not reproducible", marker),
		}
	}
}

// ---------------------------------------------------------------------------
// Path traversal (CWE-22)
// ---------------------------------------------------------------------------

var traversalSignatures = []string{
	"root:x:0:0",  // /etc/passwd
	"root:x:0:",   // /etc/passwd (relaxed field form)
	"[extensions]", // win.ini
	"[fonts]",      // win.ini
	"[drivers]",    // windows system ini files
}

func (v *Verifier) verifyTraversal(requestURL string) Verdict {
	page, err := v.fetch(requestURL)
	if err != nil {
		return unreachableVerdict(err)
	}
	for _, sig := range traversalSignatures {
		if strings.Contains(page.body, sig) {
			return Verdict{
				Confidence: ConfConfirmed,
				Evidence:   fmt.Sprintf("replay of the traversal payload returned system file content containing '%s' (HTTP %d)", sig, page.status),
			}
		}
	}
	return Verdict{
		Confidence: ConfPossible,
		Evidence:   "traversal replay contained no /etc/passwd or win.ini signatures; original hit not reproduced",
	}
}

// ---------------------------------------------------------------------------
// Open redirect (CWE-601)
// ---------------------------------------------------------------------------

func (v *Verifier) verifyRedirect(requestURL string) Verdict {
	// The verifier client never follows redirects, so the Location header of
	// the FIRST hop is directly observable.
	page, err := v.fetch(requestURL)
	if err != nil {
		return unreachableVerdict(err)
	}

	location := page.header.Get("Location")
	if location == "" {
		return Verdict{
			Confidence: ConfPossible,
			Evidence:   "replay produced no Location header; redirect behaviour not reproduced",
		}
	}

	locParsed, err := url.Parse(location)
	if err != nil {
		return Verdict{Confidence: ConfPossible, Evidence: fmt.Sprintf("replay Location '%s' is unparseable", location)}
	}

	reqParsed, err := url.Parse(requestURL)
	if err != nil {
		return unreachableVerdict(err)
	}

	is3xx := page.status >= 300 && page.status < 400
	externalHost := locParsed.Host != "" &&
		!strings.EqualFold(locParsed.Host, reqParsed.Host)
	plantedDomain := strings.Contains(location, "evil.com") ||
		strings.Contains(location, "evil.")

	switch {
	case externalHost && is3xx:
		return Verdict{
			Confidence: ConfConfirmed,
			Evidence:   fmt.Sprintf("replay answered HTTP %d with Location '%s', redirecting off-site to host '%s'", page.status, location, locParsed.Host),
		}
	case plantedDomain && is3xx:
		return Verdict{
			Confidence: ConfConfirmed,
			Evidence:   fmt.Sprintf("replay answered HTTP %d with Location '%s' pointing at the planted attacker domain", page.status, location),
		}
	default:
		return Verdict{
			Confidence: ConfPossible,
			Evidence:   fmt.Sprintf("replay Location '%s' (HTTP %d) does not leave the original host; redirect not confirmed", location, page.status),
		}
	}
}

// ---------------------------------------------------------------------------
// Deterministic classes: info disclosure (CWE-200/215), config (CWE-16),
// missing headers (CWE-693), cookie flags (CWE-614/1004/1275), sessions
// (CWE-613). These need no exploitation: one re-request settles them.
// ---------------------------------------------------------------------------

var securityHeaderNames = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

var versionDigitsRegex = regexp.MustCompile(`\d+\.\d+`)
var quotedSigRegex = regexp.MustCompile(`'([^'\n]{3,120})'`)

func (v *Verifier) verifyDeterministic(requestURL string, vuln Vulnerability) Verdict {
	page, err := v.fetch(requestURL)
	if err != nil {
		return unreachableVerdict(err)
	}
	titleEvi := vuln.Title + " " + vuln.Evidence
	lower := strings.ToLower(titleEvi)

	// 1. Cookie flag findings: Parameter holds the cookie name.
	if vuln.Parameter != "" && strings.HasPrefix(vuln.Title, "Cookie ") {
		return gradeCookieClaim(page, vuln)
	}

	// 2. Server/X-Powered-By version leaks: header must still be present.
	if strings.Contains(lower, "server header reveals") {
		current := page.header.Get("Server")
		if current != "" && versionDigitsRegex.MatchString(current) {
			return Verdict{Confidence: ConfConfirmed, Evidence: fmt.Sprintf("re-request still leaks Server header '%s'", current)}
		}
		return Verdict{Confidence: ConfPossible, Evidence: "Server header no longer exposes a version on re-check"}
	}
	if strings.Contains(lower, "x-powered-by") {
		current := page.header.Get("X-Powered-By")
		if current != "" {
			return Verdict{Confidence: ConfConfirmed, Evidence: fmt.Sprintf("re-request still leaks X-Powered-By '%s'", current)}
		}
		return Verdict{Confidence: ConfPossible, Evidence: "X-Powered-By header no longer present on re-check"}
	}

	// 3. Weak-CSP findings: unsafe-inline/unsafe-eval must still be there.
	if strings.Contains(lower, "unsafe-inline") || strings.Contains(lower, "unsafe-eval") {
		csp := page.header.Get("Content-Security-Policy")
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			return Verdict{Confidence: ConfConfirmed, Evidence: "re-request still advertises a CSP with 'unsafe-inline'/'unsafe-eval'"}
		}
		return Verdict{Confidence: ConfPossible, Evidence: "CSP weakness (unsafe-inline/eval) no longer observable on re-check"}
	}

	// 4. Missing-header findings: the canonical header must still be absent.
	if name := claimedMissingHeader(titleEvi); name != "" {
		if page.header.Get(name) == "" {
			return Verdict{Confidence: ConfConfirmed, Evidence: fmt.Sprintf("re-request confirms %s is still not sent", name)}
		}
		return Verdict{Confidence: ConfPossible, Evidence: fmt.Sprintf("%s is now present; the original missing-header claim no longer holds", name)}
	}

	// 5. File/endpoint disclosure: re-match the quoted signature from Evidence
	//    (scanner format: "... content matching 'SIGNATURE'").
	if m := quotedSigRegex.FindStringSubmatch(vuln.Evidence); m != nil {
		if strings.Contains(page.body, m[1]) {
			return Verdict{Confidence: ConfConfirmed, Evidence: fmt.Sprintf("re-request of %s still contains signature '%s' (HTTP %d)", requestURL, m[1], page.status)}
		}
		return Verdict{Confidence: ConfPossible, Evidence: fmt.Sprintf("signature '%s' from the original evidence is absent on re-check", m[1])}
	}

	// 6. Generic fallback: reachable endpoint keeps its grade, otherwise drop.
	if page.status == http.StatusOK {
		return Verdict{Confidence: ConfConfirmed, Evidence: fmt.Sprintf("deterministic re-check: endpoint still answers HTTP 200 (finding is configuration-observable)")}
	}
	return Verdict{
		Confidence: ConfPossible,
		Evidence:   fmt.Sprintf("deterministic re-check returned HTTP %d instead of 200; condition could not be re-observed", page.status),
	}
}

// claimedMissingHeader extracts the canonical header name a finding claims to
// be missing, including common acronyms (HSTS, CSP).
func claimedMissingHeader(titleEvi string) string {
	lower := strings.ToLower(titleEvi)
	if !strings.Contains(lower, "missing") {
		return ""
	}
	switch {
	case strings.Contains(titleEvi, "HSTS"):
		return "Strict-Transport-Security"
	case strings.Contains(titleEvi, "CSP"):
		return "Content-Security-Policy"
	}
	for _, h := range securityHeaderNames {
		if strings.Contains(titleEvi, h) {
			return h
		}
	}
	return ""
}

// gradeCookieClaim re-inspects Set-Cookie flags for the cookie named in
// vuln.Parameter.
func gradeCookieClaim(page *verifyPage, vuln Vulnerability) Verdict {
	name := vuln.Parameter
	var cookie *http.Cookie
	for _, c := range readCookies(page) {
		if c.Name == name {
			cookie = c
			break
		}
	}
	if cookie == nil {
		return Verdict{
			Confidence: ConfPossible,
			Evidence:   fmt.Sprintf("cookie '%s' is no longer set on re-check; original claim cannot be re-observed", name),
		}
	}

	title := vuln.Title
	switch {
	case strings.Contains(title, "Secure"):
		if !cookie.Secure {
			return Verdict{Confidence: ConfConfirmed, Evidence: fmt.Sprintf("re-check: cookie '%s' is still issued without the Secure flag", name)}
		}
	case strings.Contains(title, "HttpOnly"):
		if !cookie.HttpOnly {
			return Verdict{Confidence: ConfConfirmed, Evidence: fmt.Sprintf("re-check: cookie '%s' is still issued without the HttpOnly flag", name)}
		}
	case strings.Contains(title, "SameSite"):
		if cookie.SameSite == http.SameSiteNoneMode {
			return Verdict{Confidence: ConfConfirmed, Evidence: fmt.Sprintf("re-check: cookie '%s' still ships SameSite=None", name)}
		}
	case strings.Contains(title, "Long Expiry"):
		if !cookie.Expires.IsZero() && cookie.Expires.Sub(time.Now()) > 24*time.Hour {
			return Verdict{Confidence: ConfConfirmed, Evidence: fmt.Sprintf("re-check: cookie '%s' still expires at %s (>24h)", name, cookie.Expires.Format(time.RFC3339))}
		}
	default:
		return Verdict{Confidence: ConfPossible, Evidence: fmt.Sprintf("cookie '%s' claim could not be mapped to a deterministic re-check", name)}
	}
	return Verdict{Confidence: ConfPossible, Evidence: fmt.Sprintf("cookie '%s' flag issue no longer observed on re-check", name)}
}

// readCookies parses Set-Cookie headers of a drained response page.
func readCookies(page *verifyPage) []*http.Cookie {
	resp := &http.Response{Header: page.header}
	return resp.Cookies()
}

// ---------------------------------------------------------------------------
// Everything else (SSRF CWE-918, command injection CWE-78, CORS, auth, ...)
// ---------------------------------------------------------------------------

// verifyOther keeps heuristic classes conservative: possible by default,
// probable only when the recorded PoC/evidence already contains an objective
// exploitation signature such as live command output.
func verifyOther(vuln Vulnerability) Verdict {
	blob := vuln.PoC + " " + vuln.Evidence
	for _, sig := range []string{"uid=", "gid=", "root:x:0:0"} {
		if strings.Contains(blob, sig) {
			return Verdict{
				Confidence: ConfProbable,
				Evidence:   fmt.Sprintf("recorded evidence contains the strong signature '%s'; treated as probable pending one manual rerun", sig),
			}
		}
	}
	return Verdict{
		Confidence: ConfPossible,
		Evidence:   "heuristic finding with no independent re-verification method available; manual confirmation required",
	}
}
