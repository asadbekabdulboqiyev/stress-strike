// checks_passive.go implements the OWASP Top 10 (2021) passive check family.
//
// What "passive" means here
// -------------------------
// A passive check never mutates state, never guesses, and never sends a byte a
// normal browser would not send. Every probe this file issues is a plain GET of
// a URL that is either a configured scan path, a well-known public location
// (/robots.txt, /.env, ...), or a deliberately nonexistent control path used to
// calibrate the soft-404 baseline. There is no SQL payload, no fuzzing, no HTTP
// method other than GET, and no login. Everything goes through Requester
// (probe.go) so Guard's scope allowlist, rate limit, budget and timeout still
// apply, and every probe is unit-tested against an in-memory fake Requester.
//
// What this file refuses to do
// ----------------------------
//   - It never claims XSS, SQLi or any other exploitable flaw it did not see.
//     A missing header is reported as a hardening gap, not as a vulnerability.
//   - It never reports a fixed-path finding (/.env, /Dockerfile, ...) unless the
//     mandatory soft-404 baseline says the response differs from what a
//     certainly-nonexistent path returns, AND the body matches a content
//     signature. Status 200 alone proves nothing on the modern web.
//   - It never emits a finding without Evidence. Evidence always starts with
//     confidence=<confirmed|high|heuristic|informational>; followed by a quoted
//     observation and a false-positive rationale. Vulnerability has no
//     Confidence field (vuln_scanner.go is frozen), so the confidence lives in
//     that Evidence prefix, and passiveConfidenceLevels is the canonical set.
//   - It never echoes a cookie value or a JWT. Cookie values become
//     <redacted len=N>; a JWT is referenced only by SHA-256.
//   - It never flags 403/401 as an exposed artifact: 403 on .htaccess is the
//     correct, secure answer.
//
// Request budget with the default single path: 3 soft-404 controls + 1 page +
// 2 host-header probes + <=21 artifact probes + 2 metafile probes + <=25
// source-map probes, i.e. roughly 55 GETs.
//
// OWASP mapping: findings carry the same "A05:2021 Security Misconfiguration"
// style Category strings used by vuln_scanner.go, so they merge into one report
// with the rest of the tool.
package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

// ---------------------------------------------------------------------------
// Check identifiers. One prefix per weakness family so a report reader can tell
// two findings apart and so dedup has a stable key component.
// ---------------------------------------------------------------------------

const (
	passiveCheckIDHeaders   = "PSV-HDR"      // security headers present
	passiveCheckIDCSP       = "PSV-CSP"      // Content-Security-Policy analysis
	passiveCheckIDClickjack = "PSV-CLICK"    // X-Frame-Options / frame-ancestors
	passiveCheckIDHSTS      = "PSV-HSTS"     // Strict-Transport-Security
	passiveCheckIDCookie    = "PSV-COOKIE"   // Set-Cookie attributes
	passiveCheckIDPrefix    = "PSV-PREFIX"   // __Host- / __Secure- cookie prefixes
	passiveCheckIDJWTAlg    = "PSV-JWTALG"   // JWT alg weaknesses
	passiveCheckIDJWTExp    = "PSV-JWTEXP"   // JWT missing expiry
	passiveCheckIDJWTCrypto = "PSV-JWTCRYPT" // JWT mixed signing algorithms
	passiveCheckIDCache     = "PSV-CACHE"    // Cache-Control on sensitive responses
	passiveCheckIDHost      = "PSV-HOST"     // Host header reflection
	passiveCheckIDMeta      = "PSV-META"     // robots.txt / security.txt
	passiveCheckIDArtifact  = "PSV-ARTIFACT" // exposed config/source artifacts
	passiveCheckIDSrcMap    = "PSV-SRCMAP"   // exposed JavaScript source maps
	passiveCheckIDMixed     = "PSV-MIXED"    // mixed content
	passiveCheckIDSRI       = "PSV-SRI"      // missing Subresource Integrity
	passiveCheckIDBanner    = "PSV-BANNER"   // server version banners
	passiveCheckIDComment   = "PSV-COMMENT"  // secrets in HTML comments
	passiveCheckIDError     = "PSV-ERR"      // verbose error messages
)

// OWASP Top 10 (2021) category strings. Same spelling as vuln_scanner.go so a
// merged report groups them correctly.
const (
	passiveCategoryMisconfig = "A05:2021 Security Misconfiguration"
	passiveCategoryCrypto    = "A02:2021 Cryptographic Failures"
	passiveCategoryInjection = "A03:2021 Injection"
	passiveCategoryAuth      = "A07:2021 Identification and Authentication Failures"
	passiveCategoryIntegrity = "A08:2021 Software and Data Integrity Failures"
)

// Evidence confidence vocabulary. Vulnerability has no Confidence field, so the
// level is carried as the first token of Evidence: "confidence=<level>; ...".
const (
	passiveConfidenceConfirmed     = "confirmed"     // observed byte-for-byte
	passiveConfidenceHigh          = "high"          // strong signature, one manual look advised
	passiveConfidenceHeuristic     = "heuristic"     // pattern match; exploitability not proven
	passiveConfidenceInformational = "informational" // hygiene / fingerprinting only
)

// passiveConfidenceLevels is the canonical set. Tests assert every finding uses
// exactly one of these, and only these, as its Evidence prefix.
var passiveConfidenceLevels = map[string]bool{
	passiveConfidenceConfirmed:     true,
	passiveConfidenceHigh:          true,
	passiveConfidenceHeuristic:     true,
	passiveConfidenceInformational: true,
}

// CVSS values. They are consistent with the Severity field: info findings score
// 0.0, low ~2.6, medium ~5.3, high 7.5. Hardening gaps (missing headers) are
// explicitly NOT scored as exploitable flaws.
const (
	passiveCVSSInfo   = 0.0
	passiveCVSSLow    = 2.6
	passiveCVSSMedium = 5.3
	passiveCVSSHigh   = 7.5
)

// passiveCVSSFor keeps the score consistent with the severity label. A finding
// whose severity was raised or lowered dynamically (a cookie that is only a
// session cookie, a reflection that only sometimes reaches a token) must not
// keep the score the old label would have justified.
func passiveCVSSFor(severity string) float64 {
	switch severity {
	case "critical":
		return 9.8
	case "high":
		return passiveCVSSHigh
	case "medium":
		return passiveCVSSMedium
	case "low":
		return passiveCVSSLow
	default:
		return passiveCVSSInfo
	}
}

// Caps. A scanner must never be talked into unbounded work.
const (
	// passiveMaxPaths caps PassiveOptions.Paths. Extra entries are dropped.
	passiveMaxPaths = 25
	// passiveMaxMapProbes caps how many "<script>.map" fetches one scan makes.
	passiveMaxMapProbes = 25
	// passiveMaxMixedResources caps mixed-content and SRI findings per scan, so
	// a page that references hundreds of http:// assets cannot flood the report.
	passiveMaxMixedResources = 25
	// passiveMaxResourcesPerPage caps how many <script>/<link> elements are
	// remembered per page, so a pathological page cannot blow up memory.
	passiveMaxResourcesPerPage = 200
	// passiveMaxCommentsPerPage caps remembered HTML comments.
	passiveMaxCommentsPerPage = 40
	// passiveMaxCommentBytes caps the bytes taken from one HTML comment.
	passiveMaxCommentBytes = 2048
	// passiveJWTScanLimit bounds the JWT regex over a response body.
	passiveJWTScanLimit = 256 << 10
	// passiveMaxJWTsPerFind caps JWT regex hits per text.
	passiveMaxJWTsPerFind = 10
	// passiveMaxJWTsTotal caps distinct JWTs remembered per scan.
	passiveMaxJWTsTotal = 50
	// passiveMaxExcerpt bounds any evidence excerpt.
	passiveMaxExcerpt = 160
	// passiveSoft404Samples is the number of nonexistent control paths fetched
	// to build the soft-404 baseline.
	passiveSoft404Samples = 3
	// passiveSoft404TolerancePct is the +/- body length tolerance used together
	// with a matching <title> to recognise a themed 404.
	passiveSoft404TolerancePct = 2
	// passiveHostCanary is the hostname used by the Host header canary probes.
	passiveHostCanary = "ss-canary.invalid"
	// passiveHSTSMinAge is the HSTS max-age considered adequate (1 year).
	passiveHSTSMinAge = 31536000
	// passiveSensitiveCacheMaxAge is the Cache-Control max-age above which a
	// cacheable authenticated response is worth reporting.
	passiveSensitiveCacheMaxAge = 1000
	// passiveHostWindow bounds the bytes taken around a Host canary reflection.
	passiveHostWindow = 160
	// passiveMaxArtifacts caps how many artifact paths are probed per scan.
	passiveMaxArtifacts = 25
)

// References. Every URL here was fetched and confirmed to return HTTP 200
// before it was added; do not add an unverified reference.
const (
	passiveRefTopA02 = "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
	passiveRefTopA03 = "https://owasp.org/Top10/A03_2021-Injection/"
	passiveRefTopA05 = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
	passiveRefTopA07 = "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
	passiveRefTopA08 = "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"

	passiveRefWSTGHeaders   = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/14-Other_HTTP_Security_Header_Misconfigurations"
	passiveRefWSTGCSP       = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/12-Content_Security_Policy"
	passiveRefWSTGHSTS      = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/07-HTTP_Strict_Transport_Security"
	passiveRefWSTGFiles     = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/03-File_Extensions_Handling_for_Sensitive_Information"
	passiveRefWSTGBackup    = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
	passiveRefWSTGCache     = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication/06-Browser_Cache_Weaknesses"
	passiveRefWSTGMetafiles = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"
	passiveRefWSTGLEak      = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage"
	passiveRefWSTGCookies   = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management/02-Cookies_Attributes"
	passiveRefWSTGJWT       = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management/10-JSON_Web_Tokens"
	passiveRefWSTGHost      = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/17-Host_Header_Injection"
	passiveRefWSTGStack     = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Error_Handling/02-Stack_Traces"
	passiveRefWSTGClickjack = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side/09-Clickjacking"
	passiveRefWSTGResource  = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side/06-Client-side_Resource_Manipulation"

	passiveRefCSHeaders   = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
	passiveRefCSCSP       = "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
	passiveRefCSHSTS      = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
	passiveRefCSSession   = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
	passiveRefCSJWT       = "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html"
	passiveRefCSClickjack = "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
	passiveRefCSErrors    = "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
	passiveRefCSTLS       = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
	passiveRefCSWebCache  = "https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html"
	passiveRefCSDocker    = "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"

	passiveRefMDNCookie = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie"
	passiveRefMDNCSP    = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy"
	passiveRefMDNXFO    = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options"
	passiveRefMDNHSTS   = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security"
	passiveRefMDNXCTO   = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options"
	passiveRefMDNRP     = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy"
	passiveRefMDNPP     = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy"
	passiveRefMDNCC     = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control"
	passiveRefMDNSRI    = "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"

	passiveRefRFC9116 = "https://www.rfc-editor.org/rfc/rfc9116"
	passiveRefRFC6265 = "https://www.rfc-editor.org/rfc/rfc6265"
	passiveRefRFC7234 = "https://www.rfc-editor.org/rfc/rfc7234"
	passiveRefRFC7519 = "https://www.rfc-editor.org/rfc/rfc7519"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// PassiveOptions configures a PassiveScanner. The zero value is valid and means
// "fetch / with the default read cap and the scanner User-Agent".
type PassiveOptions struct {
	// Paths are the page paths to fetch and analyse. Default: []string{"/"}.
	// Each entry must be root-relative: "/app", "/search?q=x". An entry with its
	// own scheme or host is rejected, a full URL is not accepted, and entries are
	// capped at passiveMaxPaths (extras are dropped, in order). Duplicates are
	// collapsed.
	Paths []string

	// MaxBodyBytes caps how much of each response is read. 0 (or negative) means
	// DefaultProbeLimit. It is never reduced below 1.
	MaxBodyBytes int64

	// UserAgent overrides ScannerUserAgent for these probes. Empty means
	// ScannerUserAgent, so a probe is always identifiable in the target's log.
	UserAgent string

	// KnownSubdomains tells the HSTS check the operator has confirmed subdomains
	// exist. That is the only case where a missing includeSubDomains is worth
	// reporting at all.
	KnownSubdomains bool
}

// PassiveScanner runs the passive check family against one base URL. It is safe
// for sequential use; ScanAll itself is not concurrent.
type PassiveScanner struct {
	base    *url.URL
	req     Requester
	opts    PassiveOptions
	maxBody int64
	paths   []passivePath

	noteMu sync.Mutex
	notes  []PassiveProbeNote
}

// PassiveProbeNote records why a probe did not produce a result: a policy
// refusal (with its sentinel name), a transport error, or a panicking check.
//
// Method is the HTTP method for a refused probe. For a panic it names the phase
// or check that died (for example "check jwt"), so a note is always traceable.
type PassiveProbeNote struct {
	Method   string `json:"method"`
	URL      string `json:"url"`
	Sentinel string `json:"sentinel,omitempty"`
	Err      string `json:"error"`
}

// NewPassiveScanner builds a scanner for baseURL. It fails closed: a nil
// Requester, an empty or unparseable URL, a missing host, userinfo in the URL,
// or a scheme other than http/https all return an error. It never guesses a
// scheme and never prepends "http://".
func NewPassiveScanner(baseURL string, req Requester, opts PassiveOptions) (*PassiveScanner, error) {
	if req == nil {
		return nil, errors.New("passive: requester is nil (build a Guard first)")
	}
	raw := strings.TrimSpace(baseURL)
	if raw == "" {
		return nil, errors.New("passive: base URL is empty")
	}
	base, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("passive: base URL %q: %w", raw, err)
	}
	if base.Scheme == "" {
		return nil, fmt.Errorf("passive: base URL %q has no scheme; http:// or https:// is required and nothing is assumed for you", raw)
	}
	if !strings.EqualFold(base.Scheme, "http") && !strings.EqualFold(base.Scheme, "https") {
		return nil, fmt.Errorf("passive: base URL scheme %q is not http/https", base.Scheme)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("passive: base URL %q has no host", raw)
	}
	if base.User != nil {
		return nil, fmt.Errorf("passive: base URL %q must not carry userinfo; use the Requester for credentials", raw)
	}
	base.Scheme = strings.ToLower(base.Scheme)
	base.Fragment = ""
	if base.Path == "" {
		base.Path = "/"
	}

	entries := opts.Paths
	if len(entries) == 0 {
		entries = []string{"/"}
	}
	seen := map[string]struct{}{}
	paths := make([]passivePath, 0, len(entries))
	for _, entry := range entries {
		if len(paths) >= passiveMaxPaths {
			break
		}
		if strings.TrimSpace(entry) == "" {
			// An empty entry means the site root, so Paths: []string{""} is
			// treated exactly like Paths: []string{"/"}.
			entry = "/"
		}
		pp, perr := passiveProbePath(entry)
		if perr != nil {
			return nil, perr
		}
		if _, dup := seen[pp.display]; dup {
			continue
		}
		seen[pp.display] = struct{}{}
		paths = append(paths, pp)
	}

	maxBody := opts.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultProbeLimit
	}

	return &PassiveScanner{
		base:    base,
		req:     req,
		opts:    opts,
		maxBody: maxBody,
		paths:   paths,
	}, nil
}

// Notes returns a copy of the probe notes recorded so far: policy refusals,
// transport errors and any check that panicked. A check with notes still
// contributes its findings; the note explains what it could not see.
func (p *PassiveScanner) Notes() []PassiveProbeNote {
	if p == nil {
		return nil
	}
	p.noteMu.Lock()
	defer p.noteMu.Unlock()
	out := make([]PassiveProbeNote, len(p.notes))
	copy(out, p.notes)
	return out
}

// ScanAll runs every passive check and returns findings sorted by severity
// (critical first), then ID, then URL, then title. It never panics: each check
// runs behind its own recover, and a check that dies is recorded in Notes
// instead of aborting the scan.
//
// A nil or cancelled context is tolerated. Probes refused by policy are not
// sent and land in Notes with their sentinel name.
//
// Order of work: the soft-404 baseline is built first (it is mandatory and the
// fixed-path checks depend on it), then the configured pages are fetched, then
// the checks run in a fixed order so results are reproducible.
func (p *PassiveScanner) ScanAll(ctx context.Context) []Vulnerability {
	if p == nil || p.req == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	acc := passiveNewFindingSet()
	// The baseline and the page set are fetched outside the per-check recover,
	// so they are guarded too: a Requester that panics must degrade the scan to
	// "nothing seen", never take the process down.
	var baseline *passiveSoft404Baseline
	var pages []*passiveResponse
	p.passiveGuard("soft-404 baseline", func() { baseline = p.passiveSoft404(ctx) })
	p.passiveGuard("page fetch", func() { pages = p.passiveFetchPages(ctx) })
	if baseline == nil {
		baseline = &passiveSoft404Baseline{hashes: map[string]struct{}{}}
	}
	for _, check := range p.passiveCheckCatalog() {
		p.passiveRunCheck(check, ctx, acc, pages, baseline)
	}
	return acc.materialize()
}

// passiveGuard runs fn, converting any panic into a probe note. It is the
// shared recover used by every phase of ScanAll, including the baseline and the
// page fetch, so a Requester that panics degrades the scan instead of ending it.
func (p *PassiveScanner) passiveGuard(what string, fn func()) {
	defer func() {
		r := recover()
		if r == nil || p == nil {
			return
		}
		note := PassiveProbeNote{Method: what, Err: fmt.Sprintf("panic recovered: %v", r)}
		p.noteMu.Lock()
		p.notes = append(p.notes, note)
		p.noteMu.Unlock()
	}()
	fn()
}

// passiveCheck is one entry of the check catalog.
type passiveCheck struct {
	name string
	run  func(*PassiveScanner, context.Context, *passiveFindingSet, []*passiveResponse, *passiveSoft404Baseline)
}

// passiveCheckCatalog is the fixed check order. Method expressions keep every
// check on *PassiveScanner without a package-level wrapper per check.
func (p *PassiveScanner) passiveCheckCatalog() []passiveCheck {
	return []passiveCheck{
		{"security-headers", (*PassiveScanner).checkSecurityHeaders},
		{"content-security-policy", (*PassiveScanner).checkCSP},
		{"clickjacking", (*PassiveScanner).checkClickjacking},
		{"hsts", (*PassiveScanner).checkHSTS},
		{"cookies", (*PassiveScanner).checkCookies},
		{"cookie-prefixes", (*PassiveScanner).checkCookiePrefixes},
		{"jwt", (*PassiveScanner).checkJWT},
		{"cache-control", (*PassiveScanner).checkCacheControl},
		{"host-header", (*PassiveScanner).checkHostHeader},
		{"metafiles", (*PassiveScanner).checkMetafiles},
		{"artifacts", (*PassiveScanner).checkArtifacts},
		{"source-maps", (*PassiveScanner).checkSourceMaps},
		{"mixed-content-sri", (*PassiveScanner).checkMixedContentAndSRI},
		{"info-leakage", (*PassiveScanner).checkInfoLeakage},
		{"verbose-errors", (*PassiveScanner).checkVerboseErrors},
	}
}

// passiveRunCheck executes one check behind a recover so a single malformed
// response can never take down the whole scan.
func (p *PassiveScanner) passiveRunCheck(c passiveCheck, ctx context.Context, acc *passiveFindingSet, pages []*passiveResponse, baseline *passiveSoft404Baseline) {
	p.passiveGuard("check "+c.name, func() { c.run(p, ctx, acc, pages, baseline) })
}

// passiveFetchPages fetches the configured page set. A page the Requester
// refuses is simply absent; the refusal is already recorded in Notes.
func (p *PassiveScanner) passiveFetchPages(ctx context.Context) []*passiveResponse {
	pages := make([]*passiveResponse, 0, len(p.paths))
	for _, pp := range p.paths {
		if ctx.Err() != nil {
			break
		}
		resp, err := p.passiveFetch(ctx, p.passiveJoin(pp), nil, "")
		if err != nil || resp == nil {
			continue
		}
		pages = append(pages, resp)
	}
	return pages
}

// ---------------------------------------------------------------------------
// Findings: dedup, evidence, sorting
// ---------------------------------------------------------------------------

// passivePending is a finding staged before its ID is assigned.
type passivePending struct {
	checkID string
	v       Vulnerability
}

// passiveFindingSet collects findings with a dedup key of (check ID, URL,
// name), where name is the header, cookie, path or weakness the finding is
// about. IDs are assigned only at materialization time so a deduped first
// occurrence keeps its slot.
type passiveFindingSet struct {
	seen map[string]struct{}
	list []passivePending
}

func passiveNewFindingSet() *passiveFindingSet {
	return &passiveFindingSet{seen: map[string]struct{}{}}
}

// add stages one finding. An empty severity is normalized to "info"; an empty
// confidence is normalized to informational, and a Evidence that is missing its
// confidence prefix is a programming error the tests catch, not silently fixed.
func (acc *passiveFindingSet) add(checkID, name string, v Vulnerability) {
	if acc == nil {
		return
	}
	if v.Severity == "" {
		v.Severity = "info"
	}
	key := checkID + "\x00" + v.URL + "\x00" + name
	if _, dup := acc.seen[key]; dup {
		return
	}
	acc.seen[key] = struct{}{}
	acc.list = append(acc.list, passivePending{checkID: checkID, v: v})
}

// materialize assigns IDs, sorts deterministically and returns the findings.
func (acc *passiveFindingSet) materialize() []Vulnerability {
	if acc == nil || len(acc.list) == 0 {
		return nil
	}
	out := make([]Vulnerability, 0, len(acc.list))
	for _, pend := range acc.list {
		v := pend.v
		if v.ID == "" {
			v.ID = nextVulnID(pend.checkID)
		}
		out = append(out, v)
	}
	passiveSortFindings(out)
	return out
}

// passiveSeverityRank orders severities for the report. Unknown values sort as
// info rather than as critical: a typo must never inflate a finding.
func passiveSeverityRank(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}

// passiveSortFindings orders findings by severity, then ID, then URL, then
// title, then parameter. Every field used is a string comparison, so two runs
// over identical data produce an identical slice.
func passiveSortFindings(vs []Vulnerability) {
	sort.SliceStable(vs, func(i, j int) bool {
		ri, rj := passiveSeverityRank(vs[i].Severity), passiveSeverityRank(vs[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if vs[i].ID != vs[j].ID {
			return vs[i].ID < vs[j].ID
		}
		if vs[i].URL != vs[j].URL {
			return vs[i].URL < vs[j].URL
		}
		if vs[i].Title != vs[j].Title {
			return vs[i].Title < vs[j].Title
		}
		return vs[i].Parameter < vs[j].Parameter
	})
}

// passiveEvidence builds the Evidence string. Vulnerability has no Confidence
// field, so the confidence is the first token. observation is the quoted, byte
// level fact; falsePositiveCheck is what a reviewer should doubt about it.
func passiveEvidence(confidence, observation, falsePositiveCheck string) string {
	return "confidence=" + confidence + "; " + observation + " False-positive check: " + falsePositiveCheck
}

// ---------------------------------------------------------------------------
// Probe plumbing
// ---------------------------------------------------------------------------

// passivePath is one validated probe target: a root-relative path plus an
// optional query. It keeps the escaped form so a path containing an encoded "?"
// is never confused with a query separator.
type passivePath struct {
	path     string
	rawPath  string
	rawQuery string
	display  string
}

// passiveProbePath validates a probe target. It fails closed on anything that
// could smuggle a host (a scheme, a "//" prefix, userinfo) or a control
// character into the request line.
func passiveProbePath(raw string) (passivePath, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return passivePath{}, errors.New("passive: probe path is empty")
	}
	if !strings.HasPrefix(trimmed, "/") {
		return passivePath{}, fmt.Errorf("passive: probe path %q must be root-relative (start with /)", raw)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return passivePath{}, fmt.Errorf("passive: probe path %q: %w", raw, err)
	}
	if u.Scheme != "" || u.Host != "" {
		return passivePath{}, fmt.Errorf("passive: probe path %q must be root-relative with no scheme and no host", raw)
	}
	if strings.ContainsAny(u.Path, "\\\r\n\x00") {
		return passivePath{}, fmt.Errorf("passive: probe path %q contains a forbidden character", raw)
	}
	pp := passivePath{path: u.Path, rawPath: u.RawPath, rawQuery: u.RawQuery}
	pp.display = u.EscapedPath()
	if u.RawQuery != "" {
		pp.display += "?" + u.RawQuery
	}
	return pp, nil
}

// passiveJoin renders one probe target as an absolute URL on the base. Probe
// paths are root-relative on purpose: /robots.txt lives at the server root, not
// under a base path prefix, and a probe never inherits the base query string.
func (p *PassiveScanner) passiveJoin(pp passivePath) string {
	u := *p.base
	u.Fragment = ""
	u.Path = pp.path
	u.RawPath = pp.rawPath
	u.RawQuery = pp.rawQuery
	return u.String()
}

// passiveProbeURL is passiveJoin for a literal path such as "/robots.txt".
func (p *PassiveScanner) passiveProbeURL(literal string) (string, error) {
	pp, err := passiveProbePath(literal)
	if err != nil {
		return "", err
	}
	return p.passiveJoin(pp), nil
}

// passiveResponse is one fetched probe result, already read and parsed.
type passiveResponse struct {
	rawURL string
	path   string
	status int
	header http.Header
	body   []byte
	html   passiveHTMLInfo
}

// passiveFetch performs one policy-checked GET through the Requester. It never
// builds an *http.Client: the Requester seam is the only network path.
func (p *PassiveScanner) passiveFetch(ctx context.Context, rawURL string, extraHeaders map[string]string, hostOverride string) (*passiveResponse, error) {
	if p == nil || p.req == nil {
		return nil, errors.New("passive: scanner is not initialised")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.req.Check(ctx, http.MethodGet, rawURL, false); err != nil {
		p.passiveNote(rawURL, http.MethodGet, err)
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	ua := strings.TrimSpace(p.opts.UserAgent)
	if ua == "" {
		ua = ScannerUserAgent
	}
	req.Header.Set("User-Agent", ua)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	if hostOverride != "" {
		// Go's transport ignores a "Host" entry in Header, so the request's Host
		// field is the only thing that actually rewrites the Host header.
		req.Host = hostOverride
	}
	resp, err := p.req.Do(req)
	if err != nil {
		p.passiveNote(rawURL, http.MethodGet, err)
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("passive: requester returned a nil response")
	}
	body, err := ReadBody(resp, p.maxBody)
	if err != nil {
		p.passiveNote(rawURL, http.MethodGet, err)
		return nil, err
	}
	out := &passiveResponse{rawURL: rawURL, status: resp.StatusCode, header: resp.Header, body: body}
	if resp.Header != nil {
		if u, uerr := url.Parse(rawURL); uerr == nil {
			out.path = u.Path
		}
		if passiveLooksHTML(resp.Header.Get("Content-Type"), body) {
			out.html = passiveParseHTML(body)
			out.html.isHTML = true
		}
	}
	return out, nil
}

// passiveSentinelName names the policy refusal that stopped a probe, so a note
// says why instead of just that something failed.
func passiveSentinelName(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrOutOfScope):
		return "ErrOutOfScope"
	case errors.Is(err, ErrBudgetExhausted):
		return "ErrBudgetExhausted"
	case errors.Is(err, ErrRateLimited):
		return "ErrRateLimited"
	case errors.Is(err, ErrIntrusiveDisabled):
		return "ErrIntrusiveDisabled"
	case errors.Is(err, ErrDryRun):
		return "ErrDryRun"
	default:
		return ""
	}
}

// passiveNote records why a probe produced nothing. It is safe to call from any
// check; notes are only read after ScanAll returns.
func (p *PassiveScanner) passiveNote(rawURL, method string, err error) {
	if p == nil || err == nil {
		return
	}
	note := PassiveProbeNote{Method: method, URL: rawURL, Sentinel: passiveSentinelName(err), Err: err.Error()}
	p.noteMu.Lock()
	defer p.noteMu.Unlock()
	p.notes = append(p.notes, note)
}

// ---------------------------------------------------------------------------
// HTML parsing (golang.org/x/net/html, already a direct dependency)
// ---------------------------------------------------------------------------

// passiveResource is one <script src> or <link href> the page referenced.
type passiveResource struct {
	rawURL    string
	integrity string
	rel       string
}

// passiveHTMLInfo is the part of a page the passive checks care about. Nothing
// is retained beyond the caps, so a hostile page cannot exhaust memory.
type passiveHTMLInfo struct {
	isHTML   bool
	title    string
	scripts  []passiveResource
	links    []passiveResource
	comments []string
}

// passiveLooksHTML decides whether to run the HTML parser. A declared
// Content-Type is authoritative; only when it is absent does the body get a
// bounded sniff. This keeps JSON, source maps and error pages out of the HTML
// paths where they would otherwise produce nonsense findings.
func passiveLooksHTML(contentType string, body []byte) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct != "" {
		return strings.Contains(ct, "html")
	}
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	prefix := strings.ToLower(string(head))
	return strings.Contains(prefix, "<!doctype html") || strings.Contains(prefix, "<html") ||
		strings.Contains(prefix, "<head") || strings.Contains(prefix, "<body")
}

// passiveParseHTML walks the page with a streaming tokenizer and keeps only the
// title, script/link resources (with their integrity attribute) and a bounded
// sample of comments.
func passiveParseHTML(body []byte) passiveHTMLInfo {
	var info passiveHTMLInfo
	z := html.NewTokenizer(bytes.NewReader(body))
	inTitle := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			// Also covers io.EOF: malformed markup ends the walk, never the scan.
			return info
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := strings.ToLower(string(name))
			attrs := passiveTagAttrs(z, hasAttr)
			switch tag {
			case "title":
				inTitle = true
			case "script":
				src := strings.TrimSpace(attrs["src"])
				if src != "" && len(info.scripts) < passiveMaxResourcesPerPage {
					info.scripts = append(info.scripts, passiveResource{rawURL: src, integrity: strings.TrimSpace(attrs["integrity"])})
				}
			case "link":
				href := strings.TrimSpace(attrs["href"])
				if href != "" && len(info.links) < passiveMaxResourcesPerPage {
					info.links = append(info.links, passiveResource{
						rawURL:    href,
						integrity: strings.TrimSpace(attrs["integrity"]),
						rel:       strings.ToLower(strings.TrimSpace(attrs["rel"])),
					})
				}
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if strings.EqualFold(string(name), "title") {
				inTitle = false
			}
		case html.TextToken:
			if inTitle && info.title == "" {
				info.title = strings.TrimSpace(string(z.Text()))
			}
		case html.CommentToken:
			if len(info.comments) < passiveMaxCommentsPerPage {
				c := string(z.Text())
				if len(c) > passiveMaxCommentBytes {
					c = c[:passiveMaxCommentBytes]
				}
				info.comments = append(info.comments, c)
			}
		}
	}
}

// passiveTagAttrs drains a tag's attributes into a lowercased map.
func passiveTagAttrs(z *html.Tokenizer, hasAttr bool) map[string]string {
	attrs := map[string]string{}
	for hasAttr {
		key, val, more := z.TagAttr()
		attrs[strings.ToLower(string(key))] = string(val)
		hasAttr = more
	}
	return attrs
}

// ---------------------------------------------------------------------------
// Soft-404 baseline (mandatory for every fixed-path check)
// ---------------------------------------------------------------------------

// passiveSoft404Sample is one control response.
type passiveSoft404Sample struct {
	status int
	length int
	title  string
}

// passiveSoft404Baseline describes what certainly-nonexistent paths look like
// on this target right now. A fixed-path check must reject a candidate that
// matches it, because a 200 that looks like the site's themed 404 is not a file.
type passiveSoft404Baseline struct {
	ok      bool
	samples []passiveSoft404Sample
	hashes  map[string]struct{}
	// control is the first control response body and URL. The verbose error
	// check reuses it instead of spending a request on a path it already saw.
	controlURL string
	control    []byte
}

// passiveSoft404 builds the baseline by fetching
// /passive-nonexistent-<random> passiveSoft404Samples times. A control fetch
// that fails is simply missing; the baseline still works with fewer samples,
// and with none at all it rejects nothing (an unavailable baseline must never
// be read as "no soft 404 detected").
func (p *PassiveScanner) passiveSoft404(ctx context.Context) *passiveSoft404Baseline {
	baseline := &passiveSoft404Baseline{hashes: map[string]struct{}{}}
	for i := 0; i < passiveSoft404Samples; i++ {
		literal := "/passive-nonexistent-" + randToken()
		rawURL, err := p.passiveProbeURL(literal)
		if err != nil {
			continue
		}
		resp, err := p.passiveFetch(ctx, rawURL, nil, "")
		if err != nil || resp == nil {
			continue
		}
		if len(baseline.samples) == 0 {
			baseline.controlURL = resp.rawURL
			baseline.control = resp.body
		}
		baseline.hashes[passiveBodyHash(resp.body)] = struct{}{}
		baseline.samples = append(baseline.samples, passiveSoft404Sample{
			status: resp.status,
			length: len(resp.body),
			title:  resp.html.title,
		})
	}
	baseline.ok = len(baseline.samples) > 0
	return baseline
}

// rejects reports whether a candidate response is indistinguishable from the
// site's own "nothing here" answer. The rule is strict on purpose:
//
//   - the status must match a control response, and then either
//   - the body SHA-256 is one of the control hashes, or
//   - the body length is within +/-2% of a control body AND the normalized
//     <title> matches, with a non-empty title required so that two different
//     untitled files of similar size are never conflated.
//
// When the baseline could not be built, nothing is rejected: silence beats a
// false negative dressed up as certainty.
func (b *passiveSoft404Baseline) rejects(resp *passiveResponse) bool {
	if b == nil || !b.ok || resp == nil {
		return false
	}
	hash := passiveBodyHash(resp.body)
	for _, sample := range b.samples {
		if resp.status != sample.status {
			continue
		}
		if _, dup := b.hashes[hash]; dup {
			return true
		}
		title := strings.TrimSpace(resp.html.title)
		if title == "" {
			continue
		}
		if passiveWithinPercent(len(resp.body), sample.length, passiveSoft404TolerancePct) &&
			passiveNormalizeTitle(title) == passiveNormalizeTitle(sample.title) {
			return true
		}
	}
	return false
}

// passiveBodyHash is the hex SHA-256 of a response body.
func passiveBodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// passiveWithinPercent compares two lengths with an integer percentage
// tolerance, so no floating point rounding can widen the window.
func passiveWithinPercent(a, b, pct int) bool {
	if b == 0 {
		return a == 0
	}
	diff := int64(a) - int64(b)
	if diff < 0 {
		diff = -diff
	}
	return diff*100 <= int64(b)*int64(pct)
}

// passiveNormalizeTitle lowercases and collapses whitespace so "404 Not Found"
// and "404   not found" compare equal.
func passiveNormalizeTitle(title string) string {
	return strings.Join(strings.Fields(strings.ToLower(title)), " ")
}

// ---------------------------------------------------------------------------
// Content-Security-Policy parsing
// ---------------------------------------------------------------------------

// passiveCSPPolicy is one parsed CSP header value. Directives are lowercased
// keys; a directive with no value keeps an empty (non-nil) entry so "present
// but malformed" is distinguishable from "absent".
type passiveCSPPolicy struct {
	raw        string
	source     string
	directives map[string][]string
}

func passiveParseCSP(raw, source string) passiveCSPPolicy {
	pol := passiveCSPPolicy{raw: raw, source: source, directives: map[string][]string{}}
	for _, segment := range strings.Split(raw, ";") {
		fields := strings.Fields(segment)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		pol.directives[name] = append(pol.directives[name], fields[1:]...)
	}
	return pol
}

func (pol passiveCSPPolicy) has(directive string) bool {
	_, ok := pol.directives[directive]
	return ok
}

func (pol passiveCSPPolicy) values(directive string) []string {
	return pol.directives[directive]
}

// effectiveScriptSrc returns the directive that actually governs scripts:
// script-src if present, otherwise default-src, otherwise nothing at all (in
// which case scripts are unrestricted and there is nothing to quote).
func (pol passiveCSPPolicy) effectiveScriptSrc() (string, []string, bool) {
	if vals, ok := pol.directives["script-src"]; ok {
		return "script-src", vals, true
	}
	if vals, ok := pol.directives["default-src"]; ok {
		return "default-src", vals, true
	}
	return "", nil, false
}

func passiveCSPHasWildcard(vals []string) bool {
	for _, v := range vals {
		if v == "*" {
			return true
		}
	}
	return false
}

func passiveCSPHasToken(vals []string, want string) bool {
	for _, v := range vals {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func passiveCSPHasNonceOrHash(vals []string) bool {
	for _, v := range vals {
		lower := strings.ToLower(v)
		if strings.HasPrefix(lower, "nonce-") ||
			strings.HasPrefix(lower, "sha256-") ||
			strings.HasPrefix(lower, "sha384-") ||
			strings.HasPrefix(lower, "sha512-") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// X-Frame-Options and frame-ancestors state
// ---------------------------------------------------------------------------

// passiveXFOValues splits every X-Frame-Options field into directive tokens.
func passiveXFOValues(h http.Header) []string {
	var out []string
	if h == nil {
		return out
	}
	for _, raw := range h.Values("X-Frame-Options") {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// passiveXFOProtects reports whether the effective (first) X-Frame-Options
// value is one browsers still implement. ALLOW-FROM was removed from every
// browser, so it protects nothing.
func passiveXFOProtects(vals []string) bool {
	if len(vals) == 0 {
		return false
	}
	first := strings.ToUpper(vals[0])
	return first == "DENY" || first == "SAMEORIGIN"
}

// passiveXFOObsolete reports a directive browsers ignore entirely.
func passiveXFOObsolete(vals []string) bool {
	if len(vals) == 0 {
		return false
	}
	return strings.HasPrefix(strings.ToUpper(vals[0]), "ALLOW-FROM")
}

// passiveFrameAncestors inspects only the enforced CSP (a report-only policy
// does not frame-protect anything). present is true when a directive exists,
// value is its raw tokens, and enforcing is true only when it would actually
// restrict: "frame-ancestors *" and a valueless "frame-ancestors" restrict
// nothing.
func passiveFrameAncestors(h http.Header) (present bool, value string, enforcing bool) {
	if h == nil {
		return false, "", false
	}
	for _, raw := range h.Values("Content-Security-Policy") {
		pol := passiveParseCSP(raw, "Content-Security-Policy")
		vals, ok := pol.directives["frame-ancestors"]
		if !ok {
			continue
		}
		present = true
		value = strings.TrimSpace(strings.Join(vals, " "))
		if value == "" || passiveCSPHasWildcard(vals) {
			continue
		}
		enforcing = true
	}
	return present, value, enforcing
}

// passiveValidXFO reports a still-implemented X-Frame-Options value.
func passiveValidXFO(h http.Header) bool {
	return passiveXFOProtects(passiveXFOValues(h))
}

// ---------------------------------------------------------------------------
// Set-Cookie parsing and redaction
// ---------------------------------------------------------------------------

// passiveCookie is one parsed Set-Cookie. Attribute values are kept (they are
// not secret) under lowercased names; flags map to an empty string.
type passiveCookie struct {
	name  string
	value string
	attrs map[string]string
}

func passiveParseSetCookie(raw string) passiveCookie {
	cookie := passiveCookie{attrs: map[string]string{}}
	segments := strings.Split(raw, ";")
	if len(segments) == 0 {
		return cookie
	}
	first := segments[0]
	if eq := strings.Index(first, "="); eq >= 0 {
		cookie.name = strings.TrimSpace(first[:eq])
		cookie.value = strings.TrimSpace(first[eq+1:])
	} else {
		cookie.name = strings.TrimSpace(first)
	}
	for _, segment := range segments[1:] {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		name, value := segment, ""
		if eq := strings.Index(segment, "="); eq >= 0 {
			name = strings.TrimSpace(segment[:eq])
			value = strings.TrimSpace(segment[eq+1:])
		}
		key := strings.ToLower(name)
		if _, exists := cookie.attrs[key]; !exists {
			cookie.attrs[key] = value
		}
	}
	return cookie
}

func (c passiveCookie) has(attr string) bool {
	_, ok := c.attrs[strings.ToLower(attr)]
	return ok
}

func (c passiveCookie) valueOf(attr string) (string, bool) {
	v, ok := c.attrs[strings.ToLower(attr)]
	return v, ok
}

// passiveSessionCookieRe matches cookie names that plausibly carry a session.
// It is deliberately broad: the finding is about the missing attribute, and the
// evidence names the exact cookie, so a reviewer can dismiss a false friend.
var passiveSessionCookieRe = regexp.MustCompile(`(?i)(session|sessid|phpsessid|jsessionid|asp\.net_sessionid|sid|auth|token|jwt|remember|sso)`)

// passiveRedactCookieValue replaces a cookie's value with a length marker and
// keeps the name and the attributes verbatim, so evidence can name the cookie
// and its flags without ever printing the secret.
func passiveRedactCookieValue(raw string) string {
	eq := strings.Index(raw, "=")
	if eq < 0 {
		return strings.TrimSpace(raw)
	}
	name := strings.TrimSpace(raw[:eq])
	rest := raw[eq+1:]
	value, tail := rest, ""
	if i := strings.Index(rest, ";"); i >= 0 {
		value, tail = rest[:i], rest[i:]
	}
	return name + "=<redacted len=" + strconv.Itoa(len(strings.TrimSpace(value))) + ">" + tail
}

// ---------------------------------------------------------------------------
// JWT inspection
// ---------------------------------------------------------------------------

// passiveJWTRe matches the three base64url segments of a JWS. It requires both
// header and payload to start with "eyJ", the base64url of "{", which filters
// out most random dotted strings without needing a decode per candidate.
var passiveJWTRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{2,}\.?[A-Za-z0-9_-]*`)

// passiveJWTInfo is what could be decoded from one observed token. headerOK is
// false when the header is not decodable JSON, in which case no claim about the
// algorithm is made at all; payloadOK is false for encrypted (JWE) payloads, in
// which case no claim about expiry is made.
type passiveJWTInfo struct {
	hash      string
	alg       string
	typ       string
	kid       string
	source    string
	rawURL    string
	headerOK  bool
	payloadOK bool
	hasExp    bool
	hasIat    bool
}

func passiveFindJWTs(text string) []string {
	if len(text) > passiveJWTScanLimit {
		text = text[:passiveJWTScanLimit]
	}
	return passiveJWTRe.FindAllString(text, passiveMaxJWTsPerFind)
}

// passiveDecodeJWT extracts the header and expiry claim from a token. The token
// itself is never returned: the SHA-256 is the only thing evidence may quote.
func passiveDecodeJWT(token, source, rawURL string) passiveJWTInfo {
	info := passiveJWTInfo{source: source, rawURL: rawURL}
	sum := sha256.Sum256([]byte(token))
	info.hash = hex.EncodeToString(sum[:])
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return info
	}
	head, err := passiveBase64URL(parts[0])
	if err != nil {
		return info
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(head, &header) != nil {
		return info
	}
	info.headerOK = true
	info.alg = header.Alg
	info.typ = header.Typ
	info.kid = header.Kid
	payload, err := passiveBase64URL(parts[1])
	if err != nil {
		return info
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil {
		return info
	}
	info.payloadOK = true
	_, info.hasExp = claims["exp"]
	_, info.hasIat = claims["iat"]
	return info
}

func passiveBase64URL(segment string) ([]byte, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(segment); err == nil {
		return raw, nil
	}
	return base64.URLEncoding.DecodeString(segment)
}

// passiveJWSymmetric and passiveJWTAsymmetric classify an "alg" value. "none"
// is neither, and an unknown value is neither, so a mixed-algorithm finding can
// only appear when both families were actually observed.
func passiveJWSymmetric(alg string) bool {
	return strings.HasPrefix(strings.ToUpper(alg), "HS")
}

func passiveJWTAsymmetric(alg string) bool {
	upper := strings.ToUpper(alg)
	for _, prefix := range []string{"RS", "ES", "PS", "EDDSA", "ED25519", "ECDH"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Cache-Control parsing
// ---------------------------------------------------------------------------

// passiveCacheDirectives lowercases directive names and keeps their values.
// "no-store" and "no-cache" map to an empty value.
func passiveCacheDirectives(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value := part, ""
		if eq := strings.Index(part, "="); eq >= 0 {
			name = strings.TrimSpace(part[:eq])
			value = strings.TrimSpace(part[eq+1:])
		}
		out[strings.ToLower(name)] = value
	}
	return out
}

// ---------------------------------------------------------------------------
// Redaction and excerpts
// ---------------------------------------------------------------------------

// passiveSecretishRe matches "keyword = value" shapes. Values are redacted in
// every evidence string this file produces, so a scan report cannot leak the
// very secret it found.
var passiveSecretishRe = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|token|authorization|bearer|credential)\b\s*[:=]\s*("?)([^\s"';,]{1,120})("?)`)

func passiveRedactSecretish(text string) string {
	return passiveSecretishRe.ReplaceAllString(text, "$1=<redacted>")
}

// passiveTruncate bounds a string for evidence without pretending to know
// whether the cut landed mid-token.
func passiveTruncate(text string, max int) string {
	if max <= 0 || len(text) <= max {
		return text
	}
	return text[:max] + "...(truncated)"
}

// passiveExcerptAround returns a bounded window around an offset, collapsed to
// one line so evidence stays readable in a terminal report.
func passiveExcerptAround(body []byte, at, window int) string {
	if len(body) == 0 || at < 0 || at >= len(body) {
		return ""
	}
	start := at - window/2
	if start < 0 {
		start = 0
	}
	end := at + window/2
	if end > len(body) {
		end = len(body)
	}
	fragment := strings.ReplaceAll(string(body[start:end]), "\n", " ")
	fragment = strings.ReplaceAll(fragment, "\r", " ")
	return passiveTruncate(fragment, window)
}

// ---------------------------------------------------------------------------
// Check 1: security headers present (WSTG-CONF-14 / WSTG-HEAD)
// ---------------------------------------------------------------------------

// checkSecurityHeaders reports missing or malformed defence-in-depth headers.
// Every finding here is a hardening gap, never an exploitable flaw, and the
// evidence says so: a missing header is a byte-level fact about a header map,
// not a claim that XSS or anything else exists.
func (p *PassiveScanner) checkSecurityHeaders(_ context.Context, acc *passiveFindingSet, pages []*passiveResponse, _ *passiveSoft404Baseline) {
	for _, page := range pages {
		if page == nil || page.header == nil {
			continue
		}
		h := page.header
		// Reported per path: a CDN or proxy routinely adds or drops headers per
		// route, so / and /app are independent observations.
		csp := strings.TrimSpace(h.Get("Content-Security-Policy"))
		reportOnly := strings.TrimSpace(h.Get("Content-Security-Policy-Report-Only"))
		if csp == "" && reportOnly == "" {
			acc.add(passiveCheckIDHeaders, "Content-Security-Policy", Vulnerability{
				Title:     "Response has no Content-Security-Policy header",
				Severity:  "medium",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSMedium,
				CWE:       "CWE-693",
				URL:       page.rawURL,
				Parameter: "Content-Security-Policy",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s answered HTTP %d carrying neither Content-Security-Policy nor Content-Security-Policy-Report-Only.", page.rawURL, page.status),
					"header absence is a byte-level fact, not an inference. This is a defence-in-depth hardening gap and is NOT evidence that XSS, or any other flaw, exists."),
				Impact:      "Hardening gap, not directly exploitable: without a CSP there is no second layer to contain an injection flaw if one exists elsewhere in the application.",
				Remediation: "Serve a restrictive Content-Security-Policy, for example default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none', then move toward nonce or hash based script loading.",
				References:  []string{passiveRefWSTGCSP, passiveRefCSCSP, passiveRefMDNCSP, passiveRefTopA05},
			})
		}

		xcto := strings.TrimSpace(h.Get("X-Content-Type-Options"))
		switch {
		case xcto == "":
			acc.add(passiveCheckIDHeaders, "X-Content-Type-Options", Vulnerability{
				Title:     "Response has no X-Content-Type-Options header",
				Severity:  "low",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSLow,
				CWE:       "CWE-693",
				URL:       page.rawURL,
				Parameter: "X-Content-Type-Options",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s answered HTTP %d carrying no X-Content-Type-Options header field.", page.rawURL, page.status),
					"header absence is a byte-level fact. This is a hardening gap that widens MIME sniffing behaviour; it is not itself an exploitable flaw."),
				Impact:      "Hardening gap: a browser may MIME-sniff an ambiguous response into an active type, which matters only if another flaw lets an attacker place such a response.",
				Remediation: "Add X-Content-Type-Options: nosniff to every response.",
				References:  []string{passiveRefWSTGHeaders, passiveRefCSHeaders, passiveRefMDNXCTO},
			})
		case !strings.EqualFold(xcto, "nosniff"):
			acc.add(passiveCheckIDHeaders, "X-Content-Type-Options", Vulnerability{
				Title:     "X-Content-Type-Options is present but not nosniff",
				Severity:  "low",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSLow,
				CWE:       "CWE-693",
				URL:       page.rawURL,
				Parameter: "X-Content-Type-Options",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s answered HTTP %d with X-Content-Type-Options: %s.", page.rawURL, page.status, passiveTruncate(xcto, passiveMaxExcerpt)),
					"the only value browsers implement is nosniff; any other value was quoted verbatim and is treated as absent."),
				Impact:      "Hardening gap: MIME sniffing is not disabled by an unrecognised value.",
				Remediation: "Set X-Content-Type-Options to exactly nosniff.",
				References:  []string{passiveRefMDNXCTO},
			})
		}

		referrer := strings.TrimSpace(h.Get("Referrer-Policy"))
		switch {
		case referrer == "":
			acc.add(passiveCheckIDHeaders, "Referrer-Policy", Vulnerability{
				Title:     "Response has no Referrer-Policy header",
				Severity:  "low",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSLow,
				CWE:       "CWE-200",
				URL:       page.rawURL,
				Parameter: "Referrer-Policy",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s answered HTTP %d carrying no Referrer-Policy header field.", page.rawURL, page.status),
					"header absence is a byte-level fact. Without a policy a browser falls back to its default, which sends the full URL cross-origin; this is a hygiene gap, not a demonstrated leak."),
				Impact:      "Hygiene gap: full URLs (which can carry reset tokens or query identifiers) may be disclosed to third-party origins through the Referer header.",
				Remediation: "Add Referrer-Policy: strict-origin-when-cross-origin, or no-referrer where the referrer is never needed.",
				References:  []string{passiveRefWSTGHeaders, passiveRefMDNRP},
			})
		case passiveReferrerLeaky(referrer):
			acc.add(passiveCheckIDHeaders, "Referrer-Policy", Vulnerability{
				Title:     "Referrer-Policy sends the full URL cross-origin",
				Severity:  "low",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSLow,
				CWE:       "CWE-200",
				URL:       page.rawURL,
				Parameter: "Referrer-Policy",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s answered HTTP %d with Referrer-Policy: %s.", page.rawURL, page.status, passiveTruncate(referrer, passiveMaxExcerpt)),
					"the value was quoted verbatim. Only the two values that keep the full URL cross-origin are reported; other values are treated as adequate to avoid noise."),
				Impact:      "Hygiene gap: any full-URL query string (including one-time tokens) is disclosed to third-party origins.",
				Remediation: "Use Referrer-Policy: strict-origin-when-cross-origin.",
				References:  []string{passiveRefMDNRP},
			})
		}

		if strings.TrimSpace(h.Get("Permissions-Policy")) == "" {
			acc.add(passiveCheckIDHeaders, "Permissions-Policy", Vulnerability{
				Title:     "Response has no Permissions-Policy header",
				Severity:  "info",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSInfo,
				CWE:       "CWE-693",
				URL:       page.rawURL,
				Parameter: "Permissions-Policy",
				Evidence: passiveEvidence(passiveConfidenceInformational,
					fmt.Sprintf("%s answered HTTP %d carrying no Permissions-Policy header field.", page.rawURL, page.status),
					"this is pure hygiene: a browser feature-policy default is in effect, and nothing here is exploitable. Reported as informational on purpose."),
				Impact:      "Hygiene only: powerful browser features (camera, microphone, geolocation) are not explicitly constrained by the server.",
				Remediation: "Add a Permissions-Policy that disables features the application never uses.",
				References:  []string{passiveRefMDNPP},
			})
		}
	}
}

// passiveReferrerLeaky reports the two Referrer-Policy values that keep sending
// the full URL to any HTTPS origin.
func passiveReferrerLeaky(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "unsafe-url", "no-referrer-when-downgrade":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Check 2: Content-Security-Policy analysis (WSTG-CONF-12)
// ---------------------------------------------------------------------------

// checkCSP analyses every CSP header value. Weaknesses are reported once per
// policy per URL: an enforced policy and a report-only policy with the same
// weakness produce one finding, whose evidence names which header it came from.
func (p *PassiveScanner) checkCSP(_ context.Context, acc *passiveFindingSet, pages []*passiveResponse, _ *passiveSoft404Baseline) {
	for _, page := range pages {
		if page == nil || page.header == nil {
			continue
		}
		enforced := page.header.Values("Content-Security-Policy")
		reportOnly := page.header.Values("Content-Security-Policy-Report-Only")
		if len(enforced) == 0 && len(reportOnly) > 0 {
			acc.add(passiveCheckIDCSP, "csp-report-only-only", Vulnerability{
				Title:     "Content-Security-Policy is report-only, nothing is enforced",
				Severity:  "medium",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSMedium,
				CWE:       "CWE-693",
				URL:       page.rawURL,
				Parameter: "Content-Security-Policy-Report-Only",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s answered HTTP %d with Content-Security-Policy-Report-Only (%d field(s)) and no enforced Content-Security-Policy.", page.rawURL, page.status, len(reportOnly)),
					"a report-only policy never blocks anything; the header values were quoted verbatim, so this is a deployment observation, not an inference about intent."),
				Impact:      "A report-only policy is a measurement tool, not a control: an injected script still runs. Enforcement is the missing half.",
				Remediation: "Promote the report-only policy to Content-Security-Policy once the report backlog is clean, keeping report-uri or report-to for observation.",
				References:  []string{passiveRefWSTGCSP, passiveRefCSCSP, passiveRefMDNCSP},
			})
		}
		for _, raw := range enforced {
			p.passiveAnalyzeCSP(acc, page, passiveParseCSP(raw, "Content-Security-Policy"), true)
		}
		for _, raw := range reportOnly {
			p.passiveAnalyzeCSP(acc, page, passiveParseCSP(raw, "Content-Security-Policy-Report-Only"), false)
		}
	}
}

// passiveAnalyzeCSP reports the weaknesses this scanner can prove from a header
// value alone: a wildcard script source, unsafe-inline without a nonce or hash,
// unsafe-eval, and an object-src that is not 'none'. Frame-ancestors is reported
// only as an info modernisation note when a valid X-Frame-Options is already
// doing the job, so the two clickjacking checks never overlap.
func (p *PassiveScanner) passiveAnalyzeCSP(acc *passiveFindingSet, page *passiveResponse, pol passiveCSPPolicy, enforcing bool) {
	scope := "enforced Content-Security-Policy"
	if !enforcing {
		scope = "Content-Security-Policy-Report-Only (not enforced)"
	}
	quoted := func(vals []string) string { return passiveTruncate(strings.Join(vals, " "), passiveMaxExcerpt) }

	if directive, vals, ok := pol.effectiveScriptSrc(); ok && passiveCSPHasWildcard(vals) {
		acc.add(passiveCheckIDCSP, "csp-wildcard-script-src", Vulnerability{
			Title:     "Content-Security-Policy allows scripts from any origin",
			Severity:  "medium",
			Category:  passiveCategoryMisconfig,
			CVSS:      passiveCVSSMedium,
			CWE:       "CWE-693",
			URL:       page.rawURL,
			Parameter: directive,
			Evidence: passiveEvidence(passiveConfidenceConfirmed,
				fmt.Sprintf("%s: %s directive %q has the wildcard token %q.", page.rawURL, scope, directive, quoted(vals)),
				"a literal '*' token was quoted from the header value. The wildcard permits any network origin for scripts, which defeats the main purpose of the policy."),
			Impact:      "The policy cannot contain an injected script: any attacker-controlled origin is an allowed script source.",
			Remediation: "Replace the wildcard with an explicit origin list, ideally moving to nonce or hash based script loading with strict-dynamic.",
			References:  []string{passiveRefWSTGCSP, passiveRefCSCSP, passiveRefMDNCSP},
		})
	}

	if directive, vals, ok := pol.effectiveScriptSrc(); ok &&
		passiveCSPHasToken(vals, "'unsafe-inline'") && !passiveCSPHasNonceOrHash(vals) {
		acc.add(passiveCheckIDCSP, "csp-unsafe-inline-scripts", Vulnerability{
			Title:     "Content-Security-Policy permits inline scripts",
			Severity:  "medium",
			Category:  passiveCategoryMisconfig,
			CVSS:      passiveCVSSMedium,
			CWE:       "CWE-693",
			URL:       page.rawURL,
			Parameter: directive,
			Evidence: passiveEvidence(passiveConfidenceConfirmed,
				fmt.Sprintf("%s: %s directive %q contains 'unsafe-inline' with no nonce- or sha token (%s).", page.rawURL, scope, directive, quoted(vals)),
				"both the directive name and its tokens were quoted verbatim. 'unsafe-inline' is ignored only when a nonce or hash is present, which is why the absence of those is part of the evidence."),
			Impact:      "Any inline script executes, so an injected script tag bypasses the policy entirely.",
			Remediation: "Issue a per-request nonce (or per-script hashes), use strict-dynamic, and drop 'unsafe-inline' from script-src.",
			References:  []string{passiveRefWSTGCSP, passiveRefCSCSP},
		})
	}

	if directive, vals, ok := pol.effectiveScriptSrc(); ok && passiveCSPHasToken(vals, "'unsafe-eval'") {
		acc.add(passiveCheckIDCSP, "csp-unsafe-eval", Vulnerability{
			Title:     "Content-Security-Policy allows eval()",
			Severity:  "medium",
			Category:  passiveCategoryMisconfig,
			CVSS:      passiveCVSSMedium,
			CWE:       "CWE-693",
			URL:       page.rawURL,
			Parameter: directive,
			Evidence: passiveEvidence(passiveConfidenceConfirmed,
				fmt.Sprintf("%s: %s directive %q contains 'unsafe-eval' (%s).", page.rawURL, scope, directive, quoted(vals)),
				"quoted verbatim. 'unsafe-eval' permits the JavaScript compiler functions, which is a real weakening of the policy but not an exploitable flaw on its own."),
			Impact:      "A payload that reaches eval(), Function() or a template compiler is not blocked by the policy.",
			Remediation: "Remove 'unsafe-eval' and precompile templates or remove dynamic evaluation.",
			References:  []string{passiveRefWSTGCSP},
		})
	}

	if !pol.has("object-src") || !passiveCSPHasToken(pol.values("object-src"), "'none'") {
		existing := quoted(pol.values("object-src"))
		if existing == "" {
			existing = "(directive absent)"
		}
		acc.add(passiveCheckIDCSP, "csp-object-src", Vulnerability{
			Title:     "Content-Security-Policy does not set object-src 'none'",
			Severity:  "low",
			Category:  passiveCategoryMisconfig,
			CVSS:      passiveCVSSLow,
			CWE:       "CWE-693",
			URL:       page.rawURL,
			Parameter: "object-src",
			Evidence: passiveEvidence(passiveConfidenceConfirmed,
				fmt.Sprintf("%s: %s object-src is %s.", page.rawURL, scope, existing),
				"the OWASP CSP cheat sheet recommends object-src 'none'; the directive value was quoted verbatim, and plugin content is legacy in every current browser, so this is a low-severity hygiene item."),
			Impact:      "Legacy plugin content (<object>, <embed>) is not explicitly blocked.",
			Remediation: "Add object-src 'none' to the policy.",
			References:  []string{passiveRefCSCSP, passiveRefWSTGCSP},
		})
	}

	// Reported only when a valid X-Frame-Options is already present, so it never
	// duplicates check 3's clickjacking finding.
	if enforcing && !pol.has("frame-ancestors") && passiveValidXFO(page.header) {
		acc.add(passiveCheckIDCSP, "csp-frame-ancestors", Vulnerability{
			Title:     "Content-Security-Policy has no frame-ancestors directive",
			Severity:  "info",
			Category:  passiveCategoryMisconfig,
			CVSS:      passiveCVSSInfo,
			CWE:       "CWE-1021",
			URL:       page.rawURL,
			Parameter: "frame-ancestors",
			Evidence: passiveEvidence(passiveConfidenceInformational,
				fmt.Sprintf("%s: the enforced Content-Security-Policy has no frame-ancestors directive, while X-Frame-Options is %s.", page.rawURL, passiveTruncate(strings.Join(passiveXFOValues(page.header), ", "), passiveMaxExcerpt)),
				"the policy was parsed directive by directive and frame-ancestors is absent; X-Frame-Options is still enforcing framing protection, so this is reported as an informational modernisation note, not as a clickjacking finding."),
			Impact:      "Hygiene only: X-Frame-Options is still enforced, but it cannot express the frame-ancestors allowlist that modern policies use.",
			Remediation: "Add frame-ancestors 'none' (or an explicit allowlist) to the enforced policy.",
			References:  []string{passiveRefWSTGClickjack, passiveRefCSClickjack, passiveRefMDNXFO},
		})
	}
}

// ---------------------------------------------------------------------------
// Check 3: clickjacking (WSTG-CLNT-09)
// ---------------------------------------------------------------------------

// checkClickjacking reports framing protection that is missing or dead.
// frame-ancestors wins outright when it is enforcing, because a browser that
// implements CSP ignores X-Frame-Options entirely; a present but permissive
// frame-ancestors is reported even when X-Frame-Options says DENY, because the
// permissive CSP is what the browser obeys.
func (p *PassiveScanner) checkClickjacking(_ context.Context, acc *passiveFindingSet, pages []*passiveResponse, _ *passiveSoft404Baseline) {
	for _, page := range pages {
		if page == nil || page.header == nil {
			continue
		}
		// Clickjacking needs a document a browser would render in a frame.
		if page.status < 200 || page.status > 299 || !page.html.isHTML {
			continue
		}
		present, value, enforcing := passiveFrameAncestors(page.header)
		if enforcing {
			continue
		}
		vals := passiveXFOValues(page.header)
		switch {
		case present:
			acc.add(passiveCheckIDClickjack, "frame-ancestors-permissive", Vulnerability{
				Title:     "Content-Security-Policy frame-ancestors does not restrict framing",
				Severity:  "medium",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSMedium,
				CWE:       "CWE-1021",
				URL:       page.rawURL,
				Parameter: "frame-ancestors",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s: the enforced Content-Security-Policy carries frame-ancestors with the value %q, which permits any framing context; X-Frame-Options is %s.", page.rawURL, passiveTruncate(value, passiveMaxExcerpt), passiveTruncate(strings.Join(vals, ", "), passiveMaxExcerpt)),
					"a present-but-permissive frame-ancestors supersedes X-Frame-Options in every browser that implements CSP, so a DENY value alongside it does not protect this page."),
				Impact:      "The page can be framed by any origin, so an attacker can overlay or disguise the UI and trick a user into acting inside their session.",
				Remediation: "Set frame-ancestors 'none', or 'self' plus an explicit allowlist of the origins that legitimately frame the page.",
				References:  []string{passiveRefWSTGClickjack, passiveRefCSClickjack, passiveRefMDNXFO},
			})
		case len(vals) == 0:
			acc.add(passiveCheckIDClickjack, "no-framing-protection", Vulnerability{
				Title:     "Page can be framed by any origin (no clickjacking protection)",
				Severity:  "medium",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSMedium,
				CWE:       "CWE-1021",
				URL:       page.rawURL,
				Parameter: "X-Frame-Options",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s answered HTTP %d with neither an X-Frame-Options header field nor a frame-ancestors directive in any enforced Content-Security-Policy.", page.rawURL, page.status),
					"both protection mechanisms were checked and neither is present; whether this specific page is worth framing depends on its UI, which a passive check cannot judge, so the finding is stated as a missing control."),
				Impact:      "An attacker can frame the page and disguise its controls, so a user's clicks can be hijacked into attacker-chosen actions inside their session.",
				Remediation: "Add X-Frame-Options: DENY (or SAMEORIGIN) and the equivalent CSP frame-ancestors 'none'.",
				References:  []string{passiveRefWSTGClickjack, passiveRefCSClickjack, passiveRefMDNXFO},
			})
		case passiveXFOObsolete(vals):
			acc.add(passiveCheckIDClickjack, "xfo-allow-from", Vulnerability{
				Title:     "X-Frame-Options ALLOW-FROM is ignored by current browsers",
				Severity:  "medium",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSMedium,
				CWE:       "CWE-1021",
				URL:       page.rawURL,
				Parameter: "X-Frame-Options",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s: X-Frame-Options is %q, and no frame-ancestors directive is present.", page.rawURL, passiveTruncate(strings.Join(vals, ", "), passiveMaxExcerpt)),
					"ALLOW-FROM was removed from every current browser, so the header is treated as absent; the exact value was quoted so a reviewer can confirm it is not DENY or SAMEORIGIN."),
				Impact:      "The intended framing allowlist is not applied by any current browser, so the page is framable by any origin.",
				Remediation: "Replace ALLOW-FROM with CSP frame-ancestors, and keep X-Frame-Options: DENY or SAMEORIGIN for older browsers.",
				References:  []string{passiveRefWSTGClickjack, passiveRefMDNXFO},
			})
		case !passiveXFOProtects(vals):
			acc.add(passiveCheckIDClickjack, "xfo-unrecognised", Vulnerability{
				Title:     "X-Frame-Options value is not one browsers implement",
				Severity:  "low",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSLow,
				CWE:       "CWE-1021",
				URL:       page.rawURL,
				Parameter: "X-Frame-Options",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s: X-Frame-Options is %q, which is neither DENY nor SAMEORIGIN.", page.rawURL, passiveTruncate(strings.Join(vals, ", "), passiveMaxExcerpt)),
					"only DENY and SAMEORIGIN are implemented; the unrecognised value was quoted verbatim rather than assumed to work."),
				Impact:      "Framing protection may not apply at all, because browsers ignore values they do not recognise.",
				Remediation: "Set X-Frame-Options to DENY, or SAMEORIGIN if same-origin framing is required.",
				References:  []string{passiveRefMDNXFO},
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Check 4: HTTP Strict Transport Security (WSTG-CONF-07)
// ---------------------------------------------------------------------------

// checkHSTS inspects Strict-Transport-Security. It only runs on an https base:
// reporting a missing HSTS header on an http target would be nonsense, since
// the header cannot be delivered over a plaintext first hop.
func (p *PassiveScanner) checkHSTS(_ context.Context, acc *passiveFindingSet, pages []*passiveResponse, _ *passiveSoft404Baseline) {
	if p.base == nil || !strings.EqualFold(p.base.Scheme, "https") {
		return
	}
	for _, page := range pages {
		if page == nil || page.header == nil {
			continue
		}
		raw := strings.TrimSpace(page.header.Get("Strict-Transport-Security"))
		if raw == "" {
			acc.add(passiveCheckIDHSTS, "hsts-absent", Vulnerability{
				Title:     "Response has no Strict-Transport-Security header",
				Severity:  "medium",
				Category:  passiveCategoryCrypto,
				CVSS:      passiveCVSSMedium,
				CWE:       "CWE-319",
				URL:       page.rawURL,
				Parameter: "Strict-Transport-Security",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s answered over https with no Strict-Transport-Security header field.", page.rawURL),
					"the base URL scheme is https and the header is absent, which is a byte-level fact. Whether a user can be downgraded depends on the network path, which this scanner does not test."),
				Impact:      "A first visit over http, or a stripped response on an open network, leaves the session exposed to SSL stripping because the browser is never told to insist on https.",
				Remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains (and preload only after confirming every subdomain is https).",
				References:  []string{passiveRefWSTGHSTS, passiveRefCSHSTS, passiveRefMDNHSTS, passiveRefTopA02},
			})
			continue
		}
		maxAge, ok := passiveHSTSMaxAge(raw)
		switch {
		case !ok:
			acc.add(passiveCheckIDHSTS, "hsts-malformed", Vulnerability{
				Title:     "Strict-Transport-Security header has no parseable max-age",
				Severity:  "medium",
				Category:  passiveCategoryCrypto,
				CVSS:      passiveCVSSMedium,
				CWE:       "CWE-319",
				URL:       page.rawURL,
				Parameter: "Strict-Transport-Security",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s: Strict-Transport-Security is %q and contains no max-age directive; browsers ignore the header in that state.", page.rawURL, passiveTruncate(raw, passiveMaxExcerpt)),
					"the header value was quoted verbatim and parsed directive by directive."),
				Impact:      "The header is inert: the browser never learns to force https, so the transport guarantee the operator believes is configured is not in effect.",
				Remediation: "Set a valid max-age, for example Strict-Transport-Security: max-age=31536000; includeSubDomains.",
				References:  []string{passiveRefCSHSTS, passiveRefMDNHSTS},
			})
		case maxAge == 0:
			acc.add(passiveCheckIDHSTS, "hsts-zero-max-age", Vulnerability{
				Title:     "Strict-Transport-Security max-age=0 disables HSTS",
				Severity:  "medium",
				Category:  passiveCategoryCrypto,
				CVSS:      passiveCVSSMedium,
				CWE:       "CWE-319",
				URL:       page.rawURL,
				Parameter: "Strict-Transport-Security",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s: Strict-Transport-Security is %q, and max-age=0 tells the browser to stop enforcing https for this host.", page.rawURL, passiveTruncate(raw, passiveMaxExcerpt)),
					"max-age=0 is a deliberate opt-out in the RFC, not a formatting error; the value was quoted verbatim."),
				Impact:      "Any previously cached HSTS state is cleared, so the host becomes strippable again on an open network.",
				Remediation: "Set a positive max-age (at least 31536000) or remove the header entirely if HSTS is genuinely not wanted.",
				References:  []string{passiveRefCSHSTS, passiveRefMDNHSTS},
			})
		case maxAge < passiveHSTSMinAge:
			acc.add(passiveCheckIDHSTS, "hsts-short-max-age", Vulnerability{
				Title:     "Strict-Transport-Security max-age is below one year",
				Severity:  "low",
				Category:  passiveCategoryCrypto,
				CVSS:      passiveCVSSLow,
				CWE:       "CWE-319",
				URL:       page.rawURL,
				Parameter: "Strict-Transport-Security",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s: Strict-Transport-Security is %q (max-age=%d, below the %d recommended by the OWASP cheat sheet).", page.rawURL, passiveTruncate(raw, passiveMaxExcerpt), maxAge, passiveHSTSMinAge),
					"the max-age was parsed from the quoted header value. A short max-age is a policy choice rather than a defect, so it is reported as low."),
				Impact:      "The https guarantee lapses between refreshes, which widens the window for a stripping attack after the cache expires.",
				Remediation: "Raise max-age to at least 31536000 seconds and keep it refreshed on every https response.",
				References:  []string{passiveRefCSHSTS, passiveRefMDNHSTS},
			})
		}
		if p.opts.KnownSubdomains && !passiveHSTSHasDirective(raw, "includesubdomains") {
			acc.add(passiveCheckIDHSTS, "hsts-no-include-subdomains", Vulnerability{
				Title:     "Strict-Transport-Security has no includeSubDomains",
				Severity:  "info",
				Category:  passiveCategoryCrypto,
				CVSS:      passiveCVSSInfo,
				CWE:       "CWE-319",
				URL:       page.rawURL,
				Parameter: "Strict-Transport-Security",
				Evidence: passiveEvidence(passiveConfidenceInformational,
					fmt.Sprintf("%s: Strict-Transport-Security is %q without includeSubDomains, and the scan was told subdomains exist.", page.rawURL, passiveTruncate(raw, passiveMaxExcerpt)),
					"reported only because the operator declared KnownSubdomains; without that declaration this is left alone, since a missing includeSubDomains on a host with no subdomains is noise."),
				Impact:      "Hygiene only: subdomains remain reachable over http without a cached HSTS state of their own.",
				Remediation: "Add includeSubDomains once every subdomain serves https, then consider preload.",
				References:  []string{passiveRefCSHSTS, passiveRefMDNHSTS},
			})
		}
	}
}

// passiveHSTSMaxAge parses the max-age directive, tolerating quotes.
func passiveHSTSMaxAge(raw string) (int, bool) {
	match := passiveHSTSMaxAgeRe.FindStringSubmatch(raw)
	if match == nil {
		return 0, false
	}
	value, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, false
	}
	return value, true
}

func passiveHSTSHasDirective(raw, directive string) bool {
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := part
		if eq := strings.Index(part, "="); eq >= 0 {
			name = strings.TrimSpace(part[:eq])
		}
		if strings.EqualFold(name, directive) {
			return true
		}
	}
	return false
}

var passiveHSTSMaxAgeRe = regexp.MustCompile(`(?i)\bmax-age\s*=\s*"?(\d+)"?`)

// ---------------------------------------------------------------------------
// Check 5: cookie attributes (WSTG-SESS-02)
// ---------------------------------------------------------------------------

// checkCookies reports missing cookie attributes. Cookie values are never
// echoed: evidence quotes the Set-Cookie line with the value replaced by a
// length marker, so a report can name the cookie without disclosing it.
func (p *PassiveScanner) checkCookies(_ context.Context, acc *passiveFindingSet, pages []*passiveResponse, _ *passiveSoft404Baseline) {
	for _, page := range pages {
		if page == nil || page.header == nil {
			continue
		}
		https := strings.EqualFold(passiveBaseScheme(page.rawURL), "https")
		for _, raw := range page.header.Values("Set-Cookie") {
			cookie := passiveParseSetCookie(raw)
			if cookie.name == "" {
				continue
			}
			redacted := passiveRedactCookieValue(raw)
			sessionish := passiveSessionCookieRe.MatchString(cookie.name)

			if sessionish && !cookie.has("httponly") {
				acc.add(passiveCheckIDCookie, "cookie-no-httponly:"+cookie.name, Vulnerability{
					Title:     fmt.Sprintf("Cookie %q is not HttpOnly", passiveTruncate(cookie.name, passiveMaxExcerpt)),
					Severity:  "medium",
					Category:  passiveCategoryAuth,
					CVSS:      passiveCVSSMedium,
					CWE:       "CWE-1004",
					URL:       page.rawURL,
					Parameter: cookie.name,
					Evidence: passiveEvidence(passiveConfidenceConfirmed,
						fmt.Sprintf("%s: Set-Cookie was %s, with no HttpOnly attribute.", page.rawURL, redacted),
						"the attribute list was parsed segment by segment and HttpOnly is absent. The cookie name matches a session-like pattern, so any script executing in the page could read it; whether such a script exists is out of scope for this passive check."),
					Impact:      "Any cross-site scripting flaw, however minor, becomes a session theft instead of a defaced page.",
					Remediation: "Add HttpOnly to every cookie that is not read by client-side script.",
					References:  []string{passiveRefWSTGCookies, passiveRefCSSession, passiveRefMDNCookie, passiveRefRFC6265},
				})
			}

			if https && !cookie.has("secure") {
				severity := "low"
				title := fmt.Sprintf("Cookie %q is not Secure on an https site", passiveTruncate(cookie.name, passiveMaxExcerpt))
				if sessionish {
					severity = "medium"
				}
				acc.add(passiveCheckIDCookie, "cookie-no-secure:"+cookie.name, Vulnerability{
					Title:     title,
					Severity:  severity,
					Category:  passiveCategoryCrypto,
					CVSS:      passiveCVSSFor(severity),
					CWE:       "CWE-614",
					URL:       page.rawURL,
					Parameter: cookie.name,
					Evidence: passiveEvidence(passiveConfidenceConfirmed,
						fmt.Sprintf("%s is https and Set-Cookie was %s, with no Secure attribute.", page.rawURL, redacted),
						"the page URL scheme is https and the attribute list was parsed segment by segment; Secure is absent. The cookie is still delivered over any http request to this host, so an open network can capture it."),
					Impact:      "The cookie is sent in cleartext on any http request to this host, exposing it to interception on an open network.",
					Remediation: "Add Secure to every cookie set on an https site.",
					References:  []string{passiveRefWSTGCookies, passiveRefCSSession, passiveRefMDNCookie, passiveRefRFC6265},
				})
			}

			sameSite, hasSameSite := cookie.valueOf("samesite")
			switch {
			case !hasSameSite:
				acc.add(passiveCheckIDCookie, "cookie-no-samesite:"+cookie.name, Vulnerability{
					Title:     fmt.Sprintf("Cookie %q has no SameSite attribute", passiveTruncate(cookie.name, passiveMaxExcerpt)),
					Severity:  "low",
					Category:  passiveCategoryAuth,
					CVSS:      passiveCVSSLow,
					CWE:       "CWE-1275",
					URL:       page.rawURL,
					Parameter: cookie.name,
					Evidence: passiveEvidence(passiveConfidenceConfirmed,
						fmt.Sprintf("%s: Set-Cookie was %s, with no SameSite attribute.", page.rawURL, redacted),
						"the attribute list was parsed segment by segment and SameSite is absent. Current browsers default to Lax, so the practical impact is limited to cross-site subresource and iframe contexts; that is why this is low rather than medium."),
					Impact:      "Cross-site subresource and iframe contexts still receive the cookie, which keeps some CSRF surface open on older browsers.",
					Remediation: "Set SameSite=Lax (or Strict where the flow allows); use None only together with Secure.",
					References:  []string{passiveRefWSTGCookies, passiveRefCSSession, passiveRefMDNCookie},
				})
			case strings.EqualFold(strings.TrimSpace(sameSite), "none") && !cookie.has("secure"):
				acc.add(passiveCheckIDCookie, "cookie-samesite-none-insecure:"+cookie.name, Vulnerability{
					Title:     fmt.Sprintf("Cookie %q sets SameSite=None without Secure", passiveTruncate(cookie.name, passiveMaxExcerpt)),
					Severity:  "high",
					Category:  passiveCategoryAuth,
					CVSS:      passiveCVSSHigh,
					CWE:       "CWE-1275",
					URL:       page.rawURL,
					Parameter: cookie.name,
					Evidence: passiveEvidence(passiveConfidenceConfirmed,
						fmt.Sprintf("%s: Set-Cookie was %s; SameSite=None is present but Secure is not.", page.rawURL, redacted),
						"both attributes were parsed from the quoted Set-Cookie line. Current browsers reject a SameSite=None cookie that is not Secure, so this is either a broken cross-site flow or a cookie intended to be sent cross-site over http."),
					Impact:      "Browsers refuse the cookie outright, which breaks the cross-site flow; where it is still accepted, the cookie travels over plaintext.",
					Remediation: "Add Secure alongside SameSite=None, or switch to SameSite=Lax if the cross-site flow is not required.",
					References:  []string{passiveRefWSTGCookies, passiveRefCSSession, passiveRefMDNCookie},
				})
			}
		}
	}
}

// passiveBaseScheme returns the scheme of an absolute URL, or "" when it cannot be
// parsed. It exists so a malformed probe URL can never be mistaken for http.
func passiveBaseScheme(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Scheme
}

// ---------------------------------------------------------------------------
// Check 6: __Host- and __Secure- cookie prefixes
// ---------------------------------------------------------------------------

// checkCookiePrefixes verifies that cookies claiming a browser-enforced prefix
// actually satisfy the prefix contract. A prefix that lies is worse than no
// prefix: the operator believes the browser is enforcing the attributes while
// the cookie itself does not carry them.
func (p *PassiveScanner) checkCookiePrefixes(_ context.Context, acc *passiveFindingSet, pages []*passiveResponse, _ *passiveSoft404Baseline) {
	for _, page := range pages {
		if page == nil || page.header == nil {
			continue
		}
		https := strings.EqualFold(passiveBaseScheme(page.rawURL), "https")
		for _, raw := range page.header.Values("Set-Cookie") {
			cookie := passiveParseSetCookie(raw)
			if cookie.name == "" {
				continue
			}
			var violations []string
			prefix := ""
			switch {
			case strings.HasPrefix(cookie.name, "__Host-"):
				prefix = "__Host-"
				if !cookie.has("secure") {
					violations = append(violations, "Secure is missing")
				}
				if domain, ok := cookie.valueOf("domain"); ok && domain != "" {
					violations = append(violations, "a Domain attribute is set ("+passiveTruncate(domain, passiveMaxExcerpt)+")")
				}
				if path, ok := cookie.valueOf("path"); ok && path != "/" {
					violations = append(violations, "Path is "+passiveTruncate(strconv.Quote(path), passiveMaxExcerpt)+" instead of /")
				}
			case strings.HasPrefix(cookie.name, "__Secure-"):
				prefix = "__Secure-"
				if !cookie.has("secure") {
					violations = append(violations, "Secure is missing")
				}
			default:
				continue
			}
			// On a plain http base the Secure attribute cannot be set at all, so
			// flagging its absence would be noise: only the non-Secure violations
			// still apply there, and Domain/Path do.
			if len(violations) == 0 {
				continue
			}
			severity := "medium"
			if prefix == "__Secure-" && !https {
				continue
			}
			acc.add(passiveCheckIDPrefix, "prefix:"+prefix+":"+cookie.name, Vulnerability{
				Title:     fmt.Sprintf("Cookie %q claims the %s prefix but violates it", passiveTruncate(cookie.name, passiveMaxExcerpt), prefix),
				Severity:  severity,
				Category:  passiveCategoryAuth,
				CVSS:      passiveCVSSFor(severity),
				CWE:       "CWE-614",
				URL:       page.rawURL,
				Parameter: cookie.name,
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s: Set-Cookie was %s; %s prefix violations: %s.", page.rawURL, passiveRedactCookieValue(raw), prefix, strings.Join(violations, "; ")),
					"the attribute list was parsed segment by segment and each violation is a concrete attribute comparison, not a guess. A conforming browser drops such a cookie entirely, so the finding means either a broken login or a cookie that never received the protection the name promises."),
				Impact:      "Either the cookie is silently rejected (breaking the flow it belongs to), or it keeps a Domain or path scope the prefix was supposed to forbid.",
				Remediation: "For __Host- cookies: Secure, Path=/ and no Domain attribute. For __Secure- cookies: Secure is mandatory. Set them from the response host only.",
				References:  []string{passiveRefWSTGCookies, passiveRefCSSession, passiveRefMDNCookie, passiveRefRFC6265},
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Check 7: JWT inspection (WSTG-SESS-10)
// ---------------------------------------------------------------------------

// checkJWT decodes JWTs observed in response bodies and cookies. It never
// rewrites or replays a token: it only decodes the header and the expiry claim,
// and evidence references the token by SHA-256 alone.
//
// Three weaknesses, three separate IDs, because their severity and confidence
// differ:
//
//   - alg "none"      -> high,  heuristic (whether the server accepts it is untested)
//   - missing exp     -> low,   heuristic, and only when the payload really decoded
//   - mixed HS and RS -> medium, heuristic, and only when both families were seen
//     across the scan (a single HS256 login token is normal and not flagged)
func (p *PassiveScanner) checkJWT(_ context.Context, acc *passiveFindingSet, pages []*passiveResponse, _ *passiveSoft404Baseline) {
	type candidate struct {
		token  string
		source string
	}
	var (
		seen          []passiveJWTInfo
		seenHash      = map[string]struct{}{}
		tokenCount    int
		sawSymmetric  bool
		sawAsymmetric bool
	)
	for _, page := range pages {
		if page == nil {
			continue
		}
		var candidates []candidate
		for _, token := range passiveFindJWTs(string(page.body)) {
			candidates = append(candidates, candidate{token: token, source: "response body"})
		}
		for _, raw := range page.header.Values("Set-Cookie") {
			cookie := passiveParseSetCookie(raw)
			value := strings.Trim(cookie.value, `"'`)
			if value == "" {
				continue
			}
			for _, token := range passiveFindJWTs(value) {
				candidates = append(candidates, candidate{token: token, source: "Set-Cookie value"})
			}
		}
		for _, item := range candidates {
			if tokenCount >= passiveMaxJWTsTotal {
				break
			}
			sum := sha256.Sum256([]byte(item.token))
			hash := hex.EncodeToString(sum[:])
			if _, dup := seenHash[hash]; dup {
				continue
			}
			seenHash[hash] = struct{}{}
			tokenCount++
			info := passiveDecodeJWT(item.token, item.source, page.rawURL)
			if !info.headerOK {
				continue
			}
			seen = append(seen, info)
			if passiveJWSymmetric(info.alg) {
				sawSymmetric = true
			}
			if passiveJWTAsymmetric(info.alg) {
				sawAsymmetric = true
			}
			p.passiveJWTWeakness(acc, info)
		}
	}
	if sawSymmetric && sawAsymmetric {
		p.passiveJWTMixedAlgorithms(acc, seen)
	}
}

// passiveJWTWeakness emits the per-token findings: alg none and a missing exp.
func (p *PassiveScanner) passiveJWTWeakness(acc *passiveFindingSet, info passiveJWTInfo) {
	if strings.EqualFold(strings.TrimSpace(info.alg), "none") {
		acc.add(passiveCheckIDJWTAlg, "jwt-alg-none:"+info.hash, Vulnerability{
			Title:     "JWT header sets alg to none (unsigned token accepted into the pipeline)",
			Severity:  "high",
			Category:  passiveCategoryAuth,
			CVSS:      passiveCVSSHigh,
			CWE:       "CWE-347",
			URL:       info.rawURL,
			Parameter: info.source,
			Evidence: passiveEvidence(passiveConfidenceHeuristic,
				fmt.Sprintf("%s: a JWT observed in the %s decodes as {\"alg\":%q,\"typ\":%q,\"kid\":%q}; SHA-256 of the token is %s.", info.rawURL, info.source, info.alg, passiveTruncate(info.typ, 64), passiveTruncate(info.kid, 64), info.hash),
				"the header JSON decoded cleanly and alg is none (matched case-insensitively, as implementations accept NONE and None). Whether the server accepts such a token is NOT tested: this scanner never sends a forged token, so the severity assumes the naive verifier. Confirm with one manual login attempt before escalation."),
			Impact:      "If the server verifies by algorithm name alone, any attacker can mint a token for any subject and take over the account. This scanner did not test acceptance, so treat the claim as requiring confirmation.",
			Remediation: "Reject the none algorithm explicitly, pin the expected algorithm server-side, and verify the signature before parsing claims.",
			References:  []string{passiveRefWSTGJWT, passiveRefCSJWT, passiveRefRFC7519, passiveRefTopA07},
		})
	}
	if info.payloadOK && !info.hasExp {
		acc.add(passiveCheckIDJWTExp, "jwt-no-exp:"+info.hash, Vulnerability{
			Title:     "JWT carries no exp claim (no built-in expiry)",
			Severity:  "low",
			Category:  passiveCategoryAuth,
			CVSS:      passiveCVSSLow,
			CWE:       "CWE-613",
			URL:       info.rawURL,
			Parameter: info.source,
			Evidence: passiveEvidence(passiveConfidenceHeuristic,
				fmt.Sprintf("%s: a JWT observed in the %s has a payload that decodes to JSON without an \"exp\" claim; SHA-256 of the token is %s (alg=%q).", info.rawURL, info.source, info.hash, passiveTruncate(info.alg, 32)),
				"expiry was checked only because the payload decoded as JSON: an encrypted or opaque token would produce no finding at all. The server may still enforce its own lifetime elsewhere, which is why this is low and heuristic rather than medium."),
			Impact:      "A stolen token stays valid indefinitely unless the server maintains a separate revocation list, widening the window for replay after a leak.",
			Remediation: "Add a short exp claim and validate it server-side, backed by server-side revocation for logout.",
			References:  []string{passiveRefWSTGJWT, passiveRefCSJWT, passiveRefRFC7519, passiveRefTopA07},
		})
	}
}

// passiveJWTMixedAlgorithms reports HS/RS mixing across the scan. The mixed
// precondition is what keeps a normal HS256-only login flow from being flagged.
func (p *PassiveScanner) passiveJWTMixedAlgorithms(acc *passiveFindingSet, infos []passiveJWTInfo) {
	var symmetric, asymmetric []passiveJWTInfo
	for _, info := range infos {
		switch {
		case passiveJWSymmetric(info.alg):
			symmetric = append(symmetric, info)
		case passiveJWTAsymmetric(info.alg):
			asymmetric = append(asymmetric, info)
		}
	}
	if len(symmetric) == 0 || len(asymmetric) == 0 {
		return
	}
	first := symmetric[0]
	acc.add(passiveCheckIDJWTCrypto, "jwt-mixed-algorithms:"+first.hash, Vulnerability{
		Title:     "Application mixes symmetric and asymmetric JWT signing algorithms",
		Severity:  "medium",
		Category:  passiveCategoryIntegrity,
		CVSS:      passiveCVSSMedium,
		CWE:       "CWE-347",
		URL:       first.rawURL,
		Parameter: first.source,
		Evidence: passiveEvidence(passiveConfidenceHeuristic,
			fmt.Sprintf("%s: observed symmetric alg %q (token SHA-256 %s) and asymmetric alg %q (token SHA-256 %s) on the same target.", first.rawURL, first.alg, first.hash, asymmetric[0].alg, asymmetric[0].hash),
			"both families were decoded from header JSON on this target, so the mixing is an observation; the RISK is an inference, because a verifier that discovers the algorithm from the token can be switched between HS and RS modes. Whether this server does that was not tested."),
		Impact:      "If any verification path derives the algorithm from the token, an RS256 public key can be reused as an HS256 shared secret to forge tokens.",
		Remediation: "Configure one allowed algorithm per key, never a list derived from the token, and never fall back from asymmetric to symmetric.",
		References:  []string{passiveRefWSTGJWT, passiveRefCSJWT, passiveRefRFC7519, passiveRefTopA08},
	})
}

// ---------------------------------------------------------------------------
// Check 8: Cache-Control on sensitive responses (WSTG-SESS-06)
// ---------------------------------------------------------------------------

// checkCacheControl reports exactly four situations on responses that carry
// session material (a Set-Cookie) or live on a sensitive path:
//
//	public or max-age >= 1000 -> shared-cacheable / long-lived, high on a
//	                             Set-Cookie response, medium otherwise
//	no-cache only              -> stored and replayed after revalidation, low
//	absent on a Set-Cookie     -> left to browser and proxy defaults, medium
//
// A response that says no-store is clean and gets nothing. No finding is raised
// for an absent header on a non-cookie sensitive path: that case has no session
// material to protect and would drown the report.
func (p *PassiveScanner) checkCacheControl(_ context.Context, acc *passiveFindingSet, pages []*passiveResponse, _ *passiveSoft404Baseline) {
	for _, page := range pages {
		if page == nil || page.header == nil {
			continue
		}
		setsCookie := len(page.header.Values("Set-Cookie")) > 0
		sensitivePath := passiveSensitivePathRe.MatchString(page.path)
		if !setsCookie && !sensitivePath {
			continue
		}
		raw := strings.TrimSpace(page.header.Get("Cache-Control"))
		directives := passiveCacheDirectives(raw)
		if _, clean := directives["no-store"]; clean {
			continue
		}
		trigger := "a Set-Cookie header"
		if !setsCookie {
			trigger = "the sensitive path " + passiveTruncate(page.path, passiveMaxExcerpt)
		}
		_, public := directives["public"]
		maxAgeValue, hasMaxAge := directives["max-age"]
		maxAge, atoiErr := strconv.Atoi(maxAgeValue)
		longLived := public
		if hasMaxAge && atoiErr == nil && maxAge >= passiveSensitiveCacheMaxAge {
			longLived = true
		}
		noCache := func() bool { _, ok := directives["no-cache"]; return ok }

		switch {
		case longLived:
			severity := "medium"
			if setsCookie {
				severity = "high"
			}
			acc.add(passiveCheckIDCache, "cache-cacheable", Vulnerability{
				Title:     "Sensitive response is cacheable by shared caches",
				Severity:  severity,
				Category:  passiveCategoryAuth,
				CVSS:      passiveCVSSFor(severity),
				CWE:       "CWE-524",
				URL:       page.rawURL,
				Parameter: "Cache-Control",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s set %s and carried Cache-Control: %s.", page.rawURL, trigger, passiveTruncate(raw, passiveMaxExcerpt)),
					"the header value and the trigger were both read verbatim from the response. Whether a particular shared cache actually stores it depends on that cache's behaviour, which this scanner does not probe: no cache-poisoning attempt is ever made, this is the header contract only."),
				Impact:      "A shared proxy or a shared machine can replay an authenticated response, exposing session material to another user of the same cache.",
				Remediation: "Send Cache-Control: no-store, no-cache, must-revalidate, private on responses that set a cookie or return user-specific content.",
				References:  []string{passiveRefWSTGCache, passiveRefCSWebCache, passiveRefMDNCC, passiveRefRFC7234},
			})
		case noCache():
			acc.add(passiveCheckIDCache, "cache-no-cache-only", Vulnerability{
				Title:     "Sensitive response allows caching with revalidation only",
				Severity:  "low",
				Category:  passiveCategoryAuth,
				CVSS:      passiveCVSSLow,
				CWE:       "CWE-524",
				URL:       page.rawURL,
				Parameter: "Cache-Control",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s set %s and carried Cache-Control: %s, with no no-store directive.", page.rawURL, trigger, passiveTruncate(raw, passiveMaxExcerpt)),
					"no-cache is not no-store: the response may still be stored and replayed after a revalidation request, and that distinction is exactly what the quoted directives show."),
				Impact:      "The response may still be written to disk or a shared cache and replayed, so session material can survive on a shared machine.",
				Remediation: "Use no-store in addition to no-cache for responses that set a cookie.",
				References:  []string{passiveRefWSTGCache, passiveRefMDNCC, passiveRefRFC7234},
			})
		case raw == "" && setsCookie:
			acc.add(passiveCheckIDCache, "cache-absent", Vulnerability{
				Title:     "Response sets a cookie but sends no Cache-Control",
				Severity:  "medium",
				Category:  passiveCategoryAuth,
				CVSS:      passiveCVSSMedium,
				CWE:       "CWE-524",
				URL:       page.rawURL,
				Parameter: "Cache-Control",
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("%s set a cookie (name redacted) and carried no Cache-Control header field.", page.rawURL),
					"the absence of the header is a byte-level fact. Intermediary defaults normally avoid storing Set-Cookie responses, so this is medium rather than high, but the behaviour is left to defaults the operator does not control."),
				Impact:      "Caching of an authenticated response is delegated to browser and proxy defaults instead of being stated by the server.",
				Remediation: "State the policy explicitly: Cache-Control: no-store, no-cache, must-revalidate, private on every cookie-setting response.",
				References:  []string{passiveRefWSTGCache, passiveRefMDNCC, passiveRefRFC7234},
			})
		}
	}
}

// passiveSensitivePathRe matches paths that normally return session or account
// material. It is only consulted for responses that do not set a cookie.
var passiveSensitivePathRe = regexp.MustCompile(`(?i)^/(admin|account|dashboard|profile|checkout|cart|order|orders|billing|payment|payments|settings|user|users|api/v\d+/me|session|auth)(/|$)`)

// ---------------------------------------------------------------------------
// Check 9: Host header canary (WSTG-INP-17)
// ---------------------------------------------------------------------------

// checkHostHeader sends two benign probes per configured path: one with the
// request Host set to an unresolvable canary, one with X-Forwarded-Host. The
// canary is never a domain anyone owns, so a reflection in the response is
// attributable to this probe and nothing else.
//
// No cache-poisoning attempt is made: the probe is a plain GET, the canary is
// not inserted into any stored value on purpose, and no request is repeated to
// see whether a cache retained it. Location reflection is reported as the
// redirect-poisoning vector it is; body reflection stays informational.
func (p *PassiveScanner) checkHostHeader(ctx context.Context, acc *passiveFindingSet, _ []*passiveResponse, _ *passiveSoft404Baseline) {
	for _, pp := range p.paths {
		if ctx.Err() != nil {
			return
		}
		target := p.passiveJoin(pp)
		p.passiveHostProbe(ctx, acc, target, passiveHostHeaderDirect)
		if ctx.Err() != nil {
			return
		}
		p.passiveHostProbe(ctx, acc, target, passiveHostHeaderForwarded)
	}
}

const (
	passiveHostHeaderDirect    = "Host"
	passiveHostHeaderForwarded = "X-Forwarded-Host"
)

// passiveHostProbe issues one canary probe and records what came back.
func (p *PassiveScanner) passiveHostProbe(ctx context.Context, acc *passiveFindingSet, target, headerName string) {
	var (
		resp *passiveResponse
		err  error
	)
	if headerName == passiveHostHeaderDirect {
		resp, err = p.passiveFetch(ctx, target, nil, passiveHostCanary)
	} else {
		resp, err = p.passiveFetch(ctx, target, map[string]string{headerName: passiveHostCanary}, "")
	}
	if err != nil || resp == nil {
		return
	}
	if location := strings.TrimSpace(resp.header.Get("Location")); location != "" && strings.Contains(location, passiveHostCanary) {
		tokenContext := passiveHostTokenContext(location)
		severity, confidence := passiveHostSeverity(true, tokenContext)
		acc.add(passiveCheckIDHost, "host:"+headerName+":location", Vulnerability{
			Title:     "Host canary reflected into the Location header (redirect poisoning)",
			Severity:  severity,
			Category:  passiveCategoryInjection,
			CVSS:      passiveCVSSFor(severity),
			CWE:       "CWE-644",
			URL:       target,
			Parameter: headerName,
			Evidence: passiveEvidence(confidence,
				fmt.Sprintf("GET %s with %s: %s returned Location: %s, containing the canary %q.", target, passiveHostProbeDescription(headerName), target, passiveTruncate(passiveRedactSecretish(location), passiveMaxExcerpt), passiveHostCanary),
				"the canary hostname is unresolvable and owned by nobody, so its presence in a Location value is attributable to this probe alone and not to any third party. Whether a shared cache would store this redirect is NOT tested: no cache-poisoning request is made, and the token-context verdict, where present, is an inference from nearby URL structure."),
			Impact:      "A password-reset or login redirect can be steered to an attacker-controlled host once the poisoned Location is followed or cached; no cache or mailbox was exercised here.",
			Remediation: "Never derive redirects from the Host header or X-Forwarded-Host: build absolute URLs from a configured canonical origin, and reject unknown hosts at the edge.",
			References:  []string{passiveRefWSTGHost, passiveRefTopA03, passiveRefCSWebCache},
		})
		return
	}
	if index := strings.Index(string(resp.body), passiveHostCanary); index >= 0 {
		window := passiveExcerptAround(resp.body, index, passiveHostWindow)
		tokenContext := passiveHostTokenContext(window)
		severity, confidence := passiveHostSeverity(false, tokenContext)
		acc.add(passiveCheckIDHost, "host:"+headerName+":body", Vulnerability{
			Title:     "Host canary reflected into the response body",
			Severity:  severity,
			Category:  passiveCategoryInjection,
			CVSS:      passiveCVSSFor(severity),
			CWE:       "CWE-644",
			URL:       target,
			Parameter: headerName,
			Evidence: passiveEvidence(confidence,
				fmt.Sprintf("GET %s with %s: the response body contains the canary %q at offset %d, context: %q.", target, passiveHostProbeDescription(headerName), passiveHostCanary, index, window),
				"the canary is unresolvable and owned by nobody, so the reflection is real; the SEVERITY is the part that needs a second look, because whether the reflected value feeds a token, an email or only a log line is read from the surrounding bytes, not proven by them."),
			Impact:      "Untrusted input reaches rendered output. This scanner does NOT claim XSS: whether the reflection is HTML-encoded or reaches a script context was not tested.",
			Remediation: "Ignore X-Forwarded-Host unless it comes from a trusted proxy, and normalise the host against an allowlist before it is used in any output.",
			References:  []string{passiveRefWSTGHost, passiveRefTopA03},
		})
	}
}

func passiveHostProbeDescription(headerName string) string {
	if headerName == passiveHostHeaderDirect {
		return "the request Host set to " + passiveHostCanary
	}
	return "an " + headerName + ": " + passiveHostCanary + " header"
}

// passiveHostSeverity grades a reflection. A Location reflection with a
// token-looking neighbour is the high case; a plain body reflection stays
// informational because rendering a hostname is ordinary behaviour.
func passiveHostSeverity(isLocation, tokenContext bool) (severity, confidence string) {
	switch {
	case isLocation && tokenContext:
		return "high", passiveConfidenceHeuristic
	case isLocation:
		return "medium", passiveConfidenceConfirmed
	case tokenContext:
		return "medium", passiveConfidenceConfirmed
	default:
		return "info", passiveConfidenceConfirmed
	}
}

// passiveHostTokenContext reports whether a reflection sits next to something
// that looks like a credential carried in a URL.
var passiveHostTokenContextRe = regexp.MustCompile(`(?i)(token|reset|verify|confirm|ticket|otp|code|key|session)=[A-Za-z0-9_\-\.%]{8,}`)

func passiveHostTokenContext(window string) bool {
	return passiveHostTokenContextRe.MatchString(window)
}

// ---------------------------------------------------------------------------
// Check 10: webserver metafiles (WSTG-INFO-03)
// ---------------------------------------------------------------------------

// checkMetafiles fetches /robots.txt and /.well-known/security.txt. A path the
// probe refused yields no finding of any kind: absence is only claimable when
// the request actually happened.
func (p *PassiveScanner) checkMetafiles(ctx context.Context, acc *passiveFindingSet, _ []*passiveResponse, baseline *passiveSoft404Baseline) {
	p.passiveCheckRobots(ctx, acc, baseline)
	p.passiveCheckSecurityTxt(ctx, acc, baseline)
}

// passiveCheckRobots reports sensitive paths the operator chose to advertise.
// An empty or 404 robots.txt is the correct default and gets no finding.
func (p *PassiveScanner) passiveCheckRobots(ctx context.Context, acc *passiveFindingSet, baseline *passiveSoft404Baseline) {
	rawURL, err := p.passiveProbeURL("/robots.txt")
	if err != nil {
		return
	}
	resp, err := p.passiveFetch(ctx, rawURL, nil, "")
	if err != nil || resp == nil {
		return
	}
	if resp.status < 200 || resp.status > 299 {
		return
	}
	if baseline.rejects(resp) {
		return
	}
	if !passiveLooksRobots(resp.body) {
		return
	}
	var exposed []string
	for _, line := range strings.Split(string(resp.body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)
		if !strings.HasPrefix(lower, "disallow:") && !strings.HasPrefix(lower, "allow:") {
			continue
		}
		if colon := strings.Index(trimmed, ":"); colon >= 0 {
			target := strings.TrimSpace(trimmed[colon+1:])
			if target != "" && passiveSensitivePathRe.MatchString(target) {
				exposed = append(exposed, passiveTruncate(trimmed, passiveMaxExcerpt))
				if len(exposed) >= 3 {
					break
				}
			}
		}
	}
	if len(exposed) == 0 {
		return
	}
	acc.add(passiveCheckIDMeta, "robots-sensitive-paths", Vulnerability{
		Title:     "robots.txt advertises sensitive paths to anonymous clients",
		Severity:  "low",
		Category:  passiveCategoryMisconfig,
		CVSS:      passiveCVSSLow,
		CWE:       "CWE-200",
		URL:       rawURL,
		Parameter: "robots.txt",
		Evidence: passiveEvidence(passiveConfidenceConfirmed,
			fmt.Sprintf("%s returned HTTP %d with %d-byte body advertising: %s.", rawURL, resp.status, len(resp.body), strings.Join(exposed, " | ")),
			"Disallow only tells well-behaved crawlers where to stay out; the quoted lines were read verbatim from a 2xx body that did not match the soft-404 baseline. Disallow is not access control, and an attacker can walk the same list."),
		Impact:      "Paths the operator considers unimportant are handed out as a to-do list, so reconnaissance that would need guessing is handed over instead.",
		Remediation: "Never rely on robots.txt for access control: authenticate the paths it names, and stop listing anything sensitive at all.",
		References:  []string{passiveRefWSTGMetafiles, passiveRefWSTGLEak, passiveRefTopA05},
	})
}

// passiveLooksRobots requires an actual robots directive, so an HTML page
// served as 200 at /robots.txt cannot be mistaken for a metafile.
func passiveLooksRobots(body []byte) bool {
	return passiveRobotsDirectiveRe.Match(body)
}

var passiveRobotsDirectiveRe = regexp.MustCompile(`(?im)^\s*(user-agent|allow|disallow|sitemap|crawl-delay)\s*:`)

// passiveCheckSecurityTxt reports a missing or incomplete RFC 9116 contact
// point. Only 404 and 410 count as "absent": a 403 means the file exists and is
// protected, and a 3xx is a canonicalisation this scanner does not follow.
func (p *PassiveScanner) passiveCheckSecurityTxt(ctx context.Context, acc *passiveFindingSet, baseline *passiveSoft404Baseline) {
	rawURL, err := p.passiveProbeURL("/.well-known/security.txt")
	if err != nil {
		return
	}
	resp, err := p.passiveFetch(ctx, rawURL, nil, "")
	if err != nil || resp == nil {
		return
	}
	validFormat := resp.status >= 200 && resp.status <= 299 && !baseline.rejects(resp) && passiveLooksSecurityTxt(resp.body)
	if validFormat && passiveSecurityTxtHasContact(resp.body) {
		return
	}
	if !validFormat && resp.status != 404 && resp.status != 410 {
		// 401/403 mean the file exists and is protected; 3xx and 5xx mean we do
		// not know. Silence is the only honest answer for all of them.
		return
	}
	evidence := ""
	if validFormat {
		evidence = passiveEvidence(passiveConfidenceConfirmed,
			fmt.Sprintf("%s returned HTTP %d with %d bytes of RFC 9116 content but no Contact: line.", rawURL, resp.status, len(resp.body)),
			"the body parsed as a security.txt (field: value lines) and the absence of Contact: was checked line by line; an unreachable contact point means a reporter has nowhere to go.")
	} else {
		evidence = passiveEvidence(passiveConfidenceConfirmed,
			fmt.Sprintf("%s returned HTTP %d, so no RFC 9116 contact point is published at the well-known location.", rawURL, resp.status),
			"only a 404 or 410 (or a non-security.txt body at this path) is treated as absent: a 401, 403 or redirect is deliberately NOT reported, because those responses do not prove the file is missing.")
	}
	acc.add(passiveCheckIDMeta, "security-txt-missing", Vulnerability{
		Title:       "No usable security.txt contact point is published",
		Severity:    "info",
		Category:    passiveCategoryMisconfig,
		CVSS:        passiveCVSSInfo,
		CWE:         "CWE-200",
		URL:         rawURL,
		Parameter:   "security.txt",
		Evidence:    evidence,
		Impact:      "Hygiene only: a researcher who finds a real flaw has no signed, machine-readable route to report it, so disclosure goes elsewhere or nowhere.",
		Remediation: "Publish /.well-known/security.txt with a Contact: line, an Expires: field and the policy URL, as required by RFC 9116.",
		References:  []string{passiveRefRFC9116, passiveRefWSTGMetafiles},
	})
}

func passiveLooksSecurityTxt(body []byte) bool {
	return passiveSecurityTxtFieldRe.Match(body)
}

func passiveSecurityTxtHasContact(body []byte) bool {
	return passiveSecurityTxtContactRe.Match(body)
}

var (
	passiveSecurityTxtFieldRe   = regexp.MustCompile(`(?im)^[A-Za-z][A-Za-z0-9-]*\s*:\s*\S+`)
	passiveSecurityTxtContactRe = regexp.MustCompile(`(?im)^\s*contact\s*:\s*\S+`)
)

// ---------------------------------------------------------------------------
// Check 11: exposed configuration and source artifacts (WSTG-CONF-03/04)
// ---------------------------------------------------------------------------

// passiveArtifactSpec is one fixed-path probe. A finding needs all of:
// HTTP 2xx, a body the soft-404 baseline does not recognise, a body that is not
// an HTML document, and a content signature that matches. Status 200 on its own
// proves nothing, because every theme on the web answers 200 for missing files.
type passiveArtifactSpec struct {
	path     string
	label    string
	severity string
	regex    *regexp.Regexp
	minHits  int
	magic    []byte
	offset   int
}

// passiveArtifacts is the fixed probe list. .dockerignore is deliberately NOT
// present: it has no reliable content signature (it is a comment-and-glob file
// identical in shape to a .gitignore), and probing it would mean reporting on
// status alone, which this scanner refuses to do.
var passiveArtifacts = []passiveArtifactSpec{
	{path: "/Dockerfile", label: "a Dockerfile (FROM instruction)", severity: "medium",
		regex: regexp.MustCompile(`(?m)^FROM\s+\S+`), minHits: 1},
	{path: "/docker-compose.yml", label: "a Compose file (top-level services key)", severity: "medium",
		regex: regexp.MustCompile(`(?m)^\s*services:\s*$`), minHits: 1},
	{path: "/.git/HEAD", label: "a Git HEAD reference", severity: "medium",
		regex: regexp.MustCompile(`(?m)^(ref: refs/heads/|\[core\])`), minHits: 1},
	{path: "/.git/config", label: "a Git config (INI section)", severity: "medium",
		regex: regexp.MustCompile(`(?m)^\s*\[(core|remote|branch)\]`), minHits: 1},
	{path: "/.git/config.bak", label: "a backed-up Git config (INI section)", severity: "medium",
		regex: regexp.MustCompile(`(?m)^\s*\[(core|remote|branch)\]`), minHits: 1},
	{path: "/.svn/wc.db", label: "an SQLite database (SVN working copy)", severity: "medium",
		magic: []byte("SQLite format 3\x00")},
	{path: "/.hg/hgrc", label: "a Mercurial hgrc (INI section)", severity: "medium",
		regex: regexp.MustCompile(`(?m)^\s*\[(paths|ui|extensions|hooks|web)\]`), minHits: 1},
	{path: "/.htaccess", label: "an Apache .htaccess (rewrite or auth directive)", severity: "medium",
		regex: regexp.MustCompile(`(?m)^\s*(<IfModule|RewriteEngine|RewriteCond|RewriteRule|Options|DirectoryIndex|AuthType|Require|Deny|Allow|AddHandler|SetEnv)\b`), minHits: 1},
	{path: "/web.config", label: "an IIS web.config (<configuration>)", severity: "medium",
		regex: regexp.MustCompile(`(?is)<configuration[\s>]`), minHits: 1},
	{path: "/.env", label: "a dotenv file (multiple KEY=value entries)", severity: "medium",
		regex: regexp.MustCompile(`(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S+`), minHits: 2},
	{path: "/.env?XDEBUG_SESSION_START=phpstorm", label: "a dotenv file (multiple KEY=value entries)", severity: "medium",
		regex: regexp.MustCompile(`(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S+`), minHits: 2},
	{path: "/composer.json", label: "a Composer manifest (require block)", severity: "medium",
		regex: regexp.MustCompile(`(?m)^\s*"require"\s*:`), minHits: 1},
	{path: "/.npmrc", label: "an npmrc with registry or auth settings", severity: "medium",
		regex: regexp.MustCompile(`(?m)^\s*(?:_auth|_authToken|registry|email|always-auth|//\S+:_authToken)\s*=`), minHits: 1},
	{path: "/id_rsa", label: "a PEM private key block", severity: "medium",
		regex: regexp.MustCompile(`-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----`), minHits: 1},
	{path: "/index.php.bak", label: "a backed-up PHP source file", severity: "medium",
		regex: regexp.MustCompile(`(?is)<\?php`), minHits: 1},
	{path: "/index.php~", label: "a backed-up PHP source file", severity: "medium",
		regex: regexp.MustCompile(`(?is)<\?php`), minHits: 1},
	{path: "/backup.sql", label: "a SQL dump (CREATE/INSERT/DROP statement)", severity: "medium",
		regex: regexp.MustCompile(`(?is)\b(?:CREATE TABLE|INSERT INTO|DROP TABLE)\b`), minHits: 1},
	{path: "/nginx.conf", label: "an nginx server block", severity: "medium",
		regex: regexp.MustCompile(`(?m)^\s*(?:server|http|location|upstream)\s*\{`), minHits: 1},
	{path: "/.gitlab-ci.yml", label: "a GitLab CI pipeline (2+ top-level keys)", severity: "medium",
		regex: regexp.MustCompile(`(?m)^(?:stages|variables|include|image|services|before_script|after_script|workflow|pages|default|cache)\s*:`), minHits: 2},
	{path: "/.DS_Store", label: "a macOS Finder directory listing (Bud1 magic)", severity: "low",
		magic: []byte("Bud1")},
	{path: "/Thumbs.db", label: "a Windows thumbnail cache (OLE2 container)", severity: "low",
		magic: []byte("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")},
}

// checkArtifacts probes each fixed path and reports only content-signature
// matches that survive the soft-404 baseline. 401 and 403 responses are skipped
// outright: 403 on .htaccess is the correct, secure answer and must never be
// reported as a leak.
func (p *PassiveScanner) checkArtifacts(ctx context.Context, acc *passiveFindingSet, _ []*passiveResponse, baseline *passiveSoft404Baseline) {
	for index, spec := range passiveArtifacts {
		if index >= passiveMaxArtifacts {
			break
		}
		if ctx.Err() != nil {
			return
		}
		rawURL, err := p.passiveProbeURL(spec.path)
		if err != nil {
			continue
		}
		resp, err := p.passiveFetch(ctx, rawURL, nil, "")
		if err != nil || resp == nil {
			continue
		}
		if resp.status < 200 || resp.status > 299 {
			continue
		}
		// An HTML document at these paths is the site's own page (usually a
		// themed 404), never a Dockerfile or a dotenv file.
		if resp.html.isHTML {
			continue
		}
		if baseline.rejects(resp) {
			continue
		}
		excerpt, ok := passiveArtifactSignature(spec, resp)
		if !ok {
			continue
		}
		acc.add(passiveCheckIDArtifact, "artifact:"+spec.path, Vulnerability{
			Title:     fmt.Sprintf("Exposed artifact at %s", spec.path),
			Severity:  spec.severity,
			Category:  passiveCategoryMisconfig,
			CVSS:      passiveCVSSFor(spec.severity),
			CWE:       "CWE-538",
			URL:       rawURL,
			Parameter: spec.path,
			Evidence: passiveEvidence(passiveConfidenceHigh,
				fmt.Sprintf("GET %s returned HTTP %d with a %d-byte body matching %s: %s. It does not match any of the soft-404 control responses.", rawURL, resp.status, len(resp.body), spec.label, excerpt),
				"a content signature and a soft-404 baseline, not the status code, decided this; still, a signature can match quoted or example content, so one manual confirmation is advised before escalation. No 401 or 403 response is ever reported here."),
			Impact:      "Repository metadata, build definitions or configuration become readable to anonymous clients, which usually hands an attacker source code, internal hostnames or credentials for the next step.",
			Remediation: "Serve the application from a directory that contains only published assets, block dotfile and backup extensions at the web server, and rotate any secret this file contains.",
			References:  []string{passiveRefWSTGFiles, passiveRefWSTGBackup, passiveRefCSDocker, passiveRefTopA05},
		})
	}
}

// passiveArtifactSignature returns the evidence excerpt for a matched spec.
func passiveArtifactSignature(spec passiveArtifactSpec, resp *passiveResponse) (string, bool) {
	if len(spec.magic) > 0 {
		start := spec.offset
		end := start + len(spec.magic)
		if len(resp.body) < end || !bytes.Equal(resp.body[start:end], spec.magic) {
			return "", false
		}
		preview := strings.Map(func(r rune) rune {
			if r < 0x20 || r > 0x7e {
				return '.'
			}
			return r
		}, string(resp.body[start:min(end+24, len(resp.body))]))
		return fmt.Sprintf("magic bytes %s at offset %d (%q)", hex.EncodeToString(spec.magic), start, preview), true
	}
	if spec.regex == nil {
		return "", false
	}
	hits := spec.regex.FindAllString(string(resp.body), 5)
	if len(hits) < spec.minHits {
		return "", false
	}
	parts := make([]string, 0, 3)
	for i, hit := range hits {
		if i >= 3 {
			break
		}
		parts = append(parts, passiveTruncate(passiveRedactSecretish(strings.ReplaceAll(strings.TrimSpace(hit), "\n", " ")), passiveMaxExcerpt))
	}
	return strings.Join(parts, " | "), true
}

// ---------------------------------------------------------------------------
// Check 12: published JavaScript source maps (WSTG-CONF-04)
// ---------------------------------------------------------------------------

// checkSourceMaps fetches "<script>.map" and "<stylesheet>.map" for resources
// the page actually referenced, on the target host only. A map on another host
// belongs to that host's operator and is never probed.
func (p *PassiveScanner) checkSourceMaps(ctx context.Context, acc *passiveFindingSet, pages []*passiveResponse, baseline *passiveSoft404Baseline) {
	probes := 0
	probed := map[string]struct{}{}
	for _, page := range pages {
		if ctx.Err() != nil {
			return
		}
		pageURL, err := url.Parse(page.rawURL)
		if err != nil {
			continue
		}
		for _, resource := range p.passivePageResources(page) {
			if probes >= passiveMaxMapProbes {
				return
			}
			ref, rerr := url.Parse(resource.rawURL)
			if rerr != nil {
				continue
			}
			abs := pageURL.ResolveReference(ref)
			if abs.Scheme != "http" && abs.Scheme != "https" {
				continue
			}
			if !sameHost(abs, p.base) {
				continue
			}
			mapURL := *abs
			mapURL.Fragment = ""
			if !strings.HasSuffix(strings.ToLower(mapURL.Path), ".map") {
				mapURL.Path += ".map"
				mapURL.RawPath = ""
			}
			target := mapURL.String()
			if _, dup := probed[target]; dup {
				continue
			}
			probed[target] = struct{}{}
			probes++
			resp, ferr := p.passiveFetch(ctx, target, nil, "")
			if ferr != nil || resp == nil {
				continue
			}
			if resp.status < 200 || resp.status > 299 || resp.html.isHTML || baseline.rejects(resp) {
				continue
			}
			var probe map[string]json.RawMessage
			if json.Unmarshal(resp.body, &probe) != nil {
				continue
			}
			if _, hasSources := probe["sources"]; !hasSources {
				continue
			}
			if _, hasMappings := probe["mappings"]; !hasMappings {
				continue
			}
			var parsed struct {
				Sources  []string `json:"sources"`
				Mappings string   `json:"mappings"`
			}
			_ = json.Unmarshal(resp.body, &parsed)
			acc.add(passiveCheckIDSrcMap, "sourcemap:"+target, Vulnerability{
				Title:     "JavaScript source map is published on the target host",
				Severity:  "medium",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSMedium,
				CWE:       "CWE-540",
				URL:       target,
				Parameter: resource.rawURL,
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("GET %s (referenced by %s) returned HTTP %d with %d bytes of JSON carrying both a \"sources\" array (%d entries) and a \"mappings\" string of %d bytes.", target, page.rawURL, resp.status, len(resp.body), len(parsed.Sources), len(parsed.Mappings)),
					"the response was required to be JSON with the source-map keys present, and it did not match the soft-404 baseline; the published file is the evidence, not an inference. Whether the mapped sources contain live secrets is not judged here."),
				Impact:      "Original, unminified source is handed out: real identifiers, comments and internal paths, which shortens reconnaissance and can expose configuration the build was meant to strip.",
				Remediation: "Do not publish .map files in production, or gate them behind authentication and remove them from the deployed bundle.",
				References:  []string{passiveRefWSTGBackup, passiveRefWSTGFiles, passiveRefWSTGResource, passiveRefTopA05},
			})
		}
	}
}

// passivePageResources is the script and stylesheet set a check may walk. The
// slice is freshly allocated so a caller appending to it can never corrupt the
// parsed page.
func (p *PassiveScanner) passivePageResources(page *passiveResponse) []passiveResource {
	if page == nil {
		return nil
	}
	out := make([]passiveResource, 0, len(page.html.scripts)+len(page.html.links))
	out = append(out, page.html.scripts...)
	for _, link := range page.html.links {
		if strings.Contains(link.rel, "stylesheet") {
			out = append(out, link)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Check 13: mixed content and Subresource Integrity (WSTG-CLNT-06)
// ---------------------------------------------------------------------------

// checkMixedContentAndSRI runs on https targets only. The two are mutually
// exclusive per resource: an http:// subresource is the mixed-content finding
// (medium, it travels in cleartext), anything else cross-origin without an
// integrity attribute is the SRI finding (low, it is a hardening gap).
func (p *PassiveScanner) checkMixedContentAndSRI(_ context.Context, acc *passiveFindingSet, pages []*passiveResponse, _ *passiveSoft404Baseline) {
	if p.base == nil || !strings.EqualFold(p.base.Scheme, "https") {
		return
	}
	mixed, sri := 0, 0
	for _, page := range pages {
		if page == nil || !page.html.isHTML {
			continue
		}
		pageURL, err := url.Parse(page.rawURL)
		if err != nil {
			continue
		}
		for _, resource := range p.passivePageResources(page) {
			ref, rerr := url.Parse(resource.rawURL)
			if rerr != nil {
				continue
			}
			abs := pageURL.ResolveReference(ref)
			kind := "stylesheet link"
			if resource.rel == "" {
				kind = "script"
			}
			if abs.Scheme == "http" {
				if mixed >= passiveMaxMixedResources {
					return
				}
				mixed++
				acc.add(passiveCheckIDMixed, "mixed:"+abs.String(), Vulnerability{
					Title:     "Page loads an active resource over plain http",
					Severity:  "medium",
					Category:  passiveCategoryCrypto,
					CVSS:      passiveCVSSMedium,
					CWE:       "CWE-319",
					URL:       page.rawURL,
					Parameter: resource.rawURL,
					Evidence: passiveEvidence(passiveConfidenceConfirmed,
						fmt.Sprintf("The https page %s references a %s at %s, which is fetched over http.", page.rawURL, kind, abs.String()),
						"the scheme of the resolved URL was read verbatim from the page HTML, so the downgrade is a fact; the MITM risk depends on the network path, which this scanner does not test."),
					Impact:      "On any hostile network the subresource can be replaced in transit, and a replaced script runs with the page's full privileges.",
					Remediation: "Reference every subresource over https, or use protocol-relative URLs only if every origin supports both schemes.",
					References:  []string{passiveRefWSTGResource, passiveRefTopA02, passiveRefCSTLS},
				})
				continue
			}
			if abs.Scheme != "https" {
				continue
			}
			if resource.integrity != "" || !passiveCrossOrigin(abs, pageURL) {
				continue
			}
			if sri >= passiveMaxMixedResources {
				return
			}
			sri++
			acc.add(passiveCheckIDSRI, "sri:"+abs.String(), Vulnerability{
				Title:     "Cross-origin resource is loaded without Subresource Integrity",
				Severity:  "low",
				Category:  passiveCategoryIntegrity,
				CVSS:      passiveCVSSLow,
				CWE:       "CWE-494",
				URL:       page.rawURL,
				Parameter: resource.rawURL,
				Evidence: passiveEvidence(passiveConfidenceConfirmed,
					fmt.Sprintf("The https page %s references a %s at %s with no integrity attribute.", page.rawURL, kind, abs.String()),
					"the element's attributes were parsed from the page and the integrity attribute is absent, which is a byte-level fact. Whether that origin is inside your own control plane is a judgement this scanner cannot make, so severity stays low."),
				Impact:      "If that origin is ever compromised, its replacement script executes without any check by the browser.",
				Remediation: "Pin third-party scripts and styles with an integrity attribute and crossorigin, or self-host them.",
				References:  []string{passiveRefMDNSRI, passiveRefTopA08, passiveRefCSCSP},
			})
		}
	}
}

// passiveCrossOrigin compares scheme and host (host carries the port).
func passiveCrossOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return true
	}
	return !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Host, b.Host)
}

// ---------------------------------------------------------------------------
// Check 14: information leakage in headers and comments (WSTG-INFO-05)
// ---------------------------------------------------------------------------

// passiveBannerHeaders are the response headers that fingerprint a stack.
var passiveBannerHeaders = []string{
	"Server",
	"X-Powered-By",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
	"X-Runtime",
	"X-Debug-Token",
}

// passiveVersionRe finds a version-shaped token in a banner.
var passiveVersionRe = regexp.MustCompile(`\b\d+\.\d+(?:\.\d+)*\b`)

// checkInfoLeakage reports version banners and secrets left in HTML comments.
// Both are hygiene findings: they are never described as exploitable, and
// comment evidence is redacted so the report cannot leak the secret it found.
func (p *PassiveScanner) checkInfoLeakage(_ context.Context, acc *passiveFindingSet, pages []*passiveResponse, _ *passiveSoft404Baseline) {
	for _, page := range pages {
		if page == nil || page.header == nil {
			continue
		}
		for _, name := range passiveBannerHeaders {
			value := strings.TrimSpace(page.header.Get(name))
			if value == "" {
				continue
			}
			severity := "info"
			title := fmt.Sprintf("Response discloses the %s header", name)
			if passiveVersionRe.MatchString(value) {
				severity = "low"
				title = fmt.Sprintf("Response discloses a %s version banner", name)
			}
			acc.add(passiveCheckIDBanner, "banner:"+name, Vulnerability{
				Title:     title,
				Severity:  severity,
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSFor(severity),
				CWE:       "CWE-200",
				URL:       page.rawURL,
				Parameter: name,
				Evidence: passiveEvidence(passiveConfidenceInformational,
					fmt.Sprintf("GET %s returned %s: %s.", page.rawURL, name, passiveTruncate(passiveRedactSecretish(value), passiveMaxExcerpt)),
					"the header value was read verbatim. Fingerprinting only narrows which known issues to look at; it is not itself a vulnerability, which is why the confidence is informational and no exploit is claimed."),
				Impact:      "Hygiene only: an attacker can match a product and version to its known issue list without any detection being raised.",
				Remediation: "Remove or genericise product headers at the edge, and keep versions off the wire entirely.",
				References:  []string{passiveRefWSTGLEak, passiveRefWSTGHeaders, passiveRefTopA05},
			})
		}

		if !page.html.isHTML {
			continue
		}
		for _, comment := range page.html.comments {
			excerpt, ok := passiveCommentSecret(comment)
			if !ok {
				continue
			}
			acc.add(passiveCheckIDComment, "comment-secret", Vulnerability{
				Title:     "HTML comment contains a secret-shaped string",
				Severity:  "low",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSLow,
				CWE:       "CWE-200",
				URL:       page.rawURL,
				Parameter: "HTML comment",
				Evidence: passiveEvidence(passiveConfidenceHeuristic,
					fmt.Sprintf("An HTML comment on %s contains: %s.", page.rawURL, excerpt),
					"the value shape (keyword followed by a value, or a TODO marker next to a secret keyword) was matched and the value itself is redacted. Whether the string is a live credential or documentation cannot be told from the bytes, so the confidence is heuristic: confirm it before acting."),
				Impact:      "Comment text ships to every visitor and is visible in page source, so an abandoned debug note can become working credentials.",
				Remediation: "Strip HTML comments from production templates and rotate anything that ever appeared in one.",
				References:  []string{passiveRefWSTGLEak, passiveRefTopA05},
			})
			break // one finding per URL keeps a comment-heavy page readable
		}
	}
}

var (
	// passiveCommentSecretRe is the keyword half of the two-tier comment rule.
	passiveCommentSecretRe = regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|token|credential)\b`)
	// passiveTodoRe is the marker half: a TODO next to a keyword is the classic
	// abandoned debug note.
	passiveTodoRe = regexp.MustCompile(`(?i)\b(?:todo|fixme|hack|xxx)\b`)
)

// passiveCommentSecret returns a redacted excerpt when a comment carries either
// a keyword with a value or a TODO marker beside a secret keyword.
func passiveCommentSecret(comment string) (string, bool) {
	if match := passiveSecretishRe.FindString(comment); match != "" {
		return passiveTruncate(passiveRedactSecretish(match), passiveMaxExcerpt), true
	}
	if passiveTodoRe.MatchString(comment) {
		if match := passiveCommentSecretRe.FindString(comment); match != "" {
			return passiveTruncate(match, passiveMaxExcerpt), true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Check 15: verbose errors and stack traces (WSTG-ERRH-02)
// ---------------------------------------------------------------------------

// passiveErrorMarkers are error shapes that are unmistakable in a response
// body. They are deliberately narrow: a documentation page that *discusses* an
// error is possible, so every finding is heuristic and quotes what matched.
var passiveErrorMarkers = []struct {
	label string
	re    *regexp.Regexp
}{
	{"java-stack-trace", regexp.MustCompile(`(?m)^[ \t]*at [\w$.]+\([\w$.]+\.java:\d+\)`)},
	{"php-fatal-error", regexp.MustCompile(`(?i)Fatal error:\s+\S`)},
	{"python-traceback", regexp.MustCompile(`(?m)^Traceback \(most recent call last\):`)},
	{"dotnet-stack-frame", regexp.MustCompile(`(?m)^[ \t]+at [\w.]+\([\w., ]+\) in [^\n]+:line \d+`)},
	{"mysql-syntax-error", regexp.MustCompile(`(?i)You have an error in your SQL syntax|SQLSTATE\[[0-9A-Z]+\]`)},
	{"postgres-error", regexp.MustCompile(`(?i)PostgreSQL query failed|PG::[A-Za-z]+Error|unterminated quoted string at or near`)},
	{"oracle-error", regexp.MustCompile(`(?i)\bORA-\d{5}\b`)},
}

// checkVerboseErrors looks for stack traces and database errors in the bodies
// already fetched: the soft-404 control response (the site's own error page)
// and each scanned page. No extra request is spent, because a control response
// was bought as part of the mandatory baseline.
func (p *PassiveScanner) checkVerboseErrors(_ context.Context, acc *passiveFindingSet, pages []*passiveResponse, baseline *passiveSoft404Baseline) {
	type candidate struct {
		// displayURL is the stable URL reported to the user.
		displayURL string
		// probeURL is the URL that was actually fetched, quoted in the evidence.
		probeURL string
		// control marks the soft-404 control sample: it was fetched at a random
		// nonexistent path, so the report points at the site root and says so.
		control bool
		body    []byte
	}
	bodies := make([]candidate, 0, len(pages)+1)
	if baseline != nil && baseline.controlURL != "" && len(baseline.control) > 0 {
		bodies = append(bodies, candidate{
			displayURL: p.base.String(),
			probeURL:   baseline.controlURL,
			control:    true,
			body:       baseline.control,
		})
	}
	for _, page := range pages {
		if page == nil {
			continue
		}
		bodies = append(bodies, candidate{displayURL: page.rawURL, probeURL: page.rawURL, body: page.body})
	}
	for _, item := range bodies {
		if len(item.body) == 0 {
			continue
		}
		text := string(item.body)
		if len(text) > passiveJWTScanLimit {
			text = text[:passiveJWTScanLimit]
		}
		for _, marker := range passiveErrorMarkers {
			match := marker.re.FindString(text)
			if match == "" {
				continue
			}
			excerpt := passiveRedactSecretish(strings.ReplaceAll(strings.TrimSpace(match), "\n", " "))
			observation := fmt.Sprintf("GET %s returned a body matching %s: %s.", item.probeURL, marker.label, passiveTruncate(excerpt, passiveMaxExcerpt))
			if item.control {
				observation = fmt.Sprintf("The site's soft-404 control page (fetched at a random nonexistent path, %s) returned a body matching %s: %s.", item.probeURL, marker.label, passiveTruncate(excerpt, passiveMaxExcerpt))
			}
			acc.add(passiveCheckIDError, "error:"+marker.label, Vulnerability{
				Title:     "Response body contains a verbose application error",
				Severity:  "medium",
				Category:  passiveCategoryMisconfig,
				CVSS:      passiveCVSSFor("medium"),
				CWE:       "CWE-209",
				URL:       item.displayURL,
				Parameter: marker.label,
				Evidence: passiveEvidence(passiveConfidenceHeuristic,
					observation,
					"the pattern is specific (a Java frame, a Python traceback header, a SQLSTATE code) but the body may be an example or documentation rather than a live failure, so the confidence is heuristic: reload the URL once to confirm."),
				Impact:      "Stack traces hand over real file paths, framework versions, query fragments and sometimes credentials, which turns a small mistake into a roadmap for the next attack.",
				Remediation: "Disable debug output in production, return a generic error page, and log the detail server-side only (see the OWASP Error Handling cheat sheet).",
				References:  []string{passiveRefWSTGStack, passiveRefCSErrors, passiveRefTopA05},
			})
		}
	}
}
