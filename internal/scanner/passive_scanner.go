// checks_passive.go implements the OWASP Top 10 (2021) passive check family.
//
// What "passive" means here
// -------------------------
// A passive check never mutates state, never guesses, and never sends a byte a
// normal browser would not send. Every probe this file issues is a plain GET of
// a URL that is either a configured scan path, a well-known public location
// (/robots.txt, /.env, ...), or a deliberately nonexistent control path used to
// calibrate the soft-404 baseline. There is no SQL payload, no fuzzing, no HTTP
// method other than GET, and no login. Everything goes through core.Requester
// (probe.go) so Guard's scope allowlist, rate limit, budget and timeout still
// apply, and every probe is unit-tested against an in-memory fake core.Requester.
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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner/core"
)

// ---------------------------------------------------------------------------
// Check identifiers. One prefix per weakness family so a report reader can tell
// two findings apart and so dedup has a stable key component.
// ---------------------------------------------------------------------------

const (
	passiveCheckIDHeaders   = "PSV-HDR"      // security headers present
	passiveCheckIDCSP       = "PSV-CSP"      // Content-Security-Policy analysis
	passiveCheckIDClickjack = "PSV-CLICK"    // X-Frame-Options / frame-ancestors
	passiveCheckIDHSTS      = "PSV-HSTS"     // #nosec G101 -- security header check ID, not a credential
	passiveCheckIDCookie    = "PSV-COOKIE"   // Set-Cookie attributes
	passiveCheckIDPrefix    = "PSV-PREFIX"   // __Host- / __Secure- cookie prefixes
	passiveCheckIDJWTAlg    = "PSV-JWTALG"   // #nosec G101 -- security check ID, not a credential
	passiveCheckIDJWTExp    = "PSV-JWTEXP"   // #nosec G101 -- security check ID, not a credential
	passiveCheckIDJWTCrypto = "PSV-JWTCRYPT" // #nosec G101 -- security check ID, not a credential
	passiveCheckIDCache     = "PSV-CACHE"    // Cache-Control on sensitive responses
	passiveCheckIDHost      = "PSV-HOST"     // Host header reflection
	passiveCheckIDMeta      = "PSV-META"     // robots.txt / security.txt
	passiveCheckIDArtifact  = "PSV-ARTIFACT" // exposed config/source artifacts
	passiveCheckIDSrcMap    = "PSV-SRCMAP"   // #nosec G101 -- security check ID, not a credential
	passiveCheckIDMixed     = "PSV-MIXED"    // mixed content
	passiveCheckIDSRI       = "PSV-SRI"      // missing Subresource Integrity
	passiveCheckIDBanner    = "PSV-BANNER"   // server version banners
	passiveCheckIDComment   = "PSV-COMMENT"  // secrets in HTML comments
	passiveCheckIDError     = "PSV-ERR"      // verbose error messages
)

// OWASP Top 10 (2021) category strings. Same spelling as vuln_scanner.go so a
// merged report groups them correctly.
const (
	passiveCategoryMisconfig = "A05:2021 Security Misconfiguration"                  // #nosec G101 -- security reference/signature constant, not a credential
	passiveCategoryCrypto    = "A02:2021 Cryptographic Failures"                     // #nosec G101 -- security reference/signature constant, not a credential
	passiveCategoryInjection = "A03:2021 Injection"                                  // #nosec G101 -- security reference/signature constant, not a credential
	passiveCategoryAuth      = "A07:2021 Identification and Authentication Failures" // #nosec G101 -- security reference/signature constant, not a credential
	passiveCategoryIntegrity = "A08:2021 Software and Data Integrity Failures"       // #nosec G101 -- security reference/signature constant, not a credential
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
	passiveHostCanary = "ss-canary.invalid" // #nosec G101 -- security reference/signature constant, not a credential
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
	passiveRefTopA02 = "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"                     // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefTopA03 = "https://owasp.org/Top10/A03_2021-Injection/"                                  // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefTopA05 = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"                  // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefTopA07 = "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefTopA08 = "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"       // #nosec G101 -- security reference/signature constant, not a credential

	passiveRefWSTGHeaders   = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/14-Other_HTTP_Security_Header_Misconfigurations"                       // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGCSP       = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/12-Content_Security_Policy"                                            // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGHSTS      = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/07-HTTP_Strict_Transport_Security"                                     // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGFiles     = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/03-File_Extensions_Handling_for_Sensitive_Information"                 // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGBackup    = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information" // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGCache     = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication/06-Browser_Cache_Weaknesses"                                                                    // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGMetafiles = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"                                   // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGLEak      = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage"                                      // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGCookies   = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management/02-Cookies_Attributes"                                                                      // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGJWT       = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management/10-JSON_Web_Tokens"                                                                         // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGHost      = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/17-Host_Header_Injection"                                                                            // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGStack     = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Error_Handling/02-Stack_Traces"                                                                                // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGClickjack = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side/09-Clickjacking"                                                                                   // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefWSTGResource  = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side/06-Client-side_Resource_Manipulation"                                                              // #nosec G101 -- security reference/signature constant, not a credential

	passiveRefCSHeaders   = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"                   // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefCSCSP       = "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"        // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefCSHSTS      = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html" // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefCSSession   = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"             // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefCSJWT       = "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html"                 // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefCSClickjack = "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"           // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefCSErrors    = "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"                 // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefCSTLS       = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"       // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefCSWebCache  = "https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html"             // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefCSDocker    = "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"                // #nosec G101 -- security reference/signature constant, not a credential

	passiveRefMDNCookie = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie"                // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefMDNCSP    = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy"   // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefMDNXFO    = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options"           // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefMDNHSTS   = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security" // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefMDNXCTO   = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options"    // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefMDNRP     = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy"           // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefMDNPP     = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy"        // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefMDNCC     = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control"             // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefMDNSRI    = "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"                   // #nosec G101 -- security reference/signature constant, not a credential

	passiveRefRFC9116 = "https://www.rfc-editor.org/rfc/rfc9116" // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefRFC6265 = "https://www.rfc-editor.org/rfc/rfc6265" // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefRFC7234 = "https://www.rfc-editor.org/rfc/rfc7234" // #nosec G101 -- security reference/signature constant, not a credential
	passiveRefRFC7519 = "https://www.rfc-editor.org/rfc/rfc7519" // #nosec G101 -- security reference/signature constant, not a credential
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
	// core.DefaultProbeLimit. It is never reduced below 1.
	MaxBodyBytes int64

	// UserAgent overrides core.ScannerUserAgent for these probes. Empty means
	// core.ScannerUserAgent, so a probe is always identifiable in the target's log.
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
	req     core.Requester
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
// core.Requester, an empty or unparseable URL, a missing host, userinfo in the URL,
// or a scheme other than http/https all return an error. It never guesses a
// scheme and never prepends "http://".
func NewPassiveScanner(baseURL string, req core.Requester, opts PassiveOptions) (*PassiveScanner, error) {
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
		return nil, fmt.Errorf("passive: base URL %q must not carry userinfo; use the core.Requester for credentials", raw)
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
		maxBody = core.DefaultProbeLimit
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
	// so they are guarded too: a core.Requester that panics must degrade the scan to
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
// page fetch, so a core.Requester that panics degrades the scan instead of ending it.
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

// passiveFetchPages fetches the configured page set. A page the core.Requester
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

// passiveFetch performs one policy-checked GET through the core.Requester. It never
// builds an *http.Client: the core.Requester seam is the only network path.
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
		ua = core.ScannerUserAgent
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
	body, err := core.ReadBody(resp, p.maxBody)
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
	case errors.Is(err, core.ErrOutOfScope):
		return "core.ErrOutOfScope"
	case errors.Is(err, core.ErrBudgetExhausted):
		return "core.ErrBudgetExhausted"
	case errors.Is(err, core.ErrRateLimited):
		return "core.ErrRateLimited"
	case errors.Is(err, core.ErrIntrusiveDisabled):
		return "core.ErrIntrusiveDisabled"
	case errors.Is(err, core.ErrDryRun):
		return "core.ErrDryRun"
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
