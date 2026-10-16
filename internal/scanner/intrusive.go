// intrusive.go is the deliberately dangerous half of the OWASP web-vulnerability
// scanner: the probes that inject payloads into a live target. Everything here
// is OFF BY DEFAULT and non-destructive by construction.
//
// SAFETY RULES (these are the point of the file, not a preamble)
//
//  1. Canary origins only. Every value a probe injects that is meant to "come
//     back" uses the reserved, non-resolving TLD ss-canary.invalid (RFC 2606).
//     The scanner is structurally incapable of causing a request to a third
//     party: it never uses 169.254.169.254 or any cloud metadata address, and
//     never phones a public collaborator (interactsh-style) service. That
//     trades away the detection of a few blind SSRF cases for the guarantee
//     that the tool can never pull cloud credentials or leak scan traffic to
//     an outside box.
//  2. No writes, ever, except the bounded write-method probe. Probe bodies are
//     empty. No DDL, no DML, no stacked queries, no file uploads, no brute
//     force, no DoS amplification: no large bodies and no concurrency at all
//     (ScanAll is strictly sequential).
//  3. Never print sensitive file contents. Path traversal reports ONLY
//     "signature matched: <name>"; the response body of a traversal probe can
//     never reach Evidence or PoC, and neither can anything credential-shaped.
//  4. Bounded work. MaxParams/MaxEndpoints caps, hard-coded per-probe request
//     caps (documented as consts below), a hard cap on the SENT sleep
//     duration, the Requester's timeout/budget/rate policy, and ReadBody caps
//     on every response (4 KiB for traversal).
//  5. Read-only verbs by default. GET only unless AllowPost is set explicitly;
//     the only PUT/DELETE in this file is the write-method probe.
//  6. Fail closed. A precondition that cannot be proven (an absent write
//     method, an unstable timing baseline, a target that echoes signatures for
//     every path) means the probe does not run and no finding is emitted,
//     never a guess.
//
// A probe runs only when BOTH its IntrusiveOptions flag is set AND the
// Requester's intrusive opt-in allows it (Check(ctx, method, url, true)).
// With every flag false, ScanAll returns nothing, Enabled() returns nothing,
// and not a single byte is sent.
//
// DELIBERATE OMISSIONS
//
//   - Header-carrier CRLF injection is NOT implemented. Go's net/http
//     transport refuses to write a header value containing CR/LF ("net/http:
//     invalid header field value"), so a request whose request headers carry a
//     raw CRLF cannot be expressed in this codebase at all. Only the
//     query-parameter carrier and the form-body carrier exist, and both cover
//     the same server-side defect (a value that is decoded and echoed into a
//     response header).
//   - Blind SSRF without an out-of-band channel cannot be confirmed. SSRF
//     findings are labelled heuristic and the evidence says exactly that.
//
// A single IntrusiveScanner is single-use: ScanAll is not re-entrant, shares
// its request budget across calls, and must not be run concurrently.
package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ── public API ───────────────────────────────────────────────────────────────

// IntrusiveOptions selects which intrusive probe families may run. Every family
// is off by default: the zero value sends nothing and finds nothing.
type IntrusiveOptions struct {
	// CRLFInjection probes header/response-splitting indicators by injecting a
	// percent-encoded CRLF plus a canary header into parameters.
	CRLFInjection bool

	// BooleanSQLi compares "' AND 1=1-- " against "' AND 1=2-- " (and
	// "1 AND 1=1" against "1 AND 1=2") on the same parameter, and refuses to
	// report unless a benign differing-suffix control stays identical.
	BooleanSQLi bool

	// TimeBasedSQLi measures a baseline and then asks for a hard-capped 2s
	// database sleep. It is the only probe with a timing side effect on the
	// target, and it is the slowest probe by construction.
	TimeBasedSQLi bool

	// PathTraversal injects read-only traversal signatures (plus a nonexistent
	// canary file) and confirms ONLY on unambiguous signatures.
	PathTraversal bool

	// SSRFIndicators injects canary and closed-port loopback URLs into
	// URL-shaped parameters and looks for a differential signal.
	SSRFIndicators bool

	// WriteMethodProbes issues PUT and DELETE against a random, provably
	// nonexistent path. It is the only probe that writes anything.
	WriteMethodProbes bool

	// AllowPost allows POST bodies as a probe carrier. When it is false only
	// GET is used (the write-method probe's PUT/DELETE is a separate,
	// independently gated family).
	AllowPost bool

	// MaxParams caps how many parameters are probed per endpoint. <=0 means 3.
	MaxParams int

	// MaxEndpoints caps how many endpoints are probed. <=0 means 5.
	MaxEndpoints int
}

// IntrusiveScanner runs the intrusive probes. Build it with
// NewIntrusiveScanner, which fails closed on anything questionable.
type IntrusiveScanner struct {
	base *url.URL
	req  Requester
	opts IntrusiveOptions

	// budget and timeBudget bound the total requests this scanner will ever
	// attempt, independently of the Requester's own budget.
	budget     int
	timeBudget int

	// timeFloor is the detection floor for the time-based probe. It defaults
	// to intrusiveTimeFloor (2s). Tests may lower it; nothing ever lowers the
	// SLEEP(2)/pg_sleep(2) that is actually SENT to the target.
	timeFloor time.Duration

	// gateClosed records a structural refusal from the Requester
	// (ErrIntrusiveDisabled or ErrOutOfScope), so the scan stops asking instead
	// of burning the whole budget on refusals.
	gateClosed bool
}

// NewIntrusiveScanner builds an intrusive scanner for baseURL.
//
// It fails closed: a nil Requester, an empty or unparsable URL, a URL without a
// host, a URL carrying userinfo, or a scheme other than http/https are all
// construction errors. Nothing is sent here — the constructor touches no
// network at all.
func NewIntrusiveScanner(baseURL string, req Requester, opts IntrusiveOptions) (*IntrusiveScanner, error) {
	if req == nil {
		return nil, errors.New("intrusive scanner: nil Requester (fail closed)")
	}
	raw := strings.TrimSpace(baseURL)
	if raw == "" {
		return nil, errors.New("intrusive scanner: empty base URL (fail closed)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("intrusive scanner: unparsable base URL: %w", err)
	}
	if u.Host == "" {
		return nil, errors.New("intrusive scanner: base URL has no host (fail closed)")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("intrusive scanner: scheme %q is not http(s) (fail closed)", u.Scheme)
	}
	if u.User != nil {
		return nil, errors.New("intrusive scanner: base URL carries userinfo (fail closed)")
	}
	// A fragment is never sent and only confuses request URL reconstruction.
	u.Fragment, u.RawFragment = "", ""
	u.Scheme = scheme

	opts.MaxParams = intrusiveClampCap(opts.MaxParams, intrusiveDefaultMaxParams)
	opts.MaxEndpoints = intrusiveClampCap(opts.MaxEndpoints, intrusiveDefaultMaxEndpoints)

	return &IntrusiveScanner{
		base:       u,
		req:        req,
		opts:       opts,
		budget:     intrusiveMaxTotalRequests,
		timeBudget: intrusiveTimeMaxRequests,
		timeFloor:  intrusiveTimeFloor,
	}, nil
}

// Enabled returns the names of the probe families this scanner is configured to
// run, in a fixed order, so a CLI can report them honestly.
//
// It reflects the IntrusiveOptions only and performs no network I/O: whether
// the Requester's intrusive opt-in also allows a family is discovered at scan
// time, never here. With no option set it returns an empty slice.
func (i *IntrusiveScanner) Enabled() []string {
	if i == nil {
		return []string{}
	}
	names := make([]string, 0, 6)
	if i.opts.CRLFInjection {
		names = append(names, intrusiveProbeCRLF)
	}
	if i.opts.BooleanSQLi {
		names = append(names, intrusiveProbeBooleanSQLi)
	}
	if i.opts.TimeBasedSQLi {
		names = append(names, intrusiveProbeTimeSQLi)
	}
	if i.opts.PathTraversal {
		names = append(names, intrusiveProbeTraversal)
	}
	if i.opts.SSRFIndicators {
		names = append(names, intrusiveProbeSSRF)
	}
	if i.opts.WriteMethodProbes {
		names = append(names, intrusiveProbeWriteMethod)
	}
	return names
}

// ScanAll runs every enabled probe family and returns the findings in a
// deterministic order: endpoint order, then probe family, then parameter order.
//
// It returns an empty (never nil) slice when nothing is enabled, and never
// panics: a refusal from the Requester, a dead context or a transport error all
// simply produce no findings.
func (i *IntrusiveScanner) ScanAll(ctx context.Context) []Vulnerability {
	findings := []Vulnerability{}
	if i == nil || i.req == nil || i.base == nil {
		return findings
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if len(i.Enabled()) == 0 || ctx.Err() != nil {
		return findings
	}
	for _, ep := range i.endpoints() {
		if i.gateClosed || ctx.Err() != nil {
			break
		}
		findings = append(findings, i.scanCRLFInjection(ctx, ep)...)
		findings = append(findings, i.scanBooleanSQLi(ctx, ep)...)
		findings = append(findings, i.scanTimeBasedSQLi(ctx, ep)...)
		findings = append(findings, i.scanPathTraversal(ctx, ep)...)
		findings = append(findings, i.scanSSRFIndicators(ctx, ep)...)
	}
	if !i.gateClosed && ctx.Err() == nil && i.opts.WriteMethodProbes {
		findings = append(findings, i.scanWriteMethods(ctx)...)
	}
	return findings
}

// ── constants: payloads, caps and detection thresholds ───────────────────────

// Defaults applied when the corresponding IntrusiveOptions field is <= 0.
const (
	intrusiveDefaultMaxParams    = 3
	intrusiveDefaultMaxEndpoints = 5
)

// intrusiveMaxTotalRequests is the whole-scan request allowance this file will
// ever attempt, on top of the Requester's own budget. Worst case with the
// default caps: per endpoint CRLF 3 + Boolean 3x6=18 + traversal 12 + SSRF 16
// = 49, times 5 endpoints = 245, plus the time-based cap (18, counted
// separately) and the write-method probe (4).
const intrusiveMaxTotalRequests = 256

// intrusiveLengthDeltaPercent is the materiality bar: a body difference only
// counts when the SHA-256 differs AND the length differs by more than this
// percentage of the longer response. One byte of echo is not a differential.
const intrusiveLengthDeltaPercent = 5

const (
	intrusiveFormContentType = "application/x-www-form-urlencoded"
	intrusiveIDPrefix        = "INTR"
	intrusiveWritePathPrefix = "intrusive-nonexistent-"
)

// Probe family names reported by Enabled().
const (
	intrusiveProbeCRLF        = "crlf-injection"
	intrusiveProbeBooleanSQLi = "boolean-sqli"
	intrusiveProbeTimeSQLi    = "time-based-sqli"
	intrusiveProbeTraversal   = "path-traversal"
	intrusiveProbeSSRF        = "ssrf-indicators"
	intrusiveProbeWriteMethod = "write-method-probes"
)

// Confidence vocabulary. Vulnerability has no Confidence field, so confidence
// is encoded as a "confidence=<value>; ..." prefix in Evidence.
const (
	intrusiveConfidenceConfirmed     = "confirmed"
	intrusiveConfidenceHigh          = "high"
	intrusiveConfidenceHeuristic     = "heuristic"
	intrusiveConfidenceInformational = "informational"
)

// CRLF carrier. The sequence is injected percent-encoded, so it stays inert on
// the wire and only becomes a real CRLF if the target decodes the parameter
// (or the form field) and echoes it into a response header.
const (
	intrusiveCRLFSuffix      = "%0d%0aX-SS-Canary:1"
	intrusiveCRLFCanaryName  = "X-SS-Canary"
	intrusiveCRLFMarker      = "X-SS-Canary"
	intrusiveCRLFMaxPerParam = 2 // one GET, plus one POST when AllowPost is set
)

// Boolean SQLi payloads. The numeric family is appended to the original value,
// so a value of "1" becomes "1 AND 1=1" / "1 AND 1=2".
const (
	intrusiveSQLiQuoteTrue  = "' AND 1=1-- "
	intrusiveSQLiQuoteFalse = "' AND 1=2-- "
	intrusiveSQLiNumTrue    = " AND 1=1"
	intrusiveSQLiNumFalse   = " AND 1=2"
	intrusiveSQLiControlTag = "ssqctl"
	intrusiveSQLiPairs      = 2                        // payload pairs per parameter (quote and numeric)
	intrusiveSQLiRequests   = intrusiveSQLiPairs*2 + 2 // + the mandatory control pair
)

// Time-based SQLi. The sent sleep is hard-capped at 2 seconds and is only ever
// these two literals: no computed, multiplied or longer delay ever leaves this
// process. intrusiveTimeFloor is the detection floor (see IntrusiveScanner).
const (
	intrusiveSleepMySQL      = "' AND SLEEP(2)-- "
	intrusiveSleepPostgres   = "';SELECT pg_sleep(2)-- "
	intrusiveTimeFloor       = 2 * time.Second
	intrusiveTimeRepeats     = 3 // samples per payload family
	intrusiveTimeConfirms    = 2 // samples that must exceed the threshold
	intrusiveTimeMaxParams   = 2
	intrusiveTimeBaselineN   = 3 // baseline requests, median wins
	intrusiveTimeMaxRequests = 18
	// intrusiveTimeJitterFactor: if the slowest baseline sample is more than
	// this many times the median, the endpoint is timing-noisy and no delay
	// proves anything, so the probe fails closed.
	intrusiveTimeJitterFactor = 4
	// intrusiveTimeNoiseFloor keeps the jitter check meaningful on an unloaded
	// host where the median baseline is a fraction of a millisecond.
	intrusiveTimeNoiseFloor = 5 * time.Millisecond
)

// Path traversal. Payloads are appended to parameter values and, separately,
// appended to the endpoint path.
var intrusiveTraversalPayloads = []string{
	"../../../../etc/passwd",
	"..%2f..%2f..%2f..%2fetc%2fpasswd",
	"....//....//etc/passwd",
	`..\..\..\..\windows\win.ini`,
}

const (
	intrusiveTraversalCanaryFile = "passive-canary-" // + <rand> + ".txt"
	intrusiveTraversalCanaryExt  = ".txt"
	intrusivePasswdSignature     = "root:x:0:0:"
	intrusiveWinINISignature     = "[fonts]"
	intrusiveTraversalReadLimit  = 4 << 10 // 4 KiB, per the safety rules
	intrusiveTraversalPathProbes = 2       // canary + payload, per parameter slot
)

// intrusiveSignature maps an unambiguous byte signature to the name reported in
// a finding. The signature itself is never echoed back to the operator.
type intrusiveSignature struct {
	marker string
	name   string
}

var intrusiveTraversalSignatures = []intrusiveSignature{
	{marker: intrusivePasswdSignature, name: "/etc/passwd"},
	{marker: intrusiveWinINISignature, name: "windows/win.ini"},
}

// SSRF indicator parameters. The canary host is the RFC 2606 reserved,
// non-resolving TLD; the loopback URLs point at a CLOSED port on purpose, so a
// successful body fetch can never be observed.
const intrusiveSSRFParamPattern = `(?i)^(url|uri|link|src|source|dest|destination|redirect|next|target|callback|webhook|feed|host|domain|proxy|fetch|image|img|file|path|return|returnurl)$`

// intrusiveSSRFCanaryHost is the RFC 2606 reserved, non-resolving TLD the whole
// file uses for values that are meant to "come back". It never resolves, so the
// scanner cannot pull cloud credentials or phone an outside box.
const intrusiveSSRFCanaryHost = "ss-canary.invalid"

var (
	intrusiveSSRFParamRe = regexp.MustCompile(intrusiveSSRFParamPattern)

	intrusiveSSRFPayloads = []string{
		"http://ss-canary.invalid/",
		"http://127.0.0.1:1/",
		"http://[::1]:1/",
		"ss-canary.invalid",
	}

	// intrusiveSSRFErrorNeedles are resolution/refusal phrases that a target
	// shows only when it actually tried to reach the injected origin. The
	// payload text itself is deliberately NOT a needle: a target that merely
	// echoes the parameter must not look like an SSRF.
	intrusiveSSRFErrorNeedles = []string{
		"no such host",
		"cannot resolve",
		"can not resolve",
		"could not resolve",
		"name resolution",
		"temporary failure in name resolution",
		"nodename nor servname provided",
		"getaddrinfo",
		"host not found",
		"unknown host",
		"connection refused",
		"econnrefused",
		"dial tcp",
	}

	intrusiveSSRFMaxParams = 2
	intrusiveSSRFRequests  = len(intrusiveSSRFPayloads) * 2 // payload + same-length control
)

// Write-method probe caps. The path is random per run, and a GET must prove it
// is a 404 before anything is written.
const (
	intrusiveWriteRandomLen = 12
	intrusiveWriteRequests  = 4 // GET, PUT, GET, DELETE
)

// Reference sets per family. The WSTG links are the slugs OWASP's own
// navigation uses (verified, not guessed); the CWE links are the stable
// definitions pages.
var (
	intrusiveRefCRLF = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/15-HTTP_Response_Splitting",
		"https://owasp.org/Top10/A03_2021-Injection/",
		"https://cwe.mitre.org/data/definitions/93.html",
	}
	intrusiveRefSQLi = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection",
		"https://owasp.org/Top10/A03_2021-Injection/",
		"https://cwe.mitre.org/data/definitions/89.html",
	}
	intrusiveRefBlindSQLi = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection",
		"https://owasp.org/Top10/A03_2021-Injection/",
		"https://cwe.mitre.org/data/definitions/89.html",
	}
	intrusiveRefTraversal = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization/01-Directory_Traversal_File_Include",
		"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		"https://cwe.mitre.org/data/definitions/22.html",
	}
	intrusiveRefSSRF = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/19-Server-Side_Request_Forgery",
		"https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/",
		"https://cwe.mitre.org/data/definitions/918.html",
	}
	intrusiveRefWriteMethod = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/06-HTTP_Methods",
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/03-HTTP_Verb_Tampering",
		"https://cwe.mitre.org/data/definitions/650.html",
	}
)

// ── endpoint and parameter model ─────────────────────────────────────────────

// intrusiveParam is one query parameter, kept in both decoded and raw form so a
// probe can rebuild a request that differs from the original in exactly one
// value, byte for byte, everywhere else.
type intrusiveParam struct {
	name     string // decoded name, used for reporting and the SSRF filter
	value    string // decoded value, the thing payloads are appended to
	rawName  string // the key exactly as it appeared
	rawPair  string // the whole "key=value" exactly as it appeared
	rawValue string // the value exactly as it appeared
}

// intrusiveEndpoint is one URL to probe. base never carries a query; rawQuery
// is the original query, rawPairs is every original pair in order, and params is
// a prefix of rawPairs capped by MaxParams, so a request rebuilt through
// withPairRawValue still carries every original parameter.
type intrusiveEndpoint struct {
	base     string
	rawQuery string
	rawPairs []string
	all      []intrusiveParam
	params   []intrusiveParam
}

// asIs returns the endpoint URL exactly as configured (no injected payload).
func (ep intrusiveEndpoint) asIs() string {
	if ep.rawQuery == "" {
		return ep.base
	}
	return ep.base + "?" + ep.rawQuery
}

// withPairRawValue rebuilds the endpoint URL with one parameter's raw value
// replaced by rawValue. Every other parameter keeps its original raw bytes.
func (ep intrusiveEndpoint) withPairRawValue(idx int, rawValue string) string {
	if idx < 0 || idx >= len(ep.params) || idx >= len(ep.rawPairs) {
		return ep.asIs()
	}
	pairs := make([]string, len(ep.rawPairs))
	copy(pairs, ep.rawPairs)
	pairs[idx] = ep.params[idx].rawName + "=" + rawValue
	return ep.base + "?" + strings.Join(pairs, "&")
}

// withPathSegment appends a raw path segment to the endpoint path.
func (ep intrusiveEndpoint) withPathSegment(segment string) string {
	return strings.TrimSuffix(ep.base, "/") + "/" + segment
}

// endpoints returns the endpoints to probe: the base URL first, then every
// URL-shaped parameter whose value is a same-origin absolute path. A candidate
// whose parsed value carries a scheme or a host is skipped, so an endpoint can
// never leave the base origin — that is rule 1, enforced structurally.
func (i *IntrusiveScanner) endpoints() []intrusiveEndpoint {
	out := []intrusiveEndpoint{}
	base := i.endpointFromURL(i.base)
	out = append(out, base)
	seen := map[string]bool{base.asIs(): true}
	for _, p := range base.all {
		if len(out) >= i.opts.MaxEndpoints {
			break
		}
		if !intrusiveSSRFParamRe.MatchString(p.name) {
			continue
		}
		ref, err := url.Parse(p.value)
		if err != nil || ref == nil {
			continue
		}
		// Same origin or nothing: no scheme, no host, no userinfo.
		if ref.Scheme != "" || ref.Host != "" || ref.User != nil {
			continue
		}
		if !strings.HasPrefix(ref.Path, "/") {
			continue
		}
		cand := &url.URL{
			Scheme:   i.base.Scheme,
			Host:     i.base.Host,
			Path:     ref.Path,
			RawQuery: ref.RawQuery,
		}
		ep := i.endpointFromURL(cand)
		if seen[ep.asIs()] {
			continue
		}
		seen[ep.asIs()] = true
		out = append(out, ep)
	}
	if len(out) > i.opts.MaxEndpoints {
		out = out[:i.opts.MaxEndpoints]
	}
	return out
}

func (i *IntrusiveScanner) endpointFromURL(u *url.URL) intrusiveEndpoint {
	escPath := u.EscapedPath()
	if escPath == "" {
		escPath = "/"
	}
	all := intrusiveParseQuery(u.RawQuery)
	params := all
	if len(params) > i.opts.MaxParams {
		params = all[:i.opts.MaxParams]
	}
	rawPairs := make([]string, len(all))
	for idx, p := range all {
		rawPairs[idx] = p.rawPair
	}
	return intrusiveEndpoint{
		base:     u.Scheme + "://" + u.Host + escPath,
		rawQuery: u.RawQuery,
		rawPairs: rawPairs,
		all:      all,
		params:   params,
	}
}

// intrusiveParseQuery splits a raw query in order, keeping the raw bytes of
// every pair. Map-based url.ParseQuery would destroy the order and make a scan
// non-reproducible.
func intrusiveParseQuery(rawQuery string) []intrusiveParam {
	if rawQuery == "" {
		return []intrusiveParam{}
	}
	out := []intrusiveParam{}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		rawName, rawValue := pair, ""
		if eq := strings.IndexByte(pair, '='); eq >= 0 {
			rawName, rawValue = pair[:eq], pair[eq+1:]
		}
		name, err := url.QueryUnescape(rawName)
		if err != nil {
			name = rawName
		}
		if name == "" {
			continue
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			value = rawValue
		}
		out = append(out, intrusiveParam{
			name:     name,
			value:    value,
			rawName:  rawName,
			rawPair:  pair,
			rawValue: rawValue,
		})
	}
	return out
}

// ── the one place this file talks to the Requester ───────────────────────────

// intrusiveSnapshot is a fully read, already closed response.
type intrusiveSnapshot struct {
	status int
	header http.Header
	body   []byte
	length int
	hash   string
}

// hasHeaderFold reports whether the response carries a header with this name,
// ignoring case.
func (s intrusiveSnapshot) hasHeaderFold(name string) bool {
	for k, vs := range s.header {
		if !strings.EqualFold(k, name) || len(vs) == 0 {
			continue
		}
		for _, v := range vs {
			if v != "" {
				return true
			}
		}
	}
	return false
}

// hasSplitLocation reports whether the response carries more than one Location
// header (the classic observable of a split redirect target), or a Location
// value that still contains a raw CR or LF.
func (s intrusiveSnapshot) hasSplitLocation() bool {
	locs := s.header.Values("Location")
	if len(locs) > 1 {
		return true
	}
	for _, v := range locs {
		if strings.ContainsAny(v, "\r\n") {
			return true
		}
	}
	return false
}

// containsFold reports whether the body contains any of the needles,
// case-insensitively, and returns the needle that matched.
func (s intrusiveSnapshot) containsFold(needles []string) string {
	if len(s.body) == 0 {
		return ""
	}
	haystack := strings.ToLower(string(s.body))
	for _, n := range needles {
		if n == "" {
			continue
		}
		if strings.Contains(haystack, strings.ToLower(n)) {
			return n
		}
	}
	return ""
}

// fetch is the only function in this file that touches the network. It applies,
// in order: the Requester's intrusive opt-in (before the request is built!), the
// local budget, and a bounded body read that always closes the response.
//
// The second result is false whenever nothing usable came back: the caller
// skips the probe and reports nothing rather than guessing.
func (i *IntrusiveScanner) fetch(ctx context.Context, method, rawURL string, body []byte, limit int64) (intrusiveSnapshot, bool) {
	empty := intrusiveSnapshot{}
	if i == nil || i.req == nil || i.gateClosed {
		return empty, false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return empty, false
	}
	// Rule: activating a family requires BOTH the scanner option and the
	// Requester's intrusive opt-in. Ask before building anything.
	if err := i.req.Check(ctx, method, rawURL, true); err != nil {
		if errors.Is(err, ErrIntrusiveDisabled) || errors.Is(err, ErrOutOfScope) {
			// Structural refusal: this Requester will never allow intrusive
			// work for this target, so stop asking.
			i.gateClosed = true
		}
		return empty, false
	}
	if i.budget <= 0 {
		return empty, false
	}
	i.budget--

	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return empty, false
	}
	if len(body) > 0 {
		// Probe bodies are empty except for the form carriers, which carry
		// exactly one parameter and nothing else.
		httpReq.Header.Set("Content-Type", intrusiveFormContentType)
		httpReq.ContentLength = int64(len(body))
	}
	// User-Agent is deliberately not set here: identification policy belongs to
	// the Requester (Guard sets ScannerUserAgent).

	resp, err := i.req.Do(httpReq)
	if err != nil || resp == nil {
		return empty, false
	}
	raw, _ := ReadBody(resp, limit) // ReadBody always closes the body
	return intrusiveSnapshot{
		status: resp.StatusCode,
		header: resp.Header,
		body:   raw,
		length: len(raw),
		hash:   intrusiveSHA256Hex(raw),
	}, true
}

// intrusiveMaterialBodyDelta reports whether two responses differ materially:
// different SHA-256 AND a length difference above intrusiveLengthDeltaPercent
// of the longer response. It also returns the observed percentage.
func intrusiveMaterialBodyDelta(a, b intrusiveSnapshot) (bool, int) {
	if a.hash == b.hash {
		return false, 0
	}
	longest := a.length
	if b.length > longest {
		longest = b.length
	}
	if longest == 0 {
		return false, 0
	}
	delta := a.length - b.length
	if delta < 0 {
		delta = -delta
	}
	pct := delta * 100 / longest
	return pct > intrusiveLengthDeltaPercent, pct
}

func intrusiveSHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// intrusiveClampCap maps a non-positive cap to its default.
func intrusiveClampCap(given, def int) int {
	if given <= 0 {
		return def
	}
	return given
}

// intrusiveRandToken returns n lowercase hex characters drawn from
// crypto/rand. It never panics: if the platform RNG fails it falls back to a
// time-derived token, which is still unpredictable enough for a probe path and
// still unique per run.
func intrusiveRandToken(n int) string {
	if n <= 0 {
		return ""
	}
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.ToLower(fmt.Sprintf("%x", time.Now().UnixNano()) + strings.Repeat("0", n))[:n]
	}
	return hex.EncodeToString(buf)[:n]
}

// ── finding construction ─────────────────────────────────────────────────────

// intrusiveEvidence formats the confidence prefix the report relies on,
// because Vulnerability has no Confidence field.
func intrusiveEvidence(confidence, detail string) string {
	return "confidence=" + confidence + "; " + detail
}

type intrusiveFindingSpec struct {
	title       string
	severity    string
	category    string
	cvss        float64
	cwe         string
	url         string
	parameter   string
	evidence    string
	impact      string
	remediation string
	references  []string
	poc         string
}

func (s intrusiveFindingSpec) build() Vulnerability {
	return Vulnerability{
		ID:          nextVulnID(intrusiveIDPrefix),
		Title:       s.title,
		Severity:    s.severity,
		Category:    s.category,
		CVSS:        s.cvss,
		CWE:         s.cwe,
		URL:         s.url,
		Parameter:   s.parameter,
		Evidence:    s.evidence,
		Impact:      s.impact,
		Remediation: s.remediation,
		References:  s.references,
		PoC:         s.poc,
	}
}

// ── probe 1: CRLF / response splitting ───────────────────────────────────────

// scanCRLFInjection injects a percent-encoded CRLF plus a canary header into
// parameters. It confirms only when the response actually carries the canary
// header, or an observably split Location header; a payload merely reflected
// in the body is a much weaker signal and is reported as a heuristic.
func (i *IntrusiveScanner) scanCRLFInjection(ctx context.Context, ep intrusiveEndpoint) []Vulnerability {
	out := []Vulnerability{}
	if !i.opts.CRLFInjection {
		return out
	}
	for idx, p := range ep.params {
		if i.gateClosed || ctx.Err() != nil {
			return out
		}
		// Carrier 1: query parameter. The CRLF stays percent-encoded on the
		// wire, so it is inert until something decodes it.
		encValue := url.QueryEscape(p.value) + intrusiveCRLFSuffix
		rawURL := ep.withPairRawValue(idx, encValue)
		if snap, ok := i.fetch(ctx, http.MethodGet, rawURL, nil, 0); ok {
			if f, hit := i.crlfFinding(rawURL, p.name, "query parameter", snap); hit {
				out = append(out, f)
			}
		}
		if !i.opts.AllowPost {
			continue
		}
		// Carrier 2: form body, only with explicit AllowPost.
		formBody := url.QueryEscape(p.name) + "=" + encValue
		if snap, ok := i.fetch(ctx, http.MethodPost, ep.asIs(), []byte(formBody), 0); ok {
			if f, hit := i.crlfFinding(ep.asIs(), p.name, "form body", snap); hit {
				out = append(out, f)
			}
		}
	}
	return out
}

// intrusiveCRLFBodyNeedles are the byte sequences that prove the injected CR/LF
// survived into the response body. Requiring the control character to be
// adjacent to the marker is deliberate: a target that strips CR and LF but
// still echoes the value leaves the bare marker behind, and reporting that as
// an injection indicator would be a false positive.
var intrusiveCRLFBodyNeedles = [][]byte{
	[]byte("\r\n" + intrusiveCRLFMarker),
	[]byte("\n" + intrusiveCRLFMarker),
}

// intrusiveCRLFReflected reports whether the response body carries the injected
// CR/LF plus canary marker, i.e. the control characters were neither rejected
// nor neutralised before output.
func intrusiveCRLFReflected(body []byte) bool {
	for _, needle := range intrusiveCRLFBodyNeedles {
		if bytes.Contains(body, needle) {
			return true
		}
	}
	return false
}

func (i *IntrusiveScanner) crlfFinding(rawURL, param, carrier string, snap intrusiveSnapshot) (Vulnerability, bool) {
	if snap.hasHeaderFold(intrusiveCRLFCanaryName) {
		return intrusiveFindingSpec{
			title:     "CRLF injection produced a response header (HTTP response splitting)",
			severity:  "high",
			category:  "A03:2021 - Injection",
			cvss:      7.5,
			cwe:       "CWE-93",
			url:       rawURL,
			parameter: param,
			evidence: intrusiveEvidence(intrusiveConfidenceConfirmed,
				fmt.Sprintf("the injected %s response header is present on a %d response, delivered via the %s carrier; the payload is inert on the wire and only becomes a header once the target decodes it",
					intrusiveCRLFCanaryName, snap.status, carrier)),
			impact:      "An attacker who can inject CRLF can split the response, forge headers (Set-Cookie, Location, Content-Type), poison caches and smuggle a second response to the client.",
			remediation: "Never write attacker-controlled bytes into response headers. Reject or percent-encode CR (0x0d) and LF (0x0a) at the boundary, and validate values against the header grammar before setting them.",
			references:  intrusiveRefCRLF,
			poc:         fmt.Sprintf("%s carrier, parameter %q, payload %q", carrier, param, intrusiveCRLFSuffix),
		}.build(), true
	}
	if snap.hasSplitLocation() {
		return intrusiveFindingSpec{
			title:     "CRLF injection split the Location header",
			severity:  "high",
			category:  "A03:2021 - Injection",
			cvss:      7.5,
			cwe:       "CWE-93",
			url:       rawURL,
			parameter: param,
			evidence: intrusiveEvidence(intrusiveConfidenceConfirmed,
				fmt.Sprintf("the response carries an observably split Location header after the %s carrier injected %q", carrier, intrusiveCRLFSuffix)),
			impact:      "A split redirect header lets an attacker control the redirect target or append headers the client will trust.",
			remediation: "Reject CR and LF in values that are copied into the Location header, and build redirects from validated, allowlisted destinations only.",
			references:  intrusiveRefCRLF,
			poc:         fmt.Sprintf("%s carrier, parameter %q, payload %q", carrier, param, intrusiveCRLFSuffix),
		}.build(), true
	}
	if intrusiveCRLFReflected(snap.body) {
		return intrusiveFindingSpec{
			title:     "CRLF payload reflected unencoded in the response body",
			severity:  "medium",
			category:  "A03:2021 - Injection",
			cvss:      5.3,
			cwe:       "CWE-93",
			url:       rawURL,
			parameter: param,
			evidence: intrusiveEvidence(intrusiveConfidenceHeuristic,
				fmt.Sprintf("the injected CR/LF sequence survives into a %d response body, immediately ahead of the canary marker %q; this is a reflection indicator, not a demonstrated header injection", snap.status, intrusiveCRLFMarker)),
			impact:      "Unencoded reflection of control characters is the precondition for response splitting and for client-side header injection in downstream components.",
			remediation: "Context-encode every reflected value and strip control characters before output.",
			references:  intrusiveRefCRLF,
			poc:         fmt.Sprintf("%s carrier, parameter %q, payload %q", carrier, param, intrusiveCRLFSuffix),
		}.build(), true
	}
	return Vulnerability{}, false
}

// ── probe 2: boolean-based SQL injection ─────────────────────────────────────

// scanBooleanSQLi compares a "true" payload against a "false" payload and
// reports only when those two differ materially while a benign
// differing-suffix control does not. Without that control this probe is just a
// cache/echo/normalization noise detector, which is why it is mandatory.
func (i *IntrusiveScanner) scanBooleanSQLi(ctx context.Context, ep intrusiveEndpoint) []Vulnerability {
	out := []Vulnerability{}
	if !i.opts.BooleanSQLi {
		return out
	}
	if i.budget < len(ep.params)*intrusiveSQLiRequests {
		// Not enough budget for a complete comparison on every parameter: run
		// no half comparisons at all (fail closed).
		return out
	}
	for idx, p := range ep.params {
		if i.gateClosed || ctx.Err() != nil {
			return out
		}
		rawURL := func(payload string) string {
			return ep.withPairRawValue(idx, url.QueryEscape(p.value+payload))
		}
		quoteTrue, okQ1 := i.fetch(ctx, http.MethodGet, rawURL(intrusiveSQLiQuoteTrue), nil, 0)
		quoteFalse, okQ2 := i.fetch(ctx, http.MethodGet, rawURL(intrusiveSQLiQuoteFalse), nil, 0)
		numTrue, okN1 := i.fetch(ctx, http.MethodGet, rawURL(intrusiveSQLiNumTrue), nil, 0)
		numFalse, okN2 := i.fetch(ctx, http.MethodGet, rawURL(intrusiveSQLiNumFalse), nil, 0)
		if !okQ1 || !okQ2 || !okN1 || !okN2 {
			continue
		}
		// The mandatory benign control: two same-shape values whose only
		// difference is a random suffix. If those differ materially, so does
		// everything on this endpoint, and nothing here proves anything.
		ctrlA, okC1 := i.fetch(ctx, http.MethodGet,
			rawURL(intrusiveSQLiControlTag+intrusiveRandToken(6)), nil, 0)
		ctrlB, okC2 := i.fetch(ctx, http.MethodGet,
			rawURL(intrusiveSQLiControlTag+intrusiveRandToken(6)), nil, 0)
		if !okC1 || !okC2 {
			continue
		}
		controlDiffers, controlPct := intrusiveMaterialBodyDelta(ctrlA, ctrlB)
		if controlDiffers {
			// Fail closed: the endpoint is non-deterministic, so no pair of
			// responses proves anything at all.
			continue
		}
		quoteDiffers, quotePct := intrusiveMaterialBodyDelta(quoteTrue, quoteFalse)
		numDiffers, numPct := intrusiveMaterialBodyDelta(numTrue, numFalse)
		if !quoteDiffers && !numDiffers {
			continue
		}
		pairs := []string{}
		if quoteDiffers {
			pairs = append(pairs, fmt.Sprintf("%q vs %q (%d%% length delta)", intrusiveSQLiQuoteTrue, intrusiveSQLiQuoteFalse, quotePct))
		}
		if numDiffers {
			pairs = append(pairs, fmt.Sprintf("%q vs %q (%d%% length delta)", intrusiveSQLiNumTrue, intrusiveSQLiNumFalse, numPct))
		}
		out = append(out, intrusiveFindingSpec{
			title:     "Boolean-based SQL injection indicator",
			severity:  "high",
			category:  "A03:2021 - Injection",
			cvss:      8.2,
			cwe:       "CWE-89",
			url:       ep.asIs(),
			parameter: p.name,
			evidence: intrusiveEvidence(intrusiveConfidenceHeuristic,
				fmt.Sprintf("payload pair(s) %s produced materially different responses, while the mandatory benign differing-suffix control did not differ (%d%% length delta, hash %s vs %s); this is a differential signal only, no query was executed or verified",
					strings.Join(pairs, "; "), controlPct, ctrlA.hash[:12], ctrlB.hash[:12])),
			impact:      "If the differential is caused by a query, an attacker can read or infer arbitrary database data without any write access, and in many deployments escalate to code execution.",
			remediation: "Use parameterised queries or a safe ORM for every database interaction, and never concatenate user input into SQL. Keep the database account least-privileged.",
			references:  intrusiveRefSQLi,
			poc: fmt.Sprintf("GET %s with parameter %q set to <original value> + %s, compared against the same with %s",
				ep.base, p.name, intrusiveSQLiQuoteTrue, intrusiveSQLiQuoteFalse),
		}.build())
	}
	return out
}

// ── probe 3: time-based SQL injection ────────────────────────────────────────

// scanTimeBasedSQLi measures a payload-free baseline, then asks for a
// hard-capped 2s database sleep. Timing is always a heuristic: a slow response
// proves delay, never a specific engine.
func (i *IntrusiveScanner) scanTimeBasedSQLi(ctx context.Context, ep intrusiveEndpoint) []Vulnerability {
	out := []Vulnerability{}
	if !i.opts.TimeBasedSQLi {
		return out
	}
	params := ep.params
	if len(params) > intrusiveTimeMaxParams {
		params = params[:intrusiveTimeMaxParams]
	}
	for idx, p := range params {
		if i.gateClosed || ctx.Err() != nil {
			return out
		}
		// Precondition: a baseline we can trust.
		baseline, ok := i.timeBaseline(ctx, ep, idx, p)
		if !ok {
			continue
		}
		threshold := 3 * baseline
		if threshold < i.timeFloor {
			threshold = i.timeFloor
		}
		for _, payload := range []string{intrusiveSleepMySQL, intrusiveSleepPostgres} {
			if i.timeBudget < intrusiveTimeRepeats {
				// Not enough budget for a full sample set: report nothing.
				return out
			}
			over, worst := 0, time.Duration(0)
			for r := 0; r < intrusiveTimeRepeats; r++ {
				rawURL := ep.withPairRawValue(idx, url.QueryEscape(p.value+payload))
				start := time.Now()
				_, sent := i.fetch(ctx, http.MethodGet, rawURL, nil, 0)
				elapsed := time.Since(start)
				if !sent {
					break
				}
				// The per-family cap is a real budget, not a comment: spend it.
				i.timeBudget--
				if elapsed > worst {
					worst = elapsed
				}
				if elapsed > threshold {
					over++
				}
			}
			if over < intrusiveTimeConfirms {
				continue
			}
			out = append(out, intrusiveFindingSpec{
				title:     "Time-based SQL injection indicator",
				severity:  "high",
				category:  "A03:2021 - Injection",
				cvss:      8.2,
				cwe:       "CWE-89",
				url:       ep.asIs(),
				parameter: p.name,
				evidence: intrusiveEvidence(intrusiveConfidenceHeuristic,
					fmt.Sprintf("payload %q delayed the response for %s on %d of %d repeats, against a %s threshold derived from a %s baseline (baseline requests are payload-free); the sent sleep is hard-capped at 2s and timing alone can never prove a specific engine",
						payload, worst.Round(time.Millisecond), over, intrusiveTimeRepeats, threshold.Round(time.Millisecond), baseline.Round(time.Millisecond))),
				impact:      "A blind, time-based injection lets an attacker exfiltrate database contents one bit at a time without any visible error or write.",
				remediation: "Use parameterised queries for every database interaction, and treat any endpoint whose response time tracks user input as a defect until proven otherwise.",
				references:  intrusiveRefBlindSQLi,
				poc: fmt.Sprintf("GET %s with parameter %q set to <original value> + %q, repeated %d times",
					ep.base, p.name, payload, intrusiveTimeRepeats),
			}.build())
		}
	}
	return out
}

// timeBaseline takes payload-free samples and returns their median. It fails
// closed when the endpoint is too noisy for a delay to mean anything.
func (i *IntrusiveScanner) timeBaseline(ctx context.Context, ep intrusiveEndpoint, idx int, p intrusiveParam) (time.Duration, bool) {
	zero := time.Duration(0)
	if i.timeBudget < intrusiveTimeBaselineN+intrusiveTimeRepeats {
		return zero, false
	}
	rawURL := ep.withPairRawValue(idx, url.QueryEscape(p.value))
	samples := make([]time.Duration, 0, intrusiveTimeBaselineN)
	for r := 0; r < intrusiveTimeBaselineN; r++ {
		start := time.Now()
		_, sent := i.fetch(ctx, http.MethodGet, rawURL, nil, 0)
		if !sent {
			return zero, false
		}
		i.timeBudget--
		samples = append(samples, time.Since(start))
	}
	sort.Slice(samples, func(a, b int) bool { return samples[a] < samples[b] })
	median := samples[len(samples)/2]
	slowest := samples[len(samples)-1]
	ceiling := intrusiveTimeJitterFactor * maxDuration(median, intrusiveTimeNoiseFloor)
	if slowest > ceiling {
		// Fail closed: the baseline is unstable, so no delay we measure later
		// can be attributed to a payload.
		return zero, false
	}
	return median, true
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// ── probe 4: path traversal ──────────────────────────────────────────────────

// scanPathTraversal injects read-only traversal signatures through the path and
// through every probed parameter, and confirms ONLY on unambiguous signatures.
// The response body of a traversal probe never reaches a finding: this probe
// reports "signature matched: <name>" and nothing else.
func (i *IntrusiveScanner) scanPathTraversal(ctx context.Context, ep intrusiveEndpoint) []Vulnerability {
	out := []Vulnerability{}
	if !i.opts.PathTraversal {
		return out
	}
	if i.budget < (len(intrusiveTraversalPayloads)+intrusiveTraversalPathProbes)*(len(ep.params)+1) {
		// Not enough budget for the full signature sweep: run nothing rather
		// than a partial sweep that could report one signature and miss the
		// suppression canary (fail closed).
		return out
	}

	// Carrier sweep for one payload: the path, then each probed parameter.
	type carrierResponse struct {
		carrier string
		rawURL  string
		snap    intrusiveSnapshot
	}
	sweep := func(payload string) []carrierResponse {
		res := []carrierResponse{}
		pathURL := ep.withPathSegment(payload)
		if snap, ok := i.fetch(ctx, http.MethodGet, pathURL, nil, intrusiveTraversalReadLimit); ok {
			res = append(res, carrierResponse{"path", pathURL, snap})
		}
		for idx, p := range ep.params {
			if i.gateClosed || ctx.Err() != nil {
				return res
			}
			// The payload is appended raw on purpose: "..%2f" must stay
			// percent-encoded and the backslash variant must stay literal.
			rawURL := ep.withPairRawValue(idx, url.QueryEscape(p.value)+payload)
			if snap, ok := i.fetch(ctx, http.MethodGet, rawURL, nil, intrusiveTraversalReadLimit); ok {
				res = append(res, carrierResponse{"parameter " + p.name, rawURL, snap})
			}
		}
		return res
	}

	// Step 1: the canary. A file that cannot exist must not come back with a
	// signature in it; if it does, this target echoes signatures and no
	// traversal here is proven (fail closed on that signature).
	canary := intrusiveTraversalCanaryFile + intrusiveRandToken(8) + intrusiveTraversalCanaryExt
	suppressed := map[string]bool{}
	for _, cr := range sweep(canary) {
		for _, sig := range intrusiveTraversalSignatures {
			if bytes.Contains(cr.snap.body, []byte(sig.marker)) {
				suppressed[sig.name] = true
			}
		}
	}

	// Step 2: the signatures themselves. One finding per signature per
	// endpoint, from the first carrier that matched.
	reported := map[string]bool{}
	for _, payload := range intrusiveTraversalPayloads {
		for _, cr := range sweep(payload) {
			if i.gateClosed || ctx.Err() != nil {
				return out
			}
			for _, sig := range intrusiveTraversalSignatures {
				if suppressed[sig.name] || reported[sig.name] {
					continue
				}
				if !bytes.Contains(cr.snap.body, []byte(sig.marker)) {
					continue
				}
				reported[sig.name] = true
				out = append(out, intrusiveFindingSpec{
					title:     "Path traversal signature matched: " + sig.name,
					severity:  "high",
					category:  "A01:2021 - Broken Access Control",
					cvss:      7.5,
					cwe:       "CWE-22",
					url:       cr.rawURL,
					parameter: cr.carrier,
					evidence: intrusiveEvidence(intrusiveConfidenceConfirmed,
						"signature matched: "+sig.name+" (read-only traversal probe; the response body is deliberately withheld, as is any credential-shaped content)"),
					impact:      "A traversal lets an attacker read files outside the web root, including configuration and secrets, and can escalate to full compromise.",
					remediation: "Resolve the requested path against a fixed root and reject anything that escapes it. Never build filesystem paths from raw user input, and run the service with the least filesystem privilege.",
					references:  intrusiveRefTraversal,
					poc: fmt.Sprintf("GET %s via the %s carrier with payload %q (probe file %q did not exist, which is how we know this is not an echo)",
						cr.rawURL, cr.carrier, payload, canary),
				}.build())
			}
		}
	}
	return out
}

// ── probe 5: SSRF indicators ─────────────────────────────────────────────────

// scanSSRFIndicators injects a canary URL, a closed-port loopback URL and a
// plain canary host into URL-shaped parameters, each against a benign
// same-length control. Blind SSRF cannot be confirmed without an out-of-band
// channel, so every finding here is a heuristic and says so.
func (i *IntrusiveScanner) scanSSRFIndicators(ctx context.Context, ep intrusiveEndpoint) []Vulnerability {
	out := []Vulnerability{}
	if !i.opts.SSRFIndicators {
		return out
	}
	matched := 0
	for idx, p := range ep.params {
		if i.gateClosed || ctx.Err() != nil {
			return out
		}
		if !intrusiveSSRFParamRe.MatchString(p.name) {
			continue
		}
		matched++
		if matched > intrusiveSSRFMaxParams {
			break
		}
		if i.budget < intrusiveSSRFRequests {
			return out
		}
		for _, payload := range intrusiveSSRFPayloads {
			// Mandatory control: a benign value of exactly the same length, so
			// a target that merely echoes a parameter of this shape produces
			// the same status and the same length, and no differential fires.
			control := intrusiveRandToken(len(payload))
			canaryURL := ep.withPairRawValue(idx, url.QueryEscape(payload))
			controlURL := ep.withPairRawValue(idx, url.QueryEscape(control))
			canarySnap, okC := i.fetch(ctx, http.MethodGet, canaryURL, nil, 0)
			controlSnap, okB := i.fetch(ctx, http.MethodGet, controlURL, nil, 0)
			if !okC || !okB {
				continue
			}
			reason := i.ssrfDifferentialReason(canarySnap, controlSnap)
			if reason == "" {
				continue
			}
			out = append(out, intrusiveFindingSpec{
				title:     "SSRF indicator in a URL-shaped parameter",
				severity:  "medium",
				category:  "A10:2021 - Server-Side Request Forgery (SSRF)",
				cvss:      5.3,
				cwe:       "CWE-918",
				url:       ep.asIs(),
				parameter: p.name,
				evidence: intrusiveEvidence(intrusiveConfidenceHeuristic,
					fmt.Sprintf("parameter %q treated the injected value %q differently from a benign same-length control (%s); blind SSRF cannot be confirmed without an out-of-band channel, and this probe uses only the RFC 2606 reserved non-resolving host %q plus loopback addresses on a closed port, so no third party was ever contacted",
						p.name, payload, reason, intrusiveSSRFCanaryHost)),
				impact:      "If the target fetches attacker-controlled URLs, an attacker can reach internal services, cloud metadata endpoints and the scanner's own network neighbourhood.",
				remediation: "Never fetch a URL taken from user input without an allowlist of schemes and destinations, and block loopback, link-local and private ranges at the resolver or the egress firewall.",
				references:  intrusiveRefSSRF,
				poc: fmt.Sprintf("GET %s with parameter %q set to %q, compared against the same parameter set to a benign same-length value",
					ep.base, p.name, payload),
			}.build())
		}
	}
	return out
}

// ssrfDifferentialReason returns why the canary response is materially
// different from the control, or "" when it is not. Only a differential counts:
// an absolute status or length means nothing, because the control went through
// the same code path.
func (i *IntrusiveScanner) ssrfDifferentialReason(canary, control intrusiveSnapshot) string {
	if canary.status != control.status {
		return fmt.Sprintf("status %d for the canary vs %d for the control", canary.status, control.status)
	}
	if material, pct := intrusiveMaterialBodyDelta(canary, control); material {
		return fmt.Sprintf("%d%% length delta for the canary vs the control", pct)
	}
	if needle := canary.containsFold(intrusiveSSRFErrorNeedles); needle != "" && control.containsFold(intrusiveSSRFErrorNeedles) == "" {
		return fmt.Sprintf("the canary response mentions %q while the control does not", needle)
	}
	return ""
}

// ── probe 6: HTTP write methods ──────────────────────────────────────────────

// scanWriteMethods is the only probe in this file that writes anything, and it
// is bounded to a random path that a GET first proves does not exist. The
// bodies are always empty: a zero-byte file at a random path, cleaned up
// afterwards, with the outcome recorded honestly in the finding.
func (i *IntrusiveScanner) scanWriteMethods(ctx context.Context) []Vulnerability {
	if !i.opts.WriteMethodProbes {
		return nil
	}
	if i.budget < intrusiveWriteRequests {
		return nil
	}
	path := "/" + intrusiveWritePathPrefix + intrusiveRandToken(intrusiveWriteRandomLen) + ".txt"
	rawURL := i.base.Scheme + "://" + i.base.Host + path

	// Precondition: prove the path does not exist. If the target answers with
	// anything but 404 we stop, because that path may be a real resource.
	pre, ok := i.fetch(ctx, http.MethodGet, rawURL, nil, 0)
	if !ok || pre.status != http.StatusNotFound {
		return nil
	}

	// The only write: an empty-body PUT to a provably nonexistent random path.
	put, ok := i.fetch(ctx, http.MethodPut, rawURL, nil, 0)
	if !ok {
		return nil
	}
	switch put.status {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		// Accepted: verify, then clean up. 200 is included on purpose: plenty
		// of servers answer a successful PUT with an empty 200 body, and
		// treating that as "method not accepted" was a false negative.
	default:
		// 405/403/501 (and anything else) means the method is not accepted, so
		// there is nothing to clean up and nothing to report.
		return nil
	}

	created := false
	verify := "a follow-up GET could not be read"
	if after, okAfter := i.fetch(ctx, http.MethodGet, rawURL, nil, 0); okAfter {
		if after.status == http.StatusOK {
			created = true
			verify = "a follow-up GET returned 200, so the resource exists"
		} else {
			verify = fmt.Sprintf("a follow-up GET returned %d, so no resource is readable", after.status)
		}
	}

	// Cleanup: always attempted after an accepted PUT, whether or not the
	// resource became visible, and touching only the random path we wrote.
	del, delOK := i.fetch(ctx, http.MethodDelete, rawURL, nil, 0)
	var cleanup string
	switch {
	case !delOK:
		cleanup = "cleanup attempted: no (the DELETE request was refused or failed), so the zero-byte file may still exist"
	case del.status == http.StatusOK || del.status == http.StatusNoContent || del.status == http.StatusAccepted:
		cleanup = fmt.Sprintf("cleanup attempted: yes (DELETE returned %d)", del.status)
	default:
		cleanup = fmt.Sprintf("cleanup attempted: yes but it FAILED (DELETE returned %d), so the zero-byte file may still exist", del.status)
	}

	const residual = "residual side effect: a zero-byte file at a random path may have been created; "
	title := "HTTP write method accepted but no resource was created"
	severity, confidence := "medium", intrusiveConfidenceHigh
	if created {
		title = "HTTP write method accepted: a resource was created on a random path"
		severity, confidence = "high", intrusiveConfidenceConfirmed
	}
	return []Vulnerability{intrusiveFindingSpec{
		title:     title,
		severity:  severity,
		category:  "A01:2021 - Broken Access Control",
		cvss:      7.5,
		cwe:       "CWE-650",
		url:       rawURL,
		parameter: "(request method)",
		evidence: intrusiveEvidence(confidence,
			fmt.Sprintf("an empty-body PUT to a random nonexistent path returned %d; %s; %s%s",
				put.status, verify, residual, cleanup)),
		impact:      "Unrestricted write methods let an attacker create, overwrite or delete resources, and often turn a read-only flaw into remote code execution.",
		remediation: "Disable unused HTTP methods at the server or the reverse proxy, and enforce method-based authorisation on every route. Never let a client choose the method a resource accepts.",
		references:  intrusiveRefWriteMethod,
		poc: fmt.Sprintf("GET %s -> 404, PUT %s (empty body) -> %d, GET %s, DELETE %s",
			rawURL, rawURL, put.status, rawURL, rawURL),
	}.build()}
}
