// passive_parsers.go — shared parsers: HTML, soft-404 baseline, CSP/xfo/cookie/JWT decoding
//
// This file is one part of the passive OWASP check family. The family
// contract (what a passive check may send, what it must never claim, how
// evidence is written) is documented at the top of passive_scanner.go.
package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

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
