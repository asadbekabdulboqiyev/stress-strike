// passive_checks_headers.go — header checks: CSP, clickjacking, HSTS, cookies, JWT, mixed algorithms
//
// This file is one part of the passive OWASP check family. The family
// contract (what a passive check may send, what it must never claim, how
// evidence is written) is documented at the top of passive_scanner.go.
package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

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
