// passive_checks_exposure.go — exposure checks: cache-control, host header, metafiles, artifacts, SRI, leaks
//
// This file is one part of the passive OWASP check family. The family
// contract (what a passive check may send, what it must never claim, how
// evidence is written) is documented at the top of passive_scanner.go.
package scanner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner/core"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

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
			if !core.SameHost(abs, p.base) {
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
