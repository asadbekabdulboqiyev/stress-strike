// Package fingerprint provides UAFor/HeadersFor: given a TLS ClientHello
// profile, return the matching browser User-Agent and Client Hints so the
// TLS fingerprint and the HTTP headers tell the same story. A WAF that
// cross-checks JA3/JA4 against the User-Agent will otherwise spot the
// mismatch and block.
//
// All strings are browser-typical; none is a literal "stress-strike" token,
// which is what makes the header/hello pair consistent.
package fingerprint

import "strings"

// UAFor returns the browser User-Agent that matches the given TLS profile.
// Empty profile (Default / Golang) returns "", meaning "caller keeps its own
// UA". Unknown profiles fall back to a generic modern desktop Chrome UA.
func UAFor(p Profile) string {
	switch p {
	case Chrome, Chrome133:
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
	case Chrome120:
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	case Firefox, Firefox102:
		return "Mozilla/5.0 (Windows NT 10.0; Win64; rv:121.0) Gecko/20100101 Firefox/121.0"
	case Safari:
		return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
	case Edge:
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0"
	case IOS:
		return "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
	case AndroidOkHttp:
		return "okhttp/4.12.0"
	case Randomized, RandomizedALPN, RandomizedNoALPN:
		// Randomized hello should pair with a generic UA, not a pinned one.
		return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
	case Default, Golang:
		return ""
	}
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
}

// HeadersFor returns the Client Hint headers that match the UA chosen by UAFor.
// Sec-CH-UA and Sec-CH-UA-Platform echo the UA's brand/platform so a WAF that
// correlates JA3 with Sec-CH-UA sees a coherent client.
func HeadersFor(p Profile) map[string]string {
	m := map[string]string{}
	ua := UAFor(p)
	switch {
	case strings.Contains(ua, "Chrome/133") && !strings.Contains(ua, "Edg/"):
		m["Sec-CH-UA"] = `"Chromium";v="133", "Google Chrome";v="133", "Not=A?Brand";v="99"`
		m["Sec-CH-UA-Mobile"] = "?0"
		m["Sec-CH-UA-Platform"] = `"Windows"`
	case strings.Contains(ua, "Chrome/120"):
		m["Sec-CH-UA"] = `"Chromium";v="120", "Google Chrome";v="120", "Not=A?Brand";v="99"`
		m["Sec-CH-UA-Mobile"] = "?0"
		m["Sec-CH-UA-Platform"] = `"Windows"`
	case strings.Contains(ua, "Firefox/"):
		// Firefox does not send Sec-CH-UA.
	case strings.Contains(ua, "Edg/"):
		m["Sec-CH-UA"] = `"Chromium";v="133", "Microsoft Edge";v="133", "Not=A?Brand";v="99"`
		m["Sec-CH-UA-Mobile"] = "?0"
		m["Sec-CH-UA-Platform"] = `"Windows"`
	case strings.Contains(ua, "Safari/605.1.15") && strings.Contains(ua, "Version/17"):
		m["Sec-CH-UA"] = `"Not:A-Brand";v="99", "Safari";v="17"`
		m["Sec-CH-UA-Mobile"] = "?0"
		m["Sec-CH-UA-Platform"] = `"macOS"`
	case strings.Contains(ua, "Mobile/"):
		m["Sec-CH-UA"] = `"Not:A-Brand";v="99", "Safari";v="17"`
		m["Sec-CH-UA-Mobile"] = "?1"
		m["Sec-CH-UA-Platform"] = `"iOS"`
	}
	return m
}

// Resolve returns the effective fingerprint profile, User-Agent and extra
// headers for a caller, applying defaults when the profile is empty.
func Resolve(p Profile) (Profile, string, map[string]string) {
	if p == Default {
		p = Golang
	}
	return p, UAFor(p), HeadersFor(p)
}
