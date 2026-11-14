package bounty

// scope.go — target-in-scope matching.
//
// Scope files are written by humans and vary wildly. Rather than pretend to
// parse every policy language, this package documents one simple rule:
//
//   - One entry per line. Blank lines and lines beginning with '#' are ignored.
//   - An entry is a URL, a host[:port], or a domain. A leading "*." is accepted
//     and treated the same as the bare domain.
//   - Target and entry are reduced to lowercase hostnames (scheme, port, path,
//     userinfo and a trailing dot are dropped).
//   - The target is in scope when its host equals the entry host or is a
//     subdomain of it ("api.example.com" matches an "example.com" entry).
//
// Path- and method-level scoping is NOT interpreted: an entry
// "https://example.com/api" scopes the whole host, not just /api. That is
// deliberately conservative in one direction (it can over-approximate scope)
// and is stated here so a triager does not read more into a pass than it
// proves. Entries that do not parse as a URL or host are ignored.

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// scopeContains reports whether target is covered by the entries in scope.
func scopeContains(scope []byte, target string) (bool, error) {
	want, err := normalizeHost(target)
	if err != nil {
		return false, fmt.Errorf("bounty: target %q: %w", target, err)
	}
	for _, line := range strings.Split(string(scope), "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		got, err := normalizeHost(entry)
		if err != nil {
			// A scope file is prose as often as it is data. A line that is not
			// a host is not evidence of anything; it simply matches nothing.
			continue
		}
		if hostMatches(want, got) {
			return true, nil
		}
	}
	return false, nil
}

// normalizeHost reduces a URL, host[:port] or domain to a lowercase hostname.
func normalizeHost(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty host")
	}
	// A wildcard entry and a bare domain name the same host here.
	s = strings.TrimPrefix(s, "*.")
	if s == "" {
		return "", errors.New("empty host")
	}

	raw := s
	if !strings.Contains(raw, "://") {
		raw = "//" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("not a URL or host: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("not a URL or host")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", errors.New("empty host")
	}
	if strings.ContainsAny(host, " \t/\\") {
		return "", errors.New("host contains invalid characters")
	}
	return host, nil
}

// hostMatches implements exact-or-subdomain matching with a dot boundary, so
// "notexample.com" never matches an "example.com" entry.
func hostMatches(target, entry string) bool {
	if target == entry {
		return true
	}
	return strings.HasSuffix(target, "."+entry)
}
