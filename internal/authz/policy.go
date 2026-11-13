package authz

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Mode selects how strict the default decision is.
type Mode int

const (
	// ModePermissive allows public, loopback, and (when AllowPrivate is set)
	// private targets. It always denies metadata, link-local, multicast,
	// reserved, and CGNAT targets unless an explicit rule allows them.
	ModePermissive Mode = iota
	// ModeStrict denies every target that does not match an allow-list rule.
	ModeStrict
)

// String returns the mode name used in config files and audit records.
func (m Mode) String() string {
	switch m {
	case ModePermissive:
		return "permissive"
	case ModeStrict:
		return "strict"
	default:
		return fmt.Sprintf("mode(%d)", int(m))
	}
}

// ParseMode parses a mode name.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "permissive", "standard", "default":
		return ModePermissive, nil
	case "strict":
		return ModeStrict, nil
	default:
		return ModePermissive, fmt.Errorf("unknown authz mode %q (want 'permissive' or 'strict')", s)
	}
}

// Operation is the kind of activity being authorized.
type Operation int

const (
	// OpLoadTest is a normal load test or replay.
	OpLoadTest Operation = iota
	// OpScan is the TLS/WAF scanner.
	OpScan
	// OpPentest is the offensive scanner. It always requires an explicit,
	// matching authorization entry.
	OpPentest
)

// String returns the name used in audit records and policy errors.
func (o Operation) String() string {
	switch o {
	case OpLoadTest:
		return "run"
	case OpScan:
		return "scan"
	case OpPentest:
		return "pentest"
	default:
		return fmt.Sprintf("op(%d)", int(o))
	}
}

// Rule is an explicit authorization entry. A rule allows matching targets
// until it expires.
type Rule struct {
	// Pattern is one of: "*", "*.example.com", "host.example.com", an IP, or a
	// CIDR such as "10.0.0.0/8".
	Pattern string `json:"pattern"`
	// Until is the expiry. Zero means no expiry.
	Until time.Time `json:"until,omitempty"`
	// Approver names the person or team that granted authorization.
	Approver string `json:"approver,omitempty"`
	// Ticket links the authorization to a change/incident record.
	Ticket string `json:"ticket,omitempty"`
	// Reason is a human-readable justification.
	Reason string `json:"reason,omitempty"`
}

// active reports whether the rule applies at now.
func (r Rule) active(now time.Time) bool {
	return r.Until.IsZero() || now.Before(r.Until)
}

// namesTarget reports whether the pattern names the host or address it covers,
// rather than describing a scope that happens to contain it.
//
// The distinction is the difference between consent and convenience. A rule for
// "shop.example.com" or "203.0.113.7" says *this* target may be attacked; a rule
// for "*.example.com" or "10.0.0.0/8" only says a region of the network is in
// scope. Metadata access, pentests and --authorized tickets therefore require a
// rule that names the target: a /8 with an approver on it must never stand in
// for an approval of the one host inside that /8 which is about to be scanned.
func (r Rule) namesTarget() bool {
	p := strings.TrimSpace(r.Pattern)
	if p == "" || strings.HasPrefix(p, "*") {
		return false
	}
	// A CIDR block is a range, not a target, however narrow it is: /32 and /128
	// included, so "which host was approved" never depends on subnet arithmetic.
	if strings.Contains(p, "/") {
		return false
	}
	return true
}

// matches reports whether the rule covers t.
func (r Rule) matches(t Target) bool {
	p := strings.TrimSpace(r.Pattern)
	if p == "" {
		return false
	}
	if p == "*" {
		return true
	}
	if strings.Contains(p, "/") {
		if _, ipnet, err := net.ParseCIDR(p); err == nil {
			for _, ip := range t.IPs {
				if ipnet.Contains(ip) {
					return true
				}
			}
		}
		return false
	}
	if strings.HasPrefix(p, "*.") {
		suffix := strings.ToLower(strings.TrimPrefix(p, "*."))
		// Subdomains only: "*.example.com" does NOT cover "example.com". The
		// scanner's scope allow-list makes the same choice, and for the same
		// reason — an authorization written for a wildcard must not silently
		// grant the apex as well, since the apex is usually the one host with
		// production data behind it.
		return strings.HasSuffix(t.Host, "."+suffix)
	}
	p = strings.ToLower(p)
	if p == t.Host {
		return true
	}
	if ip := net.ParseIP(p); ip != nil {
		for _, tip := range t.IPs {
			if tip.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// Policy is the authorization configuration.
type Policy struct {
	// Mode selects the default decision.
	Mode Mode `json:"mode"`
	// AllowPrivate permits RFC1918 targets without an explicit rule.
	AllowPrivate bool `json:"allow_private"`
	// Rules are explicit authorizations.
	Rules []Rule `json:"rules,omitempty"`
}

// DefaultPolicy is the built-in policy: permissive for public and loopback
// targets, deny for everything dangerous.
func DefaultPolicy() Policy {
	return Policy{Mode: ModePermissive, AllowPrivate: false}
}

// Decision is the outcome of a policy check.
type Decision struct {
	Allowed bool
	Class   Class
	// Rule is the matched authorization pattern, empty when none matched.
	Rule string
	// Reason explains a denial or names the authorizing rule.
	Reason string
}

// Check decides whether op against t is permitted at now.
func (p Policy) Check(t Target, op Operation, now time.Time) Decision {
	class := t.Class()
	d := Decision{Class: class}

	// Find the best matching active rule. A rule that names the target wins
	// over a range or a wildcard, so a narrow authorization is never shadowed
	// by a broad one.
	var wildcard, named *Rule
	for i := range p.Rules {
		r := &p.Rules[i]
		if !r.active(now) || !r.matches(t) {
			continue
		}
		if r.namesTarget() {
			named = r
			break
		}
		if wildcard == nil {
			wildcard = r
		}
	}
	matched := named
	if matched == nil {
		matched = wildcard
	}

	// Metadata: always denied unless a rule names it. Neither a wildcard nor a
	// CIDR that happens to contain 169.254.169.254 may unlock the
	// instance-metadata service.
	if class == ClassMetadata {
		if named == nil {
			d.Reason = fmt.Sprintf("refusing to send traffic to cloud instance metadata (%s) — this is the credential-theft path", t.Host)
			return d
		}
		return d.allow(named, "metadata explicitly authorized")
	}

	// Offensive scanning always needs an active authorization that names the
	// target. A wildcard or a CIDR is a scope, never a consent for one host.
	if op == OpPentest {
		if named == nil {
			d.Reason = fmt.Sprintf("pentest against %s requires an authorization entry naming that host (approver + ticket); a wildcard or CIDR rule is not enough", t.Host)
			return d
		}
		return d.allow(named, "pentest explicitly authorized")
	}

	if matched != nil {
		return d.allow(matched, "covered by authorization")
	}

	if p.Mode == ModeStrict {
		d.Reason = fmt.Sprintf("strict policy: %s is not in the allow-list", t.Host)
		return d
	}

	switch class {
	case ClassPublic, ClassLoopback:
		d.Allowed = true
		d.Reason = "public/loopback target"
		return d
	case ClassPrivate:
		if p.AllowPrivate {
			d.Allowed = true
			d.Reason = "private target allowed by allow_private"
			return d
		}
		d.Reason = fmt.Sprintf("%s resolves to a private address (%s); pass an authorization entry or --allow-private", t.Host, t.IPs)
		return d
	case ClassCGNAT:
		d.Reason = fmt.Sprintf("%s resolves to a carrier-grade NAT address (%s)", t.Host, t.IPs)
		return d
	case ClassLinkLocal:
		d.Reason = fmt.Sprintf("%s resolves to a link-local address (%s)", t.Host, t.IPs)
		return d
	case ClassMulticast:
		d.Reason = fmt.Sprintf("%s resolves to a multicast address (%s)", t.Host, t.IPs)
		return d
	case ClassReserved:
		d.Reason = fmt.Sprintf("%s resolves to a reserved/non-routable address (%s)", t.Host, t.IPs)
		return d
	default:
		d.Reason = fmt.Sprintf("%s is not allowed", t.Host)
		return d
	}
}

func (d Decision) allow(r *Rule, why string) Decision {
	d.Allowed = true
	d.Rule = r.Pattern
	who := r.Approver
	if who == "" {
		who = "unspecified approver"
	}
	if r.Ticket != "" {
		d.Reason = fmt.Sprintf("%s (%s, %s, ticket %s)", why, r.Pattern, who, r.Ticket)
	} else {
		d.Reason = fmt.Sprintf("%s (%s, %s)", why, r.Pattern, who)
	}
	return d
}

// AuthorizedBy reports whether an active rule that names t carries the given
// ticket, and returns the matched pattern. It is the check behind the
// --authorized flag: the operator names a ticket that an approver already
// recorded, and the run proceeds only if such a rule exists.
//
// The rule must name the target (a host or an address). A ticket on a wildcard
// or on a CIDR block does not count: the point of the flag is that a named
// human approved *this* host.
func (p Policy) AuthorizedBy(t Target, ticket string, now time.Time) (string, bool) {
	if strings.TrimSpace(ticket) == "" {
		return "", false
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if !r.active(now) || !r.matches(t) || !r.namesTarget() {
			continue
		}
		if r.Ticket == ticket {
			return r.Pattern, true
		}
	}
	return "", false
}

// LoadPolicy reads a policy JSON file.
func LoadPolicy(path string) (Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	p := DefaultPolicy()
	if err := json.Unmarshal(raw, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}
	return p, nil
}

// LoadPolicyOrDefault reads path, falling back to the default policy when the
// file does not exist.
func LoadPolicyOrDefault(path string) (Policy, error) {
	p, err := LoadPolicy(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultPolicy(), nil
		}
		return Policy{}, err
	}
	return p, nil
}

// AddEnvRules appends rules from a comma-separated STRESS_STRIKE_ALLOW-style
// value. Each entry is a pattern, optionally "pattern@RFC3339" for an expiry.
func (p *Policy) AddEnvRules(spec string) error {
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		r := Rule{Pattern: item, Approver: "environment", Reason: "STRESS_STRIKE_ALLOW"}
		if i := strings.LastIndex(item, "@"); i > 0 {
			if ts, err := time.Parse(time.RFC3339, item[i+1:]); err == nil {
				r.Pattern = item[:i]
				r.Until = ts
			}
		}
		if r.Pattern == "" {
			return fmt.Errorf("empty allow pattern in %q", spec)
		}
		p.Rules = append(p.Rules, r)
	}
	return nil
}
