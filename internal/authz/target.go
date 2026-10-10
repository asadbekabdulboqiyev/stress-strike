// Package authz is stress-strike's authorization and consent layer.
//
// It answers one question before any traffic is sent: is this run permitted?
// The layer exists because a load generator and an offensive scanner are, from
// the network's point of view, indistinguishable from a denial-of-service tool
// and an attacker. Enterprise buyers need proof that the tool cannot be turned
// against cloud metadata endpoints, internal networks, or third-party hosts by
// accident or by a malicious insider.
//
// Three pieces:
//
//	target.go   classify a target (public / private / link-local / metadata)
//	policy.go   decide allow or deny from a policy and an allow-list
//	audit.go    append-only, hash-chained record of every decision
//	notify.go   best-effort webhook/Slack notification for offensive runs
package authz

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Class is the network class of a resolved target address.
type Class int

const (
	// ClassPublic is a globally routable address.
	ClassPublic Class = iota
	// ClassLoopback is 127.0.0.0/8 or ::1.
	ClassLoopback
	// ClassPrivate is RFC1918 or an IPv6 unique-local address.
	ClassPrivate
	// ClassCGNAT is 100.64.0.0/10 (carrier-grade NAT, also used by some clouds).
	ClassCGNAT
	// ClassLinkLocal is 169.254.0.0/16 or fe80::/10.
	ClassLinkLocal
	// ClassMulticast is a multicast or interface-local group.
	ClassMulticast
	// ClassReserved is unspecified, documentation, or otherwise not routable.
	ClassReserved
	// ClassMetadata is a cloud instance-metadata service. These endpoints hand
	// out temporary IAM credentials to anything that can reach them, so they
	// are treated as the most dangerous class.
	ClassMetadata
)

// String returns the lowercase name used in policy rules and audit records.
func (c Class) String() string {
	switch c {
	case ClassPublic:
		return "public"
	case ClassLoopback:
		return "loopback"
	case ClassPrivate:
		return "private"
	case ClassCGNAT:
		return "cgnat"
	case ClassLinkLocal:
		return "link-local"
	case ClassMulticast:
		return "multicast"
	case ClassReserved:
		return "reserved"
	case ClassMetadata:
		return "metadata"
	default:
		return fmt.Sprintf("class(%d)", int(c))
	}
}

// severity ranks classes by how much scrutiny they require. Higher is worse.
func (c Class) severity() int {
	switch c {
	case ClassPublic:
		return 0
	case ClassLoopback:
		return 1
	case ClassPrivate:
		return 2
	case ClassCGNAT:
		return 3
	case ClassLinkLocal:
		return 4
	case ClassReserved:
		return 5
	case ClassMulticast:
		return 6
	case ClassMetadata:
		return 7
	default:
		return 99
	}
}

// metadataHosts are instance-metadata service hostnames that must be blocked
// even when DNS is used to reach them.
var metadataHosts = map[string]bool{
	"metadata.google.internal": true,
	"metadata.goog":            true,
	"instance-data":            true,
	"metadata":                 true,
}

// metadataIPs are well-known instance-metadata addresses across clouds.
var metadataIPs = []string{
	"169.254.169.254", // AWS, Azure, GCP, DigitalOcean, Oracle
	"169.254.170.2",   // AWS ECS task metadata
	"100.100.100.200", // Alibaba Cloud
	"fd00:ec2::254",   // AWS IMDS over IPv6
}

// Resolver resolves a host to addresses. net.DefaultResolver satisfies it; the
// indirection exists so tests never touch the network.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Target is a classified destination.
type Target struct {
	// Raw is the original URL or host string.
	Raw string
	// Host is the hostname (no port), lowercased.
	Host string
	// Port is the port, if any.
	Port string
	// IPs are the resolved addresses (a single literal address if Host was an IP).
	IPs []net.IP
	// Classes holds the class of each entry in IPs, in the same order.
	Classes []Class
}

// Class returns the most restrictive class among the target's addresses.
func (t Target) Class() Class {
	worst := ClassPublic
	for _, c := range t.Classes {
		if c.severity() > worst.severity() {
			worst = c
		}
	}
	return worst
}

// Classify parses raw and resolves it just far enough to classify the
// destination. It never sends application traffic.
//
// raw may be a URL (https://api.example.com/x), a host, or a host:port.
func Classify(ctx context.Context, raw string, r Resolver) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	if r == nil {
		r = net.DefaultResolver
	}

	host, port := splitHostPort(raw)
	host = strings.ToLower(host)
	if host == "" {
		return Target{}, fmt.Errorf("cannot parse host from %q", raw)
	}

	t := Target{Raw: raw, Host: host, Port: port}

	if metadataHosts[host] {
		t.Classes = []Class{ClassMetadata}
		return t, nil
	}

	// IP literal: classify directly, no DNS.
	if ip := net.ParseIP(host); ip != nil {
		t.IPs = []net.IP{ip}
		t.Classes = []Class{ClassifyIP(ip)}
		return t, nil
	}

	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return t, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return t, fmt.Errorf("resolve %q: no addresses", host)
	}
	for _, a := range addrs {
		t.IPs = append(t.IPs, a.IP)
		t.Classes = append(t.Classes, ClassifyIP(a.IP))
	}
	return t, nil
}

// splitHostPort accepts a full URL or a bare host[:port].
func splitHostPort(raw string) (host, port string) {
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			return u.Hostname(), u.Port()
		}
	}
	// Strip any path/query so "example.com/path" works.
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if h, p, err := net.SplitHostPort(raw); err == nil {
		return h, p
	}
	return raw, ""
}

// Worst returns the more restrictive of two classes.
func Worst(a, b Class) Class {
	if b.severity() > a.severity() {
		return b
	}
	return a
}

// ClassifyIP returns the class of a single address.
func ClassifyIP(ip net.IP) Class {
	for _, s := range metadataIPs {
		if m := net.ParseIP(s); m != nil && m.Equal(ip) {
			return ClassMetadata
		}
	}
	switch {
	case ip.IsUnspecified():
		return ClassReserved
	case ip.IsLoopback():
		return ClassLoopback
	case ip.IsMulticast() || ip.IsInterfaceLocalMulticast():
		return ClassMulticast
	case ip.IsLinkLocalUnicast():
		return ClassLinkLocal
	case inCGNAT(ip):
		return ClassCGNAT
	case ip.IsPrivate():
		return ClassPrivate
	case ip.IsGlobalUnicast():
		return ClassPublic
	default:
		return ClassReserved
	}
}

// inCGNAT reports whether ip is in 100.64.0.0/10.
func inCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 100 && v4[1]&0xc0 == 64 // 100.64.0.0 – 100.127.255.255
}
