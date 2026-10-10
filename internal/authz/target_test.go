package authz

import (
	"context"
	"fmt"
	"net"
	"testing"
)

type fakeResolver map[string][]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f[host]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", host)
	}
	out := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func TestClassifyIP(t *testing.T) {
	cases := []struct {
		ip   string
		want Class
	}{
		{"8.8.8.8", ClassPublic},
		{"1.1.1.1", ClassPublic},
		{"127.0.0.1", ClassLoopback},
		{"::1", ClassLoopback},
		{"10.0.0.5", ClassPrivate},
		{"192.168.1.10", ClassPrivate},
		{"172.16.4.4", ClassPrivate},
		{"fd00::1", ClassPrivate},
		{"100.64.0.1", ClassCGNAT},
		{"100.127.255.254", ClassCGNAT},
		{"169.254.1.1", ClassLinkLocal},
		{"fe80::1", ClassLinkLocal},
		{"224.0.0.1", ClassMulticast},
		{"0.0.0.0", ClassReserved},
		{"169.254.169.254", ClassMetadata},
		{"169.254.170.2", ClassMetadata},
		{"100.100.100.200", ClassMetadata},
	}
	for _, c := range cases {
		if got := ClassifyIP(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("ClassifyIP(%s) = %s, want %s", c.ip, got, c.want)
		}
	}
}

func TestClassifyMetadataHostname(t *testing.T) {
	tgt, err := Classify(context.Background(), "http://metadata.google.internal/computeMetadata/v1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Class() != ClassMetadata {
		t.Fatalf("class = %s, want metadata", tgt.Class())
	}
}

func TestClassifyIPLiteral(t *testing.T) {
	tgt, err := Classify(context.Background(), "http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Class() != ClassMetadata {
		t.Fatalf("class = %s, want metadata", tgt.Class())
	}
	if tgt.Host != "169.254.169.254" {
		t.Fatalf("host = %q", tgt.Host)
	}
}

func TestClassifyResolvesAndPicksWorst(t *testing.T) {
	r := fakeResolver{"evil.example": {"93.184.216.34", "10.1.2.3"}}
	tgt, err := Classify(context.Background(), "https://evil.example/", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.IPs) != 2 {
		t.Fatalf("got %d IPs", len(tgt.IPs))
	}
	if tgt.Class() != ClassPrivate {
		t.Fatalf("class = %s, want private (worst of public+private)", tgt.Class())
	}
}

func TestClassifyHostPort(t *testing.T) {
	tgt, err := Classify(context.Background(), "example.com:8443", fakeResolver{"example.com": {"93.184.216.34"}})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Host != "example.com" || tgt.Port != "8443" {
		t.Fatalf("host/port = %q/%q", tgt.Host, tgt.Port)
	}
}
