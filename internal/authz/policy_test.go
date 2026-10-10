package authz

import (
	"context"
	"testing"
	"time"
)

func target(t *testing.T, raw string, r Resolver) Target {
	t.Helper()
	tgt, err := Classify(context.Background(), raw, r)
	if err != nil {
		t.Fatal(err)
	}
	return tgt
}

var publicResolver = fakeResolver{
	"api.example.com":  {"93.184.216.34"},
	"shop.example.com": {"93.184.216.35"},
}

func TestDefaultPolicyAllowsPublic(t *testing.T) {
	tgt := target(t, "https://api.example.com", publicResolver)
	d := DefaultPolicy().Check(tgt, OpLoadTest, time.Now())
	if !d.Allowed {
		t.Fatalf("public target denied: %s", d.Reason)
	}
}

func TestMetadataDeniedEvenUnderWildcard(t *testing.T) {
	tgt := target(t, "http://169.254.169.254/latest/meta-data/", nil)
	p := DefaultPolicy()
	p.Rules = []Rule{{Pattern: "*", Approver: "ciso"}}
	d := p.Check(tgt, OpLoadTest, time.Now())
	if d.Allowed {
		t.Fatal("wildcard rule must not unlock instance metadata")
	}
}

func TestMetadataAllowedOnlyByExactRule(t *testing.T) {
	tgt := target(t, "http://169.254.169.254/latest/meta-data/", nil)
	p := DefaultPolicy()
	p.Rules = []Rule{{
		Pattern:  "169.254.169.254",
		Approver: "ciso@corp",
		Ticket:   "SEC-42",
		Until:    time.Now().Add(time.Hour),
	}}
	d := p.Check(tgt, OpLoadTest, time.Now())
	if !d.Allowed {
		t.Fatalf("exact metadata rule should allow: %s", d.Reason)
	}
}

func TestPrivateDeniedByDefault(t *testing.T) {
	tgt := target(t, "http://internal.local", fakeResolver{"internal.local": {"10.0.0.5"}})
	d := DefaultPolicy().Check(tgt, OpLoadTest, time.Now())
	if d.Allowed {
		t.Fatal("private target should be denied by default")
	}
}

func TestPrivateAllowedWithFlag(t *testing.T) {
	tgt := target(t, "http://internal.local", fakeResolver{"internal.local": {"10.0.0.5"}})
	p := DefaultPolicy()
	p.AllowPrivate = true
	d := p.Check(tgt, OpLoadTest, time.Now())
	if !d.Allowed {
		t.Fatalf("private target denied with allow_private: %s", d.Reason)
	}
}

func TestPrivateAllowedByCIDRRule(t *testing.T) {
	tgt := target(t, "http://internal.local", fakeResolver{"internal.local": {"10.0.0.5"}})
	p := DefaultPolicy()
	p.Rules = []Rule{{Pattern: "10.0.0.0/8", Approver: "netops"}}
	d := p.Check(tgt, OpLoadTest, time.Now())
	if !d.Allowed {
		t.Fatalf("CIDR rule should allow: %s", d.Reason)
	}
}

func TestExpiredRuleDoesNotAllow(t *testing.T) {
	tgt := target(t, "http://internal.local", fakeResolver{"internal.local": {"10.0.0.5"}})
	p := DefaultPolicy()
	p.Rules = []Rule{{Pattern: "10.0.0.0/8", Until: time.Now().Add(-time.Minute)}}
	if p.Check(tgt, OpLoadTest, time.Now()).Allowed {
		t.Fatal("expired rule must not allow")
	}
}

func TestPentestRequiresExactRule(t *testing.T) {
	tgt := target(t, "https://shop.example.com", publicResolver)
	p := DefaultPolicy()
	if d := p.Check(tgt, OpPentest, time.Now()); d.Allowed {
		t.Fatal("pentest should require explicit authorization")
	}
	p.Rules = []Rule{{Pattern: "*.example.com", Approver: "ciso"}}
	if d := p.Check(tgt, OpPentest, time.Now()); d.Allowed {
		t.Fatal("wildcard must not satisfy a pentest authorization")
	}
	p.Rules = []Rule{{Pattern: "shop.example.com", Approver: "ciso", Ticket: "PEN-1"}}
	if d := p.Check(tgt, OpPentest, time.Now()); !d.Allowed {
		t.Fatalf("exact pentest rule should allow: %s", d.Reason)
	}
}

func TestStrictModeDeniesPublicWithoutRule(t *testing.T) {
	tgt := target(t, "https://api.example.com", publicResolver)
	p := Policy{Mode: ModeStrict}
	if d := p.Check(tgt, OpLoadTest, time.Now()); d.Allowed {
		t.Fatal("strict mode must deny unmatched targets")
	}
	p.Rules = []Rule{{Pattern: "api.example.com", Approver: "sec"}}
	if d := p.Check(tgt, OpLoadTest, time.Now()); !d.Allowed {
		t.Fatalf("strict mode should allow listed target: %s", d.Reason)
	}
}

func TestWildcardSubdomainRule(t *testing.T) {
	tgt := target(t, "https://staging.example.com", fakeResolver{"staging.example.com": {"10.0.0.9"}})
	p := DefaultPolicy()
	p.Rules = []Rule{{Pattern: "*.example.com", Approver: "sec"}}
	if d := p.Check(tgt, OpLoadTest, time.Now()); !d.Allowed {
		t.Fatalf("subdomain wildcard should match: %s", d.Reason)
	}
	other := target(t, "https://example.org", fakeResolver{"example.org": {"10.0.0.9"}})
	if d := p.Check(other, OpLoadTest, time.Now()); d.Allowed {
		t.Fatal("wildcard must not match a different domain")
	}
}

func TestAddEnvRules(t *testing.T) {
	p := DefaultPolicy()
	if err := p.AddEnvRules("staging.internal,10.0.0.0/8@2030-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("got %d rules", len(p.Rules))
	}
	if p.Rules[1].Pattern != "10.0.0.0/8" || p.Rules[1].Until.IsZero() {
		t.Fatalf("expiry not parsed: %+v", p.Rules[1])
	}
}

func TestPentestRequiresExactEvenWithWildcardPresent(t *testing.T) {
	tgt := target(t, "https://api.example.com", publicResolver)
	p := DefaultPolicy()
	p.Rules = []Rule{
		{Pattern: "*", Approver: "wide"},
		{Pattern: "api.example.com", Approver: "exact"},
	}
	d := p.Check(tgt, OpPentest, time.Now())
	if !d.Allowed || d.Rule != "api.example.com" {
		t.Fatalf("exact rule should win: allowed=%v rule=%q", d.Allowed, d.Rule)
	}
}
