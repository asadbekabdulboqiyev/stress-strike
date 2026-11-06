package scanner

// subdomain_test.go — coverage for passive subdomain enumeration: the crt.sh
// certificate-transparency client, DNS record queries, host resolution and the
// aggregation helpers.
//
// crt.sh goes through the package-level http.DefaultClient, so the network is
// replaced with a scripted RoundTripper. No test in this package uses
// t.Parallel, which makes swapping the client safe.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// subdomainRoundTripper adapts a function to http.RoundTripper.
type subdomainRoundTripper func(*http.Request) (*http.Response, error)

func (f subdomainRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// withDefaultHTTPClient swaps http.DefaultClient for the duration of the test.
func withDefaultHTTPClient(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	prev := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: rt}
	t.Cleanup(func() { http.DefaultClient = prev })
}

// errReadCloser fails on every Read.
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (errReadCloser) Close() error             { return nil }

// collectAdd returns an add callback plus the ordered record of what it saw.
type addedName struct {
	name    string
	source  string
	methods []string
}

func collectAdd() (func(name, source string, methods ...string), *[]addedName) {
	var got []addedName
	return func(name, source string, methods ...string) {
		got = append(got, addedName{name: name, source: source, methods: append([]string(nil), methods...)})
	}, &got
}

func TestCrtShParsesEntries(t *testing.T) {
	var seenURL, seenUA string
	withDefaultHTTPClient(t, subdomainRoundTripper(func(r *http.Request) (*http.Response, error) {
		seenURL = r.URL.String()
		seenUA = r.Header.Get("User-Agent")
		body := `[
			{"common_name":"a.example.com","name_value":"a.example.com\n*.wild.example.com"},
			{"common_name":"x","name_value":"api.example.com"}
		]`
		return passiveTestResponse(200, http.Header{"Content-Type": {"application/json"}}, body), nil
	}))

	add, got := collectAdd()
	if err := crtSh(context.Background(), "example.com", add); err != nil {
		t.Fatalf("crtSh: %v", err)
	}

	if !strings.Contains(seenURL, "crt.sh") || !strings.Contains(seenURL, "example.com") {
		t.Errorf("requested URL = %q, want the crt.sh query", seenURL)
	}
	if !strings.Contains(seenUA, "subenum") {
		t.Errorf("User-Agent = %q", seenUA)
	}

	// Both name_value and common_name are mined, wildcard prefix stripped.
	// There is no dedupe at this layer (EnumerateSubdomains owns that), so
	// a.example.com legitimately appears twice: once as name_value, once as
	// common_name.
	want := []string{"a.example.com", "wild.example.com", "a.example.com", "api.example.com", "x"}
	if len(*got) != len(want) {
		t.Fatalf("added %+v, want %v", *got, want)
	}
	for i, name := range want {
		if (*got)[i].name != name {
			t.Errorf("add[%d].name = %q, want %q", i, (*got)[i].name, name)
		}
		if (*got)[i].source != "crt.sh" {
			t.Errorf("add[%d].source = %q, want crt.sh", i, (*got)[i].source)
		}
		if len((*got)[i].methods) != 1 || (*got)[i].methods[0] != "cert" {
			t.Errorf("add[%d].methods = %v, want [cert]", i, (*got)[i].methods)
		}
	}
}

func TestCrtShFailures(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		withDefaultHTTPClient(t, subdomainRoundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection reset")
		}))
		add, got := collectAdd()
		if err := crtSh(context.Background(), "example.com", add); err == nil {
			t.Fatal("crtSh swallowed a transport error")
		}
		if len(*got) != 0 {
			t.Errorf("add was called %d time(s) after a failed request", len(*got))
		}
	})

	t.Run("non-JSON body", func(t *testing.T) {
		withDefaultHTTPClient(t, subdomainRoundTripper(func(*http.Request) (*http.Response, error) {
			return passiveTestResponse(200, nil, "<html>rate limited</html>"), nil
		}))
		add, _ := collectAdd()
		if err := crtSh(context.Background(), "example.com", add); err == nil {
			t.Fatal("crtSh accepted an HTML body")
		}
	})

	t.Run("body read error", func(t *testing.T) {
		withDefaultHTTPClient(t, subdomainRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: errReadCloser{}}, nil
		}))
		add, _ := collectAdd()
		if err := crtSh(context.Background(), "example.com", add); err == nil {
			t.Fatal("crtSh ignored a body read error")
		}
	})

	t.Run("empty entry list", func(t *testing.T) {
		withDefaultHTTPClient(t, subdomainRoundTripper(func(*http.Request) (*http.Response, error) {
			return passiveTestResponse(200, nil, `[]`), nil
		}))
		add, got := collectAdd()
		if err := crtSh(context.Background(), "example.com", add); err != nil {
			t.Fatalf("crtSh: %v", err)
		}
		if len(*got) != 0 {
			t.Errorf("added %+v for an empty log", *got)
		}
	})
}

// --- hermetic DNS stubs -----------------------------------------------------

// dnsStub scripted answers for the four lookup seams. Missing names fail with
// a not-found error, so each test spells out exactly what resolves.
type dnsStub struct {
	hosts    map[string][]string
	cnames   map[string]string
	mx       map[string][]*net.MX
	txt      map[string][]string
	hostsErr error
	calls    int
}

func withDNSStub(t *testing.T, st *dnsStub) {
	t.Helper()
	prevHost, prevCNAME, prevMX, prevTXT := lookupHostFn, lookupCNAMEFn, lookupMXFn, lookupTXTFn
	notFound := func(host string) error {
		return &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	lookupHostFn = func(_ context.Context, host string) ([]string, error) {
		st.calls++
		if st.hostsErr != nil {
			return nil, st.hostsErr
		}
		if ips, ok := st.hosts[host]; ok {
			return ips, nil
		}
		return nil, notFound(host)
	}
	lookupCNAMEFn = func(_ context.Context, host string) (string, error) {
		if cname, ok := st.cnames[host]; ok {
			return cname, nil
		}
		// The standard resolver canonicalises a name to itself when no CNAME
		// exists; resolveHost filters that case out.
		return host, nil
	}
	lookupMXFn = func(_ context.Context, host string) ([]*net.MX, error) {
		if mx, ok := st.mx[host]; ok {
			return mx, nil
		}
		return nil, notFound(host)
	}
	lookupTXTFn = func(_ context.Context, host string) ([]string, error) {
		if txt, ok := st.txt[host]; ok {
			return txt, nil
		}
		return nil, notFound(host)
	}
	t.Cleanup(func() {
		lookupHostFn, lookupCNAMEFn, lookupMXFn, lookupTXTFn = prevHost, prevCNAME, prevMX, prevTXT
	})
}

func TestDNSQueryRecordsHost(t *testing.T) {
	st := &dnsStub{
		hosts:  map[string][]string{"localhost": {"127.0.0.1", "::1"}},
		mx:     map[string][]*net.MX{"localhost": {{Host: "mail.localhost.", Pref: 10}}},
		txt:    map[string][]string{"localhost": {"v=spf1 -all"}},
		cnames: map[string]string{"localhost": "edge.localhost."},
	}
	withDNSStub(t, st)

	add, got := collectAdd()
	dnsQuery(context.Background(), "localhost", add, "A", "MX", "TXT")

	// One add per successful type iteration (A, MX, TXT), plus the MX host and
	// the TXT presence marker.
	if len(*got) != 5 {
		t.Fatalf("add called %d time(s): %+v", len(*got), *got)
	}

	hostAdds, mxAdd, txtAdd := 0, 0, 0
	for _, a := range *got {
		switch {
		case a.name == "localhost" && len(a.methods) > 2:
			hostAdds++
			if a.source != "dns" {
				t.Errorf("host add source = %q, want dns", a.source)
			}
			// The requested types are recorded alongside the resolved
			// addresses, on every iteration.
			for _, want := range []string{"A", "MX", "TXT", "127.0.0.1", "::1"} {
				found := false
				for _, m := range a.methods {
					if m == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("methods = %v, missing %q", a.methods, want)
				}
			}
		case a.name == "mail.localhost." && len(a.methods) == 1 && a.methods[0] == "MX":
			mxAdd++
		case a.name == "localhost" && len(a.methods) == 1 && a.methods[0] == "TXT":
			txtAdd++
		default:
			t.Errorf("unexpected add: %+v", a)
		}
	}
	if hostAdds != 3 {
		t.Errorf("host recorded %d time(s), want 3 (once per type)", hostAdds)
	}
	if mxAdd != 1 {
		t.Errorf("MX host recorded %d time(s), want 1", mxAdd)
	}
	if txtAdd != 1 {
		t.Errorf("TXT presence recorded %d time(s), want 1", txtAdd)
	}
}

func TestDNSQueryLookupFailure(t *testing.T) {
	st := &dnsStub{hostsErr: errors.New("resolver unavailable")}
	withDNSStub(t, st)

	add, got := collectAdd()
	dnsQuery(context.Background(), "example.com", add, "A", "MX", "TXT")
	if len(*got) != 0 {
		t.Errorf("add was called after failed lookups: %+v", *got)
	}
}

func TestDNSQueryCancelledContext(t *testing.T) {
	st := &dnsStub{hosts: map[string][]string{"localhost": {"127.0.0.1"}}}
	withDNSStub(t, st)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	add, got := collectAdd()
	dnsQuery(ctx, "localhost", add, "A", "MX", "TXT")
	if len(*got) != 0 {
		t.Errorf("dnsQuery queried with a cancelled context: %+v", *got)
	}
	if st.calls != 0 {
		t.Errorf("resolver was called %d time(s) after cancellation", st.calls)
	}
}

func TestResolveHostReportsMethods(t *testing.T) {
	st := &dnsStub{
		hosts:  map[string][]string{"localhost": {"127.0.0.1"}},
		cnames: map[string]string{"localhost": "edge.localhost."},
		mx:     map[string][]*net.MX{"localhost": {{Host: "mail.localhost.", Pref: 5}}},
	}
	withDNSStub(t, st)

	ips, methods := resolveHost(context.Background(), "localhost")
	if len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Errorf("ips = %v, want [127.0.0.1]", ips)
	}
	want := []string{"A/AAAA", "CNAME:edge.localhost.", "MX"}
	if len(methods) != len(want) {
		t.Fatalf("methods = %v, want %v", methods, want)
	}
	for i := range want {
		if methods[i] != want[i] {
			t.Errorf("methods[%d] = %q, want %q", i, methods[i], want[i])
		}
	}
}

func TestResolveHostNoRecords(t *testing.T) {
	st := &dnsStub{hostsErr: errors.New("no such host")}
	withDNSStub(t, st)

	ips, methods := resolveHost(context.Background(), "gone.example.com")
	if len(ips) != 0 || len(methods) != 0 {
		t.Errorf("unresolvable host produced ips=%v methods=%v", ips, methods)
	}
}

func TestAppendUnique(t *testing.T) {
	base := []string{"a", "b"}
	got := appendUnique(base, "b", "c", "a", "d")
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("appendUnique = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("appendUnique[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if got := appendUnique(nil, "only"); len(got) != 1 || got[0] != "only" {
		t.Errorf("appendUnique(nil, only) = %v", got)
	}
	if got := appendUnique([]string{"a"}); len(got) != 1 || got[0] != "a" {
		t.Errorf("appendUnique with no values = %v", got)
	}
}

func TestAtomicAdd(t *testing.T) {
	n := 0
	atomicAdd(&n)
	atomicAdd(&n)
	if n != 2 {
		t.Errorf("atomicAdd twice = %d, want 2", n)
	}
}

func TestEnumerateSubdomainsCancelled(t *testing.T) {
	withDefaultHTTPClient(t, subdomainRoundTripper(func(*http.Request) (*http.Response, error) {
		return passiveTestResponse(200, nil, `[{"name_value":"localhost\napi.localhost"}]`), nil
	}))
	st := &dnsStub{hosts: map[string][]string{"localhost": {"127.0.0.1"}}}
	withDNSStub(t, st)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := EnumerateSubdomains(ctx, "localhost", nil)
	if res == nil {
		t.Fatal("EnumerateSubdomains returned nil")
	}
	if res.Target != "localhost" {
		t.Errorf("Target = %q", res.Target)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want positive", res.Duration)
	}
	// The passive goroutines are detached from the ctx.Done exit; give them a
	// moment so the swaps in t.Cleanup cannot race them.
	time.Sleep(100 * time.Millisecond)
}

func TestEnumerateSubdomainsFullRun(t *testing.T) {
	withDefaultHTTPClient(t, subdomainRoundTripper(func(*http.Request) (*http.Response, error) {
		body := `[
			{"name_value":"localhost\napi.localhost"},
			{"name_value":"not-ours.example.com"}
		]`
		return passiveTestResponse(200, nil, body), nil
	}))
	st := &dnsStub{
		hosts: map[string][]string{
			"localhost":     {"127.0.0.1"},
			"api.localhost": {"127.0.0.2"},
		},
	}
	withDNSStub(t, st)

	prevWait := passiveWait
	passiveWait = 100 * time.Millisecond
	t.Cleanup(func() { passiveWait = prevWait })

	res := EnumerateSubdomains(context.Background(), "localhost", nil)
	if res == nil {
		t.Fatal("EnumerateSubdomains returned nil")
	}
	if res.Found < 2 {
		t.Fatalf("Found = %d, want at least localhost + api.localhost (%+v)", res.Found, res.Subdomains)
	}
	names := make(map[string]Subdomain, len(res.Subdomains))
	for _, s := range res.Subdomains {
		names[s.Name] = s
	}
	for _, want := range []string{"localhost", "api.localhost"} {
		s, ok := names[want]
		if !ok {
			t.Errorf("%q missing from %+v", want, res.Subdomains)
			continue
		}
		if len(s.IPs) == 0 {
			t.Errorf("%q has no resolved IPs", want)
		}
	}
	if _, ok := names["not-ours.example.com"]; ok {
		t.Error("a name outside the target apex was accepted")
	}
	if res.Resolved != 2 {
		t.Errorf("Resolved = %d, want 2", res.Resolved)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v", res.Duration)
	}
}
