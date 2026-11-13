package core

// transport_test.go — the shared transport primitives.
//
// SameHost is the one definition of "same host" the crawler and the passive
// checks both use. Its previous implementation compared Host, which carries the
// port, while its comment claimed the port was ignored; that mismatch is pinned
// here so the two cannot drift apart again.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/fingerprint"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestSameHost(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
		why  string
	}{
		{"https://example.com/", "https://example.com/a", true, "same host, same scheme"},
		{"https://example.com/", "https://example.com:443/", true, "written default port is the same site"},
		{"http://example.com/", "http://example.com:80/", true, "written http default port"},
		{"http://example.com/", "https://example.com/", true, "an http→https upgrade stays in scope"},
		{"https://EXAMPLE.com/", "https://example.com/", true, "host names are case-insensitive"},
		{"http://127.0.0.1:49911/", "http://127.0.0.1:49912/", false, "two explicit ports are two services"},
		{"https://example.com:8443/", "https://example.com:9443/", false, "different non-default ports"},
		{"https://example.com/", "https://example.com:8080/", false, "an absent port never matches a non-default port"},
		{"https://example.com/", "https://example.org/", false, "different host names"},
		{"https://example.com/", "https://sub.example.com/", false, "a subdomain is a different host"},
	}

	for _, c := range cases {
		if got := SameHost(mustURL(t, c.a), mustURL(t, c.b)); got != c.want {
			t.Errorf("SameHost(%q, %q) = %v, want %v (%s)", c.a, c.b, got, c.want, c.why)
		}
		// The relation is symmetric.
		if got := SameHost(mustURL(t, c.b), mustURL(t, c.a)); got != c.want {
			t.Errorf("SameHost(%q, %q) = %v, want %v (symmetric check)", c.b, c.a, got, c.want)
		}
	}
}

func TestSameHostNilAndHostless(t *testing.T) {
	empty := mustURL(t, "/just/a/path")
	host := mustURL(t, "https://example.com/")

	if SameHost(nil, host) || SameHost(host, nil) || SameHost(nil, nil) {
		t.Error("a nil URL must never be the same host as anything")
	}
	if SameHost(empty, host) || SameHost(host, empty) {
		t.Error("a URL with no host must never match a real host")
	}
}

func TestPortsCompatible(t *testing.T) {
	cases := []struct {
		pa, pb string
		want   bool
	}{
		{"", "", true},
		{"", "80", true},
		{"", "443", true},
		{"80", "", true},
		{"443", "", true},
		{"", "8080", false},
		{"8080", "", false},
		{"8080", "8080", true},
		{"8080", "9090", false},
	}
	for _, c := range cases {
		if got := portsCompatible(c.pa, c.pb); got != c.want {
			t.Errorf("portsCompatible(%q, %q) = %v, want %v", c.pa, c.pb, got, c.want)
		}
	}
}

// TestApplyHeadersKeepsCallerValues: the profile supplies defaults, never
// overrides. A caller that set its own UA keeps it.
func TestApplyHeadersKeepsCallerValues(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("User-Agent", "caller-agent/1.0")

	ApplyHeaders(req, fingerprint.Default)

	if got := req.Header.Get("User-Agent"); got != "caller-agent/1.0" {
		t.Errorf("User-Agent = %q, want the caller's value to survive", got)
	}
}

func TestDefaultHeaderHookUsesBaseTransport(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("User-Agent") == "" {
			t.Error("hook did not stamp a User-Agent")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := &http.Client{Transport: DefaultHeaderHook{Profile: fingerprint.Default}}
	res, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", res.StatusCode)
	}
}

// TestNewHTTPClientDoesNotFollowRedirects: every scanner check needs the raw
// 3xx and its Location header.
func TestNewHTTPClientDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	client := NewHTTPClient(fingerprint.Default, 5*time.Second, false)
	res, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want the 302 to be returned unfollowed", res.StatusCode)
	}
}

func TestReadBody(t *testing.T) {
	t.Run("nil response and nil body", func(t *testing.T) {
		if b, err := ReadBody(nil, 0); b != nil || err != nil {
			t.Errorf("ReadBody(nil) = %v, %v; want nil, nil", b, err)
		}
		if b, err := ReadBody(&http.Response{}, 0); b != nil || err != nil {
			t.Errorf("ReadBody(no body) = %v, %v; want nil, nil", b, err)
		}
	})

	t.Run("respects an explicit limit", func(t *testing.T) {
		res := &http.Response{Body: io.NopCloser(strings.NewReader("abcdefghij"))}
		b, err := ReadBody(res, 4)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "abcd" {
			t.Errorf("body = %q, want the first 4 bytes", b)
		}
	})

	t.Run("limit <= 0 means the default cap", func(t *testing.T) {
		res := &http.Response{Body: io.NopCloser(strings.NewReader("hello"))}
		b, err := ReadBody(res, 0)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "hello" {
			t.Errorf("body = %q, want hello", b)
		}
	})

	t.Run("closes the body", func(t *testing.T) {
		closed := false
		res := &http.Response{Body: &trackingBody{
			Reader: strings.NewReader("x"),
			onClose: func() {
				closed = true
			},
		}}
		if _, err := ReadBody(res, 0); err != nil {
			t.Fatal(err)
		}
		if !closed {
			t.Error("ReadBody must close the response body")
		}
	})
}

type trackingBody struct {
	io.Reader
	onClose func()
}

func (b *trackingBody) Close() error {
	b.onClose()
	return nil
}

// TestSendProbeStampsUserAgent and follows the path contract: the caller's path
// replaces the target's, and the scanner UA is present.
func TestSendProbeStampsUserAgent(t *testing.T) {
	var gotUA, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := SendProbe(srv.URL, http.MethodGet, "/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if gotPath != "/probe" {
		t.Errorf("path = %q, want /probe", gotPath)
	}
	if gotUA == "" {
		t.Error("SendProbe sent no User-Agent")
	}
}

func TestSendProbeRejectsABadTarget(t *testing.T) {
	if _, err := SendProbe("://bad", http.MethodGet, "/", nil); err == nil {
		t.Fatal("SendProbe with an unparseable target must fail")
	}
}
