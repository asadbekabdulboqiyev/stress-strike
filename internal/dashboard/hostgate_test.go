package dashboard

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withLocalAddr attaches the connection's local address the way net/http does,
// so hostAllowed has the same input it has in production.
func withLocalAddr(r *http.Request, addr string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, mustAddr(addr)))
}

func mustAddr(hostport string) net.Addr {
	a, err := net.ResolveTCPAddr("tcp", hostport)
	if err != nil {
		panic(err)
	}
	return a
}

// TestHostGateRejectsRebinding is the regression test for the DNS-rebinding
// hole: on a loopback listener, a request whose Host names some other domain
// is the exact shape a rebinding attack produces, and it must be refused.
func TestHostGateRejectsRebinding(t *testing.T) {
	s := NewServer()

	// evil.com resolves to 127.0.0.1, so the connection arrives on loopback
	// while the browser believes it is talking to its own origin — which means
	// no Origin header, so sameOrigin() alone would let it through.
	for _, host := range []string{
		"evil.com:8888",
		"evil.com",
		"attacker.example",
		"127.0.0.1.nip.io:8888",
		"localhost.evil.com:8888",
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/history", nil)
		r.Host = host
		r = withLocalAddr(r, "127.0.0.1:8888")

		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, r)

		if rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: status = %d, want 421 (DNS rebinding must be refused)", host, rec.Code)
		}
	}
}

// TestHostGateAcceptsLoopbackNames pins the cases a real browser produces when
// the operator does what the start script tells them to do.
func TestHostGateAcceptsLoopbackNames(t *testing.T) {
	s := NewServer()

	for _, host := range []string{
		"127.0.0.1:8888",
		"localhost:8888",
		"localhost",
		"[::1]:8888",
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/version", nil)
		r.Host = host
		r = withLocalAddr(r, "127.0.0.1:8888")

		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, r)

		if rec.Code == http.StatusMisdirectedRequest {
			t.Errorf("Host %q was refused, want it allowed (loopback name)", host)
		}
	}
}

// TestHostGateIPv6Loopback covers a listener bound to [::1]: the Host header
// arrives as a bracketed literal and must match.
func TestHostGateIPv6Loopback(t *testing.T) {
	s := NewServer()
	r := httptest.NewRequest(http.MethodGet, "/api/history", nil)
	r.Host = "evil.com:8888"
	r = withLocalAddr(r, "[::1]:8888")

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)

	if rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("status = %d, want 421 on an IPv6 loopback listener", rec.Code)
	}
}

// TestHostGateAllowsNetworkBind documents the deliberate carve-out: an operator
// who exposes the dashboard on a real interface addresses it by machine name,
// so the Host header cannot be required to be loopback. The auth middleware is
// the control there, and the binary refuses to expose without it.
func TestHostGateAllowsNetworkBind(t *testing.T) {
	s := NewServer()
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.Host = "loadtest.internal:8888"
	r = withLocalAddr(r, "10.0.0.5:8888")

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)

	if rec.Code == http.StatusMisdirectedRequest {
		t.Errorf("status = %d, want the request allowed on a non-loopback bind", rec.Code)
	}
}

// TestHostGateAllowedHostsEscapeHatch covers a reverse proxy that terminates
// TLS on loopback and forwards its own Host header.
func TestHostGateAllowedHostsEscapeHatch(t *testing.T) {
	s := NewServer()
	s.SetAllowedHosts("loadtest.example.com", "LOADTEST.example.com:443")

	r := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	r.Host = "loadtest.example.com"
	r = withLocalAddr(r, "127.0.0.1:8888")

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)

	if rec.Code == http.StatusMisdirectedRequest {
		t.Errorf("status = %d, want an explicitly allowed host to pass", rec.Code)
	}

	// A name that was not allowed stays refused.
	r2 := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	r2.Host = "other.example.com"
	r2 = withLocalAddr(r2, "127.0.0.1:8888")
	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusMisdirectedRequest {
		t.Errorf("status = %d, want 421 for a host that was not allowed", rec2.Code)
	}
}

// TestHostGateRejectsEmptyHost covers HTTP/1.0 clients with no Host header: a
// browser was never told to visit an address with no name, so there is no
// legitimate origin behind it.
func TestHostGateRejectsEmptyHost(t *testing.T) {
	s := NewServer()
	r := httptest.NewRequest(http.MethodGet, "/api/history", nil)
	r.Host = ""
	r = withLocalAddr(r, "127.0.0.1:8888")

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)

	if rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("status = %d, want 421 for an empty Host", rec.Code)
	}
}

// TestHostGateAppliesToOpsEndpoints closes the "the gate forgot one path"
// hole. A rebinding page reaching /metrics would leak internal counters, and
// /healthz would confirm the dashboard is running.
func TestHostGateAppliesToOpsEndpoints(t *testing.T) {
	s := NewServer()
	for _, path := range []string{"/healthz", "/readyz", "/metrics", "/api/", "/"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = "evil.com:8888"
		r = withLocalAddr(r, "127.0.0.1:8888")

		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, r)

		if rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("path %q: status = %d, want 421", path, rec.Code)
		}
	}
}

// TestHostnameOf pins the address parsing the gate depends on.
func TestHostnameOf(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:8888": "127.0.0.1",
		"localhost:8888": "localhost",
		"[::1]:8888":     "::1",
		"[::1]":          "::1",
		"localhost":      "localhost",
		"":               "",
		"evil.com:80":    "evil.com",
	}
	for in, want := range cases {
		if got := hostnameOf(in); got != want {
			t.Errorf("hostnameOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIsLoopbackHost pins what counts as naming this machine.
func TestIsLoopbackHost(t *testing.T) {
	yes := []string{"localhost", "LOCALHOST", "127.0.0.1", "127.0.0.5", "::1"}
	no := []string{"", "evil.com", "10.0.0.1", "127.0.0.1.evil.com", "localhost.evil.com"}

	for _, h := range yes {
		if !isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = false, want true", h)
		}
	}
	for _, h := range no {
		if isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = true, want false", h)
		}
	}
}

// TestHostGateExemptWhenNoLocalAddr keeps direct ServeHTTP calls in the
// existing suite working: without a real connection there is nothing to bind
// the decision to, and production always supplies the value.
func TestHostGateExemptWhenNoLocalAddr(t *testing.T) {
	s := NewServer()
	r := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	r.Host = "example.com" // httptest's default

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)

	if rec.Code == http.StatusMisdirectedRequest {
		t.Errorf("status = %d, want the gate to be inert without a local address", rec.Code)
	}
}

// TestHostGateRealServer proves the gate is live on a real listener, not only
// when the context value is injected by a test.
func TestHostGateRealServer(t *testing.T) {
	s := NewServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	// A real client to a loopback listener sends Host 127.0.0.1:port.
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == http.StatusMisdirectedRequest {
		t.Fatalf("a real loopback request was refused (status %d)", res.StatusCode)
	}

	// The same connection shape with a foreign Host header must be refused.
	req2, err := http.NewRequest(http.MethodGet, ts.URL+"/api/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Host = "evil.com"
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("rebinding-shaped request: status = %d, want 421", res2.StatusCode)
	}
}

// TestAllowedHostsTrimsPortAndCase pins the normalisation applied on input.
func TestAllowedHostsTrimsPortAndCase(t *testing.T) {
	s := NewServer()
	s.SetAllowedHosts("  LoadTest.Example.COM:8443  ")

	s.mu.RLock()
	_, ok := s.allowedHosts["loadtest.example.com"]
	s.mu.RUnlock()

	if !ok {
		t.Fatalf("allowedHosts = %v, want the lowercased host without port", s.allowedHosts)
	}
}

// TestHostGateErrorBodyIsEmpty keeps the refusal from becoming an oracle: a
// 421 with a message would tell a probing page which names are configured.
func TestHostGateErrorBodyIsEmpty(t *testing.T) {
	s := NewServer()
	r := httptest.NewRequest(http.MethodGet, "/api/history", nil)
	r.Host = "evil.com:8888"
	r = withLocalAddr(r, "127.0.0.1:8888")

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)

	if body := strings.TrimSpace(rec.Body.String()); body != "" {
		t.Errorf("refusal body = %q, want empty", body)
	}
}
