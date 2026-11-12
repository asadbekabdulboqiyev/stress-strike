package dashboard

// hostgate.go — the DNS-rebinding defence for the dashboard control plane.
//
// A browser will happily resolve any domain to 127.0.0.1, so a page on
// evil.com can talk to this dashboard as if it were the dashboard itself. Two
// things make that dangerous here:
//
//   - the request is *same-origin* from the browser's point of view, so it
//     carries no Origin header, and sameOrigin() cannot see it;
//   - the control API can start and stop real load runs, read the run history
//     and issue certificates.
//
// The fix is to look at the Host header, which the browser must set to the
// domain it was told to request — evil.com — and refuse anything that does not
// name this machine. Only the connection's own local address is trusted for
// that decision, never a proxy header: X-Forwarded-Host is attacker-controlled
// on the request path we care about.

import (
	"net"
	"net/http"
	"strings"
)

// isLoopbackHost reports whether a host name (no port, no brackets) names the
// loopback interface. "localhost" is included because browsers and operators
// both use it; every loopback literal (127.0.0.0/8, ::1) is included because
// the dashboard defaults to 127.0.0.1.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// hostnameOf strips the port and IPv6 brackets from an HTTP Host or listen
// address. "[::1]:8888" -> "::1", "127.0.0.1:8888" -> "127.0.0.1",
// "localhost" -> "localhost". Malformed input yields "" so it fails closed.
func hostnameOf(hostport string) string {
	if hostport == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	// No port: the whole string is the host, possibly a bracketed IPv6
	// literal ("[::1]").
	return strings.Trim(hostport, "[]")
}

// SetAllowedHosts adds host names that may address this dashboard even though
// they are not loopback names: the usual reason is a reverse proxy that
// terminates TLS on 127.0.0.1 and forwards with its own Host header.
//
// The names are matched case-insensitively, with or without a port.
func (s *Server) SetAllowedHosts(hosts ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(hostnameOf(h)))
		if h != "" {
			s.allowedHosts[h] = struct{}{}
		}
	}
}

// hostAllowed is the rebinding gate.
//
// The decision keys on the address the connection actually arrived on
// (http.LocalAddrContextKey, which net/http always populates), not on anything
// the client sent:
//
//   - connection arrived on a loopback address: the Host header must name
//     loopback too (localhost, 127.0.0.0/8, ::1) or be explicitly allowed.
//     "evil.com:8888" is refused — that is the rebinding case.
//   - connection arrived on a non-loopback address: the operator has chosen to
//     expose the dashboard, so the Host header is whatever name clients use
//     and the auth middleware is the control. Allowed.
//   - no local address in the context: this is not a real network connection
//     (unit tests call ServeHTTP directly). Allowed so the gate does not have
//     to be threaded through every test; production always has the value.
func (s *Server) hostAllowed(r *http.Request) bool {
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || local == nil {
		return true
	}

	if tcp, isTCP := local.(*net.TCPAddr); isTCP {
		if !tcp.IP.IsLoopback() {
			return true
		}
	} else if !isLoopbackHost(hostnameOf(local.String())) {
		return true
	}

	host := hostnameOf(r.Host)
	if host == "" {
		// An HTTP/1.0 request without a Host header cannot be an origin
		// a browser was told to visit.
		return false
	}
	if isLoopbackHost(host) {
		return true
	}

	s.mu.RLock()
	_, allowed := s.allowedHosts[strings.ToLower(host)]
	s.mu.RUnlock()
	return allowed
}
