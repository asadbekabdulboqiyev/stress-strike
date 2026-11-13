package main

import "testing"

// TestDemoListenURL covers the -addr normalization shared by the readiness
// probe and the banner. A bare port or a wildcard host must be rewritten to
// loopback so both the probe and a browser actually work.
func TestDemoListenURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"127.0.0.1:8090", "http://127.0.0.1:8090"},
		{":9090", "http://127.0.0.1:9090"},
		{"0.0.0.0:9090", "http://127.0.0.1:9090"},
		{"[::]:9090", "http://127.0.0.1:9090"},
		{"localhost:8080", "http://localhost:8080"},
		{"192.168.1.5:7070", "http://192.168.1.5:7070"}, // explicit LAN addr kept
		{"not-an-addr", "http://not-an-addr"},           // spawn fails later; URL mirrors input
	}
	for _, c := range cases {
		if got := demoListenURL(c.in); got != c.want {
			t.Errorf("demoListenURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestProtectLabel sanity-checks the two banner states.
func TestProtectLabel(t *testing.T) {
	if got := protectLabel(true); got == "" || got[0] != 'O' {
		t.Errorf("protectLabel(true) = %q, want an ON label", got)
	}
	if got := protectLabel(false); got == "" {
		t.Errorf("protectLabel(false) = %q, want an OFF label", got)
	}
}
