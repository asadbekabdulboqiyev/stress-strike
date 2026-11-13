package main

// cli_demo_inproc_test.go — in-process coverage for `Sift demo-store`
// control-plane subcommands (status / stop) and the small URL/banner helpers.
//
// status and stop make HTTP calls to the demo store URL. Pointed at a dead
// loopback port they report "not running" without spawning anything: Status()
// only probes the port, and Stop() is a no-op for a store this process did not
// launch. So these stay hermetic and fast.

import (
	"strings"
	"testing"
)

func TestInprocDemoStoreStatusStop(t *testing.T) {
	// Nothing listens on port 1 — Status reports not running, Stop is a no-op.
	dead := "http://127.0.0.1:1/"

	t.Run("status", func(t *testing.T) {
		res := runCommandFn(t, func() { cmdDemoStoreStatus() }, "demo-store", "status", "--url", dead)
		if res.code != 0 {
			t.Fatalf("demo-store status exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
		}
		if !strings.Contains(res.stdout, "demo-store: "+dead) {
			t.Errorf("stdout = %q, want the status URL", res.stdout)
		}
		if !strings.Contains(res.stdout, "running:    false") {
			t.Errorf("stdout = %q, want running: false", res.stdout)
		}
		if !strings.Contains(res.stdout, "managed:    false") {
			t.Errorf("stdout = %q, want managed: false", res.stdout)
		}
	})

	t.Run("stop", func(t *testing.T) {
		res := runCommandFn(t, func() { cmdDemoStoreStop() }, "demo-store", "stop", "--url", dead)
		if res.code != 0 {
			t.Fatalf("demo-store stop exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
		}
		if !strings.Contains(res.stdout, "no store is listening at "+dead) {
			t.Errorf("stdout = %q, want the 'no store listening' message", res.stdout)
		}
	})
}

func TestInprocDemoStoreStatusJSON(t *testing.T) {
	dead := "http://127.0.0.1:1/"
	res := runCommandFn(t, func() { cmdDemoStoreStatus() }, "demo-store", "status", "--url", dead, "--json")
	if res.code != 0 {
		t.Fatalf("demo-store status --json exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, `"url": `+`"`+dead+`"`) && !strings.Contains(res.stdout, `"url":`+`"`+dead+`"`) {
		t.Errorf("stdout = %q, want JSON with the url", res.stdout)
	}
	if !strings.Contains(res.stdout, `"running": false`) {
		t.Errorf("stdout = %q, want running: false in JSON", res.stdout)
	}
}

func TestInprocDemoStoreListenURL(t *testing.T) {
	cases := []struct {
		listen string
		want   string
	}{
		{"127.0.0.1:8090", "http://127.0.0.1:8090"},
		{":9090", "http://127.0.0.1:9090"},
		{"0.0.0.0:8080", "http://127.0.0.1:8080"},
		{"[::]:443", "http://127.0.0.1:443"},
		{"not-host:port", "http://not-host:port"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.listen, func(t *testing.T) {
			if got := demoListenURL(tc.listen); got != tc.want {
				t.Errorf("demoListenURL(%q) = %q, want %q", tc.listen, got, tc.want)
			}
		})
	}
}

func TestInprocProtectLabel(t *testing.T) {
	if got := protectLabel(true); got != "ON  (rate limit + proof-of-work challenge + IP blocking)" {
		t.Errorf("protectLabel(true) = %q", got)
	}
	if got := protectLabel(false); got != "OFF (open target — enable with -protect)" {
		t.Errorf("protectLabel(false) = %q", got)
	}
}
