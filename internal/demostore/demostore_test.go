package demostore

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// --- Unit tests --------------------------------------------------------------

// TestDefaultURL sanity anchor for the control surface.
func TestDefaultURL(t *testing.T) {
	if DefaultURL != "http://127.0.0.1:8090" {
		t.Errorf("DefaultURL = %q", DefaultURL)
	}
}

// TestHasProtect covers the VeriGate flag detection used by Status.
func TestHasProtect(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"-addr=127.0.0.1:8090"}, false},
		{[]string{"-protect"}, true},
		{[]string{"-addr=x", "-protect"}, true},
		{[]string{"-protect=true", "-addr=x"}, true},
		{[]string{"-protect=false"}, true}, // flag present -> report ON intent
	} {
		if got := hasProtect(tc.args); got != tc.want {
			t.Errorf("hasProtect(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// TestFindUp walks upward from the working directory; in a checkout it must
// locate go.mod at the repo root, indexed relative to any nested package dir.
func TestFindUp(t *testing.T) {
	p := findUp("go.mod")
	if p == "" {
		t.Skip("no go.mod found above the working directory (not a checkout)")
	}
	base := filepath.Base(p)
	if base != "go.mod" {
		t.Errorf("findUp returned %q, want a path ending in go.mod", p)
	}
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		t.Errorf("findUp(%q) = %q is not a file (err=%v)", "go.mod", p, err)
	}
}

// TestLocateGORunFallbackFromNestedDir is the regression for the go.mod path
// bug: findUp("go.mod") returns the FILE path, so the go run fallback must
// join the examples dir against the checkout root (the file's parent), not
// against the file itself (which yielded
// "<repo>/go.mod/examples/demo_store" — not a directory).
func TestLocateGORunFallbackFromNestedDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "examples", "demo_store"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fake\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "internal", "dashboard")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(nested)

	d := New(Options{})
	bin, extra, err := d.locate()
	if err != nil {
		t.Fatalf("locate: %v", err)
	}
	if filepath.Base(bin) != "go" {
		t.Errorf("bin = %q, want the go binary", bin)
	}
	if len(extra) != 2 || extra[0] != "run" {
		t.Fatalf("extra = %v, want [run <checkout>/examples/demo_store]", extra)
	}
	want := filepath.Join(root, "examples", "demo_store")
	if extra[1] != want {
		t.Errorf("run target = %q, want %q", extra[1], want)
	}
}

// --- Lifecycle integration tests ---------------------------------------------

// helperPort extracts the port (after "--") from a re-exec'd test binary's
// args; the parent tests spawn this test binary as a fake store.
func helperPort() string {
	args := os.Args
	for i, a := range args {
		if a == "--" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// TestHelperServer is a re-exec helper: when launched by a parent test (via
// locateOverride), it plays the role of the demo store by listening on the
// port passed after "--" until it is killed. In a normal suite run it has
// nothing to do and returns immediately.
func TestHelperServer(t *testing.T) {
	port := helperPort()
	if port == "" {
		return
	}
	srv := &http.Server{
		Addr: "127.0.0.1:" + port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("helper store"))
		}),
	}
	_ = srv.ListenAndServe() // blocks until the parent kills this process
}

// freePort reserves and releases an ephemeral port for the fake store.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// newFakeStore returns a DemoStore that spawns this test binary (re-exec) as
// the fake store listening on a free ephemeral port.
func newFakeStore(t *testing.T) *DemoStore {
	t.Helper()
	port := freePort(t)
	d := New(Options{
		URL:       fmt.Sprintf("http://127.0.0.1:%d", port),
		ExtraArgs: []string{"-protect"}, // exercise protection detection
	})
	d.locateOverride = func() (string, []string, error) {
		return os.Args[0], []string{"-test.run=TestHelperServer", "--", strconv.Itoa(port)}, nil
	}
	t.Cleanup(func() { _ = d.Stop() })
	return d
}

// TestStartSpawnsAndStopReaps drives the full supervised lifecycle:
// spawn -> ready -> managed -> stop -> process gone.
func TestStartSpawnsAndStopReaps(t *testing.T) {
	d := newFakeStore(t)

	url, already, err := d.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if already {
		t.Error("Start reported already_running for a fresh spawn")
	}
	if url != d.url {
		t.Errorf("Start url = %q, want %q", url, d.url)
	}
	st := d.Status()
	if st["running"] != true || st["managed"] != true || st["protection"] != true {
		t.Errorf("after Start, status = %v, want running+managed+protection", st)
	}

	if err := d.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if d.Running() {
		t.Error("store still listening after Stop")
	}
	st = d.Status()
	if st["running"] != false || st["managed"] != false {
		t.Errorf("after Stop, status = %v, want running=false managed=false", st)
	}
}

// TestStopStartRapidSpawn is the regression for the Stop->Start supervision
// race: a Stop that only sent SIGKILL and returned immediately let the next
// Start adopt the dying process as "already running", so the caller lost the
// ability to stop the store it had spawned. Stop must block until the
// process is gone.
func TestStopStartRapidSpawn(t *testing.T) {
	d := newFakeStore(t)

	for i := 0; i < 5; i++ {
		_, _, err := d.Start()
		if err != nil {
			t.Fatalf("cycle %d Start: %v", i, err)
		}
		if err := d.Stop(); err != nil {
			t.Fatalf("cycle %d Stop: %v", i, err)
		}
		// The next Start must spawn a brand-new, managed process: if the
		// old one were still draining, Start would adopt it unmanaged.
		_, _, err = d.Start()
		if err != nil {
			t.Fatalf("cycle %d restart Start: %v", i, err)
		}
		st := d.Status()
		if st["managed"] != true {
			t.Fatalf("cycle %d restart: status = %v, want managed=true (lost supervision)", i, st)
		}
	}
}

// TestStartAdoptsExternalStore: a store already listening on the address
// (started outside the caller) is adopted as running but never managed —
// Stop must leave it untouched.
func TestStartAdoptsExternalStore(t *testing.T) {
	port := freePort(t)
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	d := New(Options{URL: fmt.Sprintf("http://127.0.0.1:%d", port)})

	url, already, err := d.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !already {
		t.Error("Start did not report already_running for an existing listener")
	}
	if url != d.url {
		t.Errorf("url = %q, want %q", url, d.url)
	}
	st := d.Status()
	if st["running"] != true {
		t.Errorf("status = %v, want running=true", st)
	}
	if st["managed"] != false {
		t.Errorf("status = %v, want managed=false for an external store", st)
	}

	if err := d.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !d.Running() {
		t.Error("Stop killed a store it did not spawn")
	}
}

// TestDoneSignalsProcessExit: the Done channel must close when a spawned
// process exits, so a foreground caller (CLI) can notice a crash.
func TestDoneSignalsProcessExit(t *testing.T) {
	d := newFakeStore(t)
	if _, _, err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	done := d.Done()
	if err := d.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case <-done:
		// expected: process exited
	default:
		t.Error("Done channel not closed after process exit")
	}
}
