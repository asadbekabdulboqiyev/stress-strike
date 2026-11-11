package main

// main_entry_test.go — in-process coverage for the master CLI entry point.
//
// main() exits through log.Fatal / os.Exit on its failure paths, so the hooks in
// hooks.go (and cliux.ExitProcess) are swapped for sentinel panics. The master's
// flags are package-level bindings to flag.CommandLine, so instead of replacing
// the FlagSet each run resets every flag to its default and parses fresh args.

import (
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
)

// mainExit is the sentinel panic payload carrying the would-be exit code.
type mainExit struct{ code int }

func resetMasterFlags(t *testing.T) {
	t.Helper()
	// Only the master's flags need a reset. The test binary's own flags must be
	// left alone: re-setting test.paniconexit0 from its DefValue (false) makes
	// testing.M.after() skip restoring the os.Exit(0) guard, which then panics
	// at the end of the run.
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "test.") {
			return
		}
		_ = f.Value.Set(f.DefValue)
	})
}

func runMasterMain(t *testing.T, args ...string) (code int) {
	t.Helper()

	prevArgs := os.Args
	prevExit, prevFatal, prevFatalf, prevCliExit := exitProcess, fatal, fatalf, cliux.ExitProcess
	defer func() {
		os.Args = prevArgs
		exitProcess, fatal, fatalf, cliux.ExitProcess = prevExit, prevFatal, prevFatalf, prevCliExit
	}()

	resetMasterFlags(t)
	os.Args = append([]string{"stress-strike-master"}, args...)
	exitProcess = func(c int) { panic(mainExit{c}) }
	cliux.ExitProcess = func(c int) { panic(mainExit{c}) }
	fatal = func(v ...any) { panic(mainExit{1}) }
	fatalf = func(format string, v ...any) { panic(mainExit{1}) }

	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(mainExit); ok {
				code = e.code
				return
			}
			panic(r)
		}
	}()
	main()
	return 0
}

func TestMasterMainHealthcheck(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"usage", []string{"healthcheck", "-bogus"}, 2},
		{"unreachable", []string{"healthcheck", "-addr", "http://127.0.0.1:1/healthz"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runMasterMain(t, tc.args...); got != tc.want {
				t.Errorf("exit = %d, want %d", got, tc.want)
			}
		})
	}

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	if got := runMasterMain(t, "healthcheck", "-addr", ok.URL); got != 0 {
		t.Errorf("healthy exit = %d, want 0", got)
	}
}

func TestMasterMainUsageErrors(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	cases := map[string][]string{
		"no target or config": {},
		"no workers":          {"-url", "http://127.0.0.1:1"},
		"missing config":      {"-config", "/nonexistent/scenario.yaml", "-workers", "127.0.0.1:1"},
		"bad fingerprint":     {"-url", "http://127.0.0.1:1", "-workers", "127.0.0.1:1", "-tls-fingerprint", "netscape"},
		"bad authorized key":  {"-url", "http://127.0.0.1:1", "-workers", "127.0.0.1:1", "-authorized-keys", "worker1=zzzz"},
		"listen unavailable":  {"-url", "http://127.0.0.1:1", "-workers", "127.0.0.1:1", "-listen", occupied.Addr().String(), "-http-addr", ""},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if got := runMasterMain(t, args...); got != 1 {
				t.Errorf("%v exit = %d, want 1", args, got)
			}
		})
	}
}

func TestMasterMainHelp(t *testing.T) {
	if got := runMasterMain(t, "--help"); got != 0 {
		t.Errorf("--help exit = %d, want 0", got)
	}
}

// TestMasterMainReachesWorkerConnect drives main() past setup and into the
// static-fleet dial step: one connection attempt to a dead loopback port with a
// short run timeout, which ends in the "Failed to connect" fatal path.
func TestMasterMainReachesWorkerConnect(t *testing.T) {
	// The dead port is held for the whole test by a listener that accepts and
	// resets each connection. Closing the listener and using the freed port
	// number would race with any other program on the host that binds
	// ephemeral ports.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	go func() {
		for {
			c, err := dead.Accept()
			if err != nil {
				return
			}
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = dead.Close() })

	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := listen.Addr().String()
	_ = listen.Close()

	done := make(chan int, 1)
	go func() {
		done <- runMasterMain(t,
			"-url", "http://127.0.0.1:1",
			"-workers", deadAddr,
			"-listen", listenAddr,
			"-http-addr", "",
			"-quiet",
			"-run-timeout", "2",
		)
	}()
	select {
	case code := <-done:
		if code != 1 {
			t.Errorf("exit = %d, want 1 (worker connect failure)", code)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("master main did not finish within 60s")
	}
}
