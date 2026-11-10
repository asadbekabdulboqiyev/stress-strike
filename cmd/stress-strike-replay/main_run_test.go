package main

// main_run_test.go — in-process coverage for the replay CLI entry point.
//
// main() calls os.Exit / log.Fatalf on every failure path, so the harness swaps
// the hooks declared in hooks.go (and cliux.ExitProcess) for sentinel panics.
// Each invocation gets a fresh flag.CommandLine because main() re-registers its
// flags on every call.

import (
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
)

// mainExit is the sentinel panic payload carrying the would-be exit code.
type mainExit struct{ code int }

func runReplayMain(t *testing.T, args ...string) (stdout string, code int) {
	t.Helper()

	prevArgs, prevStdout, prevFS := os.Args, os.Stdout, flag.CommandLine
	prevExit, prevFatal, prevCliExit := exitProcess, fatalf, cliux.ExitProcess
	defer func() {
		os.Args, os.Stdout, flag.CommandLine = prevArgs, prevStdout, prevFS
		exitProcess, fatalf, cliux.ExitProcess = prevExit, prevFatal, prevCliExit
	}()

	flag.CommandLine = flag.NewFlagSet("stress-strike-replay", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	f, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatalf("temp stdout: %v", err)
	}
	os.Stdout = f

	os.Args = append([]string{"stress-strike-replay"}, args...)
	exitProcess = func(c int) { panic(mainExit{c}) }
	cliux.ExitProcess = func(c int) { panic(mainExit{c}) }
	fatalf = func(format string, v ...any) { panic(mainExit{1}) }

	func() {
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
	}()

	if err := f.Sync(); err != nil {
		t.Fatalf("sync stdout: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek stdout: %v", err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	_ = f.Close()
	return string(b), code
}

func TestReplayMainHelp(t *testing.T) {
	if _, code := runReplayMain(t, "--help"); code != 0 {
		t.Errorf("--help exit = %d, want 0", code)
	}
}

func TestReplayMainMissingInput(t *testing.T) {
	if _, code := runReplayMain(t); code != 1 {
		t.Errorf("no args exit = %d, want 1", code)
	}
}

func TestReplayMainFlagErrors(t *testing.T) {
	cases := map[string][]string{
		"bad rate":      {"-input", "x.har", "-rate", "fast"},
		"bad pace":      {"-input", "x.har", "-pace", "warp"},
		"rps without":   {"-input", "x.har", "-pace", "rps"},
		"bad duration":  {"-input", "x.har", "-duration", "soon"},
		"missing keys":  {"-input", "x.har", "-tls-key", "/nope/key", "-tls-cert", "/nope/cert"},
		"bad extension": {"-input", "capture.txt"},
		"missing file":  {"-input", filepath.Join(t.TempDir(), "absent.har")},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, code := runReplayMain(t, args...); code != 1 {
				t.Errorf("%v exit = %d, want 1", args, code)
			}
		})
	}
}

const replayHAR = `{
  "log": {
    "version": "1.2",
    "creator": {"name": "test", "version": "1.0"},
    "entries": [
      {
        "startedDateTime": "2025-01-15T10:30:00.000Z",
        "time": 10.0,
        "request": {
          "method": "GET",
          "url": "https://example.com/api/one",
          "headers": [{"name": "Accept", "value": "application/json"}],
          "queryString": []
        },
        "response": {
          "status": 200,
          "headers": [{"name": "Content-Type", "value": "application/json"}],
          "content": {"size": 2, "mimeType": "application/json", "text": "ok"}
        }
      },
      {
        "startedDateTime": "2025-01-15T10:30:00.100Z",
        "time": 12.0,
        "request": {
          "method": "POST",
          "url": "https://example.com/api/two",
          "headers": [{"name": "Content-Type", "value": "application/json"}],
          "queryString": [],
          "postData": {"mimeType": "application/json", "text": "{\"a\":1}"}
        },
        "response": {
          "status": 201,
          "headers": [],
          "content": {"size": 2, "mimeType": "text/plain", "text": "ok"}
        }
      }
    ]
  }
}`

func TestReplayMainFullRun(t *testing.T) {
	var got atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	dir := t.TempDir()
	harPath := filepath.Join(dir, "traffic.har")
	if err := os.WriteFile(harPath, []byte(replayHAR), 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := runReplayMain(t,
		"-input", harPath,
		"-pace", "legacy",
		"-rate", "100x",
		"-concurrency", "2",
		"-duration", "30s",
		"-base-url", target.URL,
		"-skip-tls-verify",
		"-follow-redirects",
		"-validate",
		"-assert-status", "200",
		"-assert-regex", "ok",
		"-methods", "GET,POST",
		"-url-pattern", "*",
		"-status", "200,201",
		"-output-json", "replay.json",
		"-output-csv", "latency.csv",
		"-report-dir", dir,
	)
	if code != 0 {
		t.Fatalf("full run exit = %d, want 0\n%s", code, out)
	}
	for _, want := range []string{
		"Loading capture...",
		"Loading HAR:",
		"Loaded 2 packets",
		"Filtered: 2 → 2 packets",
		"REPLAY COMPLETE",
		"JSON report:",
		"CSV report:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if n := got.Load(); n < 2 {
		t.Errorf("target saw %d requests, want at least 2", n)
	}
	for _, name := range []string{"replay.json", "latency.csv"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
}

func TestReplayMainFilterDropsEverything(t *testing.T) {
	dir := t.TempDir()
	harPath := filepath.Join(dir, "traffic.har")
	if err := os.WriteFile(harPath, []byte(replayHAR), 0o644); err != nil {
		t.Fatal(err)
	}

	// DELETE matches nothing: the run must report a filter-empty failure.
	if _, code := runReplayMain(t,
		"-input", harPath,
		"-pace", "legacy",
		"-rate", "100x",
		"-methods", "DELETE",
		"-duration", "5s",
	); code != 1 {
		t.Errorf("empty filter exit = %d, want 1", code)
	}
}
