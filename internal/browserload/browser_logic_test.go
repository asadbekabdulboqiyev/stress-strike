package browserload

// browser_logic_test.go — the parts of browser load testing that do not need
// a browser.
//
// Run() itself needs a real Chromium, so its path is exercised by the e2e job.
// What is testable in-process is the logic around it: URL normalisation, the
// JS error collector, and the concurrency contract of RunConcurrent. That
// contract had a real data race — one failing tab returned the results slice
// while the other tabs were still writing into it.

import (
	"context"
	"strings"
	"testing"
	"time"

	jsonv2 "github.com/chromedp/cdproto/cdp/jsonv2"
	"github.com/chromedp/cdproto/runtime"
)

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"example.com", "https://example.com", false},
		{"example.com/path?q=1", "https://example.com/path?q=1", false},
		{"https://example.com/a", "https://example.com/a", false},
		{"http://127.0.0.1:8080/health", "http://127.0.0.1:8080/health", false},
		{"://bad", "", true},
		{"http://[::1", "", true},
	}

	for _, c := range cases {
		got, err := normalizeURL(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normalizeURL(%q) = %q, want an error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeURL(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestNormalizeURLDoesNotRewriteAnExplicitScheme: an operator who wrote
// http:// must not be silently upgraded to https://.
func TestNormalizeURLDoesNotRewriteAnExplicitScheme(t *testing.T) {
	got, err := normalizeURL("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "http://") {
		t.Fatalf("normalizeURL rewrote the scheme: %q", got)
	}
}

func jsonValue(t *testing.T, s string) jsonv2.Value {
	t.Helper()
	v, err := jsonv2.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestJSErrorLogConsoleErrors(t *testing.T) {
	var log jsErrorLog

	log.handle(&runtime.EventConsoleAPICalled{
		Type: runtime.ConsoleAPICalledTypeError,
		Args: []*runtime.RemoteObject{
			{Value: jsonValue(t, "ReferenceError: x is not defined")},
			{Value: jsonv2.Value(`42`)},
		},
	})

	got := log.snapshot()
	if len(got) != 2 {
		t.Fatalf("errors = %v, want 2 entries", got)
	}
	if got[0] != "ReferenceError: x is not defined" {
		t.Errorf("string arg = %q, want the decoded text without JSON quotes", got[0])
	}
	if got[1] != "42" {
		t.Errorf("non-string arg = %q, want its JSON text", got[1])
	}
}

// TestJSErrorLogIgnoresNonErrors keeps warnings and logs out of the report: a
// console.log is not a load-test failure.
func TestJSErrorLogIgnoresNonErrors(t *testing.T) {
	var log jsErrorLog
	for _, typ := range []runtime.ConsoleAPICalledType{
		runtime.ConsoleAPICalledTypeLog,
		runtime.ConsoleAPICalledTypeWarning,
		runtime.ConsoleAPICalledTypeInfo,
		runtime.ConsoleAPICalledTypeDebug,
	} {
		log.handle(&runtime.EventConsoleAPICalled{
			Type: typ,
			Args: []*runtime.RemoteObject{{Value: jsonValue(t, "noise")}},
		})
	}
	if got := log.snapshot(); got != nil {
		t.Fatalf("errors = %v, want nil for non-error console calls", got)
	}
}

// TestJSErrorLogExceptionWithoutDetails covers the shape that used to panic:
// an exception event whose details are missing.
func TestJSErrorLogExceptionWithoutDetails(t *testing.T) {
	var log jsErrorLog

	log.handle(&runtime.EventExceptionThrown{ExceptionDetails: nil})
	log.handle((*runtime.EventExceptionThrown)(nil))

	got := log.snapshot()
	if len(got) != 1 {
		t.Fatalf("errors = %v, want exactly one entry for the non-nil event", got)
	}
	if got[0] != "exception" {
		t.Errorf("entry = %q, want the generic \"exception\"", got[0])
	}
}

func TestJSErrorLogExceptionWithTextAndDescription(t *testing.T) {
	var log jsErrorLog
	log.handle(&runtime.EventExceptionThrown{
		ExceptionDetails: &runtime.ExceptionDetails{
			Text:      "Uncaught",
			Exception: &runtime.RemoteObject{Description: "TypeError: boom"},
		},
	})

	got := log.snapshot()
	if len(got) != 1 {
		t.Fatalf("errors = %v, want one entry", got)
	}
	for _, want := range []string{"exception: Uncaught", "TypeError: boom"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("entry %q missing %q", got[0], want)
		}
	}
}

// TestJSErrorLogIgnoresOtherEvents: the listener receives every CDP event.
func TestJSErrorLogIgnoresOtherEvents(t *testing.T) {
	var log jsErrorLog
	log.handle(&runtime.EventExecutionContextCreated{})
	log.handle(nil)
	log.handle("not an event")

	if got := log.snapshot(); got != nil {
		t.Fatalf("errors = %v, want nil", got)
	}
}

// TestJSErrorLogSnapshotIsACopy protects the caller from the event goroutine
// appending to the slice it is reading.
func TestJSErrorLogSnapshotIsACopy(t *testing.T) {
	var log jsErrorLog
	log.handle(&runtime.EventConsoleAPICalled{
		Type: runtime.ConsoleAPICalledTypeError,
		Args: []*runtime.RemoteObject{{Value: jsonValue(t, "first")}},
	})

	first := log.snapshot()
	if len(first) != 1 {
		t.Fatalf("snapshot = %v, want one entry", first)
	}

	log.handle(&runtime.EventConsoleAPICalled{
		Type: runtime.ConsoleAPICalledTypeError,
		Args: []*runtime.RemoteObject{{Value: jsonValue(t, "second")}},
	})

	if len(first) != 1 {
		t.Fatalf("an earlier snapshot grew to %d entries; it must be a copy", len(first))
	}
	if log.len() != 2 {
		t.Errorf("len() = %d, want 2", log.len())
	}
}

// TestJSErrorLogConcurrentAppends runs the race detector over the lock: the
// listener is called from chromedp's event goroutine while the caller is
// snapshotting.
func TestJSErrorLogConcurrentAppends(t *testing.T) {
	var log jsErrorLog
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			log.handle(&runtime.EventConsoleAPICalled{
				Type: runtime.ConsoleAPICalledTypeError,
				Args: []*runtime.RemoteObject{{Value: jsonValue(t, "boom")}},
			})
		}
	}()

	for i := 0; i < 200; i++ {
		_ = log.snapshot()
		_ = log.len()
	}
	<-done

	if got := log.len(); got != 200 {
		t.Errorf("len() = %d, want 200", got)
	}
}

// TestRunConcurrentRejectsNegativeN: from a flag or a formula, n can be
// negative; make() would panic.
func TestRunConcurrentRejectsNegativeN(t *testing.T) {
	r := NewRunner()
	if _, err := r.RunConcurrent(context.Background(), "example.com", -1); err == nil {
		t.Fatal("RunConcurrent(n=-1) must return an error, not panic")
	}
}

// TestRunConcurrentEmptyIsNonNil keeps the JSON shape stable: an empty slice
// encodes as [] rather than null.
func TestRunConcurrentEmptyIsNonNil(t *testing.T) {
	r := NewRunner()
	results, err := r.RunConcurrent(context.Background(), "example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	if results == nil || len(results) != 0 {
		t.Fatalf("results = %v, want an empty non-nil slice", results)
	}
}

// TestRunConcurrentWaitsForEveryTab is the regression test for the race: with
// an invalid URL every tab fails immediately, and RunConcurrent must still
// return only after all of them have written their slot.
func TestRunConcurrentWaitsForEveryTab(t *testing.T) {
	r := NewRunner()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := r.RunConcurrent(ctx, "://invalid", 4)
	if err == nil {
		t.Fatal("RunConcurrent with an invalid URL must report an error")
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want one slot per requested tab", len(results))
	}
}
