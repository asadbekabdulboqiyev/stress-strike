package browserload

// jserrors.go — collecting the page's own complaints.
//
// A page that renders but throws is a failed load test: the operator wants to
// know the SPA raised "TypeError: cannot read properties of undefined", not
// just that the document arrived. The CDP event listener below is called from
// chromedp's event goroutine, so every mutation of the log is behind the lock
// and the caller always gets a copy.
//
// The logic lives here rather than inline in Run so it can be tested without a
// browser: an event with a nil ExceptionDetails is exactly the shape that used
// to panic the listener.

import (
	"sync"

	jsonv2 "github.com/chromedp/cdproto/cdp/jsonv2"
	"github.com/chromedp/cdproto/runtime"
)

// jsErrorLog accumulates console errors and uncaught exceptions from one page
// load. The zero value is ready to use.
type jsErrorLog struct {
	mu     sync.Mutex
	errors []string
}

// handle consumes one CDP event. Anything that is not a JS error is ignored:
// this listener is registered for the whole session and receives every event.
//
// It must never panic. A malformed event from a hostile page would otherwise
// take down the load test process, and the page is the thing under test.
func (l *jsErrorLog) handle(ev interface{}) {
	switch e := ev.(type) {
	case *runtime.EventConsoleAPICalled:
		if e == nil || e.Type != "error" {
			return
		}
		var msgs []string
		for _, a := range e.Args {
			msgs = append(msgs, consoleArgText(a.Value))
		}
		l.mu.Lock()
		l.errors = append(l.errors, msgs...)
		l.mu.Unlock()

	case *runtime.EventExceptionThrown:
		if e == nil {
			return
		}
		text := "exception"
		if e.ExceptionDetails != nil {
			if e.ExceptionDetails.Text != "" {
				text = "exception: " + e.ExceptionDetails.Text
			}
			if d := e.ExceptionDetails.Exception; d != nil && d.Description != "" {
				text += " — " + d.Description
			}
		}
		l.mu.Lock()
		l.errors = append(l.errors, text)
		l.mu.Unlock()
	}
}

// consoleArgText renders one console argument the way a reader expects to see
// it. A JSON string loses its quotes; everything else keeps its JSON shape.
func consoleArgText(raw jsonv2.Value) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := jsonv2.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// snapshot returns a copy of the collected errors, or nil when there are none.
// Invariant: the returned slice is never the live slice.
func (l *jsErrorLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.errors) == 0 {
		return nil
	}
	return append([]string(nil), l.errors...)
}

// len reports how many errors have been collected so far.
func (l *jsErrorLog) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.errors)
}
