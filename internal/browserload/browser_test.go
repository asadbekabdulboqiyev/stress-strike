package browserload

import (
	"context"
	"testing"
	"time"
)

func TestRunResultFields(t *testing.T) {
	res := &RunResult{
		URL:        "https://example.com",
		LoadTime:   150 * time.Millisecond,
		DOMContent: 100 * time.Millisecond,
		StatusCode: 200,
		JSErrors:   []string{"ReferenceError: x is not defined"},
	}
	if res.URL != "https://example.com" {
		t.Errorf("url = %q, want https://example.com", res.URL)
	}
	if res.LoadTime != 150*time.Millisecond {
		t.Errorf("load_time = %v, want 150ms", res.LoadTime)
	}
	if res.StatusCode != 200 {
		t.Errorf("status = %d, want 200", res.StatusCode)
	}
	if len(res.JSErrors) != 1 {
		t.Errorf("js_errors = %v, want 1", res.JSErrors)
	}
}

func TestNewRunner(t *testing.T) {
	r := NewRunner()
	if r == nil {
		t.Fatal("NewRunner returned nil")
	}
	if len(r.opts) == 0 {
		t.Error("runner should have chrome options")
	}
}

func TestRunConcurrentEmpty(t *testing.T) {
	r := NewRunner()
	results, err := r.RunConcurrent(context.Background(), "http://example.com", 0)
	if err != nil {
		t.Errorf("RunConcurrent with n=0 returned error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("results = %v, want empty", results)
	}
}
