package browserload

import (
	"context"
	"testing"
)

func TestRunInvalidURLReturnsError(t *testing.T) {
	r := NewRunner()
	_, err := r.Run(context.Background(), "://not-a-url")
	if err == nil {
		t.Fatal("Run with invalid URL must fail")
	}
}

func TestRunConcurrentZeroRequests(t *testing.T) {
	r := NewRunner()
	results, err := r.RunConcurrent(context.Background(), "https://example.com", 0)
	if err != nil {
		t.Fatalf("RunConcurrent(n=0): %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("len(results) = %d, want 0", len(results))
	}
}
