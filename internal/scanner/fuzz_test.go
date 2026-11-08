package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// fakeRequester always allows Check and returns a canned 200 response for Do.
type fakeRequester struct {
	resp *http.Response
}

func (f *fakeRequester) Check(ctx context.Context, method, rawURL string, intrusive bool) error {
	return nil
}
func (f *fakeRequester) Do(req *http.Request) (*http.Response, error) {
	return f.resp, nil
}

func TestNewFuzzerValidation(t *testing.T) {
	// nil core.Requester.
	if _, err := NewFuzzer(FuzzConfig{BaseURL: "http://x.test", Paths: []string{"/"}}, nil); err == nil {
		t.Error("NewFuzzer(nil req) = nil error, want error")
	}
	// empty BaseURL.
	if _, err := NewFuzzer(FuzzConfig{Paths: []string{"/"}}, &fakeRequester{}); err == nil {
		t.Error("NewFuzzer(empty BaseURL) = nil error, want error")
	}
	// empty Paths.
	if _, err := NewFuzzer(FuzzConfig{BaseURL: "http://x.test"}, &fakeRequester{}); err == nil {
		t.Error("NewFuzzer(empty Paths) = nil error, want error")
	}
}

func TestLockedRand(t *testing.T) {
	r := newLockedRand(42)
	if r.next() == 0 {
		t.Error("next() = 0, want non-zero (unlikely but possible)")
	}
	if r.intn(0) != 0 {
		t.Errorf("intn(0) = %d, want 0", r.intn(0))
	}
	if r.intn(1) != 0 {
		t.Errorf("intn(1) = %d, want 0", r.intn(1))
	}
	v := r.intn(100)
	if v < 0 || v >= 100 {
		t.Errorf("intn(100) = %d, want [0,100)", v)
	}
}

func TestBinaryLittleEndianUint64(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if got := binaryLittleEndianUint64(b); got != 0x0807060504030201 {
		t.Errorf("binaryLittleEndianUint64 = %#x, want %#x", got, 0x0807060504030201)
	}
}

func TestFuzzerRun(t *testing.T) {
	canned := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}
	req := &fakeRequester{resp: canned}

	f, err := NewFuzzer(FuzzConfig{
		BaseURL:     "http://127.0.0.1:1/",
		Paths:       []string{"/item/{id}"},
		Methods:     []string{"GET"},
		Seed:        1,
		Mutations:   5,
		Concurrency: 2,
		Timeout:     time.Second,
		Intrusive:   false,
	}, req)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}

	res := f.Run(context.Background())
	if res == nil {
		t.Fatal("Run returned nil")
	}
	if res.Sent == 0 {
		t.Error("Sent = 0, want > 0")
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want positive", res.Duration)
	}
}

func TestFuzzerRunIntrusive(t *testing.T) {
	canned := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}
	req := &fakeRequester{resp: canned}

	f, err := NewFuzzer(FuzzConfig{
		BaseURL:     "http://127.0.0.1:1/",
		Paths:       []string{"/item/{id}"},
		Methods:     []string{"GET"},
		Seed:        1,
		Mutations:   5,
		Concurrency: 2,
		Timeout:     time.Second,
		Intrusive:   true,
	}, req)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}

	res := f.Run(context.Background())
	if res == nil {
		t.Fatal("Run returned nil")
	}
}

func TestKey(t *testing.T) {
	if got := key("GET", "/item/{id}"); got != "GET|/item/{id}" {
		t.Errorf("key = %q, want GET|/item/{id}", got)
	}
}

func TestIsInteresting(t *testing.T) {
	base := httpResponseSnapshot{status: 200, bodyLen: 100}
	// Same → not interesting.
	if got := isInteresting(base, base); got {
		t.Error("isInteresting(same) = true, want false")
	}
	// Different status → interesting.
	s := httpResponseSnapshot{status: 201, bodyLen: 100}
	if !isInteresting(s, base) {
		t.Error("isInteresting(diff status) = false, want true")
	}
	// Different bodyLen → interesting.
	s = httpResponseSnapshot{status: 200, bodyLen: 200}
	if !isInteresting(s, base) {
		t.Error("isInteresting(diff bodyLen) = false, want true")
	}
	// 500 → interesting.
	s = httpResponseSnapshot{status: 500, bodyLen: 100}
	if !isInteresting(s, base) {
		t.Error("isInteresting(500) = false, want true")
	}
	// 403 → interesting.
	s = httpResponseSnapshot{status: 403, bodyLen: 100}
	if !isInteresting(s, base) {
		t.Error("isInteresting(403) = false, want true")
	}
	// Slow → interesting.
	s = httpResponseSnapshot{status: 200, bodyLen: 100, duration: 10 * time.Second}
	if !isInteresting(s, base) {
		t.Error("isInteresting(slow) = false, want true")
	}
}

func TestInterestReason(t *testing.T) {
	base := httpResponseSnapshot{status: 200, bodyLen: 100}
	s := httpResponseSnapshot{status: 201, bodyLen: 100}
	got := interestReason(s, base)
	if !strings.Contains(got, "status") {
		t.Errorf("interestReason = %q, want status mention", got)
	}
}

func TestHashBytes(t *testing.T) {
	h1 := hashBytes([]byte("hello"))
	h2 := hashBytes([]byte("hello"))
	if h1 != h2 {
		t.Error("hashBytes not deterministic")
	}
	if len(h1) != 64 {
		t.Errorf("len(hashBytes) = %d, want 64 (hex sha256)", len(h1))
	}
	if got := hashBytes([]byte("")); got == "" {
		t.Error("hashBytes(empty) = empty, want non-empty")
	}
}

func TestSha256Sum(t *testing.T) {
	w := sha256Sum()
	if w == nil {
		t.Fatal("sha256Sum = nil")
	}
	_, err := w.Write([]byte("test"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	sum := w.Sum(nil)
	if len(sum) != 32 {
		t.Errorf("len(Sum) = %d, want 32", len(sum))
	}
}
