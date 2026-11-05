package scanner

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type fakeRequesterForFuzz struct {
	allowErr error
	doResp   *http.Response
	doErr    error
}

func (f *fakeRequesterForFuzz) Check(ctx context.Context, method, rawURL string, intrusive bool) error {
	return f.allowErr
}

func (f *fakeRequesterForFuzz) Do(req *http.Request) (*http.Response, error) {
	if f.doResp != nil {
		return f.doResp, nil
	}
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     make(http.Header),
		Body:       http.NoBody,
	}, f.doErr
}

func TestNewFuzzerSuccess(t *testing.T) {
	cfg := FuzzConfig{
		BaseURL:    "http://example.com",
		Paths:      []string{"/api/{id}"},
		Methods:    []string{"GET"},
		Seed:       42,
		Mutations:  10,
		Concurrency: 1,
		Timeout:    5 * time.Second,
	}
	fz, err := NewFuzzer(cfg, &fakeRequesterForFuzz{})
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	if fz == nil {
		t.Fatal("NewFuzzer returned nil")
	}
}

func TestNewFuzzerNilRequester(t *testing.T) {
	cfg := FuzzConfig{
		BaseURL:   "http://example.com",
		Paths:     []string{"/api/{id}"},
		Mutations: 10,
	}
	_, err := NewFuzzer(cfg, nil)
	if err == nil {
		t.Fatal("expected error for nil Requester")
	}
}

func TestNewFuzzerEmptyBaseURL(t *testing.T) {
	cfg := FuzzConfig{
		Paths:     []string{"/api/{id}"},
		Mutations: 10,
	}
	_, err := NewFuzzer(cfg, &fakeRequesterForFuzz{})
	if err == nil {
		t.Fatal("expected error for empty BaseURL")
	}
}

func TestNewFuzzerNoPaths(t *testing.T) {
	cfg := FuzzConfig{
		BaseURL:  "http://example.com",
		Mutations: 10,
	}
	_, err := NewFuzzer(cfg, &fakeRequesterForFuzz{})
	if err == nil {
		t.Fatal("expected error for no paths")
	}
}

func TestFuzzResultFields(t *testing.T) {
	fr := FuzzResult{
		BaseURL:     "http://example.com",
		Seed:        42,
		Sent:        10,
		Refused:     0,
		Interesting: 2,
		Findings:    []FuzzFinding{},
		Duration:    time.Second,
	}
	if fr.BaseURL != "http://example.com" {
		t.Errorf("baseURL = %q, want http://example.com", fr.BaseURL)
	}
	if fr.Seed != 42 {
		t.Errorf("seed = %d, want 42", fr.Seed)
	}
	if fr.Sent != 10 {
		t.Errorf("sent = %d, want 10", fr.Sent)
	}
	if fr.Interesting != 2 {
		t.Errorf("interesting = %d, want 2", fr.Interesting)
	}
}

func TestFuzzFindingFields(t *testing.T) {
	f := FuzzFinding{
		Method:       "GET",
		URL:          "/api/1",
		StatusCode:   200,
		BodyLen:      100,
		BodyHash:     "abc123",
		Headers:      []string{"X-Custom: value"},
		Mutation:     "path_param",
		Reason:       "status code differed from baseline",
		ResponseTime: 50 * time.Millisecond,
	}
	if f.Method != "GET" {
		t.Errorf("method = %q, want GET", f.Method)
	}
	if f.StatusCode != 200 {
		t.Errorf("status = %d, want 200", f.StatusCode)
	}
}
