package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := Run(ctx, Config{
		URL:      srv.URL,
		Users:    5,
		Duration: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalRequests == 0 {
		t.Error("no requests recorded")
	}
	if res.StatusCodes[200] == 0 {
		t.Errorf("expected 200 status codes, got %v", res.StatusCodes)
	}
	if len(res.Errors) != 0 {
		t.Errorf("unexpected errors: %v", res.Errors)
	}
}

func TestRunInvalidConfig(t *testing.T) {
	if _, err := Run(context.Background(), Config{URL: ""}); err == nil {
		t.Error("expected error for empty URL")
	}
}
