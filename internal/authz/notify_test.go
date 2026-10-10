package authz

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sampleEntry() Entry {
	return Entry{
		Seq:     7,
		Time:    time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
		Actor:   "ci",
		Action:  "pentest",
		Targets: []string{"https://shop.example.com"},
		Class:   "public",
		Allowed: false,
		Reason:  "no authorization",
	}
}

func TestNotifierJSONPostsEntry(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := (Notifier{URL: srv.URL}).Notify(context.Background(), sampleEntry()); err != nil {
		t.Fatal(err)
	}

	var decoded Entry
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("body is not the entry JSON: %v (%s)", err, got)
	}
	if decoded.Action != "pentest" || decoded.Allowed {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestNotifierSlackFormat(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	if err := (Notifier{URL: srv.URL, Format: "slack"}).Notify(context.Background(), sampleEntry()); err != nil {
		t.Fatal(err)
	}

	var payload map[string]string
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatalf("not a slack payload: %v", err)
	}
	text := payload["text"]
	if !strings.Contains(text, "BLOCKED") || !strings.Contains(text, "shop.example.com") {
		t.Fatalf("slack text = %q", text)
	}
}

func TestNotifierDisabledIsNoop(t *testing.T) {
	if err := (Notifier{}).Notify(context.Background(), sampleEntry()); err != nil {
		t.Fatalf("disabled notifier returned %v", err)
	}
}

func TestNotifierReportsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := Notifier{URL: srv.URL}.Notify(context.Background(), sampleEntry())
	if err == nil {
		t.Fatal("expected an error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v", err)
	}
}

func TestNotifierUnknownFormat(t *testing.T) {
	if err := (Notifier{URL: "http://x", Format: "xml"}).Notify(context.Background(), sampleEntry()); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}
