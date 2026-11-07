package core

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
)

func TestSendProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	resp, err := SendProbe(srv.URL, "GET", "/", nil)
	if err != nil {
		t.Fatalf("SendProbe: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", resp.Header.Get("Content-Type"))
	}
}

func TestSendProbeWithHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "test-value" {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	headers := http.Header{"X-Custom": {"test-value"}}
	resp, err := SendProbe(srv.URL, "GET", "/", headers)
	if err != nil {
		t.Fatalf("SendProbe: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestSendProbeInvalidURL(t *testing.T) {
	_, err := SendProbe("not-a-url", "GET", "/", nil)
	if err == nil {
		t.Error("SendProbe(invalid URL) = nil error, want error")
	}
}

// --- BySeverity (sort.Interface) --------------------------------------------

func TestBySeveritySort(t *testing.T) {
	vulns := []Vuln{
		{Severity: "low"},
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "info"},
		{Severity: "medium"},
	}
	s := BySeverity(vulns)
	sort.Sort(s)
	want := []string{"critical", "high", "medium", "low", "info"}
	for i, v := range s {
		if v.Severity != want[i] {
			t.Errorf("sorted[%d] = %q, want %q", i, v.Severity, want[i])
		}
	}
}
