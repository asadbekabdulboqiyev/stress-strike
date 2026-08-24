package engine

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"stress-strike/internal/config"
)

func TestRunWithTypedNilCaptureDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "typed-nil-capture",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    1,
			Duration: 1,
			Timeout:  2,
		},
		Steps: []config.Step{{Name: "health", Method: "GET", URL: srv.URL}},
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	var typedNil *BufferCapture
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := eng.Run(ctx, RunOptions{Quiet: true, Capture: typedNil}); err != nil {
		t.Fatalf("run with typed-nil capture failed: %v", err)
	}
}

func TestBufferCaptureCapsEntries(t *testing.T) {
	b := NewBufferCapture(3, DefaultCaptureBodyBytes)
	for i := 0; i < 6; i++ {
		b.Record(CapturedResponse{Method: "GET", URL: "http://x", Status: 200, Body: []byte("ok")})
	}
	kept, dropped := b.Count()
	if kept != 3 {
		t.Errorf("kept = %d, want 3", kept)
	}
	if dropped != 3 {
		t.Errorf("dropped = %d, want 3", dropped)
	}
}

func TestBufferCaptureTruncatesBody(t *testing.T) {
	const bodyCap = 16
	b := NewBufferCapture(10, bodyCap)
	payload := strings.Repeat("A", 500)
	b.Record(CapturedResponse{Status: 200, Body: []byte(payload)})

	var out bytes.Buffer
	if err := b.Render(&out); err != nil {
		t.Fatal(err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "16 bytes") {
		t.Errorf("expected truncated size note, got:\n%s", rendered)
	}
	if strings.Count(rendered, "A") > bodyCap {
		t.Error("body not truncated")
	}
}

func TestBufferCaptureBinaryBody(t *testing.T) {
	b := NewBufferCapture(1, 64)
	b.Record(CapturedResponse{Status: 200, Body: []byte{0xff, 0xfe, 0x00}})

	var out bytes.Buffer
	if err := b.Render(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "<binary 3 bytes>") {
		t.Errorf("binary marker missing:\n%s", out.String())
	}
}

func TestEngineRunWithCapture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("health-ok-body"))
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "capture-test",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    2,
			Duration: 1,
			Timeout:  2,
		},
		Steps: []config.Step{{Name: "health", Method: "GET", URL: srv.URL + "/health"}},
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	sink := NewBufferCapture(5, 1024)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := eng.Run(ctx, RunOptions{Quiet: true, Capture: sink}); err != nil {
		t.Fatal(err)
	}

	kept, _ := sink.Count()
	if kept == 0 {
		t.Fatal("expected at least one captured response")
	}

	var out bytes.Buffer
	if err := sink.Render(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "health-ok-body") {
		t.Errorf("captured body missing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "step=health") {
		t.Errorf("step name missing:\n%s", out.String())
	}
}

func TestClassifyUnsupportedSchemeIsNotConnectionError(t *testing.T) {
	uerr := &url.Error{
		Op:  "Get",
		URL: "localhost:9000",
		Err: errors.New(`unsupported protocol scheme ""`),
	}
	res := classifyError(uerr, 0)
	if res.errName != errOther {
		t.Errorf("errName = %q, want %q", res.errName, errOther)
	}

	connRefused := &url.Error{Op: "Get", URL: "http://x", Err: &net.OpError{
		Op:  "dial",
		Err: syscall.ECONNREFUSED,
	}}
	res = classifyError(connRefused, 0)
	if res.errName != errConnection {
		t.Errorf("errName = %q, want %q", res.errName, errConnection)
	}
}
