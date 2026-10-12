package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCheckNoChecks(t *testing.T) {
	res := NewChecker().Check(context.Background())
	if res.Status != StatusOK {
		t.Fatalf("status = %q, want %q", res.Status, StatusOK)
	}
	if res.Checks == nil {
		t.Fatal("Checks is nil; want non-nil empty map")
	}
	if len(res.Checks) != 0 {
		t.Fatalf("Checks = %v, want empty", res.Checks)
	}
}

func TestCheckAllPass(t *testing.T) {
	c := NewChecker()
	c.Register("db", func(ctx context.Context) error { return nil })
	c.Register("cache", func(ctx context.Context) error { return nil })

	res := c.Check(context.Background())
	if res.Status != StatusOK {
		t.Fatalf("status = %q, want %q", res.Status, StatusOK)
	}
	for _, name := range []string{"db", "cache"} {
		got, ok := res.Checks[name]
		if !ok {
			t.Fatalf("check %q missing from result", name)
		}
		if got.Status != StatusOK || got.Error != "" {
			t.Fatalf("check %q = %+v, want ok with no error", name, got)
		}
	}
}

func TestCheckOneFails(t *testing.T) {
	c := NewChecker()
	c.Register("ok", func(ctx context.Context) error { return nil })
	c.Register("broken", func(ctx context.Context) error { return errors.New("connection refused") })

	res := c.Check(context.Background())
	if res.Status != StatusDegraded {
		t.Fatalf("status = %q, want %q", res.Status, StatusDegraded)
	}
	if got := res.Checks["broken"]; got.Status != StatusDegraded || got.Error != "connection refused" {
		t.Fatalf("broken = %+v, want degraded/connection refused", got)
	}
	if got := res.Checks["ok"]; got.Status != StatusOK {
		t.Fatalf("ok = %+v, want ok", got)
	}
}

func TestCheckTimeoutNonCooperative(t *testing.T) {
	c := NewCheckerWithTimeout(25 * time.Millisecond)
	release := make(chan struct{})
	defer close(release)
	c.Register("hang", func(ctx context.Context) error {
		// Deliberately ignores ctx: the timeout must still bound the probe.
		<-release
		return nil
	})

	start := time.Now()
	res := c.Check(context.Background())
	elapsed := time.Since(start)

	if res.Status != StatusDegraded {
		t.Fatalf("status = %q, want %q", res.Status, StatusDegraded)
	}
	got := res.Checks["hang"]
	if got.Status != StatusDegraded || got.Error == "" {
		t.Fatalf("hang = %+v, want degraded with an error", got)
	}
	if !strings.Contains(got.Error, "deadline exceeded") {
		t.Fatalf("error = %q, want it to mention deadline exceeded", got.Error)
	}
	if elapsed > time.Second {
		t.Fatalf("Check took %v; the timeout did not bound it", elapsed)
	}
}

func TestCheckTimeoutCooperative(t *testing.T) {
	c := NewCheckerWithTimeout(20 * time.Millisecond)
	c.Register("slow", func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})

	res := c.Check(context.Background())
	if res.Status != StatusDegraded {
		t.Fatalf("status = %q, want degraded", res.Status)
	}
	if got := res.Checks["slow"]; got.Status != StatusDegraded || !strings.Contains(got.Error, "deadline exceeded") {
		t.Fatalf("slow = %+v, want deadline-exceeded", got)
	}
}

func TestCheckParentContextCanceled(t *testing.T) {
	c := NewChecker()
	c.Register("wait", func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := c.Check(ctx)
	if res.Status != StatusDegraded {
		t.Fatalf("status = %q, want degraded", res.Status)
	}
	if !strings.Contains(res.Checks["wait"].Error, "canceled") {
		t.Fatalf("error = %q, want it to mention cancellation", res.Checks["wait"].Error)
	}
}

func TestCheckPanicIsRecovered(t *testing.T) {
	c := NewChecker()
	c.Register("panics", func(ctx context.Context) error { panic("boom") })

	res := c.Check(context.Background())
	if res.Status != StatusDegraded {
		t.Fatalf("status = %q, want degraded", res.Status)
	}
	if got := res.Checks["panics"]; !strings.Contains(got.Error, "panic") || !strings.Contains(got.Error, "boom") {
		t.Fatalf("panics = %+v, want a recovered panic error", got)
	}
}

func TestRegisterIgnoresInvalid(t *testing.T) {
	c := NewChecker()
	c.Register("", func(ctx context.Context) error { return nil })
	c.Register("nil", nil)
	if names := c.Names(); len(names) != 0 {
		t.Fatalf("names = %v, want none", names)
	}
	if res := c.Check(context.Background()); res.Status != StatusOK {
		t.Fatalf("status = %q, want ok", res.Status)
	}
}

func TestNamesSorted(t *testing.T) {
	c := NewChecker()
	for _, name := range []string{"zeta", "alpha", "mid"} {
		c.Register(name, func(ctx context.Context) error { return nil })
	}
	got := c.Names()
	want := []string{"alpha", "mid", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names = %v, want %v", got, want)
		}
	}
}

func TestLivenessAlwaysOK(t *testing.T) {
	c := NewChecker()
	c.Register("broken", func(ctx context.Context) error { return errors.New("down") })
	c.Register("hang", func(ctx context.Context) error { select {} })

	rec := httptest.NewRecorder()
	c.LivenessHandler()(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"status":"ok"}` {
		t.Fatalf("body = %q, want {\"status\":\"ok\"}", body)
	}
}

func TestReadinessPass(t *testing.T) {
	c := NewChecker()
	c.Register("db", func(ctx context.Context) error { return nil })

	rec := httptest.NewRecorder()
	c.ReadinessHandler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Status != StatusOK {
		t.Fatalf("status = %q, want ok", res.Status)
	}
	if res.Checks["db"].Status != StatusOK {
		t.Fatalf("db = %+v, want ok", res.Checks["db"])
	}
}

func TestReadinessFail(t *testing.T) {
	c := NewChecker()
	c.Register("db", func(ctx context.Context) error { return errors.New("no route to host") })

	rec := httptest.NewRecorder()
	c.ReadinessHandler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Status != StatusDegraded {
		t.Fatalf("status = %q, want degraded", res.Status)
	}
	if res.Checks["db"].Error != "no route to host" {
		t.Fatalf("db = %+v, want error preserved", res.Checks["db"])
	}
}

func TestReadinessJSONKeysSorted(t *testing.T) {
	c := NewChecker()
	for _, name := range []string{"zeta", "alpha", "mid"} {
		c.Register(name, func(ctx context.Context) error { return nil })
	}
	rec := httptest.NewRecorder()
	c.ReadinessHandler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	body := rec.Body.String()
	ai := strings.Index(body, `"alpha"`)
	mi := strings.Index(body, `"mid"`)
	zi := strings.Index(body, `"zeta"`)
	if ai < 0 || mi < 0 || zi < 0 || ai >= mi || mi >= zi {
		t.Fatalf("check keys not sorted in %s", body)
	}
}

func TestProbeMethods(t *testing.T) {
	c := NewChecker()
	c.Register("db", func(ctx context.Context) error { return nil })

	for _, h := range []string{"liveness", "readiness"} {
		handler := c.LivenessHandler()
		want := http.StatusOK
		if h == "readiness" {
			handler = c.ReadinessHandler()
		}

		t.Run(h+"/GET", func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != want {
				t.Fatalf("status = %d, want %d", rec.Code, want)
			}
		})
		t.Run(h+"/HEAD", func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodHead, "/", nil))
			if rec.Code != want {
				t.Fatalf("status = %d, want %d", rec.Code, want)
			}
			if rec.Body.Len() != 0 {
				t.Fatalf("HEAD body = %q, want empty", rec.Body.String())
			}
		})
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(h+"/"+method, func(t *testing.T) {
				rec := httptest.NewRecorder()
				handler(rec, httptest.NewRequest(method, "/", nil))
				if rec.Code != http.StatusMethodNotAllowed {
					t.Fatalf("status = %d, want 405", rec.Code)
				}
			})
		}
	}
}

func TestServeHTTPIsReadiness(t *testing.T) {
	c := NewChecker()
	c.Register("boom", func(ctx context.Context) error { return errors.New("x") })

	rec := httptest.NewRecorder()
	var h http.Handler = c
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestConcurrentRegisterAndCheck(t *testing.T) {
	c := NewChecker()
	const registrations = 64

	var wg sync.WaitGroup

	// Registrations racing with probes.
	for i := 0; i < registrations; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Register(fmt.Sprintf("check-%03d", i), func(ctx context.Context) error { return nil })
		}(i)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 300; j++ {
				_ = c.Check(context.Background())
				rec := httptest.NewRecorder()
				c.ReadinessHandler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			}
		}()
	}
	wg.Wait()

	if got := len(c.Names()); got != registrations {
		t.Fatalf("registered %d checks, want %d", got, registrations)
	}
	if res := c.Check(context.Background()); res.Status != StatusOK {
		t.Fatalf("final status = %q, want ok", res.Status)
	}
}

func TestConcurrentSetTimeout(t *testing.T) {
	c := NewChecker()
	c.Register("ok", func(ctx context.Context) error { return nil })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.SetTimeout(time.Duration(i+1) * time.Millisecond)
				_ = c.Check(context.Background())
			}
		}(i)
	}
	wg.Wait()
}
