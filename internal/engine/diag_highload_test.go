package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

func scratchEnabled() bool { return os.Getenv("SCRATCH") != "" }

// poolSize returns the total number of idle keep-alive connections currently
// held by the transport (across all hosts), read via reflection.
func poolSize(tr *http.Transport) int {
	v := reflect.ValueOf(tr).Elem().FieldByName("idleConn")
	if !v.IsValid() || v.Kind() != reflect.Map {
		return -1
	}
	n := 0
	iter := v.MapRange()
	for iter.Next() {
		n += iter.Value().Len()
	}
	return n
}

const scratchSrvBody = "ok"

func scratchServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, scratchSrvBody)
	}))
}

// prefillN opens n sequential-ish requests through tr so that roughly n
// concurrent connections get pooled. Prefill dial rate is bounded by pacing
// when pace>0 (0 = unlimited concurrency).
func prefillN(tr *http.Transport, url string, n, concurrency int) int {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var ok atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			resp, err := tr.RoundTrip(mustReq(url))
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			ok.Add(1)
		}()
	}
	wg.Wait()
	return int(ok.Load())
}

func mustReq(url string) *http.Request {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}
	return req
}

// hammerN fires n concurrent one-shot requests through tr (fresh request per
// goroutine, mimicking 10k virtual users bursting at t=0).
func hammerN(tr *http.Transport, url string, n int) (ok, errCount int64) {
	var wg sync.WaitGroup
	var okC, errC atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := tr.RoundTrip(mustReq(url))
			if err != nil {
				errC.Add(1)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			okC.Add(1)
		}()
	}
	wg.Wait()
	return okC.Load(), errC.Load()
}

// TestScratchPoolMatrix measures, for several transport configs, how a 10k
// concurrent request burst behaves when the idle pool is (or is not) pre-warmed.
func TestScratchPoolMatrix(t *testing.T) {
	if !scratchEnabled() {
		t.Skip("scratch diagnostic")
	}
	srv := scratchServer()
	defer srv.Close()

	const users = 10_000
	// const users = 2000
	cases := []struct {
		name        string
		maxConns    int
		prefill     int
		prefillConc int
	}{
		{"cap0-noprefill", 0, 0, 0},
		{"cap0-prefill128", 0, 128, 128},
		{"cap512-noprefill", 512, 0, 0},
		{"cap512-prefill128", 512, 128, 128},
		{"cap1024-prefill128", 1024, 128, 128},
		{"cap20000-prefill128", 20000, 128, 128},
		{"cap512-prefill256", 512, 256, 128},
		{"cap4096-prefill128", 4096, 128, 128},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := baseTransport(true, "")
			tr.MaxConnsPerHost = c.maxConns
			tr.MaxIdleConnsPerHost = c.maxConns
			if c.maxConns == 0 {
				tr.MaxIdleConnsPerHost = 100_000
				tr.MaxIdleConns = 100_000
			} else {
				tr.MaxIdleConns = c.maxConns * 4
			}
			if c.prefill > 0 {
				p := prefillN(tr, srv.URL+"/health", c.prefill, c.prefillConc)
				fmt.Printf("  [%s] prefill ok=%d pool=%d\n", c.name, p, poolSize(tr))
			}
			start := time.Now()
			ok, errs := hammerN(tr, srv.URL+"/health", users)
			el := time.Since(start)
			fmt.Printf("  [%s] burst users=%d ok=%d err=%d pool=%d in %v (%.0f req/s)\n",
				c.name, users, ok, errs, poolSize(tr), el.Round(time.Millisecond),
				float64(ok)/el.Seconds())
		})
	}
}

// TestScratchEngineDial runs the REAL engine (cap=MaxConcurrency()*2) at 10k
// users under different dial-pacing profiles and reports errors + achieved RPS.
func TestScratchEngineDial(t *testing.T) {
	if !scratchEnabled() {
		t.Skip("scratch diagnostic")
	}
	srv := scratchServer()
	defer srv.Close()

	type tc struct {
		name string
		prof config.Profile
		wait time.Duration
	}
	cases := []tc{
		{"steady-10k", config.Profile{Type: config.ProfileSteady, Users: 10_000, Duration: 2, Timeout: 10}, 4 * time.Second},
		{"ramp2s-10k", config.Profile{Type: config.ProfileLinearRamp, Users: 10_000, RampUp: 2, Duration: 4, Timeout: 10}, 7 * time.Second},
		{"ramp5s-10k", config.Profile{Type: config.ProfileLinearRamp, Users: 10_000, RampUp: 5, Duration: 4, Timeout: 10}, 10 * time.Second},
		{"ramp8s-10k", config.Profile{Type: config.ProfileLinearRamp, Users: 10_000, RampUp: 8, Duration: 4, Timeout: 10}, 13 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := &config.Scenario{
				Name:    c.name,
				Profile: c.prof,
				Steps:   []config.Step{{Name: "health", Method: "GET", URL: srv.URL + "/health"}},
			}
			e, err := New(sc)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), c.wait)
			defer cancel()
			tel, err := e.Run(ctx, RunOptions{Out: io.Discard, Quiet: true})
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("  [%s] reqs=%d errors=%d errMap=%v rps=%.0f\n",
				c.name, tel.TotalRequests(), tel.TotalErrors(), tel.Errors(), tel.RPS())
		})
	}
}
