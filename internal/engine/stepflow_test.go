package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
)

// runFlowScenario runs a scenario to completion and returns the telemetry.
func runFlowScenario(t *testing.T, sc *config.Scenario) *metrics.Telemetry {
	t.Helper()
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tel, err := eng.Run(ctx, RunOptions{Out: io.Discard, Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	return tel
}

func flowScenario(steps []config.Step, profile config.Profile) *config.Scenario {
	if profile.Users == 0 {
		profile.Users = 1
	}
	if profile.Duration == 0 {
		profile.Duration = 2
	}
	if profile.Timeout == 0 {
		profile.Timeout = 5
	}
	return &config.Scenario{
		Name:    "flow-test",
		Profile: profile,
		Steps:   steps,
	}
}

// ---- on_error: continue vs stop ----

func TestOnErrorContinueRunsNextStep(t *testing.T) {
	var okHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fail":
			w.WriteHeader(500)
		case "/ok":
			okHits.Add(1)
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{
		{Name: "fail", Method: "GET", URL: srv.URL + "/fail", OnError: "continue"},
		{Name: "ok", Method: "GET", URL: srv.URL + "/ok"},
	}, config.Profile{Users: 1, Duration: 1, Timeout: 5})

	tel := runFlowScenario(t, sc)

	if okHits.Load() == 0 {
		t.Fatal("on_error=continue: next step never ran")
	}
	if tel.Errors()["status_5xx"] == 0 {
		t.Error("expected status_5xx recorded for the failed step")
	}
	if code, ok := tel.Steps[1].StatusCodes()[200]; !ok || code == 0 {
		t.Error("ok step should record 200 responses")
	}
}

func TestOnErrorDefaultStopAbortsIteration(t *testing.T) {
	var okHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fail":
			w.WriteHeader(500)
		case "/ok":
			okHits.Add(1)
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{
		{Name: "fail", Method: "GET", URL: srv.URL + "/fail"}, // on_error defaults to stop
		{Name: "ok", Method: "GET", URL: srv.URL + "/ok"},
	}, config.Profile{Users: 1, Duration: 1, Timeout: 5})

	tel := runFlowScenario(t, sc)

	if okHits.Load() != 0 {
		t.Errorf("default on_error=stop should abort iteration before /ok, hits=%d", okHits.Load())
	}
	if tel.Errors()["status_5xx"] == 0 {
		t.Error("expected status_5xx recorded")
	}
	// The aborted step must not have accumulated requests.
	if n := tel.Steps[1].Requests(); n != 0 {
		t.Errorf("ok step requests = %d, want 0", n)
	}
}

// ---- retries ----

func TestRetryThenSuccess(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 { // first two attempts fail
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{{
		Name: "flaky", Method: "GET", URL: srv.URL + "/flaky",
		Retries: 2, RetryBackoff: 0.01,
	}}, config.Profile{Users: 1, Duration: 1, Timeout: 5})

	tel := runFlowScenario(t, sc)

	st := tel.Steps[0]
	if n := st.StatusCodes()[200]; n == 0 {
		t.Error("expected a 200 from the retried step")
	}
	if n := st.StatusCodes()[500]; n != 2 {
		t.Errorf("status_500 count = %d, want exactly 2 (first iteration retries)", n)
	}
	// 3 attempts happened in the first iteration: 2 failures + 1 success.
	if st.Requests() < 3 {
		t.Errorf("requests = %d, want >= 3", st.Requests())
	}
	// Final attempt succeeded → iteration-level overall must be clean.
	if tel.Overall.ErrorCount() != 0 {
		t.Errorf("overall errors = %d, want 0 (final retry succeeded)", tel.Overall.ErrorCount())
	}
}

func TestRetryExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{{
		Name: "down", Method: "GET", URL: srv.URL + "/down",
		Retries: 2, RetryBackoff: 0.01,
	}}, config.Profile{Users: 1, Duration: 1, Timeout: 5})

	tel := runFlowScenario(t, sc)

	st := tel.Steps[0]
	if n := st.StatusCodes()[503]; n < 3 {
		t.Errorf("status_503 count = %d, want >= 3 (1 + 2 retries every iteration)", n)
	}
	if n := st.StatusCodes()[503]; n%3 != 0 {
		t.Errorf("status_503 count = %d, want a multiple of 3", n)
	}
	if tel.Overall.ErrorCount() == 0 {
		t.Error("overall should record errors when retries are exhausted")
	}
}

func TestNoRetryByDefault(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(503)
	}))
	defer srv.Close()

	// retries unset → every iteration issues exactly one request.
	sc := flowScenario([]config.Step{{
		Name: "down", Method: "GET", URL: srv.URL + "/down",
	}}, config.Profile{Users: 1, Duration: 1, Timeout: 5})

	tel := runFlowScenario(t, sc)
	st := tel.Steps[0]
	total := st.Requests()
	if int64(total) != calls.Load() {
		t.Errorf("recorded requests = %d, server calls = %d, want equal", total, calls.Load())
	}
	if total == 0 {
		t.Fatal("no requests recorded")
	}
}

// ---- conditional branching ----

func TestIfConditionTrueRunsNested(t *testing.T) {
	var inner atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/inner" {
			inner.Add(1)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{{
		Name:      "branch",
		Type:      "if",
		Condition: "${x} == 1",
		Steps:     []config.Step{{Name: "inner", Method: "GET", URL: srv.URL + "/inner"}},
	}}, config.Profile{Users: 3, Duration: 1, Timeout: 5})
	sc.Variables = map[string]string{"x": "1"}

	tel := runFlowScenario(t, sc)

	if inner.Load() == 0 {
		t.Fatal("condition true: nested step never ran")
	}
	if code, ok := tel.Steps[0].StatusCodes()[200]; !ok || code == 0 {
		t.Error("nested results should aggregate into the if step's slot")
	}
}

func TestIfConditionFalseSkipsNested(t *testing.T) {
	var inner atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/inner" {
			inner.Add(1)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{{
		Name:      "branch",
		Type:      "if",
		Condition: "${x} == 1",
		Steps:     []config.Step{{Name: "inner", Method: "GET", URL: srv.URL + "/inner"}},
	}}, config.Profile{Users: 3, Duration: 1, Timeout: 5})
	sc.Variables = map[string]string{"x": "2"}

	tel := runFlowScenario(t, sc)

	if inner.Load() != 0 {
		t.Errorf("condition false: nested step ran %d times, want 0", inner.Load())
	}
	if n := tel.Steps[0].Requests(); n != 0 {
		t.Errorf("if step requests = %d, want 0", n)
	}
}

func TestIfConditionBuiltinStatus(t *testing.T) {
	var dash atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.WriteHeader(200)
		case "/dashboard":
			dash.Add(1)
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{
		{Name: "login", Method: "GET", URL: srv.URL + "/login", OnError: "continue"},
		{
			Name:      "auth-flow",
			Type:      "if",
			Condition: "${login_status} == 200",
			Steps:     []config.Step{{Name: "dashboard", Method: "GET", URL: srv.URL + "/dashboard"}},
		},
	}, config.Profile{Users: 2, Duration: 1, Timeout: 5})

	tel := runFlowScenario(t, sc)

	if dash.Load() == 0 {
		t.Fatal("builtin ${login_status} var: dashboard branch never ran")
	}
	if n := tel.Steps[0].StatusCodes()[200]; n == 0 {
		t.Error("login step should record 200s")
	}
}

// ---- skip_on_error ----

func TestSkipOnErrorSkipsStepAfterFailure(t *testing.T) {
	var s2, s3 atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/s1":
			w.WriteHeader(500)
		case "/s2":
			s2.Add(1)
			w.WriteHeader(200)
		case "/s3":
			s3.Add(1)
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{
		{Name: "s1", Method: "GET", URL: srv.URL + "/s1", OnError: "continue"},
		{Name: "s2", Method: "GET", URL: srv.URL + "/s2", SkipOnError: true},
		{Name: "s3", Method: "GET", URL: srv.URL + "/s3"},
	}, config.Profile{Users: 1, Duration: 1, Timeout: 5})

	tel := runFlowScenario(t, sc)

	if s2.Load() != 0 {
		t.Errorf("skip_on_error: s2 ran %d times, want 0", s2.Load())
	}
	if s3.Load() == 0 {
		t.Error("iteration should continue past the skipped step")
	}
	if n := tel.Steps[1].Requests(); n != 0 {
		t.Errorf("skipped step recorded %d requests, want 0", n)
	}
}

func TestNoSkipOnErrorRunsNormally(t *testing.T) {
	var s2 atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/s1":
			w.WriteHeader(500)
		case "/s2":
			s2.Add(1)
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{
		{Name: "s1", Method: "GET", URL: srv.URL + "/s1", OnError: "continue"},
		{Name: "s2", Method: "GET", URL: srv.URL + "/s2"}, // no skip flag
	}, config.Profile{Users: 1, Duration: 1, Timeout: 5})

	runFlowScenario(t, sc)
	if s2.Load() == 0 {
		t.Error("s2 should run when skip_on_error is not set")
	}
}

// ---- think_time ----

func TestThinkTimeSlowsIterations(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{{
		Name: "ok", Method: "GET", URL: srv.URL + "/ok",
		ThinkTime: 0.15,
	}}, config.Profile{Users: 1, Duration: 1, Timeout: 5})

	runFlowScenario(t, sc)

	h := hits.Load()
	if h < 1 {
		t.Fatal("no requests issued")
	}
	// 150ms think time over a 1s window → at most ~7 iterations. Without
	// think time a local server would see thousands.
	if h > 12 {
		t.Errorf("hits = %d with think_time=0.15s over 1s; want <= 12 (think time not applied)", h)
	}
}

// ---- stop_on_status ----

func TestStopOnStatusExactHaltRun(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(429)
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{{
		Name: "rl", Method: "GET", URL: srv.URL + "/rl",
		StopOnStatus: "429",
	}}, config.Profile{Users: 1, Duration: 2, Timeout: 5})

	tel := runFlowScenario(t, sc)

	// A single user: iteration 1 hits 429 → the whole run halts → no more
	// hits for the remaining ~2s window.
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want exactly 1 (run must halt after 429)", hits.Load())
	}
	if tel.Steps[0].StatusCodes()[429] != 1 {
		t.Error("expected one 429 recorded")
	}
}

func TestStopOnStatusClassHaltRun(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(503)
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{{
		Name: "boom", Method: "GET", URL: srv.URL + "/boom",
		StopOnStatus: "5xx",
	}}, config.Profile{Users: 1, Duration: 2, Timeout: 5})

	runFlowScenario(t, sc)

	if hits.Load() != 1 {
		t.Errorf("hits = %d, want exactly 1 (run must halt after a 5xx)", hits.Load())
	}
}
