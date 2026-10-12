package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
)

// --- token bucket schedule tracking -----------------------------------------

// When the caller keeps up, the schedule skew stays near zero.
func TestTokenBucketCOZeroWhenKeepingUp(t *testing.T) {
	b := newTokenBucket(1000) // interval = 1ms
	extra, err := b.acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if extra > 5*time.Millisecond {
		t.Errorf("first acquire extra = %v, want ~0", extra)
	}
	// A token taken immediately after the previous one is at most a couple of
	// inter-arrival intervals late.
	extra, err = b.acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if extra > 5*time.Millisecond {
		t.Errorf("second acquire extra = %v, want small", extra)
	}
}

// A caller that stalls accumulates schedule skew equal to how long it was
// absent — the hidden queue time coordinated-omission correction restores.
func TestTokenBucketCORestoresStall(t *testing.T) {
	b := newTokenBucket(100) // interval = 10ms
	if _, err := b.acquire(context.Background()); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Simulate every virtual user blocked on a slow target: nobody takes a
	// token for 200ms.
	time.Sleep(200 * time.Millisecond)
	extra, err := b.acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if extra < 100*time.Millisecond {
		t.Errorf("extra after 200ms stall = %v, want >= 100ms", extra)
	}
}

// correctedDelay is a no-op without pacing (rate 0).
func TestTokenBucketCONoPacing(t *testing.T) {
	b := newTokenBucket(0)
	if got := b.correctedDelay(); got != 0 {
		t.Errorf("correctedDelay with rate 0 = %v, want 0", got)
	}
}

// A rate change re-anchors the schedule; an unchanged rate does not.
func TestTokenBucketCOResetOnRateChange(t *testing.T) {
	b := newTokenBucket(100)
	if _, err := b.acquire(context.Background()); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := b.acquire(context.Background()); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	b.mu.Lock()
	issuedBefore := b.issued
	b.mu.Unlock()
	if issuedBefore == 0 {
		t.Fatalf("issued should have advanced, got %d", issuedBefore)
	}

	// Same rate → schedule preserved.
	b.setRate(100)
	b.mu.Lock()
	sameRateIssued := b.issued
	b.mu.Unlock()
	if sameRateIssued != issuedBefore {
		t.Errorf("setRate(same) reset schedule: issued %d → %d", issuedBefore, sameRateIssued)
	}

	// Different rate → schedule re-anchored.
	b.setRate(500)
	b.mu.Lock()
	anchor, issued := b.coAnchor, b.issued
	b.mu.Unlock()
	if anchor || issued != 0 {
		t.Errorf("setRate(different) did not re-anchor: coAnchor=%v issued=%d", anchor, issued)
	}
}

// acquire propagates context cancellation instead of a phantom correction.
func TestTokenBucketCOContextCancel(t *testing.T) {
	b := newTokenBucket(0) // never grants
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	extra, err := b.acquire(ctx)
	if err == nil {
		t.Fatalf("expected context error, got extra=%v", extra)
	}
	if extra != 0 {
		t.Errorf("extra on error = %v, want 0", extra)
	}
}

// --- engine plumbing --------------------------------------------------------

func coTestScenario(t *testing.T, url string, coExtra bool, steps int) *config.Scenario {
	t.Helper()
	st := make([]config.Step, 0, steps)
	for i := 0; i < steps; i++ {
		st = append(st, config.Step{Name: "step" + string(rune('a'+i)), Method: "GET", URL: url + "/"})
	}
	sc := &config.Scenario{
		Name: "co-test",
		Profile: config.Profile{
			Users:               1,
			Duration:            5,
			RPS:                 1, // installs the limiter so `co` is meaningful
			Timeout:             5,
			CoordinatedOmission: coExtra,
		},
		Steps: st,
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	return sc
}

func newFastServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A non-zero schedule skew is added to the whole-iteration latency and to the
// first step only — never smeared across every step.
func TestRunIterationAppliesCOExtra(t *testing.T) {
	srv := newFastServer(t)
	sc := coTestScenario(t, srv.URL, true, 2)

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}
	if !eng.co {
		t.Fatal("engine.co should be true from the profile")
	}
	eng.telemetry = metrics.NewTelemetry()
	for _, st := range eng.stepStats {
		eng.telemetry.AddStep(st)
	}

	const skew = 25 * time.Millisecond
	eng.runIteration(context.Background(), 0, skew)

	if got := eng.telemetry.Overall.Latency.MinLatency(); got < skew {
		t.Errorf("overall min latency = %v, want >= %v (skew must be added)", got, skew)
	}
	if got := eng.stepStats[0].Latency.MinLatency(); got < skew {
		t.Errorf("first step min latency = %v, want >= %v (skew attributed here)", got, skew)
	}
	if got := eng.stepStats[1].Latency.MinLatency(); got >= skew {
		t.Errorf("second step min latency = %v, want < %v (skew must not leak)", got, skew)
	}
}

// With no skew the fast-handler iteration stays well under the skew value, so
// the assertion above is not vacuously true.
func TestRunIterationWithoutCOIsUnchanged(t *testing.T) {
	srv := newFastServer(t)
	sc := coTestScenario(t, srv.URL, false, 1)

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}
	if eng.co {
		t.Fatal("engine.co should be false")
	}
	eng.telemetry = metrics.NewTelemetry()
	eng.telemetry.AddStep(eng.stepStats[0])

	eng.runIteration(context.Background(), 0, 0)

	if got := eng.stepStats[0].Latency.MinLatency(); got >= 25*time.Millisecond {
		t.Errorf("plain step min latency = %v, want < 25ms for a fast handler", got)
	}
}

// End to end: a paced run whose single worker cannot keep up reports a much
// higher average latency with correction enabled than without.
func TestCoordinatedOmissionInflation(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()

	run := func(co bool) time.Duration {
		sc := &config.Scenario{
			Name: "co-e2e",
			Profile: config.Profile{
				Users:               1,
				Duration:            3,
				RPS:                 200, // wants 200/s; one worker can do ~25/s
				Timeout:             5,
				CoordinatedOmission: co,
			},
			Steps: []config.Step{{Name: "hit", Method: "GET", URL: slow.URL + "/"}},
		}
		if err := sc.Normalize(); err != nil {
			t.Fatal(err)
		}
		eng, err := New(sc)
		if err != nil {
			t.Fatal(err)
		}
		tel, err := eng.Run(context.Background(), RunOptions{Quiet: true})
		if err != nil {
			t.Fatal(err)
		}
		return tel.Overall.Latency.Avg()
	}

	plain := run(false)
	corrected := run(true)
	t.Logf("avg latency: plain=%v corrected=%v", plain, corrected)

	if plain < 30*time.Millisecond {
		t.Errorf("plain avg = %v, want ~40ms (server sleep)", plain)
	}
	if corrected <= plain*3 {
		t.Errorf("corrected avg = %v, want > 3x plain (%v) — coordinated omission not corrected", corrected, plain)
	}
}
