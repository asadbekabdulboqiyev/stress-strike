package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// collectingSink records every sample it receives. Emit runs from every
// virtual user in parallel, so the sink is mutex-guarded exactly like a real
// consumer must be.
type collectingSink struct {
	mu  sync.Mutex
	got []Sample
}

func (s *collectingSink) Emit(sample Sample) {
	s.mu.Lock()
	s.got = append(s.got, sample)
	s.mu.Unlock()
}

func (s *collectingSink) samples() []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Sample, len(s.got))
	copy(out, s.got)
	return out
}

// The sink must see exactly the measurements the run records, with usable
// fields, so an attested bundle can never disagree with the reported numbers.
func TestSampleSinkReceivesEveryRecordedRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "sink",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    4,
			Duration: 1,
			Timeout:  2,
		},
		Steps: []config.Step{{Name: "health", Method: "GET", URL: srv.URL}},
	}
	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	sink := &collectingSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tel, err := eng.Run(ctx, RunOptions{Quiet: true, Samples: sink})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	got := sink.samples()
	if len(got) == 0 {
		t.Fatal("sink received no samples")
	}
	if want := tel.TotalRequests(); uint64(len(got)) != want {
		t.Fatalf("sink samples = %d, telemetry requests = %d — they must match", len(got), want)
	}

	seen := make(map[uint64]bool, len(got))
	for _, s := range got {
		if s.Step != "health" {
			t.Errorf("step = %q, want health", s.Step)
		}
		if s.Status != http.StatusOK {
			t.Errorf("status = %d, want 200", s.Status)
		}
		// Windows cannot resolve a sub-millisecond loopback round trip: the Go
		// runtime's monotonic clock there reads the system interrupt time
		// (runtime·nanotime1 -> _INTERRUPT_TIME, i.e. the ~15.6 ms timer
		// tick), so a correctly measured fast request legitimately records
		// 0 ns. On every other platform a positive latency is what proves the
		// engine measured the request instead of fabricating a sample.
		if s.LatencyNS < 0 || (s.LatencyNS == 0 && runtime.GOOS != "windows") {
			t.Errorf("latency = %d, want > 0 (0 is only valid on Windows, where the clock cannot resolve it)", s.LatencyNS)
		}
		if s.StartNS <= 0 {
			t.Errorf("start_ns = %d, want > 0", s.StartNS)
		}
		if s.Bytes < -1 {
			t.Errorf("bytes = %d, want >= -1", s.Bytes)
		}
		if seen[s.Seq] {
			t.Errorf("duplicate seq %d", s.Seq)
		}
		seen[s.Seq] = true
	}
	// Seq must be a dense 0..n-1 range so a verifier can index samples.
	for i := uint64(0); i < uint64(len(got)); i++ {
		if !seen[i] {
			t.Errorf("seq %d missing", i)
		}
	}
}

// A run with no sink must behave exactly as before (nil check, no panic).
func TestNilSampleSinkIsSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "nil-sink",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    2,
			Duration: 1,
			Timeout:  2,
		},
		Steps: []config.Step{{Name: "health", Method: "GET", URL: srv.URL}},
	}
	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := eng.Run(ctx, RunOptions{Quiet: true}); err != nil {
		t.Fatalf("run without sink: %v", err)
	}
}

// compile-time assertion: BufferCapture-style sinks satisfy the interface.
var _ SampleSink = (*collectingSink)(nil)
