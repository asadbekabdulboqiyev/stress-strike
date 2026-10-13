package evidence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
)

// A live run must hand the collector exactly the requests the run reports, and
// every collected record must be a valid, canonical, uniquely numbered record.
func TestCollectorRecordsEveryRequestFromLiveRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "evidence",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    4,
			Duration: 1,
			Timeout:  2,
		},
		Steps: []config.Step{{Name: "health", Method: "GET", URL: srv.URL}},
	}
	eng, err := engine.New(sc)
	if err != nil {
		t.Fatal(err)
	}

	collector, err := NewCollector("test-worker-1")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tel, err := eng.Run(ctx, engine.RunOptions{Quiet: true, Samples: collector})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if err := collector.Err(); err != nil {
		t.Fatalf("collector reported unrepresentable samples: %v", err)
	}
	if got, want := uint64(collector.Count()), tel.TotalRequests(); got != want {
		t.Fatalf("collected %d records, run reported %d requests — evidence must match the report", got, want)
	}

	recs := collector.Records()
	if len(recs) == 0 {
		t.Fatal("no records collected")
	}
	if !attest.RecordsInFileOrder(recs) {
		t.Error("records are not in canonical leaf order")
	}
	seenSeq := make(map[uint64]bool, len(recs))
	for i, rec := range recs {
		if err := rec.Validate(); err != nil {
			t.Fatalf("record %d invalid: %v", i, err)
		}
		if rec.Worker != "test-worker-1" {
			t.Errorf("record %d worker = %q, want test-worker-1", i, rec.Worker)
		}
		if rec.Seq == 0 {
			t.Errorf("record %d has zero seq — the wire format is 1-based", i)
		}
		if seenSeq[rec.Seq] {
			t.Errorf("record %d repeats seq %d", i, rec.Seq)
		}
		seenSeq[rec.Seq] = true
		if rec.Status != http.StatusOK {
			t.Errorf("record %d status = %d, want 200", i, rec.Status)
		}
		if rec.LatencyNS <= 0 {
			t.Errorf("record %d latency = %d, want > 0", i, rec.LatencyNS)
		}
	}
	// The 1-based shift must be dense: 1..n.
	for i := uint64(1); i <= uint64(len(recs)); i++ {
		if !seenSeq[i] {
			t.Errorf("seq %d missing from the collected set", i)
		}
	}

	// The leaves must reproduce a root: the evidence is attestable.
	leaves, err := collector.Leaves()
	if err != nil {
		t.Fatalf("Leaves: %v", err)
	}
	if len(leaves) != len(recs) {
		t.Fatalf("Leaves = %d entries, records = %d", len(leaves), len(recs))
	}
	root := attest.MerkleRootHex(leaves)
	if root == "" || root == attest.EmptyRootHex {
		t.Fatalf("merkle root %q is empty for a non-empty run", root)
	}
	// A proof for the first leaf must verify against that root.
	proof, err := attest.MerkleProof(leaves, 0)
	if err != nil {
		t.Fatalf("MerkleProof: %v", err)
	}
	// VerifyProof takes the raw leaf value and applies the domain-separated,
	// index-bound leaf hash itself.
	if !attest.VerifyProof(attest.MerkleRoot(leaves), leaves[0], 0, proof) {
		t.Fatal("inclusion proof for leaf 0 does not verify")
	}
}

// The engine's "unknown bytes" marker must become the protocol's "not recorded"
// zero; nothing else about the record may change.
func TestCollectorNormalizesUnknownBytes(t *testing.T) {
	collector, err := NewCollector("normalize")
	if err != nil {
		t.Fatal(err)
	}
	collector.Emit(engine.Sample{
		Seq:       0,
		Step:      "health",
		StartNS:   1_700_000_000_000_000_000,
		LatencyNS: 1_500_000,
		Status:    http.StatusOK,
		Bytes:     -1,
	})

	if err := collector.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	recs := collector.Records()
	if len(recs) != 1 {
		t.Fatalf("collected %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Bytes != 0 {
		t.Errorf("bytes = %d, want 0 (unknown normalizes to not-recorded)", rec.Bytes)
	}
	if rec.Seq != 1 {
		t.Errorf("seq = %d, want 1 (engine seq 0 becomes wire seq 1)", rec.Seq)
	}
	if rec.LatencyNS != 1_500_000 {
		t.Errorf("latency = %d, want 1500000 (unchanged)", rec.LatencyNS)
	}
	if rec.StartNS != 1_700_000_000_000_000_000 {
		t.Errorf("start_ns = %d, want unchanged", rec.StartNS)
	}
}

// A sample that cannot be represented must not be silently repaired or silently
// dropped: it is counted, reported, and left out, so the caller can refuse to
// emit an incomplete bundle.
func TestCollectorRefusesUnrepresentableSample(t *testing.T) {
	collector, err := NewCollector("broken")
	if err != nil {
		t.Fatal(err)
	}
	collector.Emit(engine.Sample{Seq: 0, StartNS: 1000, LatencyNS: -5, Status: 200})
	collector.Emit(engine.Sample{Seq: 1, StartNS: 2000, LatencyNS: 1000, Status: 200})

	if collector.Err() == nil {
		t.Fatal("negative latency was accepted — the evidence would be unusable")
	}
	if collector.Dropped() != 1 {
		t.Errorf("dropped = %d, want 1", collector.Dropped())
	}
	if collector.Count() != 1 {
		t.Errorf("count = %d, want 1 (only the valid sample)", collector.Count())
	}
	if collector.Err().Error() == "" || !strings.Contains(collector.Err().Error(), "latency") {
		t.Errorf("error %q does not name the offending field", collector.Err())
	}
}

func TestNewCollectorRejectsUnusableWorkerIDs(t *testing.T) {
	for _, id := range []string{"", "   ", "\t\n"} {
		if _, err := NewCollector(id); err == nil {
			t.Errorf("worker id %q was accepted", id)
		}
	}
	if _, err := NewCollector("w1"); err != nil {
		t.Errorf("valid worker id rejected: %v", err)
	}
	// A long id is truncated rather than rejected.
	long := strings.Repeat("w", attest.MaxWorkerIDLen+50)
	c, err := NewCollector(long)
	if err != nil {
		t.Fatalf("long worker id rejected: %v", err)
	}
	if len(c.Worker()) != attest.MaxWorkerIDLen {
		t.Errorf("worker id length = %d, want %d", len(c.Worker()), attest.MaxWorkerIDLen)
	}
}

// Emit is called from every virtual user at once; the collector must not lose
// or corrupt a record under concurrency.
func TestCollectorIsSafeForConcurrentEmit(t *testing.T) {
	const goroutines, perGoroutine = 16, 250
	collector, err := NewCollector("concurrent")
	if err != nil {
		t.Fatal(err)
	}

	var seq uint64
	var seqMu sync.Mutex
	next := func() uint64 {
		seqMu.Lock()
		defer seqMu.Unlock()
		s := seq
		seq++
		return s
	}

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				collector.Emit(engine.Sample{
					Seq:       next(),
					StartNS:   int64(1_700_000_000_000_000_000 + i),
					LatencyNS: 1000,
					Status:    200,
					Bytes:     -1,
				})
			}
		}()
	}
	wg.Wait()

	if err := collector.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	recs := collector.Records()
	if len(recs) != goroutines*perGoroutine {
		t.Fatalf("collected %d records, want %d", len(recs), goroutines*perGoroutine)
	}
	seen := make(map[uint64]bool, len(recs))
	for _, rec := range recs {
		if err := rec.Validate(); err != nil {
			t.Fatalf("record invalid after concurrent collection: %v", err)
		}
		if seen[rec.Seq] {
			t.Fatalf("duplicate seq %d after concurrent collection", rec.Seq)
		}
		seen[rec.Seq] = true
	}
	if !attest.RecordsInFileOrder(recs) {
		t.Error("records are not in canonical order after concurrent collection")
	}
}

// compile-time assertion: the collector is a valid engine.SampleSink.
var _ engine.SampleSink = (*Collector)(nil)
