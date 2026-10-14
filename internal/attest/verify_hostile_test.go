package attest

// verify_hostile_test.go — regression tests for a crash reachable from the
// bundle alone.
//
// The verifier's contract is fail-closed and *total*: every input, however
// hostile, must produce a structured VerifyResult (valid == false) and the CLI
// must exit 0 or 1. A panic breaks that contract, because the process dies with
// exit code 2 and no report — exactly the case these tests pin down.

import (
	"strings"
	"testing"
)

// TestVerifyHostileAggregateCountDoesNotPanic pins the fix for a verified
// denial-of-service: verifyGlobalAggregate used to size its latency buffer from
// the decoded, attacker-controlled aggregate.count. A bundle claiming 2^62
// samples therefore panicked with "makeslice: cap out of range" before any
// check ran, and `verify --json` emitted no JSON at all.
//
// The value only has to be large enough to make the allocation impossible; the
// bundle needs no valid signature, because the schema failure is recorded as a
// check rather than an early return.
func TestVerifyHostileAggregateCountDoesNotPanic(t *testing.T) {
	const huge = "4611686018427387904" // 2^62
	hexKey := strings.Repeat("aa", 32)
	hexSig := strings.Repeat("bb", 64)

	raw := `{
	  "format": "vpmp/v1",
	  "created_at": "2026-10-13T18:00:00Z",
	  "tool": {"name": "stress-strike", "version": "0.15.0"},
	  "run": {
	    "target": "http://127.0.0.1:8080/",
	    "profile": "constant-rps",
	    "duration_ns": 1000000000,
	    "planned_rps": "1000.000"
	  },
	  "workers": [{
	    "id": "w1",
	    "public_key": "` + hexKey + `",
	    "commit": {
	      "merkle_root": "` + hexKey + `",
	      "sample_count": ` + huge + `,
	      "window_start_ns": 0,
	      "window_end_ns": 1,
	      "signature": "` + hexSig + `"
	    },
	    "aggregate": {
	      "count": ` + huge + `,
	      "sum_latency_ns": 0,
	      "min_ns": 0,
	      "max_ns": 0,
	      "hist": {"1": ` + huge + `}
	    }
	  }],
	  "aggregate": {
	    "count": ` + huge + `,
	    "sum_latency_ns": 0,
	    "p50_ns": 0,
	    "p95_ns": 0,
	    "p99_ns": 0,
	    "rps": "1000.000",
	    "co_corrected": false,
	    "co_ci95_ns": {"low_ns": 0, "high_ns": 0}
	  },
	  "integrity": {
	    "schedule_accuracy_ppm": 1000000,
	    "dropped_samples": 0,
	    "achieved_rps": "1000.000",
	    "planned_rps": "1000.000"
	  },
	  "signature": {
	    "alg": "ed25519",
	    "key": "` + hexKey + `",
	    "sig": "` + hexSig + `",
	    "covers": "sha256(canonical-bundle-without-signature)"
	  }
	}`

	b, err := ParseBundle([]byte(raw))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	// Every worker id must have at least one sidecar record, otherwise the
	// global aggregate short-circuits before the vulnerable path is reached.
	samples := map[string][]Record{
		"w1": {{Seq: 1, Worker: "w1", StartNS: 0, LatencyNS: 2, Status: 200, Bytes: 1}},
	}

	res := Verify(b, samples) // must return, not panic

	if res.Valid {
		t.Fatal("a bundle claiming 2^62 samples must not verify")
	}
	if len(res.Errors) == 0 {
		t.Fatal("fail-closed contract broken: invalid bundle recorded no errors")
	}
	if res.Summary.ChecksRun == 0 {
		t.Fatal("no report was produced: the verifier aborted before running checks")
	}
	if res.Summary.Workers != 1 {
		t.Fatalf("workers = %d, want 1", res.Summary.Workers)
	}
}
