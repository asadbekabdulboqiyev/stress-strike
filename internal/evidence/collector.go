// Package evidence connects a live engine run to the attestation layer.
//
// The engine emits one engine.Sample per executed request attempt. A Collector
// turns those samples into attest.Records — the frozen vpmp/v1 wire form — in
// canonical leaf order, so that the same measurements the run reports are also
// the ones a signed bundle commits to. Nothing here re-measures or re-orders
// the numbers: a bundle built from a Collector can never disagree with the run
// it came from.
package evidence

import (
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
)

// Collector is an engine.SampleSink that records every measurement of a run as
// an attest.Record.
//
// Emit is called from every virtual user in parallel, so the collector guards
// its buffer with a mutex and appends in arrival order; the canonical leaf
// order is applied when the records are read (see Records). A mutex on the
// per-request path is acceptable here because evidence collection is an opt-in
// mode (a run only pays it when --emit-bundle is requested) and the critical
// section is one slice append.
type Collector struct {
	worker string

	mu       sync.Mutex
	recs     []attest.Record
	firstErr error
	dropped  uint64
}

// NewCollector returns a collector for the given worker id. The id is sanitized
// to satisfy the protocol's length limit; an id that is empty (or not valid
// UTF-8) after sanitization is rejected, because an unattributable record set
// would verify against nothing.
func NewCollector(worker string) (*Collector, error) {
	id := attest.SanitizeWorkerID(worker)
	if id == "" {
		return nil, errors.New("evidence: worker id is empty")
	}
	if !utf8.ValidString(id) {
		return nil, errors.New("evidence: worker id is not valid UTF-8")
	}
	return &Collector{worker: id}, nil
}

// Worker returns the sanitized worker id records are attributed to.
func (c *Collector) Worker() string { return c.worker }

// Emit implements engine.SampleSink. It converts one engine measurement into a
// protocol record and appends it.
//
// Two conversions are deliberate and are the only ones applied:
//
//   - The engine numbers samples from 0; the wire format is 1-based, so Seq is
//     shifted by one.
//   - The engine uses a negative byte count for "body size unknown"; the wire
//     format has no such value and defines 0 as "not recorded", so a negative
//     count becomes 0. This can only ever under-report bytes, never invent
//     them.
//
// Anything else that fails record validation (a negative latency, an
// out-of-range status) is not repaired: the sample is dropped and remembered,
// and Err reports it. Repaired numbers would be manufactured numbers, and
// silently dropping a request would make the bundle claim a completeness the
// run does not have. The caller must refuse to emit a bundle when Err is
// non-nil.
func (c *Collector) Emit(s engine.Sample) {
	rec := attest.Record{
		Seq:       s.Seq + 1,
		Worker:    c.worker,
		StartNS:   s.StartNS,
		LatencyNS: s.LatencyNS,
		Status:    s.Status,
		Bytes:     s.Bytes,
	}
	if rec.Bytes < 0 {
		rec.Bytes = 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := rec.Validate(); err != nil {
		c.dropped++
		if c.firstErr == nil {
			c.firstErr = fmt.Errorf("evidence: sample %d cannot be represented as a record: %w", s.Seq, err)
		}
		return
	}
	c.recs = append(c.recs, rec)
}

// Count returns the number of records collected so far.
func (c *Collector) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.recs)
}

// Dropped returns how many samples could not be represented as records.
func (c *Collector) Dropped() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}

// Err returns the first sample that could not be represented as a record, or
// nil when every emitted sample was recorded.
//
// A non-nil Err means the collected evidence is incomplete: a bundle built from
// it would be missing requests the run actually made. Callers must treat it as
// fatal for bundle emission rather than warning about it.
func (c *Collector) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.firstErr
}

// Records returns a copy of the collected records in canonical leaf order —
// (start_ns, seq) ascending — which is the order the Merkle tree is built
// over, so the returned slice is exactly the sidecar's content and exactly the
// tree's leaves.
func (c *Collector) Records() []attest.Record {
	c.mu.Lock()
	recs := make([]attest.Record, len(c.recs))
	copy(recs, c.recs)
	c.mu.Unlock()
	return attest.SortRecords(recs)
}

// Leaves returns the canonical byte string of every record, in the same order
// as Records. These bytes are the Merkle leaves: hashing them with
// attest.LeafHash at each index reproduces the tree the bundle commits to.
func (c *Collector) Leaves() ([][]byte, error) {
	recs := c.Records()
	leaves := make([][]byte, 0, len(recs))
	for i, rec := range recs {
		leaf, err := attest.CanonicalRecord(rec)
		if err != nil {
			return nil, fmt.Errorf("evidence: record %d is not canonical: %w", i, err)
		}
		leaves = append(leaves, leaf)
	}
	return leaves, nil
}
