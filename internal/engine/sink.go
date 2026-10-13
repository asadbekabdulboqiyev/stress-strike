package engine

// Sample is one attested measurement: a single executed request attempt,
// captured with the exact latency the engine feeds into the step percentiles
// (coordinated-omission corrected when that mode is active). It is the atomic
// unit a VeriBench evidence bundle commits to, so a third party can recompute
// the run's numbers from the raw samples instead of trusting the report.
type Sample struct {
	// Seq is a monotonic, run-unique, 0-based index in emission order. The
	// vpmp/v1 wire format numbers records from 1, so a producer shifts this by
	// one when converting (see internal/evidence.Collector.Emit).
	Seq uint64
	// Step is the scenario step name that produced the request.
	Step string
	// StartNS is the wall-clock request start in Unix nanoseconds.
	StartNS int64
	// LatencyNS is the measured latency in nanoseconds (CO-corrected when the
	// run has coordinated-omission correction enabled).
	LatencyNS int64
	// Status is the protocol status code, or 0 when the attempt produced none.
	Status int
	// Bytes is the response body size in bytes, or -1 when unknown (the common
	// case: the body is drained into a pooled buffer and discarded).
	Bytes int64
}

// SampleSink consumes measurements as they are taken during a run. The engine
// calls Emit once per executed request attempt, from every virtual user in
// parallel, so implementations MUST be safe for concurrent use.
//
// Emit is expected to be cheap and non-blocking: it sits on the per-request
// path. Buffer internally and flush elsewhere if the consumer is slow.
type SampleSink interface {
	Emit(Sample)
}
