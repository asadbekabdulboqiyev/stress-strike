package attest

// record.go — one measured request, its validation, and the sidecar stream
// that carries a run's raw evidence.
//
// A sidecar file (bundle.samples.jsonl) holds exactly one canonical record per
// line, in the order the worker wrote it. It is the "receipt roll": the bundle
// commits to the hash of every line, so any single altered byte of any single
// request breaks verification (see verify.go).
//
// # Memory and size limits
//
// The sidecar is loaded as a stream (one line at a time, one record at a time)
// but the records are kept in memory, because verification needs each record
// twice — once for the Merkle tree and once for the aggregate recomputation.
// One record costs roughly 80 bytes of heap plus its worker id, so a worker's
// 5,000,000-record default cap corresponds to a few hundred megabytes of peak
// heap. LoadSamples therefore enforces explicit caps
// (SampleLoadOptions.MaxSamplesPerWorker / MaxSamplesTotal) and fails closed
// with a clear message instead of exhausting memory on a hostile file.
//
// Verifying more evidence than that is a deliberate, documented limitation of
// v1: split the run into shards, each with its own bundle, or raise the caps
// with --max-samples after checking the verifier's memory budget.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

// Record is one measured request. Every field is an integer or a string: the
// protocol has no floating point anywhere (see canonical.go).
type Record struct {
	// Seq is the worker-local, 1-based sequence number of the request. It must
	// be unique inside a worker; verification does not require it to be
	// contiguous, so a worker that dropped a scheduled request leaves a gap
	// that is visible in the evidence.
	Seq uint64 `json:"seq"`
	// Worker is the id of the worker that made the request. It must match the
	// id of the worker bundle the record is verified against.
	Worker string `json:"worker"`
	// StartNS is the intended-slot-relative wall clock (Unix nanoseconds) at
	// which the request was sent.
	StartNS int64 `json:"start_ns"`
	// LatencyNS is the measured service time in nanoseconds: the interval from
	// sending the request to receiving the complete response.
	LatencyNS int64 `json:"latency_ns"`
	// Status is the protocol status code (HTTP status for HTTP runs). Zero
	// means no status was recorded, e.g. the request failed before a response.
	Status int `json:"status"`
	// Bytes is the number of response bytes attributed to the request. Zero is
	// valid and means "not recorded" or "empty response".
	Bytes int64 `json:"bytes"`
}

// Limits on record fields. They are generous but finite so that a malformed or
// hostile sidecar cannot create absurd values that later overflow arithmetic.
const (
	// MaxWorkerIDLen bounds a worker identifier.
	MaxWorkerIDLen = 128
	// MaxStatus bounds a protocol status code.
	MaxStatus = 999
	// MaxSampleLineBytes bounds one sidecar line. A canonical record is about
	// 120 bytes; 16 KiB leaves room for a long worker id and future fields.
	MaxSampleLineBytes = 16 << 10
	// DefaultMaxSamplesPerWorker is the per-worker record cap applied by
	// LoadSamples unless overridden.
	DefaultMaxSamplesPerWorker = 5_000_000
	// DefaultMaxSamplesTotal is the whole-file record cap.
	DefaultMaxSamplesTotal = 10_000_000
)

// Validate reports whether the record is well formed. A negative latency is
// rejected here: it would mean the response arrived before it was sent, and
// allowing it would let a worker commit evidence that no real clock can
// produce.
func (r Record) Validate() error {
	switch {
	case r.Worker == "":
		return errors.New("record: worker id is empty")
	case len(r.Worker) > MaxWorkerIDLen:
		return fmt.Errorf("record: worker id is %d bytes, limit is %d", len(r.Worker), MaxWorkerIDLen)
	case !utf8.ValidString(r.Worker):
		return errors.New("record: worker id is not valid UTF-8")
	case r.Seq == 0:
		return errors.New("record: seq must be >= 1")
	case r.StartNS < 0:
		return fmt.Errorf("record: start_ns %d is negative", r.StartNS)
	case r.LatencyNS < 0:
		return fmt.Errorf("record: latency_ns %d is negative", r.LatencyNS)
	case r.Bytes < 0:
		return fmt.Errorf("record: bytes %d is negative", r.Bytes)
	case r.Status < 0 || r.Status > MaxStatus:
		return fmt.Errorf("record: status %d is outside 0..%d", r.Status, MaxStatus)
	}
	return nil
}

// CanonicalRecord renders the record as canonical JSON without a trailing
// newline. These exact bytes are the Merkle leaf value for the record, which is
// why an invalid record is rejected here rather than encoded.
func CanonicalRecord(r Record) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	worker, err := cstr(r.Worker)
	if err != nil {
		return nil, err
	}
	return encode(cObject{
		"bytes":      cInt(r.Bytes),
		"latency_ns": cInt(r.LatencyNS),
		"seq":        cUint(r.Seq),
		"start_ns":   cInt(r.StartNS),
		"status":     cInt(int64(r.Status)),
		"worker":     worker,
	}), nil
}

// RecordDigest returns the SHA-256 leaf hash of a record at the given index, as
// it appears in the worker's tree. It is exposed for tooling that prints or
// cross-checks individual leaves.
func RecordDigest(index int, r Record) ([]byte, error) {
	line, err := CanonicalRecord(r)
	if err != nil {
		return nil, err
	}
	return LeafHash(index, line), nil
}

// -----------------------------------------------------------------------------
// Sidecar stream
// -----------------------------------------------------------------------------

// SampleWriter streams canonical record lines to an io.Writer.
//
// It is the producer side of the sidecar: one record per line, keys in
// canonical order, no whitespace. Buffering happens in the writer, so a run can
// append evidence while it measures; Close must be called to flush.
type SampleWriter struct {
	w   *bufio.Writer
	buf []byte
	err error
}

// NewSampleWriter returns a writer that emits canonical JSONL records.
func NewSampleWriter(w io.Writer) *SampleWriter {
	return &SampleWriter{w: bufio.NewWriterSize(w, 64<<10)}
}

// Write encodes and buffers one record. After the first error, Write is a no-op
// and returns the original error, so a caller may keep writing in a loop and
// check once at the end.
func (sw *SampleWriter) Write(r Record) error {
	if sw.err != nil {
		return sw.err
	}
	line, err := CanonicalRecord(r)
	if err != nil {
		sw.err = err
		return err
	}
	sw.buf = append(sw.buf[:0], line...)
	sw.buf = append(sw.buf, '\n')
	if _, err := sw.w.Write(sw.buf); err != nil {
		sw.err = fmt.Errorf("samples: write line: %w", err)
		return sw.err
	}
	return nil
}

// Close flushes the buffer. It does not close the underlying writer.
func (sw *SampleWriter) Close() error {
	if sw.err != nil {
		return sw.err
	}
	if err := sw.w.Flush(); err != nil {
		sw.err = fmt.Errorf("samples: flush: %w", err)
	}
	return sw.err
}

// WriteSamples writes every record in order and flushes. It is a convenience
// wrapper around SampleWriter for callers that already hold the whole slice.
func WriteSamples(w io.Writer, recs []Record) error {
	sw := NewSampleWriter(w)
	for _, r := range recs {
		if err := sw.Write(r); err != nil {
			return err
		}
	}
	return sw.Close()
}

// SampleLoadOptions bounds and configures sidecar loading. The zero value is
// not useful; use DefaultSampleLoadOptions and adjust.
type SampleLoadOptions struct {
	// MaxSamplesPerWorker caps the records accepted for a single worker.
	MaxSamplesPerWorker int
	// MaxSamplesTotal caps the records accepted for the whole file.
	MaxSamplesTotal int
	// MaxLineBytes caps a single line.
	MaxLineBytes int
	// SkipCanonicalCheck disables the byte-for-byte canonical form check. The
	// check costs one extra canonical encoding per line and is what makes a
	// hand-edited or differently-formatted sidecar visible before any crypto
	// runs; leave it off unless loading is the bottleneck on a trusted file.
	SkipCanonicalCheck bool
}

// DefaultSampleLoadOptions returns the limits used by the verify command.
func DefaultSampleLoadOptions() SampleLoadOptions {
	return SampleLoadOptions{
		MaxSamplesPerWorker: DefaultMaxSamplesPerWorker,
		MaxSamplesTotal:     DefaultMaxSamplesTotal,
		MaxLineBytes:        MaxSampleLineBytes,
	}
}

// SampleLoadStats reports what LoadSamples saw. NonCanonicalLines and
// UnsortedLines are diagnostics: they do not fail the load, because
// verification is defined over the *values* in the file, but they tell a
// producer that its writer is not emitting the canonical form.
type SampleLoadStats struct {
	// Lines is the number of non-blank lines read.
	Lines int
	// Records is the number of accepted records (equal to Lines unless a line
	// failed canonical validation of the *line* itself, which is a warning,
	// not an error).
	Records int
	// BlankLines counts empty or whitespace-only lines.
	BlankLines int
	// NonCanonicalLines counts lines that parse but whose bytes differ from
	// their canonical encoding (extra fields, different key order, number
	// formatting, whitespace).
	NonCanonicalLines int
	// UnsortedLines counts records that were out of order relative to the
	// previous record of the same worker when compared by (start_ns, seq).
	UnsortedLines int
	// Bytes is the number of bytes read from the file.
	Bytes int64
	// Workers is the number of distinct worker ids seen.
	Workers int
}

// VerifyReader verifies that every line of r is a canonical record, without
// keeping the records. It is the cheap pre-flight a producer can run on its own
// sidecar before shipping it.
func VerifyReader(r io.Reader, opts SampleLoadOptions) (SampleLoadStats, error) {
	_, stats, err := loadSamples(r, opts)
	return stats, err
}

// LoadSamples reads a sidecar file into records grouped by worker id.
//
// Blank lines are skipped; a truncated final line, invalid UTF-8, a malformed
// record, a line over the size limit, a duplicate seq inside a worker or a
// count over the configured caps are all errors — the loader never returns
// partial evidence as if it were complete.
func LoadSamples(path string, opts SampleLoadOptions) (map[string][]Record, SampleLoadStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, SampleLoadStats{}, err
	}
	defer func() { _ = f.Close() }()
	return loadSamples(f, opts)
}

func loadSamples(r io.Reader, opts SampleLoadOptions) (map[string][]Record, SampleLoadStats, error) {
	opts = opts.withDefaults()
	var stats SampleLoadStats

	counted := &countingReader{r: r}
	scanner := bufio.NewScanner(counted)
	scanner.Buffer(make([]byte, 0, 8<<10), opts.MaxLineBytes)

	out := make(map[string][]Record)
	seenSeq := make(map[string]map[uint64]struct{})
	lastKey := make(map[string][2]int64)
	total := 0
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			stats.BlankLines++
			continue
		}
		stats.Lines++

		if !utf8.Valid(line) {
			return nil, stats, fmt.Errorf("samples: line %d is not valid UTF-8", lineNo)
		}
		var rec Record
		dec := json.NewDecoder(bytes.NewReader(line))
		if err := dec.Decode(&rec); err != nil {
			return nil, stats, fmt.Errorf("samples: line %d is not a valid record: %w", lineNo, err)
		}
		if dec.More() {
			return nil, stats, fmt.Errorf("samples: line %d contains trailing JSON data", lineNo)
		}
		if err := rec.Validate(); err != nil {
			return nil, stats, fmt.Errorf("samples: line %d: %w", lineNo, err)
		}

		if !opts.SkipCanonicalCheck {
			canonical, err := CanonicalRecord(rec)
			if err != nil {
				return nil, stats, fmt.Errorf("samples: line %d: %w", lineNo, err)
			}
			if !bytes.Equal(canonical, bytes.TrimRight(line, "\r")) {
				stats.NonCanonicalLines++
			}
		}

		seqs := seenSeq[rec.Worker]
		if seqs == nil {
			seqs = make(map[uint64]struct{})
			seenSeq[rec.Worker] = seqs
		}
		if _, dup := seqs[rec.Seq]; dup {
			return nil, stats, fmt.Errorf("samples: line %d: worker %q repeats seq %d", lineNo, rec.Worker, rec.Seq)
		}
		seqs[rec.Seq] = struct{}{}

		if prev, ok := lastKey[rec.Worker]; ok {
			if rec.StartNS < prev[0] || (rec.StartNS == prev[0] && int64(rec.Seq) < prev[1]) {
				stats.UnsortedLines++
			}
		}
		lastKey[rec.Worker] = [2]int64{rec.StartNS, int64(rec.Seq)}

		if len(out[rec.Worker]) >= opts.MaxSamplesPerWorker {
			return nil, stats, fmt.Errorf("samples: worker %q exceeds the %d record limit", rec.Worker, opts.MaxSamplesPerWorker)
		}
		total++
		if total > opts.MaxSamplesTotal {
			return nil, stats, fmt.Errorf("samples: file exceeds the %d record limit", opts.MaxSamplesTotal)
		}
		out[rec.Worker] = append(out[rec.Worker], rec)
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, stats, fmt.Errorf("samples: line %d exceeds the %d byte limit", lineNo+1, opts.MaxLineBytes)
		}
		return nil, stats, fmt.Errorf("samples: read: %w", err)
	}

	stats.Records = total
	stats.Bytes = counted.n
	stats.Workers = len(out)
	return out, stats, nil
}

func (o SampleLoadOptions) withDefaults() SampleLoadOptions {
	if o.MaxSamplesPerWorker <= 0 {
		o.MaxSamplesPerWorker = DefaultMaxSamplesPerWorker
	}
	if o.MaxSamplesTotal <= 0 {
		o.MaxSamplesTotal = DefaultMaxSamplesTotal
	}
	if o.MaxLineBytes <= 0 {
		o.MaxLineBytes = MaxSampleLineBytes
	}
	return o
}

// countingReader tracks how many bytes were consumed.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// SortRecords orders records by the canonical leaf order — (start_ns, seq)
// ascending — returning a new slice so the caller's data is untouched. The
// canonical order is what makes a proof index meaningful: leaf 42 is always
// the 43rd request that was sent, whatever order the sidecar happened to be
// written in.
func SortRecords(recs []Record) []Record {
	out := make([]Record, len(recs))
	copy(out, recs)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].StartNS != out[j].StartNS {
			return out[i].StartNS < out[j].StartNS
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

// RecordsInFileOrder reports whether recs is already in canonical leaf order.
// It is a diagnostic for producers, never a verification failure.
func RecordsInFileOrder(recs []Record) bool {
	for i := 1; i < len(recs); i++ {
		if recs[i-1].StartNS > recs[i].StartNS {
			return false
		}
		if recs[i-1].StartNS == recs[i].StartNS && recs[i-1].Seq > recs[i].Seq {
			return false
		}
	}
	return true
}

// SanitizeWorkerID is a small helper producers use to build a worker id that
// validates: it trims surrounding space and truncates to MaxWorkerIDLen. It
// deliberately does not rewrite the interior of the id, so two distinct
// workers never collapse into one.
func SanitizeWorkerID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) > MaxWorkerIDLen {
		id = id[:MaxWorkerIDLen]
	}
	return id
}
