package attest

// bundle.go — the cover sheet of a VeriBench evidence pack.
//
// # The format at a glance (vpmp/v1)
//
// A bundle is one JSON document. Its members are, in canonical order:
//
//	{
//	  "format":    "vpmp/v1",
//	  "created_at":"2026-10-13T18:00:00Z",
//	  "tool":      { "name": "...", "version": "..." },
//	  "run":       { "target": "...", "profile": "...",
//	                 "duration_ns": 10000000000, "planned_rps": "1000.000" },
//	  "workers": [
//	    { "id": "w1", "public_key": "<hex>",
//	      "commit":    { "merkle_root": "<hex>", "sample_count": N,
//	                     "window_start_ns": T0, "window_end_ns": T1,
//	                     "signature": "<hex>" },
//	      "aggregate": { "count": N, "sum_latency_ns": S,
//	                     "min_ns": A, "max_ns": B, "hist": { "<ns>": C } } }
//	  ],
//	  "aggregate": { "count": N, "sum_latency_ns": S,
//	                 "p50_ns": ..., "p95_ns": ..., "p99_ns": ...,
//	                 "rps": "1000.000", "co_corrected": false,
//	                 "co_ci95_ns": { "low_ns": 0, "high_ns": 0 } },
//	  "integrity": { "schedule_accuracy_ppm": 999000, "dropped_samples": 0,
//	                 "achieved_rps": "1000.000", "planned_rps": "1000.000" },
//	  "signature": { "alg": "ed25519", "key": "<hex>", "sig": "<hex>",
//	                 "covers": "sha256(canonical-bundle-without-signature)" }
//	}
//
// There is no floating point anywhere: rates are exact decimal strings with
// three fractional digits (see Decimal), everything else is an integer. That
// restriction is what makes the canonical encoding (canonical.go) and therefore
// the digest reproducible by any language on any platform.
//
// # Digest and signature
//
// Digest() is the SHA-256 of the *canonical bundle with the signature member
// removed*. The coordinator signature is an Ed25519 signature over those 32
// bytes; signature.covers records that choice. The workers array is sorted by
// worker id before hashing, so the order workers happen to appear in the JSON
// never changes the digest.
//
// # Reading is not trusting
//
// LoadBundle does not validate: a bundle that has been tampered with must still
// load, so that verify.go can report *what* is wrong. Validate and Verify are
// where trust is established.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
	"unicode/utf8"
)

// FormatID is the frozen format identifier carried by every bundle.
const FormatID = "vpmp/v1"

// BundleCovers is the documented subject of the coordinator signature.
const BundleCovers = "sha256(canonical-bundle-without-signature)"

// maxBundleBytes bounds a bundle read. A bundle is a summary document; 128 MiB
// is far more than any honest bundle needs and small enough that a hostile file
// cannot exhaust memory.
const maxBundleBytes = 128 << 20

// Tool identifies the software that produced the bundle.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Run describes the measurement scenario.
type Run struct {
	// Target is the URL or endpoint that was exercised.
	Target string `json:"target"`
	// Profile is the load profile name (e.g. "constant-rps").
	Profile string `json:"profile"`
	// DurationNS is the planned run duration in nanoseconds.
	DurationNS int64 `json:"duration_ns"`
	// PlannedRPS is the paced target rate, as an exact Decimal.
	PlannedRPS Decimal `json:"planned_rps"`
}

// WorkerAgg is the untrusted-but-recomputable summary a worker publishes next
// to its commit.
type WorkerAgg struct {
	// Count is the number of measured requests.
	Count uint64 `json:"count"`
	// SumLatencyNS is the sum of raw measured latencies, in nanoseconds.
	SumLatencyNS uint64 `json:"sum_latency_ns"`
	// MinNS and MaxNS bound the raw measured latencies.
	MinNS int64 `json:"min_ns"`
	MaxNS int64 `json:"max_ns"`
	// Hist is a power-of-two histogram: the key is the bucket's inclusive upper
	// bound in nanoseconds as a canonical decimal string, the value the number
	// of requests whose latency fell in that bucket. The counts sum to Count.
	Hist map[string]uint64 `json:"hist"`
}

// WorkerBundle ties a worker identity, its commit and its aggregate together.
type WorkerBundle struct {
	// ID is the worker identifier, matching every record's worker field.
	ID string `json:"id"`
	// PublicKey is the lowercase hex Ed25519 public key that signs the commit.
	PublicKey string `json:"public_key"`
	// Commit is the worker's signed commitment to its evidence.
	Commit Commit `json:"commit"`
	// Aggregate is the worker's claim about its latency distribution.
	Aggregate WorkerAgg `json:"aggregate"`
}

// CI95 is a 95% confidence interval in nanoseconds for the corrected p99.
// A zero interval is the honest encoding of "not computed" (co_corrected is
// false, or there is too little evidence to resample).
type CI95 struct {
	// LowNS is the lower bound (inclusive).
	LowNS int64 `json:"low_ns"`
	// HighNS is the upper bound (inclusive).
	HighNS int64 `json:"high_ns"`
}

// Aggregate is the run-wide summary.
type Aggregate struct {
	Count        uint64  `json:"count"`
	SumLatencyNS uint64  `json:"sum_latency_ns"`
	P50NS        int64   `json:"p50_ns"`
	P95NS        int64   `json:"p95_ns"`
	P99NS        int64   `json:"p99_ns"`
	RPS          Decimal `json:"rps"`
	COCorrected  bool    `json:"co_corrected"`
	COCI95NS     CI95    `json:"co_ci95_ns"`
}

// Integrity carries the pacing bookkeeping.
type Integrity struct {
	// ScheduleAccuracyPPM is 1e6 minus the parts-per-million deviation of the
	// achieved rate from the planned rate (so 1_000_000 means "exactly on
	// schedule").
	ScheduleAccuracyPPM int64 `json:"schedule_accuracy_ppm"`
	// DroppedSamples is the number of planned request slots that produced no
	// recorded sample.
	DroppedSamples uint64 `json:"dropped_samples"`
	// AchievedRPS is the measured rate as an exact Decimal; it must equal
	// aggregate.rps.
	AchievedRPS Decimal `json:"achieved_rps"`
	// PlannedRPS is a copy of run.planned_rps; the two must agree.
	PlannedRPS Decimal `json:"planned_rps"`
}

// BundleSignature is the coordinator's digital seal.
type BundleSignature struct {
	// Alg is the signature algorithm; vpmp/v1 only defines "ed25519".
	Alg string `json:"alg"`
	// Key is the lowercase hex Ed25519 public key of the coordinator.
	Key string `json:"key"`
	// Sig is the lowercase hex Ed25519 signature over Digest().
	Sig string `json:"sig"`
	// Covers names what the signature is over; it must equal BundleCovers.
	Covers string `json:"covers"`
}

// Bundle is a complete evidence pack.
type Bundle struct {
	Format    string          `json:"format"`
	CreatedAt string          `json:"created_at"`
	Tool      Tool            `json:"tool"`
	Run       Run             `json:"run"`
	Workers   []WorkerBundle  `json:"workers"`
	Aggregate Aggregate       `json:"aggregate"`
	Integrity Integrity       `json:"integrity"`
	Signature BundleSignature `json:"signature"`
}

// sha256Sum returns the SHA-256 digest of b as a fresh slice.
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// -----------------------------------------------------------------------------
// Structural validation
// -----------------------------------------------------------------------------

// Validate checks every structural invariant of a bundle that can be checked
// without holding the sidecar: shapes, ranges, the cross-sums between workers
// and the global aggregate, the rate identities and the pacing bookkeeping.
//
// It is deliberately strict — the protocol prefers a loud rejection over a
// plausible-looking bundle whose numbers do not add up — but it is total: a
// malformed bundle produces an error, never a panic.
func (b Bundle) Validate() error {
	if b.Format != FormatID {
		return fmt.Errorf("bundle: format is %q, want %q", b.Format, FormatID)
	}
	if _, err := time.Parse(time.RFC3339, b.CreatedAt); err != nil {
		return fmt.Errorf("bundle: created_at %q is not RFC3339: %w", b.CreatedAt, err)
	}
	if err := validTextField("tool.name", b.Tool.Name); err != nil {
		return err
	}
	if b.Tool.Version == "" {
		return errors.New("bundle: tool.version is empty")
	}
	if err := validTextField("run.target", b.Run.Target); err != nil {
		return err
	}
	if b.Run.Profile == "" {
		return errors.New("bundle: run.profile is empty")
	}
	if b.Run.DurationNS <= 0 {
		return fmt.Errorf("bundle: run.duration_ns %d must be positive", b.Run.DurationNS)
	}
	if !b.Run.PlannedRPS.Valid() {
		return fmt.Errorf("bundle: run.planned_rps %q is not a canonical decimal", b.Run.PlannedRPS)
	}
	if len(b.Workers) == 0 {
		return errors.New("bundle: workers is empty")
	}

	seen := make(map[string]struct{}, len(b.Workers))
	var sumCount uint64
	var sumLatency uint64
	for i := range b.Workers {
		w := &b.Workers[i]
		if _, dup := seen[w.ID]; dup {
			return fmt.Errorf("bundle: duplicate worker id %q", w.ID)
		}
		seen[w.ID] = struct{}{}
		if err := w.validate(); err != nil {
			return err
		}
		var err error
		sumCount, err = addUint(sumCount, w.Aggregate.Count)
		if err != nil {
			return err
		}
		sumLatency, err = addUint(sumLatency, w.Aggregate.SumLatencyNS)
		if err != nil {
			return err
		}
	}

	if err := b.Aggregate.validate(); err != nil {
		return err
	}
	if b.Aggregate.Count != sumCount {
		return fmt.Errorf("bundle: aggregate.count %d does not match the %d requests summed over workers", b.Aggregate.Count, sumCount)
	}
	if b.Aggregate.SumLatencyNS != sumLatency {
		return fmt.Errorf("bundle: aggregate.sum_latency_ns %d does not match the %d summed over workers", b.Aggregate.SumLatencyNS, sumLatency)
	}

	if err := b.Integrity.validate(b.Run, b.Aggregate); err != nil {
		return err
	}
	if err := b.Signature.validate(); err != nil {
		return err
	}
	return nil
}

func (w WorkerBundle) validate() error {
	if err := validTextField("worker.id", w.ID); err != nil {
		return err
	}
	if err := validateHexFixed(w.PublicKey, publicKeyHexLen); err != nil {
		return fmt.Errorf("bundle: worker %q public_key %w", w.ID, err)
	}
	if err := w.Commit.Validate(); err != nil {
		return fmt.Errorf("bundle: worker %q: %w", w.ID, err)
	}
	if w.Commit.SampleCount != w.Aggregate.Count {
		return fmt.Errorf("bundle: worker %q commit.sample_count %d does not match aggregate.count %d", w.ID, w.Commit.SampleCount, w.Aggregate.Count)
	}
	if err := w.Aggregate.validate(); err != nil {
		return fmt.Errorf("bundle: worker %q: %w", w.ID, err)
	}
	return nil
}

func (a WorkerAgg) validate() error {
	if a.Count == 0 {
		if a.SumLatencyNS != 0 || a.MinNS != 0 || a.MaxNS != 0 {
			return errors.New("aggregate: zero count must have zero sum, min and max")
		}
		if len(a.Hist) != 0 {
			return errors.New("aggregate: zero count must have an empty histogram")
		}
		return nil
	}
	if a.MinNS < 0 {
		return fmt.Errorf("aggregate: min_ns %d is negative", a.MinNS)
	}
	if a.MaxNS < a.MinNS {
		return fmt.Errorf("aggregate: max_ns %d is below min_ns %d", a.MaxNS, a.MinNS)
	}
	if len(a.Hist) == 0 {
		return errors.New("aggregate: non-zero count must have a histogram")
	}
	var histTotal uint64
	for key, n := range a.Hist {
		if _, err := parseBucketUpperNS(key); err != nil {
			return fmt.Errorf("aggregate: histogram key %q: %w", key, err)
		}
		if n == 0 {
			return fmt.Errorf("aggregate: histogram key %q has a zero count", key)
		}
		var err error
		histTotal, err = addUint(histTotal, n)
		if err != nil {
			return err
		}
	}
	if histTotal != a.Count {
		return fmt.Errorf("aggregate: histogram counts sum to %d, want %d", histTotal, a.Count)
	}
	return nil
}

func (a Aggregate) validate() error {
	if a.Count == 0 {
		if a.SumLatencyNS != 0 || a.P50NS != 0 || a.P95NS != 0 || a.P99NS != 0 {
			return errors.New("bundle: zero aggregate.count must have zero latencies")
		}
	} else {
		if a.P50NS < 0 || a.P95NS < a.P50NS || a.P99NS < a.P95NS {
			return fmt.Errorf("bundle: percentiles must satisfy 0 <= p50 <= p95 <= p99 (got %d, %d, %d)", a.P50NS, a.P95NS, a.P99NS)
		}
	}
	if !a.RPS.Valid() {
		return fmt.Errorf("bundle: aggregate.rps %q is not a canonical decimal", a.RPS)
	}
	if a.COCI95NS.LowNS < 0 || a.COCI95NS.HighNS < a.COCI95NS.LowNS {
		return fmt.Errorf("bundle: co_ci95_ns must satisfy 0 <= low <= high (got %d, %d)", a.COCI95NS.LowNS, a.COCI95NS.HighNS)
	}
	return nil
}

func (in Integrity) validate(run Run, agg Aggregate) error {
	if in.PlannedRPS != run.PlannedRPS {
		return fmt.Errorf("bundle: integrity.planned_rps %q does not match run.planned_rps %q", in.PlannedRPS, run.PlannedRPS)
	}
	if !in.AchievedRPS.Valid() {
		return fmt.Errorf("bundle: integrity.achieved_rps %q is not a canonical decimal", in.AchievedRPS)
	}
	if in.AchievedRPS != agg.RPS {
		return fmt.Errorf("bundle: integrity.achieved_rps %q does not match aggregate.rps %q", in.AchievedRPS, agg.RPS)
	}
	if in.ScheduleAccuracyPPM < 0 || in.ScheduleAccuracyPPM > ppmScale {
		return fmt.Errorf("bundle: integrity.schedule_accuracy_ppm %d is outside 0..%d", in.ScheduleAccuracyPPM, ppmScale)
	}
	return nil
}

func (s BundleSignature) validate() error {
	if s.Alg != "ed25519" {
		return fmt.Errorf("bundle: signature.alg %q is not supported", s.Alg)
	}
	if err := validateHexFixed(s.Key, publicKeyHexLen); err != nil {
		return fmt.Errorf("bundle: signature.key %w", err)
	}
	if err := validateHexFixed(s.Sig, signatureHexLen); err != nil {
		return fmt.Errorf("bundle: signature.sig %w", err)
	}
	if s.Covers != BundleCovers {
		return fmt.Errorf("bundle: signature.covers %q is not %q", s.Covers, BundleCovers)
	}
	return nil
}

// validTextField rejects empty, over-long or non-UTF-8 free-text fields.
func validTextField(name, v string) error {
	switch {
	case v == "":
		return fmt.Errorf("bundle: %s is empty", name)
	case len(v) > MaxWorkerIDLen*8:
		return fmt.Errorf("bundle: %s is %d bytes, which is implausibly long", name, len(v))
	case !utf8.ValidString(v):
		return fmt.Errorf("bundle: %s is not valid UTF-8", name)
	}
	return nil
}

// addUint adds two counts, refusing to wrap.
func addUint(a, b uint64) (uint64, error) {
	sum := a + b
	if sum < a {
		return 0, errors.New("bundle: count overflow")
	}
	return sum, nil
}

// -----------------------------------------------------------------------------
// Canonical encoding and digest
// -----------------------------------------------------------------------------

// canonicalValue builds the restricted canonical value model of the bundle.
// Worker order is normalised to ascending worker id so the digest never depends
// on the order the JSON happened to list workers in.
func (b Bundle) canonicalValue(withSig bool) (cObject, error) {
	obj := cObject{
		"format":     cString(b.Format),
		"created_at": cString(b.CreatedAt),
		"tool": cObject{
			"name":    cString(b.Tool.Name),
			"version": cString(b.Tool.Version),
		},
		"run": cObject{
			"target":      cString(b.Run.Target),
			"profile":     cString(b.Run.Profile),
			"duration_ns": cInt(b.Run.DurationNS),
			"planned_rps": cString(string(b.Run.PlannedRPS)),
		},
		"aggregate": cObject{
			"count":          cUint(b.Aggregate.Count),
			"sum_latency_ns": cUint(b.Aggregate.SumLatencyNS),
			"p50_ns":         cInt(b.Aggregate.P50NS),
			"p95_ns":         cInt(b.Aggregate.P95NS),
			"p99_ns":         cInt(b.Aggregate.P99NS),
			"rps":            cString(string(b.Aggregate.RPS)),
			"co_corrected":   cBool(b.Aggregate.COCorrected),
			"co_ci95_ns": cObject{
				"low_ns":  cInt(b.Aggregate.COCI95NS.LowNS),
				"high_ns": cInt(b.Aggregate.COCI95NS.HighNS),
			},
		},
		"integrity": cObject{
			"schedule_accuracy_ppm": cInt(b.Integrity.ScheduleAccuracyPPM),
			"dropped_samples":       cUint(b.Integrity.DroppedSamples),
			"achieved_rps":          cString(string(b.Integrity.AchievedRPS)),
			"planned_rps":           cString(string(b.Integrity.PlannedRPS)),
		},
	}

	sorted := make([]WorkerBundle, len(b.Workers))
	copy(sorted, b.Workers)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	workers := make(cArray, 0, len(sorted))
	for i := range sorted {
		w := &sorted[i]
		commit, err := canonicalCommitValue(w.Commit, true)
		if err != nil {
			return nil, err
		}
		hist := cObject{}
		for k, v := range w.Aggregate.Hist {
			hist[k] = cUint(v)
		}
		workers = append(workers, cObject{
			"id":         cString(w.ID),
			"public_key": cString(w.PublicKey),
			"commit":     commit,
			"aggregate": cObject{
				"count":          cUint(w.Aggregate.Count),
				"sum_latency_ns": cUint(w.Aggregate.SumLatencyNS),
				"min_ns":         cInt(w.Aggregate.MinNS),
				"max_ns":         cInt(w.Aggregate.MaxNS),
				"hist":           hist,
			},
		})
	}
	obj["workers"] = workers

	if withSig {
		obj["signature"] = cObject{
			"alg":    cString(b.Signature.Alg),
			"key":    cString(b.Signature.Key),
			"sig":    cString(b.Signature.Sig),
			"covers": cString(b.Signature.Covers),
		}
	}
	return obj, nil
}

// Canonical returns the canonical JSON encoding of the full bundle, including
// its signature.
func (b Bundle) Canonical() ([]byte, error) {
	obj, err := b.canonicalValue(true)
	if err != nil {
		return nil, err
	}
	return encode(obj), nil
}

// CanonicalUnsigned returns the canonical JSON encoding of the bundle with the
// signature member removed.
func (b Bundle) CanonicalUnsigned() ([]byte, error) {
	obj, err := b.canonicalValue(false)
	if err != nil {
		return nil, err
	}
	return encode(obj), nil
}

// Digest returns the 32-byte SHA-256 of CanonicalUnsigned — the exact bytes the
// coordinator signature covers.
func (b Bundle) Digest() ([]byte, error) {
	msg, err := b.CanonicalUnsigned()
	if err != nil {
		return nil, err
	}
	return sha256Sum(msg), nil
}

// DigestHex returns the lowercase hex form of Digest, the value printed to the
// user as the bundle fingerprint.
func (b Bundle) DigestHex() (string, error) {
	d, err := b.Digest()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(d), nil
}

// Sign fills in the coordinator signature. It sets alg, key and covers, takes
// the digest of the unsigned bundle and signs it.
func (b *Bundle) Sign(kp *Keypair) error {
	if kp == nil {
		return errors.New("bundle: Sign requires a coordinator keypair")
	}
	b.Signature = BundleSignature{
		Alg:    "ed25519",
		Key:    PublicKeyHex(kp.Public),
		Covers: BundleCovers,
	}
	digest, err := b.Digest()
	if err != nil {
		return err
	}
	sig, err := Sign(kp, digest)
	if err != nil {
		return err
	}
	b.Signature.Sig = hex.EncodeToString(sig)
	return nil
}

// VerifyCoordinatorSig checks that the coordinator signature is a valid
// Ed25519 signature over the bundle digest by the key the bundle names.
//
// It establishes authorship *relative to the key in the document*. To pin a
// coordinator identity out of band, compare Signature.Key against a key the
// verifier already trusts (see LoadPublicKeyPEM).
func (b Bundle) VerifyCoordinatorSig() error {
	if err := b.Signature.validate(); err != nil {
		return err
	}
	pub, err := ParsePublicKeyHex(b.Signature.Key)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(b.Signature.Sig)
	if err != nil {
		return fmt.Errorf("bundle: signature.sig is not hex: %w", err)
	}
	digest, err := b.Digest()
	if err != nil {
		return err
	}
	if !VerifySig(pub, digest, sig) {
		return errors.New("bundle: coordinator signature does not verify against the canonical bundle")
	}
	return nil
}

// CoordinatorKey returns the public key the bundle names as its signer.
func (b Bundle) CoordinatorKey() (string, error) {
	return b.Signature.Key, b.Signature.validate()
}

// -----------------------------------------------------------------------------
// Persistence
// -----------------------------------------------------------------------------

// SaveBundle writes the canonical bundle (plus a trailing newline) atomically
// with mode 0644.
func SaveBundle(b Bundle, path string) error {
	data, err := b.Canonical()
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("bundle: create directory: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("bundle: create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("bundle: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("bundle: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("bundle: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("bundle: install: %w", err)
	}
	return nil
}

// LoadBundle reads and parses a bundle. It deliberately does not validate:
// a tampered bundle must load so that Verify can say what is wrong.
func LoadBundle(path string) (Bundle, error) {
	f, err := os.Open(path)
	if err != nil {
		return Bundle{}, err
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(io.LimitReader(f, maxBundleBytes+1))
	if err != nil {
		return Bundle{}, fmt.Errorf("bundle: read %s: %w", path, err)
	}
	if len(raw) > maxBundleBytes {
		return Bundle{}, fmt.Errorf("bundle: %s exceeds the %d byte limit", path, maxBundleBytes)
	}

	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&b); err != nil {
		return Bundle{}, fmt.Errorf("bundle: %s is not valid JSON: %w", path, err)
	}
	if dec.More() {
		return Bundle{}, fmt.Errorf("bundle: %s contains trailing JSON data", path)
	}
	return b, nil
}

// ParseBundle is LoadBundle for callers that already hold the bytes.
func ParseBundle(raw []byte) (Bundle, error) {
	if len(raw) > maxBundleBytes {
		return Bundle{}, fmt.Errorf("bundle: document exceeds the %d byte limit", maxBundleBytes)
	}
	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&b); err != nil {
		return Bundle{}, fmt.Errorf("bundle: not valid JSON: %w", err)
	}
	if dec.More() {
		return Bundle{}, errors.New("bundle: document contains trailing JSON data")
	}
	return b, nil
}
