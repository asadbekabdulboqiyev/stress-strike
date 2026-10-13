package attest

// commit.go — a worker's cryptographic commitment to its own raw evidence.
//
// A worker does not get to merely *claim* a summary. It first folds its receipt
// roll into a single Merkle root (merkle.go) and signs a tiny structure that
// pins four facts:
//
//   - merkle_root    : the fingerprint of every recorded request;
//   - sample_count   : how many requests are behind that fingerprint;
//   - window_start_ns: when the worker's first measured request was sent;
//   - window_end_ns  : when the worker's last measured request finished.
//
// # What the signature covers
//
// The signature is an Ed25519 signature over the 32-byte SHA-256 digest of the
// *canonical commit without its own signature field* — the label
// CommitCovers names that subject ("sha256(canonical-commit-without-signature)").
// Signing a digest rather than the raw encoding is what lets an independent
// implementation recompute the same bytes from the same four facts; signing the
// commit *including* its signature would be circular and is forbidden.
//
// # Why this is enough
//
// The commit is deliberately tiny. The worker's full aggregate (counts,
// latency sums, histogram) lives next to it in the bundle, and verify.go
// recomputes that aggregate from the receipt roll and checks it against both
// the commit's sample_count and the coordinator's global aggregate. So a worker
// cannot sign a fingerprint of evidence it does not have: the samples must
// reproduce the root *and* the numbers.

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math"
)

// CommitCovers is the documented subject of a commit signature. It is not
// emitted in the bundle (the commit has no covers field in vpmp/v1); it exists
// so that this package, its tests and the format document agree on the exact
// bytes that are signed.
const CommitCovers = "sha256(canonical-commit-without-signature)"

// merkleRootHexLen is the length of a lowercase hex SHA-256 digest.
const merkleRootHexLen = 64

// publicKeyHexLen is the length of a lowercase hex Ed25519 public key.
const publicKeyHexLen = 64

// signatureHexLen is the length of a lowercase hex Ed25519 signature.
const signatureHexLen = 128

// Commit is a worker's signed commitment to its evidence.
type Commit struct {
	// MerkleRoot is the lowercase hex Merkle root of the worker's canonical
	// records, in canonical leaf order (see SortRecords).
	MerkleRoot string `json:"merkle_root"`
	// SampleCount is the number of records committed. Zero is legal and means
	// the worker recorded nothing; its root must then be EmptyRootHex.
	SampleCount uint64 `json:"sample_count"`
	// WindowStartNS is the earliest start_ns among the committed records.
	WindowStartNS int64 `json:"window_start_ns"`
	// WindowEndNS is the latest (start_ns + latency_ns) among the committed
	// records: the moment the last measured request completed.
	WindowEndNS int64 `json:"window_end_ns"`
	// Signature is the lowercase hex Ed25519 signature over CommitDigest.
	Signature string `json:"signature"`
}

// ValidateUnsigned checks everything except the signature. It is used by
// producers that are about to sign, and during incremental construction.
func (c Commit) ValidateUnsigned() error {
	if err := validateHexFixed(c.MerkleRoot, merkleRootHexLen); err != nil {
		return fmt.Errorf("commit: merkle_root %w", err)
	}
	if c.WindowStartNS < 0 {
		return fmt.Errorf("commit: window_start_ns %d is negative", c.WindowStartNS)
	}
	if c.WindowEndNS < c.WindowStartNS {
		return fmt.Errorf("commit: window_end_ns %d precedes window_start_ns %d", c.WindowEndNS, c.WindowStartNS)
	}
	if c.SampleCount == 0 && c.MerkleRoot != EmptyRootHex {
		return fmt.Errorf("commit: zero samples must commit to the empty root %s", EmptyRootHex)
	}
	if c.SampleCount > 0 && c.MerkleRoot == EmptyRootHex {
		return fmt.Errorf("commit: %d samples cannot commit to the empty root", c.SampleCount)
	}
	return nil
}

// Validate checks the commit is complete and well formed, including the
// signature field's shape. It does not perform any cryptography; that is
// VerifyCommit.
func (c Commit) Validate() error {
	if err := c.ValidateUnsigned(); err != nil {
		return err
	}
	if err := validateHexFixed(c.Signature, signatureHexLen); err != nil {
		return fmt.Errorf("commit: signature %w", err)
	}
	return nil
}

// validateHexFixed reports whether s is canonical lowercase hex of exactly
// wantHex hex characters. It rejects uppercase and redundant encodings so that
// two spellings of the same key can never produce two different signed byte
// strings. Note that wantHex counts characters, not bytes: a 32-byte Ed25519
// public key is wantHex = 64.
func validateHexFixed(s string, wantHex int) error {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("is not valid hex: %w", err)
	}
	if len(raw) != wantHex/2 {
		return fmt.Errorf("is %d bytes, want %d", len(raw), wantHex/2)
	}
	if hex.EncodeToString(raw) != s {
		return fmt.Errorf("is not canonical lowercase hex")
	}
	return nil
}

// canonicalCommitValue renders the commit as the restricted canonical value
// model. When withSig is false the signature member is omitted — that tree is
// the exact subject of CommitDigest.
func canonicalCommitValue(c Commit, withSig bool) (cObject, error) {
	if withSig {
		if err := c.Validate(); err != nil {
			return nil, err
		}
	} else if err := c.ValidateUnsigned(); err != nil {
		return nil, err
	}

	root, err := cstr(c.MerkleRoot)
	if err != nil {
		return nil, err
	}
	obj := cObject{
		"merkle_root":     root,
		"sample_count":    cUint(c.SampleCount),
		"window_start_ns": cInt(c.WindowStartNS),
		"window_end_ns":   cInt(c.WindowEndNS),
	}
	if withSig {
		sig, err := cstr(c.Signature)
		if err != nil {
			return nil, err
		}
		obj["signature"] = sig
	}
	return obj, nil
}

// CanonicalCommit returns the canonical JSON encoding of the commit, including
// its signature. It is what a bundle's workers[].commit is stored as.
func CanonicalCommit(c Commit) ([]byte, error) {
	obj, err := canonicalCommitValue(c, true)
	if err != nil {
		return nil, err
	}
	return encode(obj), nil
}

// CanonicalCommitUnsigned returns the canonical JSON encoding of the commit
// with the signature member removed.
func CanonicalCommitUnsigned(c Commit) ([]byte, error) {
	obj, err := canonicalCommitValue(c, false)
	if err != nil {
		return nil, err
	}
	return encode(obj), nil
}

// CommitDigest returns the 32-byte SHA-256 digest of the canonical commit
// without its signature. This is the exact byte string a worker signs.
func CommitDigest(c Commit) ([]byte, error) {
	msg, err := CanonicalCommitUnsigned(c)
	if err != nil {
		return nil, err
	}
	return sha256Sum(msg), nil
}

// SignCommit signs the commit's digest with the worker's key and stores the
// lowercase hex signature in the commit. The previous signature, if any, is
// cleared before the digest is computed so signing is idempotent.
func SignCommit(kp *Keypair, c *Commit) error {
	if c == nil {
		return fmt.Errorf("commit: SignCommit requires a non-nil commit")
	}
	c.Signature = ""
	msg, err := CommitDigest(*c)
	if err != nil {
		return err
	}
	sig, err := Sign(kp, msg)
	if err != nil {
		return err
	}
	c.Signature = hex.EncodeToString(sig)
	return nil
}

// VerifyCommit checks a commit's shape and that its signature is valid for the
// given public key.
func VerifyCommit(pub ed25519.PublicKey, c Commit) error {
	if err := c.Validate(); err != nil {
		return err
	}
	msg, err := CommitDigest(c)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(c.Signature)
	if err != nil {
		return fmt.Errorf("commit: signature is not hex: %w", err)
	}
	if !VerifySig(pub, msg, sig) {
		return fmt.Errorf("commit: signature does not verify for this worker key")
	}
	return nil
}

// BuildCommit is the producer helper: it canonicalises the records, folds them
// into a Merkle root, derives the observation window and signs the result.
//
// It is the only supported way to create a commit, so a producer cannot invent
// a root that does not correspond to its own records. The window is the span
// from the first start_ns to the last (start_ns + latency_ns).
func BuildCommit(kp *Keypair, recs []Record) (Commit, error) {
	ordered := SortRecords(recs)
	leaves := make([][]byte, len(ordered))
	var start, end int64
	for i, r := range ordered {
		line, err := CanonicalRecord(r)
		if err != nil {
			return Commit{}, err
		}
		leaves[i] = line
		if r.StartNS > math.MaxInt64-r.LatencyNS {
			return Commit{}, fmt.Errorf("record: start_ns %d + latency_ns %d overflows int64", r.StartNS, r.LatencyNS)
		}
		finish := r.StartNS + r.LatencyNS
		if i == 0 || r.StartNS < start {
			start = r.StartNS
		}
		if i == 0 || finish > end {
			end = finish
		}
	}

	c := Commit{
		MerkleRoot:    MerkleRootHex(leaves),
		SampleCount:   uint64(len(ordered)),
		WindowStartNS: start,
		WindowEndNS:   end,
	}
	if len(ordered) == 0 {
		c.WindowStartNS = 0
		c.WindowEndNS = 0
	}
	if err := SignCommit(kp, &c); err != nil {
		return Commit{}, err
	}
	return c, nil
}
