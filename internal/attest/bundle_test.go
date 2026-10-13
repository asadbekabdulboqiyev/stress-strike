package attest

// bundle_test.go — the cover sheet: structural validation, canonical encoding,
// the digest, and persistence.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleValidateOK(t *testing.T) {
	b, _, _ := newFixture(t, false)
	if err := b.Validate(); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	if err := b.VerifyCoordinatorSig(); err != nil {
		t.Fatalf("coordinator signature invalid: %v", err)
	}
}

func TestBundleValidateMutationTable(t *testing.T) {
	cases := map[string]func(*Bundle){
		"bad_format":        func(b *Bundle) { b.Format = "vpmp/v2" },
		"bad_created_at":    func(b *Bundle) { b.CreatedAt = "yesterday" },
		"empty_tool_name":   func(b *Bundle) { b.Tool.Name = "" },
		"empty_version":     func(b *Bundle) { b.Tool.Version = "" },
		"empty_target":      func(b *Bundle) { b.Run.Target = "" },
		"empty_profile":     func(b *Bundle) { b.Run.Profile = "" },
		"zero_duration":     func(b *Bundle) { b.Run.DurationNS = 0 },
		"bad_planned_rps":   func(b *Bundle) { b.Run.PlannedRPS = "6.5" },
		"no_workers":        func(b *Bundle) { b.Workers = nil },
		"duplicate_worker":  func(b *Bundle) { b.Workers[1].ID = b.Workers[0].ID },
		"count_mismatch":    func(b *Bundle) { b.Aggregate.Count++ },
		"sum_mismatch":      func(b *Bundle) { b.Aggregate.SumLatencyNS++ },
		"percentile_order":  func(b *Bundle) { b.Aggregate.P95NS = b.Aggregate.P99NS + 1 },
		"bad_rps_decimal":   func(b *Bundle) { b.Aggregate.RPS = "1000" },
		"integrity_planned": func(b *Bundle) { b.Integrity.PlannedRPS = "7.000" },
		"integrity_accuracy": func(b *Bundle) {
			b.Integrity.ScheduleAccuracyPPM = 1_000_001
		},
		"bad_sig_alg":    func(b *Bundle) { b.Signature.Alg = "rsa" },
		"bad_sig_covers": func(b *Bundle) { b.Signature.Covers = "something-else" },
		"short_sig":      func(b *Bundle) { b.Signature.Sig = "ab" },
		"commit_count_mismatch": func(b *Bundle) {
			b.Workers[0].Commit.SampleCount++
		},
		"zero_count_nonzero_hist": func(b *Bundle) {
			b.Workers[0].Aggregate = WorkerAgg{}
			b.Workers[0].Commit.SampleCount = 0
			b.Workers[0].Commit.MerkleRoot = EmptyRootHex
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b, _, _ := newFixture(t, false)
			mutate(&b)
			if err := b.Validate(); err == nil {
				t.Fatalf("bundle %s passed Validate", name)
			}
		})
	}
}

// TestCanonicalBundleOrderIndependent proves the digest never depends on the
// order the workers happen to appear in the JSON.
func TestCanonicalBundleOrderIndependent(t *testing.T) {
	b, _, _ := newFixture(t, false)
	d1, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}

	reversed := b
	reversed.Workers = []WorkerBundle{b.Workers[1], b.Workers[0]}
	// The signature still verifies: the canonical form sorts workers by id.
	if err := reversed.VerifyCoordinatorSig(); err != nil {
		t.Fatalf("reordering workers broke the signature: %v", err)
	}
	d2, err := reversed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if string(d1) != string(d2) {
		t.Fatal("worker order changed the digest")
	}
}

func TestBundleDigestExcludesSignature(t *testing.T) {
	b, _, _ := newFixture(t, false)
	d1, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tampered := b
	tampered.Signature.Sig = strings.Repeat("0", 128)
	d2, err := tampered.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if string(d1) != string(d2) {
		t.Fatal("the signature leaked into the digest subject")
	}
	if err := tampered.VerifyCoordinatorSig(); err == nil {
		t.Fatal("a tampered signature still verified")
	}
}

func TestBundleCanonicalTopLevelKeyOrder(t *testing.T) {
	b, _, _ := newFixture(t, false)
	canon, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	s := string(canon)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		t.Fatalf("canonical bundle is not a single object: %.60s", s)
	}
	if strings.ContainsAny(s, "\n\t") {
		t.Fatalf("canonical bundle contains whitespace")
	}
	keys := []string{`"aggregate"`, `"created_at"`, `"format"`, `"integrity"`, `"run"`, `"signature"`, `"tool"`, `"workers"`}
	prev := -1
	for _, k := range keys {
		idx := strings.Index(s, k)
		if idx < 0 {
			t.Fatalf("top-level key %s missing", k)
		}
		if idx < prev {
			t.Fatalf("top-level key %s is out of order", k)
		}
		prev = idx
	}
}

func TestSaveLoadBundleRoundTrip(t *testing.T) {
	b, _, _ := newFixture(t, false)
	path := filepath.Join(t.TempDir(), "out", "bundle.json")
	if err := SaveBundle(b, path); err != nil {
		t.Fatalf("SaveBundle: %v", err)
	}
	loaded, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if err := loaded.Validate(); err != nil {
		t.Fatalf("loaded bundle invalid: %v", err)
	}
	if err := loaded.VerifyCoordinatorSig(); err != nil {
		t.Fatalf("loaded signature invalid: %v", err)
	}
	d1, _ := b.Digest()
	d2, _ := loaded.Digest()
	if string(d1) != string(d2) {
		t.Fatal("digest changed across save/load")
	}
}

func TestParseBundleRejectsTrailingData(t *testing.T) {
	if _, err := ParseBundle([]byte(`{"format":"vpmp/v1"} {"x":1}`)); err == nil {
		t.Fatal("trailing JSON data accepted")
	}
	if _, err := ParseBundle([]byte(`not json`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

// TestLoadBundleDoesNotValidate pins "reading is not trusting": a tampered
// bundle must load so Verify can explain what is wrong.
func TestLoadBundleDoesNotValidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"format":"wrong/v9","workers":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle rejected an unvalidated bundle: %v", err)
	}
	if b.Format != "wrong/v9" {
		t.Fatalf("format = %q", b.Format)
	}
	if b.Validate() == nil {
		t.Fatal("Validate accepted a malformed bundle")
	}
}

func TestBundleCoversConstant(t *testing.T) {
	if BundleCovers != "sha256(canonical-bundle-without-signature)" {
		t.Fatalf("BundleCovers = %q", BundleCovers)
	}
	b, _, _ := newFixture(t, false)
	if b.Signature.Covers != BundleCovers {
		t.Fatalf("signature.covers = %q", b.Signature.Covers)
	}
	if b.Format != FormatID {
		t.Fatalf("format = %q, want %q", b.Format, FormatID)
	}
}

func TestBundleSignRejectsNilKeypair(t *testing.T) {
	b, _, _ := newFixture(t, false)
	if err := b.Sign(nil); err == nil {
		t.Fatal("Sign(nil) did not error")
	}
}

func TestBundleDigestHexMatchesDigest(t *testing.T) {
	b, _, _ := newFixture(t, false)
	hexDigest, err := b.DigestHex()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if len(hexDigest) != 64 || hexDigest != hexOf(raw) {
		t.Fatalf("DigestHex = %q", hexDigest)
	}
}

// hexOf is a tiny local hex encoder to avoid importing encoding/hex for one use.
func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
