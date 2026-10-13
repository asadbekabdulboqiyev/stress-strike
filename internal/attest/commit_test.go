package attest

// commit_test.go — a worker's signed commitment to its evidence.

import (
	"strings"
	"testing"
)

func TestBuildCommitAndVerify(t *testing.T) {
	kp := mustKey(t)
	recs := synthRecords("w1", 1_000_000_000, 5, 1_000_000, 500_000, 1_000)

	c, err := BuildCommit(kp, recs)
	if err != nil {
		t.Fatalf("BuildCommit: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := VerifyCommit(kp.Public, c); err != nil {
		t.Fatalf("VerifyCommit: %v", err)
	}
	if c.SampleCount != 5 {
		t.Fatalf("sample count = %d, want 5", c.SampleCount)
	}
	if c.WindowStartNS != 1_000_000_000 {
		t.Fatalf("window start = %d", c.WindowStartNS)
	}
	// Last record: start 1_004_000_000 + latency 504_000.
	if c.WindowEndNS != 1_004_504_000 {
		t.Fatalf("window end = %d, want 1004504000", c.WindowEndNS)
	}

	// Rebuild is deterministic.
	c2, err := BuildCommit(kp, recs)
	if err != nil {
		t.Fatal(err)
	}
	if c.MerkleRoot != c2.MerkleRoot || c.WindowEndNS != c2.WindowEndNS {
		t.Fatal("BuildCommit is not deterministic")
	}
	if c.Signature != c2.Signature {
		t.Fatal("Ed25519 signatures are not deterministic")
	}
}

func TestBuildCommitEmptyRecords(t *testing.T) {
	kp := mustKey(t)
	c, err := BuildCommit(kp, nil)
	if err != nil {
		t.Fatalf("BuildCommit(nil): %v", err)
	}
	if c.MerkleRoot != EmptyRootHex {
		t.Fatalf("root = %s, want the empty root", c.MerkleRoot)
	}
	if c.SampleCount != 0 || c.WindowStartNS != 0 || c.WindowEndNS != 0 {
		t.Fatalf("unexpected empty commit: %+v", c)
	}
	if err := VerifyCommit(kp.Public, c); err != nil {
		t.Fatalf("VerifyCommit on an empty commit: %v", err)
	}
}

func TestCommitDigestIgnoresSignature(t *testing.T) {
	kp := mustKey(t)
	c, err := BuildCommit(kp, synthRecords("w1", 0, 3, 1, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	d1, err := CommitDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Signature = strings.Repeat("0", 128)
	d2, err := CommitDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(d1) != string(d2) {
		t.Fatal("the signature leaked into the digest subject")
	}
}

func TestVerifyCommitRejectsTamperedField(t *testing.T) {
	kp := mustKey(t)
	c, err := BuildCommit(kp, synthRecords("w1", 0, 4, 1_000, 100, 10))
	if err != nil {
		t.Fatal(err)
	}
	c.SampleCount++
	if err := VerifyCommit(kp.Public, c); err == nil {
		t.Fatal("a tampered sample_count verified")
	}
}

func TestVerifyCommitRejectsWrongKey(t *testing.T) {
	kp, other := mustKey(t), mustKey(t)
	c, err := BuildCommit(kp, synthRecords("w1", 0, 3, 1, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCommit(other.Public, c); err == nil {
		t.Fatal("a commit verified under the wrong key")
	}
}

func TestCommitValidateRules(t *testing.T) {
	base := Commit{
		MerkleRoot:    strings.Repeat("ab", 32),
		SampleCount:   2,
		WindowStartNS: 10,
		WindowEndNS:   20,
		Signature:     strings.Repeat("cd", 64),
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("baseline commit invalid: %v", err)
	}

	cases := map[string]func(*Commit){
		"short_root":          func(c *Commit) { c.MerkleRoot = "abcd" },
		"uppercase_root":      func(c *Commit) { c.MerkleRoot = strings.ToUpper(strings.Repeat("ab", 32)) },
		"negative_start":      func(c *Commit) { c.WindowStartNS = -1 },
		"end_before_start":    func(c *Commit) { c.WindowEndNS = c.WindowStartNS - 1 },
		"zero_with_nonempty":  func(c *Commit) { c.SampleCount = 0 },
		"nonempty_with_empty": func(c *Commit) { c.MerkleRoot = EmptyRootHex },
		"short_signature":     func(c *Commit) { c.Signature = "ab" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("commit %s was accepted", name)
			}
		})
	}
}

func TestSignCommitIsIdempotent(t *testing.T) {
	kp := mustKey(t)
	c, err := BuildCommit(kp, synthRecords("w1", 0, 3, 1, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	first := c.Signature
	if err := SignCommit(kp, &c); err != nil {
		t.Fatal(err)
	}
	if c.Signature != first {
		t.Fatal("re-signing changed the signature")
	}
	if err := SignCommit(kp, nil); err == nil {
		t.Fatal("SignCommit(nil) did not error")
	}
}

func TestCanonicalCommitShape(t *testing.T) {
	c := Commit{
		MerkleRoot:    EmptyRootHex,
		SampleCount:   0,
		WindowStartNS: 0,
		WindowEndNS:   0,
		Signature:     strings.Repeat("0", 128),
	}
	unsigned, err := CanonicalCommitUnsigned(c)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"merkle_root":"` + EmptyRootHex + `","sample_count":0,"window_end_ns":0,"window_start_ns":0}`
	if string(unsigned) != want {
		t.Fatalf("canonical unsigned commit =\n  %s\nwant\n  %s", unsigned, want)
	}
	full, err := CanonicalCommit(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(full), `"signature"`) {
		t.Fatalf("signed commit is missing the signature member: %s", full)
	}
}

func TestCommitCoversConstant(t *testing.T) {
	if CommitCovers != "sha256(canonical-commit-without-signature)" {
		t.Fatalf("CommitCovers = %q", CommitCovers)
	}
}
