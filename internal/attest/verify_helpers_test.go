package attest

// verify_helpers_test.go — coverage for the pure helpers used by the verifier:
// bucket-key parsing, aggregate comparison, the proof sweep and the small
// integer/string utilities.

import (
	"bytes"
	"testing"
)

func TestParseBucketUpperNS(t *testing.T) {
	valid := map[string]int64{"0": 0, "1": 1, "3": 3, "7": 7, "1023": 1023}
	for in, want := range valid {
		got, err := parseBucketUpperNS(in)
		if err != nil {
			t.Errorf("parseBucketUpperNS(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseBucketUpperNS(%q) = %d, want %d", in, got, want)
		}
	}

	invalid := map[string]string{
		"":      "empty",
		"abc":   "non-numeric",
		"-1":    "negative",
		"007":   "non-canonical",
		"2":     "not 2^k-1",
		"1024":  "not 2^k-1",
		"99999": "not 2^k-1",
	}
	for in := range invalid {
		if _, err := parseBucketUpperNS(in); err == nil {
			t.Errorf("parseBucketUpperNS(%q) = nil error, want a rejection", in)
		}
	}
}

func TestCompareWorkerAgg(t *testing.T) {
	base := AggregateStats{
		Count:        10,
		SumLatencyNS: 500,
		MinNS:        3,
		MaxNS:        90,
		Hist:         map[string]uint64{"3": 4, "7": 6},
	}
	claim := WorkerAgg{
		Count:        10,
		SumLatencyNS: 500,
		MinNS:        3,
		MaxNS:        90,
		Hist:         map[string]uint64{"3": 4, "7": 6},
	}

	if err := compareWorkerAgg(base, claim); err != nil {
		t.Fatalf("compareWorkerAgg(matching) = %v, want nil", err)
	}

	cases := map[string]struct {
		mutate func(*AggregateStats)
		claim  WorkerAgg
	}{
		"count": {func(st *AggregateStats) { st.Count = 11 }, claim},
		"sum":   {func(st *AggregateStats) { st.SumLatencyNS = 501 }, claim},
		"min":   {func(st *AggregateStats) { st.MinNS = 2 }, claim},
		"max":   {func(st *AggregateStats) { st.MaxNS = 91 }, claim},
		"hist-key": {func(st *AggregateStats) {
			st.Hist = map[string]uint64{"3": 4, "15": 6}
		}, claim},
	}
	for name, tc := range cases {
		got := base
		tc.mutate(&got)
		// Copy the histogram so one mutation cannot leak into another case.
		if got.Hist != nil {
			clone := make(map[string]uint64, len(got.Hist))
			for k, v := range got.Hist {
				clone[k] = v
			}
			got.Hist = clone
		}
		if err := compareWorkerAgg(got, tc.claim); err == nil {
			t.Errorf("compareWorkerAgg(%s mismatch) = nil, want an error", name)
		}
	}

	// A different bucket count exercises the length check in equalHist.
	if err := compareWorkerAgg(AggregateStats{Hist: map[string]uint64{"3": 1}},
		WorkerAgg{Hist: map[string]uint64{"3": 1, "7": 0}}); err == nil {
		t.Error("compareWorkerAgg with a different bucket count = nil, want an error")
	}
}

func TestEqualHist(t *testing.T) {
	if !equalHist(nil, nil) {
		t.Error("equalHist(nil, nil) = false, want true")
	}
	if !equalHist(map[string]uint64{"1": 2}, map[string]uint64{"1": 2}) {
		t.Error("equalHist(equal) = false, want true")
	}
	if equalHist(map[string]uint64{"1": 2}, map[string]uint64{"1": 3}) {
		t.Error("equalHist(value mismatch) = true, want false")
	}
	if equalHist(map[string]uint64{"1": 2}, map[string]uint64{"2": 2}) {
		t.Error("equalHist(key mismatch) = true, want false")
	}
}

func TestSpreadIndices(t *testing.T) {
	if got := spreadIndices(0, 4); got != nil {
		t.Errorf("spreadIndices(0, 4) = %v, want nil", got)
	}
	if got := spreadIndices(-3, 2); got != nil {
		t.Errorf("spreadIndices(-3, 2) = %v, want nil", got)
	}

	if got := spreadIndices(3, 10); len(got) != 3 {
		t.Errorf("spreadIndices(3, 10) = %v, want every index", got)
	}
	if got := spreadIndices(8, 1); len(got) != 1 || got[0] != 0 {
		t.Errorf("spreadIndices(8, 1) = %v, want [0]", got)
	}
	if got := spreadIndices(8, 0); len(got) != 1 || got[0] != 0 {
		t.Errorf("spreadIndices(8, 0) = %v, want [0]", got)
	}

	got := spreadIndices(100, 5)
	if len(got) == 0 || got[0] != 0 {
		t.Fatalf("spreadIndices(100, 5) = %v, want to start at 0", got)
	}
	if got[len(got)-1] != 99 {
		t.Errorf("spreadIndices(100, 5) = %v, want to end at 99", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Errorf("spreadIndices(100, 5) = %v, want strictly increasing", got)
		}
	}

	// A tiny width over a larger n hits the duplicate-skip branch.
	for _, width := range []int{2, 3, 4} {
		res := spreadIndices(3, width)
		for i := 1; i < len(res); i++ {
			if res[i] == res[i-1] {
				t.Errorf("spreadIndices(3, %d) = %v, want distinct indices", width, res)
			}
		}
	}
}

func TestCeilLog2MaxIntShortHex(t *testing.T) {
	cases := map[int]int{0: 0, 1: 0, 2: 1, 3: 2, 4: 2, 5: 3, 8: 3, 9: 4}
	for in, want := range cases {
		if got := ceilLog2(in); got != want {
			t.Errorf("ceilLog2(%d) = %d, want %d", in, got, want)
		}
	}

	if got := maxInt(3, 7); got != 7 {
		t.Errorf("maxInt(3, 7) = %d, want 7", got)
	}
	if got := maxInt(9, 2); got != 9 {
		t.Errorf("maxInt(9, 2) = %d, want 9", got)
	}

	if got := shortHex("abcd"); got != "abcd" {
		t.Errorf("shortHex(short) = %q, want unchanged", got)
	}
	long := "0123456789abcdef0123456789abcdef"
	want := "01234567…89abcdef"
	if got := shortHex(long); got != want {
		t.Errorf("shortHex(long) = %q, want %q", got, want)
	}
}

func TestVerifyAllProofs(t *testing.T) {
	if first, fails, n := verifyAllProofs([]byte{1}, nil); first != -1 || fails != 0 || n != 0 {
		t.Errorf("verifyAllProofs(empty) = (%d, %d, %d), want (-1, 0, 0)", first, fails, n)
	}

	for _, size := range []int{1, 2, 3, 5, 8} {
		leaves := make([][]byte, size)
		for i := range leaves {
			leaves[i] = []byte{byte(i), byte(size)}
		}
		root := MerkleRoot(leaves)
		first, fails, n := verifyAllProofs(root, leaves)
		if first != -1 || fails != 0 || n != size {
			t.Errorf("verifyAllProofs(size=%d) = (%d, %d, %d), want (-1, 0, %d)", size, first, fails, n, size)
		}

		// The sweep rebuilds the sibling hashes from the given leaves, so one
		// corrupted leaf invalidates every path whose sibling chain crosses it
		// (in this tree shape that is all of them). The report still names the
		// first failing leaf and counts them, which is what the verifier uses.
		if size > 1 {
			bad := make([][]byte, size)
			copy(bad, leaves)
			bad[1] = []byte{0xff}
			first, fails, n = verifyAllProofs(root, bad)
			if first != 0 || fails != size || n != size {
				t.Errorf("verifyAllProofs(corrupt leaf 1, size=%d) = (%d, %d, %d), want (0, %d, %d)", size, first, fails, n, size, size)
			}
		}
	}

	// A root that matches nothing reports every leaf, starting at 0.
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	first, fails, n := verifyAllProofs(bytes.Repeat([]byte{0xab}, hashSize), leaves)
	if first != 0 || fails != 3 || n != 3 {
		t.Errorf("verifyAllProofs(wrong root) = (%d, %d, %d), want (0, 3, 3)", first, fails, n)
	}
}
