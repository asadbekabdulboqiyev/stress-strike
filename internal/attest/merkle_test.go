package attest

// merkle_test.go — the fingerprint tree: roots, proofs, and the index-binding
// property that pins the [a,b,c] vs [a,b,c,c] ambiguity.

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestMerkleEmptyRoot(t *testing.T) {
	if got := hex.EncodeToString(EmptyRoot()); got != EmptyRootHex {
		t.Fatalf("EmptyRoot = %s, want %s", got, EmptyRootHex)
	}
	if got := MerkleRootHex(nil); got != EmptyRootHex {
		t.Fatalf("empty MerkleRootHex = %s, want %s", got, EmptyRootHex)
	}
}

func TestMerkleRootDetectsOneByteChange(t *testing.T) {
	leaves := [][]byte{[]byte("alpha"), []byte("beta"), []byte("gamma")}
	root := MerkleRoot(leaves)

	mutated := [][]byte{[]byte("alpha"), []byte("betb"), []byte("gamma")}
	if bytes.Equal(root, MerkleRoot(mutated)) {
		t.Fatal("a one-byte leaf change did not change the root")
	}
}

// TestMerkleIndexBinding is the pinned defect: without binding the leaf hash to
// its index, [a,b,c] and [a,b,c,c] would share a root.
func TestMerkleIndexBinding(t *testing.T) {
	three := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	four := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("c")}
	if bytes.Equal(MerkleRoot(three), MerkleRoot(four)) {
		t.Fatal("[a,b,c] and [a,b,c,c] collide: leaf hashes are not index-bound")
	}

	two := [][]byte{[]byte("a"), []byte("b")}
	threeB := [][]byte{[]byte("a"), []byte("b"), []byte("b")}
	if bytes.Equal(MerkleRoot(two), MerkleRoot(threeB)) {
		t.Fatal("[a,b] and [a,b,b] collide")
	}
}

func TestLeafHashIsIndexBound(t *testing.T) {
	leaf := []byte("same-bytes")
	if bytes.Equal(LeafHash(0, leaf), LeafHash(1, leaf)) {
		t.Fatal("LeafHash ignores the index")
	}
}

func TestNodeHashIsDomainSeparated(t *testing.T) {
	l := []byte("x")
	if bytes.Equal(NodeHash(l, l), LeafHash(0, l)) {
		t.Fatal("node and leaf hashes collide")
	}
}

func TestMerkleProofEveryIndex(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 13} {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = []byte{byte(i), byte(n), 0xab}
		}
		root := MerkleRoot(leaves)
		for i := 0; i < n; i++ {
			proof, err := MerkleProof(leaves, i)
			if err != nil {
				t.Fatalf("n=%d index=%d: MerkleProof: %v", n, i, err)
			}
			if !VerifyProof(root, leaves[i], i, proof) {
				t.Fatalf("n=%d index=%d: valid proof rejected", n, i)
			}
		}
	}
}

func TestMerkleProofRejectsWrongIndex(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	root := MerkleRoot(leaves)
	proof, err := MerkleProof(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyProof(root, leaves[1], 2, proof) {
		t.Fatal("proof accepted under the wrong index")
	}
}

func TestMerkleProofRejectsWrongLeaf(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	root := MerkleRoot(leaves)
	proof, err := MerkleProof(leaves, 0)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyProof(root, []byte("A"), 0, proof) {
		t.Fatal("proof accepted for a different leaf")
	}
}

func TestMerkleProofOutOfRange(t *testing.T) {
	leaves := [][]byte{[]byte("a")}
	if _, err := MerkleProof(leaves, 1); err == nil {
		t.Fatal("index past the end accepted")
	}
	if _, err := MerkleProof(leaves, -1); err == nil {
		t.Fatal("negative index accepted")
	}
}

func TestVerifyProofMalformed(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	root := MerkleRoot(leaves)
	proof, err := MerkleProof(leaves, 0)
	if err != nil {
		t.Fatal(err)
	}

	if VerifyProof(root, leaves[0], 0, nil) {
		t.Fatal("empty proof accepted for a multi-leaf tree")
	}
	if VerifyProof(root, leaves[0], 0, [][]byte{{0x01}}) {
		t.Fatal("proof with a short element accepted")
	}
	tooLong := append(append([][]byte{}, proof...), proof[0])
	if VerifyProof(root, leaves[0], 0, tooLong) {
		t.Fatal("over-long proof accepted")
	}
	if VerifyProof(root[:31], leaves[0], 0, proof) {
		t.Fatal("proof accepted against a truncated root")
	}
	if VerifyProof(root, leaves[0], -1, proof) {
		t.Fatal("proof accepted for a negative index")
	}
}

func TestMerkleRootHexIsLowercase(t *testing.T) {
	got := MerkleRootHex([][]byte{[]byte("a")})
	if len(got) != 64 {
		t.Fatalf("root hex length = %d, want 64", len(got))
	}
	if got != strings.ToLower(got) {
		t.Fatalf("root hex is not lowercase: %s", got)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("root hex is not valid hex: %v", err)
	}
}
