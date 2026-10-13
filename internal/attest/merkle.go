package attest

// merkle.go — the fingerprint tree that locks a worker's raw evidence behind a
// single 32-byte root.
//
// # Tree definition (frozen; an independent implementation must match it)
//
// The tree is built bottom-up from the ordered leaf values (for samples, the
// leaf value of record i is CanonicalRecord(record), see record.go):
//
//  1. A leaf is hashed with a domain separator byte so that no leaf hash can
//     ever be confused with an internal node hash, and with the leaf's index so
//     that the tree commits to the *position* of every record:
//
//     LeafHash(i, leaf) = SHA-256( 0x00 || uint64_be(i) || leaf )
//
//     NodeHash(l, r)    = SHA-256( 0x01 || l || r )
//
//  2. Each level is paired up left to right. When a level has an odd number of
//     nodes, the last node is repeated (it becomes its own sibling) and the
//     tree continues with the next level — the "knockout tournament" shape
//     described in docs/EXPLAINER.md §2.2:
//
//     level[j] = NodeHash(level_prev[2j], level_prev[2j+1])     (sibling exists)
//     level[j] = NodeHash(level_prev[2j], level_prev[2j])       (right edge)
//
//     Equivalently: pad the leaf list to a power of two by repeating the last
//     node at every level, then build a perfect binary tree.
//
//  3. An empty leaf list hashes to SHA-256("") — the RFC 6962 (Certificate
//     Transparency) definition of the empty tree hash, kept for compatibility
//     with the wider transparency-log ecosystem.
//
// # Why index-bound leaves
//
// Repeating the last node is the classic Bitcoin construction, and by itself it
// admits a well-known ambiguity: the three-leaf tree [a, b, c] and the four-leaf
// tree [a, b, c, c] would produce the *same* root, so one root would no longer
// identify one leaf list (this is the same defect as CVE-2012-2459 in Bitcoin's
// block malleability). Binding each leaf hash to its index removes the
// ambiguity: leaf 3 of the four-leaf tree hashes differently from leaf 2, so the
// two trees hash differently. A test in merkle_test.go pins this property.
//
// # Proofs
//
// MerkleProof returns the audit path of one leaf: the sibling node at every
// level, bottom-up. VerifyProof recombines the path using nothing but the leaf
// index — the parity of the running index says whether the accumulated hash is
// a left or a right child, and the right-edge duplication is invisible to the
// verifier. That is why the proof carries no tree size: for this shape the
// index is sufficient, and a verifier that only holds a leaf and its index can
// still prove inclusion in a signed root.
//
// Complexity: MerkleRoot is O(n) hashes; MerkleProof is O(n) hashes for one
// leaf (build the levels, keep one at a time); VerifyProof is O(log n) hashes.
// Verify() uses the equivalent one-sweep form (verifyAllProofs, see verify.go)
// to check *every* leaf's path without O(n²) work.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
)

const (
	// leafDomain prefixes every leaf hash so a leaf can never be mistaken for
	// an internal node.
	leafDomain = 0x00
	// nodeDomain prefixes every internal node hash.
	nodeDomain = 0x01
	// hashSize is the SHA-256 digest size in bytes.
	hashSize = sha256.Size
)

// EmptyRootHex is the hex encoding of the empty tree root, SHA-256(""). It is
// the root of a worker that recorded zero samples.
const EmptyRootHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// errBadIndex is returned when a leaf index falls outside the tree.
var errBadIndex = errors.New("merkle: leaf index out of range")

// EmptyRoot returns the 32-byte root of an empty tree, SHA-256("").
func EmptyRoot() []byte {
	sum := sha256.Sum256(nil)
	return sum[:]
}

// hasher is a reusable SHA-256 state. Reusing one state across a tree keeps
// tree building allocation-free in the hot loop.
type hasher struct {
	h hash.Hash
}

func newHasher() *hasher { return &hasher{h: sha256.New()} }

// leaf returns SHA-256(0x00 || be64(index) || data).
func (s *hasher) leaf(index int, data []byte) [hashSize]byte {
	var prefix [9]byte
	prefix[0] = leafDomain
	binary.BigEndian.PutUint64(prefix[1:], uint64(index))
	s.h.Reset()
	s.h.Write(prefix[:])
	s.h.Write(data)
	var out [hashSize]byte
	s.h.Sum(out[:0])
	return out
}

// node returns SHA-256(0x01 || left || right).
func (s *hasher) node(left, right []byte) [hashSize]byte {
	s.h.Reset()
	s.h.Write([]byte{nodeDomain})
	s.h.Write(left)
	s.h.Write(right)
	var out [hashSize]byte
	s.h.Sum(out[:0])
	return out
}

// LeafHash returns the domain-separated, index-bound hash of one leaf:
// SHA-256(0x00 || uint64_be(index) || leaf). It is exported so that an
// independent implementation of the format can check itself against this one.
func LeafHash(index int, leaf []byte) []byte {
	out := newHasher().leaf(index, leaf)
	return out[:]
}

// NodeHash returns SHA-256(0x01 || left || right), the hash of an internal
// node.
func NodeHash(left, right []byte) []byte {
	out := newHasher().node(left, right)
	return out[:]
}

// levelHashes hashes the leaves and then folds the tree level by level,
// repeating the last node of an odd level until a single root remains.
func levelHashes(leaves [][]byte) [hashSize]byte {
	if len(leaves) == 0 {
		return sha256.Sum256(nil)
	}
	h := newHasher()
	cur := make([][hashSize]byte, len(leaves))
	for i, leaf := range leaves {
		cur[i] = h.leaf(i, leaf)
	}
	for len(cur) > 1 {
		next := make([][hashSize]byte, (len(cur)+1)/2)
		for j := range next {
			left := &cur[2*j]
			right := left
			if 2*j+1 < len(cur) {
				right = &cur[2*j+1]
			}
			next[j] = h.node(left[:], right[:])
		}
		cur = next
	}
	return cur[0]
}

// MerkleRoot returns the 32-byte root of the tree built from leaves, as
// defined in the file comment. The empty list returns SHA-256(""). Every leaf
// in the list is committed: changing one byte of one leaf changes the root.
func MerkleRoot(leaves [][]byte) []byte {
	root := levelHashes(leaves)
	return root[:]
}

// MerkleRootHex returns the lowercase hex encoding of MerkleRoot, which is the
// form stored in a bundle's commit.merkle_root.
func MerkleRootHex(leaves [][]byte) string {
	return hex.EncodeToString(MerkleRoot(leaves))
}

// MerkleProof returns the audit path of the leaf at index: the sibling node at
// every level, bottom-up. An index outside the tree is an error; a tree with a
// single leaf produces an empty (but non-nil) proof.
//
// The proof is O(log n) hashes in size; generating it is O(n) hashes, which is
// the right trade for the intended use — a third party proving *one* recorded
// request is in a signed root.
func MerkleProof(leaves [][]byte, index int) ([][]byte, error) {
	n := len(leaves)
	if index < 0 || index >= n {
		return nil, fmt.Errorf("%w: index %d of %d leaves", errBadIndex, index, n)
	}
	h := newHasher()
	cur := make([][hashSize]byte, n)
	for i, leaf := range leaves {
		cur[i] = h.leaf(i, leaf)
	}

	proof := make([][]byte, 0, 32)
	pos := index
	for len(cur) > 1 {
		sibling := pos ^ 1
		if sibling >= len(cur) {
			// Right edge: the node is its own sibling.
			sibling = len(cur) - 1
		}
		elem := cur[sibling]
		proof = append(proof, elem[:])

		next := make([][hashSize]byte, (len(cur)+1)/2)
		for j := range next {
			left := &cur[2*j]
			right := left
			if 2*j+1 < len(cur) {
				right = &cur[2*j+1]
			}
			next[j] = h.node(left[:], right[:])
		}
		cur = next
		pos >>= 1
	}
	return proof, nil
}

// VerifyProof reports whether leaf, at the given index, is committed by root
// under the audit path proof.
//
// It performs O(log n) hashes and needs no tree state — only the index, which
// selects the left/right side of every combination. A malformed proof (too
// short, too long, wrong contents) simply fails; the function never panics.
func VerifyProof(root, leaf []byte, index int, proof [][]byte) bool {
	if index < 0 || len(root) != hashSize {
		return false
	}
	h := newHasher()
	acc := h.leaf(index, leaf)
	pos := index
	for _, sibling := range proof {
		if len(sibling) != hashSize {
			return false
		}
		if pos&1 == 0 {
			acc = h.node(acc[:], sibling)
		} else {
			acc = h.node(sibling, acc[:])
		}
		pos >>= 1
	}
	// The tree is exhausted when the running index reaches the root, i.e. when
	// every level has been consumed. A proof that is too short leaves pos > 0.
	if pos != 0 {
		return false
	}
	return equalBytes(acc[:], root)
}

// equalBytes compares two byte slices in constant time.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
