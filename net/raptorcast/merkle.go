package raptorcast

import "github.com/zeebo/blake3"

// merkleTree ports monad-merkle: a fixed-depth binary tree over 20-byte
// truncated blake3 hashes. Leaves beyond the message's chunk count are
// zero-hashes.
type merkleTree struct {
	leafStartIdx int
	tree         []MerkleRoot
}

const merkleMaxDepth = 15

func hashToMerkle(h [32]byte) MerkleRoot {
	var m MerkleRoot
	copy(m[:], h[:MerkleHashLen])
	return m
}

// newMerkleTreeWithDepth — Rust MerkleTree::new_with_depth.
func newMerkleTreeWithDepth(leaves [][32]byte, depth int) *merkleTree {
	numLeaves := 1 << (depth - 1)
	treeLen := 2*numLeaves - 1
	leafStart := treeLen - numLeaves
	t := &merkleTree{leafStartIdx: leafStart, tree: make([]MerkleRoot, treeLen)}
	for i, leaf := range leaves {
		t.tree[leafStart+i] = hashToMerkle(leaf)
	}
	for idx := leafStart - 1; idx >= 0; idx-- {
		h := blake3.New()
		h.Write(t.tree[2*idx+1][:])
		h.Write(t.tree[2*idx+2][:])
		var full [32]byte
		copy(full[:], h.Sum(nil))
		t.tree[idx] = hashToMerkle(full)
	}
	return t
}

func (t *merkleTree) root() MerkleRoot { return t.tree[0] }

// merkleProof — Rust MerkleTree::proof → siblings in root-first order.
func (t *merkleTree) proof(leafIdx int) []MerkleRoot {
	idx := t.leafStartIdx + leafIdx
	var sib []MerkleRoot
	for idx > 0 {
		parent := (idx - 1) / 2
		sibling := 2*parent + 1
		if sibling == idx {
			sibling = 2*parent + 2
		}
		sib = append(sib, t.tree[sibling])
		idx = parent
	}
	// Rust pushes leaf→root then reverses: callers iterate .rev() in
	// compute_root; we store root-first so verify walks it directly.
	for i, j := 0, len(sib)-1; i < j; i, j = i+1, j-1 {
		sib[i], sib[j] = sib[j], sib[i]
	}
	return sib
}

// merkleProofComputeRoot — Rust MerkleProof::compute_root. `siblings` is in
// root-first order (as stored on the wire); leafIdx is the leaf's position
// among the 2^(depth-1) padded leaves.
func merkleProofComputeRoot(leafHash [32]byte, siblings []MerkleRoot, leafIdx int) (MerkleRoot, bool) {
	if len(siblings) >= merkleMaxDepth {
		return MerkleRoot{}, false
	}
	numLeaves := 1 << len(siblings)
	treeLeafStartIdx := 2*numLeaves - 1 - numLeaves // tree_len - num_leaves
	if leafIdx < 0 || leafIdx >= numLeaves {
		return MerkleRoot{}, false
	}
	cur := hashToMerkle(leafHash)
	idx := treeLeafStartIdx + leafIdx
	// Walk leaf→root, consuming siblings in reverse (leaf-most first).
	for i := len(siblings) - 1; i >= 0; i-- {
		sib := siblings[i]
		h := blake3.New()
		if idx%2 == 1 {
			h.Write(cur[:])
			h.Write(sib[:])
		} else {
			h.Write(sib[:])
			h.Write(cur[:])
		}
		var full [32]byte
		copy(full[:], h.Sum(nil))
		cur = hashToMerkle(full)
		if idx == 0 {
			return MerkleRoot{}, false
		}
		idx = (idx - 1) / 2
	}
	return cur, true
}
