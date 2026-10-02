//go:build test

package bridge_test

// Speculative-execution feasibility spike (PORTING-PLAN Phase-2 gate).
//
// MonadBFT's deferred-exec model needs per-block FinalizeBlock results that:
//   1. execute against the *speculative* parent state (block N+1 reads block
//      N's uncommitted writes),
//   2. are held as independent branches until a 2-chain finalizes them,
//   3. commit in sequence order and yield the identical app hash that linear
//      commit would produce — required so a restarted/replaying node, which
//      necessarily commits linearly, lands on the same hashes,
//   4. can be dropped for free when the branch's block is abandoned.
//
// Cosmos SDK v0.54 already executes every FinalizeBlock on a
// `cms.CacheMultiStore()` branch (baseapp/state/manager.go SetState) and
// flushes it via `MultiStore.Write()` at workingHash time (baseapp/abci.go).
// This test proves the missing generalization — *nested* branches — at the
// store/v2 level, with the same rootmulti+IAVL stack the evmd app mounts.
//
// Verified findings encoded here:
//   - nested CacheMultiStore is hash-transparent (a single flat branch and a
//     nested chain stage identical hashes at the same committed version)
//   - IAVL node hashes embed the store version, so a block's writes must
//     stage at the correct committed depth — batching two heights' writes
//     into one Commit produces a different root than two Commits
//   - flushing a branch chain tip→root with one Commit per finalized height
//     reproduces linear hashes exactly; same-value re-writes through
//     already-flushed ancestors are hash-neutral
//   - dropping a spec branch is free (no Write ⇒ no leak)

import (
	"testing"

	dbm "github.com/cosmos/cosmos-db"
	"github.com/stretchr/testify/require"

	"cosmossdk.io/log/v2"

	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	"github.com/cosmos/cosmos-sdk/store/v2/types"
)

var specBlocks = []map[string][]byte{
	{"a": []byte("one"), "b": []byte("b1")},
	{"b": []byte("b2"), "c": []byte("c2")},
	{"a": []byte("one-v3"), "d": []byte("d3")},
}

func newTestStore(t *testing.T) (*rootmulti.Store, *types.KVStoreKey) {
	t.Helper()
	cms := rootmulti.NewStore(dbm.NewMemDB(), log.NewNopLogger())
	key := types.NewKVStoreKey("main")
	cms.MountStoreWithDB(key, types.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())
	return cms, key
}

func setBlock(ms types.MultiStore, key *types.KVStoreKey, writes map[string][]byte) {
	kv := ms.GetKVStore(key)
	for k, v := range writes {
		kv.Set([]byte(k), v)
	}
}

// linearHashes commits specBlocks one height at a time — also what a
// restarted node replaying the finalized chain produces.
func linearHashes(t *testing.T) [][]byte {
	cms, key := newTestStore(t)
	var out [][]byte
	for _, b := range specBlocks {
		br := cms.CacheMultiStore()
		setBlock(br, key, b)
		br.Write()
		cms.Commit()
		out = append(out, cms.LastCommitID().Hash)
	}
	return out
}

func TestSpecExecBranchEquivalence(t *testing.T) {
	// Speculative: exec all three blocks on a nested branch chain *before*
	// any commit, then finalize in sequence order.
	cms, key := newTestStore(t)

	var chain []types.CacheMultiStore
	var parent types.MultiStore = cms
	for i, b := range specBlocks {
		br := parent.CacheMultiStore()
		if i > 0 {
			require.Equal(t, specBlocks[i-1]["b"], br.GetKVStore(key).Get([]byte("b")),
				"spec chain must read ancestors' uncommitted writes")
		}
		setBlock(br, key, b)
		chain = append(chain, br)
		parent = br
	}

	// finalize(h): merge every held branch tip→root, then one Commit per
	// height. Already-committed ancestors are re-flushed each round; their
	// same-value re-sets are hash-neutral.
	finalize := func(h int) []byte {
		for i := h - 1; i >= 0; i-- {
			chain[i].Write()
		}
		cms.Commit()
		return cms.LastCommitID().Hash
	}

	lh := linearHashes(t)
	for h := 1; h <= 3; h++ {
		require.Equal(t, lh[h-1], finalize(h),
			"height %d spec-commit hash must equal linear", h)
	}
}

func TestSpecExecBranchDrop(t *testing.T) {
	cms, key := newTestStore(t)

	br := cms.CacheMultiStore()
	setBlock(br, key, map[string][]byte{"a": []byte("one")})
	br.Write()
	cms.Commit()
	committed := cms.LastCommitID().Hash

	brBad := cms.CacheMultiStore()
	setBlock(brBad, key, map[string][]byte{"a": []byte("WRONG")})
	// drop: never Write

	require.Equal(t, committed, cms.LastCommitID().Hash)
	require.Equal(t, []byte("one"),
		cms.CacheMultiStore().GetKVStore(key).Get([]byte("a")),
		"abandoned spec branch must not leak into committed state")
}
