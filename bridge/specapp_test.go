//go:build test

package bridge_test

// SpecApp tests (PORTING-PLAN Phase-5): speculative execution runs the same
// deterministic FinalizeBlock requests on the canonical app ahead of
// finalization — AppHashes must match a fresh linearly-executed oracle app —
// and orphan divergence rewinds the store so the winner branch executes
// correctly.

import (
	"context"
	"math/big"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/evm/evmd"
	txtest "github.com/cosmos/evm/testutil/tx"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	"github.com/abhijitkrm/monadbft-go/bridge"
	"github.com/abhijitkrm/monadbft-go/types"
)

const specChainID = "monadbft-spec-test"

func specEvmdCfg(t *testing.T) bridge.EvmdConfig {
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	return bridge.EvmdConfig{
		ChainID:    specChainID,
		EVMChainID: testEvmChainID,
		Home:       t.TempDir(),
	}
}

// signTx — one real MsgEthereumTx from the funded genesis sender.
func signTx(t *testing.T, raw *evmd.EVMD, nonce uint64, to common.Address, amount *big.Int) []byte {
	t.Helper()
	sender := bridge.GenesisSenderKey()
	from := common.BytesToAddress(sender.PubKey().Address().Bytes())
	msg := evmtypes.NewTx(&evmtypes.EvmTxArgs{
		ChainID:  evmtypes.GetEthChainConfig().ChainID,
		Nonce:    nonce,
		To:       &to,
		Amount:   amount,
		GasLimit: 21_000,
		GasPrice: big.NewInt(1_000_000_000_000),
	})
	msg.From = from.Bytes()
	sdkTx, err := txtest.PrepareEthTx(raw.TxConfig(), sender, msg)
	require.NoError(t, err)
	bz, err := raw.TxConfig().TxEncoder()(sdkTx)
	require.NoError(t, err)
	return bz
}

func canonFinalize(t *testing.T, app *bridge.App, req *abcitypes.RequestFinalizeBlock) []byte {
	t.Helper()
	res, err := app.FinalizeBlock(context.Background(), req)
	require.NoError(t, err)
	require.NoError(t, app.Commit(context.Background()))
	return res.AppHash
}

func bid(h int64, seed byte) types.BlockId {
	var id types.BlockId
	id[0] = byte(h)
	id[1] = seed
	return id
}

func bidb(h int64, seed byte) []byte {
	id := bid(h, seed)
	return id[:]
}

func TestSpecAppHashParity(t *testing.T) {
	vals := bridge.MakeValidators(4)

	// oracle: a second app executing linearly
	canon, raw, err := bridge.NewEvmdApp(specEvmdCfg(t), vals)
	require.NoError(t, err)
	// spec app wraps the canonical instance
	app, _, err := bridge.NewEvmdApp(specEvmdCfg(t), vals)
	require.NoError(t, err)
	spec := bridge.NewSpecApp(app)
	require.NotNil(t, spec)

	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	amt := big.NewInt(1_000_000_000_000_000_000)

	var parent types.BlockId
	for h := int64(1); h <= 6; h++ {
		tx := signTx(t, raw, uint64(h-1), to, amt)
		req := &abcitypes.RequestFinalizeBlock{
			Txs: [][]byte{tx}, Height: h, Time: time.Unix(int64(h), 0), Hash: bidb(h, 0),
		}
		want := canonFinalize(t, canon, req)
		got, err := spec.SpecFinalize(context.Background(), req, bid(h, 0), parent)
		require.NoError(t, err)
		require.Equal(t, want, got, "height %d apphash", h)
		parent = bid(h, 0)

		rh, _, ok := spec.SpecResultSeq(h)
		require.True(t, ok)
		require.Equal(t, want, rh)
		seq, bh, _, ok := spec.SpecResultID(bid(h, 0))
		require.True(t, ok)
		require.Equal(t, h, seq)
		require.Equal(t, want, bh)
	}
	require.Equal(t, int64(6), spec.SpecTip())
}

// Orphaned spec branch: canonical winner differs → CommittedResult rewinds
// the store; the caller's sync replay lands the winner's hash.
func TestSpecAppOrphanRewind(t *testing.T) {
	vals := bridge.MakeValidators(4)

	app, araw, err := bridge.NewEvmdApp(specEvmdCfg(t), vals)
	require.NoError(t, err)
	spec := bridge.NewSpecApp(app)
	require.NotNil(t, spec)

	// oracle app for the true post-rewind result
	canon, craw, err := bridge.NewEvmdApp(specEvmdCfg(t), vals)
	require.NoError(t, err)

	to := common.HexToAddress("0x000000000000000000000000000000000000beef")
	amt := big.NewInt(100)

	// Spec-execute a 3-high branch A (blockIDs seed 0xa).
	var parent types.BlockId
	var hashA []byte
	for h := int64(1); h <= 3; h++ {
		tx := signTx(t, araw, uint64(h-1), to, amt)
		got, err := spec.SpecFinalize(context.Background(), &abcitypes.RequestFinalizeBlock{
			Txs: [][]byte{tx}, Height: h, Time: time.Unix(int64(h), 0), Hash: bidb(h, 0xa),
		}, bid(h, 0xa), parent)
		require.NoError(t, err)
		hashA = got
		parent = bid(h, 0xa)
		// oracle tracks the same branch for heights 1-2
		if h <= 2 {
			canonFinalize(t, canon, &abcitypes.RequestFinalizeBlock{
				Txs: [][]byte{tx}, Height: h, Time: time.Unix(int64(h), 0), Hash: bidb(h, 0xa),
			})
		}
	}

	// Canon commits heights 1-2 as spec'd (same IDs) — fast path serves them.
	for h := int64(1); h <= 2; h++ {
		ah, _, ok := spec.CommittedResult(h, bid(h, 0xa), func(int64) types.BlockId {
			if h == 1 {
				return types.GENESIS_BLOCK_ID
			}
			return bid(h-1, 0xa)
		})
		require.True(t, ok)
		require.NotNil(t, ah)
	}

	// Canon's height-3 winner is branch B — spec's 3a is orphaned.
	txB := signTx(t, craw, 10, to, amt)
	wantB := canonFinalize(t, canon, &abcitypes.RequestFinalizeBlock{
		Txs: [][]byte{txB}, Height: 3, Time: time.Unix(3, 0), Hash: bidb(3, 0xb),
	})
	// CommittedResult sees the mismatch, rewinds the store to 2, returns
	// miss — and pre-bumps the frontier to the canonical winner (the
	// caller's sync replay is about to land it).
	_, _, ok := spec.CommittedResult(3, bid(3, 0xb), func(int64) types.BlockId {
		return bid(2, 0xa)
	})
	require.False(t, ok)
	require.Equal(t, int64(3), spec.SpecTip())
	_, _, ok = spec.SpecResultSeq(3)
	require.False(t, ok) // orphaned entry evicted

	// The caller replays B synchronously on the (rewound) app.
	res, err := app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
		Txs: [][]byte{txB}, Height: 3, Time: time.Unix(3, 0), Hash: bidb(3, 0xb),
	})
	require.NoError(t, err)
	require.NoError(t, app.Commit(context.Background()))
	require.Equal(t, wantB, res.AppHash)
	require.NotEqual(t, hashA, wantB)
}

// A non-chaining spec submission is rejected, not guessed.
func TestSpecAppRejectsNonChaining(t *testing.T) {
	vals := bridge.MakeValidators(4)
	app, _, err := bridge.NewEvmdApp(specEvmdCfg(t), vals)
	require.NoError(t, err)
	spec := bridge.NewSpecApp(app)
	require.NotNil(t, spec)

	// gap: height 2 when tip is 0
	_, err = spec.SpecFinalize(context.Background(), &abcitypes.RequestFinalizeBlock{
		Height: 2, Time: time.Unix(2, 0), Hash: bidb(2, 0),
	}, bid(2, 0), bid(1, 0))
	require.ErrorIs(t, err, bridge.ErrSpecNotChaining)

	// height 1 with wrong parent (genesis parent is the zero ID)
	_, err = spec.SpecFinalize(context.Background(), &abcitypes.RequestFinalizeBlock{
		Height: 1, Time: time.Unix(1, 0), Hash: bidb(1, 0),
	}, bid(1, 0), bid(9, 9))
	require.Error(t, err)
}

// Orphan at the spec floor: seq-2 spec loses to a different canonical
// winner — CommittedResult rewinds the store to height 1 and the winner
// replays cleanly. (Height 1 itself never reaches spec — see
// Ledger.speculate's floor: a height-1 orphan would need version-0
// rollback, which doesn't exist.)
func TestSpecAppFloorOrphan(t *testing.T) {
	vals := bridge.MakeValidators(4)
	app, araw, err := bridge.NewEvmdApp(specEvmdCfg(t), vals)
	require.NoError(t, err)
	spec := bridge.NewSpecApp(app)
	require.NotNil(t, spec)

	to := common.HexToAddress("0x000000000000000000000000000000000000beef")

	// Canonical height 1 executes synchronously (the floor) — CommittedResult
	// bumps the spec frontier so height 2 chains.
	tx1 := signTx(t, araw, 0, to, big.NewInt(1))
	_, err = app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
		Txs: [][]byte{tx1}, Height: 1, Time: time.Unix(1, 0), Hash: bidb(1, 0),
	})
	require.NoError(t, err)
	require.NoError(t, app.Commit(context.Background()))
	_, _, ok := spec.CommittedResult(1, bid(1, 0), func(int64) types.BlockId {
		return types.GENESIS_BLOCK_ID
	})
	require.False(t, ok) // never spec'd — canonical already owns it
	require.Equal(t, int64(1), spec.SpecTip())

	// Spec-execute the losing height-2 branch.
	tx2a := signTx(t, araw, 1, to, big.NewInt(2))
	_, err = spec.SpecFinalize(context.Background(), &abcitypes.RequestFinalizeBlock{
		Txs: [][]byte{tx2a}, Height: 2, Time: time.Unix(2, 0), Hash: bidb(2, 0xa),
	}, bid(2, 0xa), bid(1, 0))
	require.NoError(t, err)

	// Oracle: canonical winner computes on a fresh app past height 1.
	canon, craw, err := bridge.NewEvmdApp(specEvmdCfg(t), vals)
	require.NoError(t, err)
	canonFinalize(t, canon, &abcitypes.RequestFinalizeBlock{
		Txs: [][]byte{tx1}, Height: 1, Time: time.Unix(1, 0), Hash: bidb(1, 0),
	})
	tx2b := signTx(t, craw, 7, to, big.NewInt(3)) // divergent tx
	wantB := canonFinalize(t, canon, &abcitypes.RequestFinalizeBlock{
		Txs: [][]byte{tx2b}, Height: 2, Time: time.Unix(2, 0), Hash: bidb(2, 0xb),
	})

	// Canonical winner differs — rewind to 1, miss, sync replay lands.
	_, _, ok = spec.CommittedResult(2, bid(2, 0xb), func(int64) types.BlockId {
		return bid(1, 0)
	})
	require.False(t, ok)
	res, err := app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
		Txs: [][]byte{tx2b}, Height: 2, Time: time.Unix(2, 0), Hash: bidb(2, 0xb),
	})
	require.NoError(t, err)
	require.NoError(t, app.Commit(context.Background()))
	require.Equal(t, wantB, res.AppHash)
}
