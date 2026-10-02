//go:build test

package bridge_test

// SpecApp parity test (PORTING-PLAN Phase-5 foundation): the shadow app
// executing the same FinalizeBlock requests must produce byte-identical
// AppHashes to the canonical linear path — the invariant that makes
// embedded delayed_execution_results verifiable — and Rewind must correctly
// discard orphaned spec heights.

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

func TestSpecAppHashParity(t *testing.T) {
	vals := bridge.MakeValidators(4)

	canon, raw, err := bridge.NewEvmdApp(specEvmdCfg(t), vals)
	require.NoError(t, err)
	spec, err := bridge.NewSpecApp(specEvmdCfg(t), vals)
	require.NoError(t, err)

	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	amt := big.NewInt(1_000_000_000_000_000_000)

	// 6 sequential heights with real EVM txs — the canonical path finalizes
	// each; the shadow executes the identical requests and must land on the
	// same AppHash per height.
	for h := int64(1); h <= 6; h++ {
		tx := signTx(t, raw, uint64(h-1), to, amt)
		req := &abcitypes.RequestFinalizeBlock{
			Txs:    [][]byte{tx},
			Height: h,
			Time:   time.Unix(int64(h), 0),
			Hash:   []byte{byte(h)},
		}
		want := canonFinalize(t, canon, req)
		got, err := spec.SpecFinalize(context.Background(), req)
		require.NoError(t, err)
		require.Equal(t, want, got, "height %d apphash", h)

		r, ok := spec.SpecResult(h)
		require.True(t, ok)
		require.Equal(t, want, r)
	}
	require.Equal(t, int64(6), spec.SpecTip())
}

func TestSpecAppRewind(t *testing.T) {
	vals := bridge.MakeValidators(4)
	spec, err := bridge.NewSpecApp(specEvmdCfg(t), vals)
	require.NoError(t, err)

	to := common.HexToAddress("0x000000000000000000000000000000000000beef")
	amt := big.NewInt(100)

	// Spec-execute a 3-high branch A.
	_, sraw, err := bridge.NewEvmdApp(specEvmdCfg(t), vals) // second handle for signing only
	require.NoError(t, err)
	var hashA []byte
	for h := int64(1); h <= 3; h++ {
		tx := signTx(t, sraw, uint64(h-1), to, amt) // nonce h-1
		got, err := spec.SpecFinalize(context.Background(), &abcitypes.RequestFinalizeBlock{
			Txs: [][]byte{tx}, Height: h, Time: time.Unix(int64(h), 0), Hash: []byte{0xa0 + byte(h)},
		})
		require.NoError(t, err)
		hashA = got
	}

	// Orphan: branch B diverges at height 3 — rewind to 2 then spec h=3'.
	require.NoError(t, spec.Rewind(2))
	require.Equal(t, int64(2), spec.SpecTip())
	_, ok := spec.SpecResult(3)
	require.False(t, ok, "orphaned spec result must be discarded")

	// A fresh canonical app computes the true h=3' result.
	canon, craw, err := bridge.NewEvmdApp(specEvmdCfg(t), vals)
	require.NoError(t, err)
	for h := int64(1); h <= 2; h++ {
		tx := signTx(t, craw, uint64(h-1), to, amt)
		canonFinalize(t, canon, &abcitypes.RequestFinalizeBlock{
			Txs: [][]byte{tx}, Height: h, Time: time.Unix(int64(h), 0), Hash: []byte{0xa0 + byte(h)},
		})
	}
	// branch B uses a different tx at h=3 (nonce 10 → different state root)
	txB := signTx(t, craw, 10, to, amt)
	wantB := canonFinalize(t, canon, &abcitypes.RequestFinalizeBlock{
		Txs: [][]byte{txB}, Height: 3, Time: time.Unix(3, 0), Hash: []byte{0xb3},
	})

	gotB, err := spec.SpecFinalize(context.Background(), &abcitypes.RequestFinalizeBlock{
		Txs: [][]byte{txB}, Height: 3, Time: time.Unix(3, 0), Hash: []byte{0xb3},
	})
	require.NoError(t, err)
	require.Equal(t, wantB, gotB, "re-executed branch must match canonical")
	require.NotEqual(t, hashA, gotB)
}
