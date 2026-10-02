//go:build test

package bridge

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	cmtcfg "github.com/cometbft/cometbft/config"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	rpcclient "github.com/cometbft/cometbft/rpc/client"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/evm/engine"
	"github.com/cosmos/evm/engine/comet"
	"github.com/cosmos/evm/evmd"
	testconstants "github.com/cosmos/evm/testutil/constants"
	txtest "github.com/cosmos/evm/testutil/tx"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// TestCometParity — the golden-oracle check: one validator, identical
// genesis, both engines in-process. Per-height app hashes can only be
// compared at h1 (from h2 on, the EIP-2935 history contract holds each
// engine's own block hash, so roots structurally differ), but execution
// parity is asserted where it matters: identical tx → identical result +
// identical post-state via identical queries.
func TestCometParity(t *testing.T) {
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	cfg := EvmdConfig{ChainID: "parity-test", EVMChainID: testconstants.EighteenDecimalsChainID, Home: t.TempDir()}
	vals := MakeValidators(1)

	genesisRaw := newRawEvmdDB(cfg, dbm.NewMemDB())
	stateBytes, err := evmdGenesisState(genesisRaw, cfg, vals)
	if err != nil {
		t.Fatal(err)
	}
	pub := cmted25519.PubKey(vals[0].ConsPub)
	genDoc := &cmttypes.GenesisDoc{
		ChainID:         cfg.ChainID,
		GenesisTime:     time.Now(),
		ConsensusParams: cmttypes.DefaultConsensusParams(),
		Validators: []cmttypes.GenesisValidator{{
			Address: pub.Address(), PubKey: pub, Power: 1,
		}},
		AppState: stateBytes,
	}
	provider := func() (*cmttypes.GenesisDoc, error) { return genDoc, nil }

	// CometBFT side: full node.NewNode in-process, single validator,
	// skip_timeout_commit for fast empty-block production.
	cometDir := t.TempDir()
	cmtCfg := cmtcfg.DefaultConfig()
	cmtCfg.SetRoot(cometDir)
	cmtCfg.P2P.ListenAddress = "tcp://127.0.0.1:0"
	cmtCfg.Consensus.SkipTimeoutCommit = true
	cmtCfg.Mempool.Recheck = false // evmd CheckTx rejects RECHECK
	ensureDir(t, filepath.Join(cometDir, "config"))
	ensureDir(t, filepath.Join(cometDir, "data"))
	cometPV := privval.NewFilePV(cmted25519.PrivKey(vals[0].ConsPriv),
		filepath.Join(cometDir, "config", "priv_validator_key.json"),
		filepath.Join(cometDir, "data", "priv_validator_state.json"))
	cometPV.Save()

	evmtypes.NewEVMConfigurator().ResetTestConfig()
	cometApp := newRawEvmdDB(cfg, dbm.NewMemDB())
	cometEng, err := comet.Start(engine.Options{
		App:            cometApp,
		Config:         cmtCfg,
		PrivValidator:  cometPV,
		NodeKey:        &p2p.NodeKey{PrivKey: cmted25519.GenPrivKey()},
		GenDocProvider: provider,
		DBProvider:     cmtcfg.DefaultDBProvider,
		Logger:         cmtlog.NewNopLogger(),
	})
	if err != nil {
		t.Fatalf("comet start: %v", err)
	}
	defer cometEng.Stop()
	cometClient := cometEng.Client()

	// MonadBFT side: engine.Start on its own dirs.
	monadDir := t.TempDir()
	monadAppDir := t.TempDir()
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	monadDB, err := dbm.NewPebbleDB("application", monadAppDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer monadDB.Close()
	monadPV := privval.NewFilePV(cmted25519.PrivKey(vals[0].ConsPriv),
		filepath.Join(monadDir, "config", "priv_validator_key.json"),
		filepath.Join(monadDir, "data", "priv_validator_state.json"))
	monadCfg := cmtcfg.DefaultConfig()
	monadCfg.SetRoot(monadDir)
	monadEng, err := Start(engine.Options{
		App:            newRawEvmdDB(cfg, monadDB),
		Config:         monadCfg,
		PrivValidator:  monadPV,
		GenDocProvider: provider,
		Logger:         cmtlog.NewNopLogger(),
	})
	if err != nil {
		t.Fatalf("monad start: %v", err)
	}
	defer monadEng.Stop()
	monadClient := monadEng.Client()

	// Wait for both chains to produce ≥6 empty blocks, then compare
	// per-height app hashes — identical genesis + identical lifecycle must
	// yield identical state roots.
	waitHeightComet(t, cometClient, 6, 60*time.Second)
	monadMe := monadEng.(*monadEngine)
	probeWaitHeight(t, monadMe, 6, 60*time.Second)

	ctx := context.Background()

	// h1 sanity: the genesis app hash convention matches (sha256 of the
	// empty pre-genesis commit). From h2 on, app hashes diverge BY DESIGN:
	// x/vm BeginBlock writes the consensus block hash into EIP-2935
	// history storage, and CometBFT's merkle header hash can never equal
	// MonadBFT's block id. Parity is therefore checked on semantic state
	// (execution results + account state), not state roots.
	cb1, err := cometClient.Block(ctx, int64Ptr(1))
	require.NoError(t, err)
	mb1, err := monadClient.Block(ctx, int64Ptr(1))
	require.NoError(t, err)
	require.Equal(t, cb1.Block.AppHash, mb1.Block.AppHash, "genesis apphash")

	// Same signed tx through both engines — result (code/gas) must match.
	tx := paritySignTx(t, cometApp, 0)
	txHash := tmhash.Sum(tx)
	if _, err := cometClient.BroadcastTxSync(ctx, tx); err != nil {
		t.Fatalf("comet broadcast: %v", err)
	}
	if _, err := monadClient.BroadcastTxSync(ctx, tx); err != nil {
		t.Fatalf("monad broadcast: %v", err)
	}
	cRes := waitTx(t, cometClient, txHash)
	mRes := waitTx(t, monadClient, txHash)
	require.Equal(t, cRes.TxResult.Code, mRes.TxResult.Code)
	require.Equal(t, cRes.TxResult.GasUsed, mRes.TxResult.GasUsed)

	// Semantic state parity: identical recipient balance + sender nonce on
	// both chains after the transfer commits.
	qb, _ := (&evmtypes.QueryBalanceRequest{
		Address: "0x000000000000000000000000000000000000dEaD",
	}).Marshal()
	var cBal, mBal []byte
	for _, c := range []struct {
		name string
		cli  rpcclient.Client
	}{{"comet", cometClient}, {"monad", monadClient}} {
		res, err := c.cli.ABCIQuery(ctx, "/cosmos.evm.vm.v1.Query/Balance", qb)
		require.NoError(t, err, c.name)
		require.Zero(t, res.Response.Code, c.name)
		if c.name == "comet" {
			cBal = res.Response.Value
		} else {
			mBal = res.Response.Value
		}
	}
	require.Equal(t, cBal, mBal, "recipient balance mismatch")
	var cBalS, mBalS evmtypes.QueryBalanceResponse
	require.NoError(t, cBalS.Unmarshal(cBal))
	require.NoError(t, mBalS.Unmarshal(mBal))
	require.Equal(t, "1000000000000000000", cBalS.Balance)
	t.Logf("parity: recipient balance=%s (both engines)", cBalS.Balance)
}

func int64Ptr(v int64) *int64 { return &v }

// paritySignTx — one signed MsgEthereumTx transfer from the funded genesis
// sender (the in-package analogue of specapp_test's signTx).
func paritySignTx(t *testing.T, raw *evmd.EVMD, nonce uint64) []byte {
	t.Helper()
	sender := GenesisSenderKey()
	from := common.BytesToAddress(sender.PubKey().Address().Bytes())
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	msg := evmtypes.NewTx(&evmtypes.EvmTxArgs{
		ChainID:  evmtypes.GetEthChainConfig().ChainID,
		Nonce:    nonce,
		To:       &to,
		Amount:   big.NewInt(1_000_000_000_000_000_000),
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

func ensureDir(t *testing.T, d string) {
	t.Helper()
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
}

func waitHeightComet(t *testing.T, c rpcclient.Client, h int64, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		st, err := c.Status(context.Background())
		if err == nil && st.SyncInfo.LatestBlockHeight >= h {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("comet height %d not reached in %s", h, d)
}

func waitTx(t *testing.T, c rpcclient.Client, hash []byte) *coretypes.ResultTx {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		res, err := c.Tx(context.Background(), hash, false)
		if err == nil {
			return res
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("tx %X not committed", hash[:8])
	return nil
}
