//go:build test

package bridge

import (
	"context"
	"testing"
	"time"

	cmtcfg "github.com/cometbft/cometbft/config"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/cosmos/evm/engine"
	testconstants "github.com/cosmos/evm/testutil/constants"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	"github.com/stretchr/testify/require"
)

// TestMonadEngineBoots drives the production engine path end-to-end: a raw
// evmd app + CometBFT-style genesis/config, engine.Start → consensus commits
// → CometBFT-shaped queries through the bridge client.
func TestMonadEngineBoots(t *testing.T) {
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	cfg := EvmdConfig{
		ChainID:    "monadbft-engine-boot",
		EVMChainID: testconstants.EighteenDecimalsChainID,
		Home:       t.TempDir(),
	}
	vals := MakeValidators(1)

	raw := newRawEvmd(cfg)
	stateBytes, err := evmdGenesisState(raw, cfg, vals)
	require.NoError(t, err)

	tmp := t.TempDir()
	pv := privval.NewFilePV(cmted25519.PrivKey(vals[0].ConsPriv),
		tmp+"/privval_key.json", tmp+"/privval_state.json")
	pub, err := pv.GetPubKey()
	require.NoError(t, err)
	require.Equal(t, vals[0].ConsAddr(), []byte(pub.Address()))

	genDoc := &cmttypes.GenesisDoc{
		ChainID:         cfg.ChainID,
		GenesisTime:     time.Now(),
		ConsensusParams: cmttypes.DefaultConsensusParams(),
		Validators: []cmttypes.GenesisValidator{{
			Address: pub.Address(), PubKey: pub, Power: 1, Name: "monad-0",
		}},
		AppState: stateBytes,
	}
	cmtCfg := cmtcfg.DefaultConfig()
	cmtCfg.SetRoot(tmp)

	eng, err := Start(engine.Options{
		App:           raw,
		Config:        cmtCfg,
		PrivValidator: pv,
		GenDocProvider: func() (*cmttypes.GenesisDoc, error) {
			return genDoc, nil
		},
		Logger: cmtlog.NewNopLogger(),
	})
	require.NoError(t, err)
	defer eng.Stop()

	client := eng.Client()

	// consensus must commit blocks via the MonadBFT node
	require.Eventually(t, func() bool {
		st, err := client.Status(context.Background())
		return err == nil && st.SyncInfo.LatestBlockHeight >= 3
	}, 30*time.Second, 100*time.Millisecond, "engine produced no commits")

	ctx := context.Background()
	st, err := client.Status(ctx)
	require.NoError(t, err)
	require.Equal(t, cfg.ChainID, st.NodeInfo.Network)

	h := st.SyncInfo.LatestBlockHeight
	blk, err := client.Block(ctx, &h)
	require.NoError(t, err)
	require.Equal(t, h, blk.Block.Height)
	require.Equal(t, cfg.ChainID, blk.Block.ChainID)

	res, err := client.BlockResults(ctx, &h)
	require.NoError(t, err)
	require.Equal(t, h, res.Height)

	// Commit(h) is synthesized from the QC certifying h — served from the
	// committed successor, or (at the tip) an observed child's header QC.
	for _, commitH := range []int64{h, h - 1} {
		commit, err := client.Commit(ctx, &commitH)
		require.NoError(t, err)
		require.Equal(t, commitH, commit.SignedHeader.Height)
	}

	vs, err := client.Validators(ctx, &h, nil, nil)
	require.NoError(t, err)
	require.Len(t, vs.Validators, 1)
	require.Equal(t, pub.Address(), vs.Validators[0].Address)

	health, err := client.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, health)

	info, err := client.ABCIInfo(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, info.Response.LastBlockHeight, h)
}
