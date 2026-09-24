package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"

	dbm "github.com/cosmos/cosmos-db"
	ethsecp256k1 "github.com/cosmos/evm/crypto/ethsecp256k1"
	"github.com/cosmos/evm/evmd"
	srvflags "github.com/cosmos/evm/server/flags"
	testconstants "github.com/cosmos/evm/testutil/constants"
	"github.com/cosmos/evm/testutil/integration/evm/network"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	"cosmossdk.io/log/v2"
	"cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/server"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
)

// EvmdConfig — parameters for an in-process evmd instance.
type EvmdConfig struct {
	ChainID    string
	EVMChainID uint64
	Home       string // appOpts FlagHome (any path; MemDB means no disk use)
}

// GenesisSenderKey — the deterministic ethsecp256k1 key funding the genesis
// account (every node derives the same sender → identical genesis). Tests
// sign MsgEthereumTx with it.
func GenesisSenderKey() *ethsecp256k1.PrivKey {
	seed := sha256.Sum256([]byte("monadbft-bridge-sender-seed-001"))
	return &ethsecp256k1.PrivKey{Key: seed[:]}
}

// NewEvmdApp constructs an evmd app on an in-memory DB and InitChains it with
// a validator set + funding account — the same genesis shape as
// evmd.SetupWithGenesisValSet. Returns the bridge App wrapper (valset
// bookkeeping installed) and the raw app for test inspection.
func NewEvmdApp(cfg EvmdConfig, vals []Validator) (*App, *evmd.EVMD, error) {
	// same option set as evmd's test harness (NewAppOptionsWithFlagHomeAndChainID)
	appOptions := simtestutil.AppOptionsMap{
		flags.FlagHome:                              cfg.Home,
		server.FlagInvCheckPeriod:                   5,
		srvflags.EVMChainID:                         cfg.EVMChainID,
		srvflags.EVMMempoolInsertQueueSize:          5000,
		srvflags.EVMMempoolPendingTxProposalTimeout: "250ms",
	}
	evmApp := evmd.NewExampleApp(
		log.NewNopLogger(), dbm.NewMemDB(), true, appOptions,
		baseapp.SetChainID(cfg.ChainID),
	)

	genesisState := evmApp.DefaultGenesis()

	// one funded genesis account (the delegator for all validators) —
	// ethsecp256k1 so the account's SDK address equals its EVM address
	// (tests can sign real MsgEthereumTx against it). Deterministic so
	// every node's genesis is byte-identical.
	senderPrivKey := GenesisSenderKey()
	acc := authtypes.NewBaseAccount(senderPrivKey.PubKey().Address().Bytes(), senderPrivKey.PubKey(), 0, 0)
	balance := banktypes.Balance{
		Address: acc.GetAddress().String(),
		Coins: sdk.NewCoins(sdk.NewCoin(
			testconstants.ChainsCoinInfo[cfg.EVMChainID].Denom,
			math.NewInt(9_000_000_000_000_000_000),
		)),
	}

	genesisState, err := simtestutil.GenesisStateWithValSet(
		evmApp.AppCodec(), genesisState, CmtValidatorSet(vals),
		[]authtypes.GenesisAccount{acc}, balance,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("genesis valset: %w", err)
	}

	// evmd genesis fixups (same as evmd.SetupWithGenesisValSet)
	var bankGenesis banktypes.GenesisState
	evmApp.AppCodec().MustUnmarshalJSON(genesisState[banktypes.ModuleName], &bankGenesis)
	bankGenesis.DenomMetadata = network.GenerateBankGenesisMetadata(cfg.EVMChainID)
	// GenesisStateWithValSet funds the bonded pool with a single bondAmt even
	// for N validators — top it up so supply (N×bondAmt) balances.
	if len(vals) > 1 {
		bondedPool := authtypes.NewModuleAddress(stakingtypes.BondedPoolName).String()
		extra := sdk.NewCoin(sdk.DefaultBondDenom, sdk.DefaultPowerReduction.MulRaw(int64(len(vals)-1)))
		for i := range bankGenesis.Balances {
			if bankGenesis.Balances[i].Address == bondedPool {
				bankGenesis.Balances[i].Coins = bankGenesis.Balances[i].Coins.Add(extra)
			}
		}
	}
	genesisState[banktypes.ModuleName] = evmApp.AppCodec().MustMarshalJSON(&bankGenesis)
	var evmGenesis evmtypes.GenesisState
	evmApp.AppCodec().MustUnmarshalJSON(genesisState[evmtypes.ModuleName], &evmGenesis)
	evmGenesis.Params.EvmDenom = testconstants.ChainsCoinInfo[cfg.EVMChainID].Denom
	genesisState[evmtypes.ModuleName] = evmApp.AppCodec().MustMarshalJSON(&evmGenesis)

	// test-chain fixup (same as evmd's integration test genesis): no EIP-1559
	// base fee, so tx tests don't depend on fee-market dynamics. Bond/mint
	// denoms stay default — the bonded pool is funded in stake.
	var fmGen feemarkettypes.GenesisState
	evmApp.AppCodec().MustUnmarshalJSON(genesisState[feemarkettypes.ModuleName], &fmGen)
	fmGen.Params.NoBaseFee = true
	genesisState[feemarkettypes.ModuleName] = evmApp.AppCodec().MustMarshalJSON(&fmGen)

	// Seed x/slashing signing infos: GenesisStateWithValSet inserts validators
	// already Bonded, so AfterValidatorBonded never fires — without this, the
	// first non-empty DecidedLastCommit makes slashing's BeginBlocker fail
	// with "no validator signing info found".
	var slashingGenesis slashingtypes.GenesisState
	evmApp.AppCodec().MustUnmarshalJSON(genesisState[slashingtypes.ModuleName], &slashingGenesis)
	for _, v := range vals {
		consAddr := sdk.ConsAddress(v.ConsAddr())
		slashingGenesis.SigningInfos = append(slashingGenesis.SigningInfos, slashingtypes.SigningInfo{
			Address: consAddr.String(),
			ValidatorSigningInfo: slashingtypes.NewValidatorSigningInfo(
				consAddr, 0, 0, time.Unix(0, 0).UTC(), false, 0,
			),
		})
	}
	genesisState[slashingtypes.ModuleName] = evmApp.AppCodec().MustMarshalJSON(&slashingGenesis)

	stateBytes, err := json.Marshal(genesisState)
	if err != nil {
		return nil, nil, err
	}

	// NewCometABCIWrapper adapts the SDK's ctx-free ABCI methods onto
	// cometbft's Application interface (the "local client" seam).
	app := NewApp(server.NewCometABCIWrapper(evmApp), vals)
	if err := app.InitChain(context.Background(), &abci.RequestInitChain{
		Validators:      []abci.ValidatorUpdate{},
		ConsensusParams: simtestutil.DefaultConsensusParams,
		AppStateBytes:   stateBytes,
		ChainId:         cfg.ChainID,
		InitialHeight:   1,
	}); err != nil {
		return nil, nil, err
	}
	return app, evmApp, nil
}
