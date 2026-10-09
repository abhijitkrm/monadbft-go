package bridge

import (
	"fmt"
	"math/big"
	"sort"
	"time"

	sdktypes "github.com/cosmos/cosmos-sdk/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	"github.com/abhijitkrm/monadbft-go/chaincfg"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/monadstate"
	"github.com/abhijitkrm/monadbft-go/swarm"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// Config — bridge testnet parameters.
type Config struct {
	ChainConfig        chaincfg.Config
	ExecutionDelay     types.SeqNum // delayed-exec window (≥3 final, ≥2 speculative)
	Speculative        bool         // legacy SpecApp execution (default: final-only)
	Delta              time.Duration
	StatesyncThreshold types.SeqNum
	EpochLength        types.SeqNum // valset boundary length
}

// DefaultConfig — single-epoch, 4-block delay, 20ms delta (Rust test params).
func DefaultConfig() Config {
	maxU64 := ^uint64(0)
	return Config{
		ChainConfig:        swarm.MockChainConfig(),
		ExecutionDelay:     types.SeqNum(4),
		Delta:              20 * time.Millisecond,
		StatesyncThreshold: types.SeqNum(1000),
		EpochLength:        types.SeqNum(maxU64),
	}
}

// NewNodes — one swarm.NodeBuilder per (app, validator) pair, wiring the
// ABCI-backed executors into the deterministic swarm driver. apps[i] must
// already be InitChain'd with the genesis doc built from vals.
func NewNodes(apps []*App, vals []Validator, cfg Config) (swarm.SwarmBuilder, error) {
	if len(apps) != len(vals) {
		return nil, fmt.Errorf("bridge: %d apps vs %d validators", len(apps), len(vals))
	}

	forkpoint := monadstate.ForkpointGenesis()
	vsd, err := apps[0].ValidatorSetData()
	if err != nil {
		return nil, err
	}
	var lockedEpochValidators []glue.ValidatorSetDataWithEpoch
	for _, le := range forkpoint.Checkpoint.ValidatorSets {
		lockedEpochValidators = append(lockedEpochValidators, glue.ValidatorSetDataWithEpoch{
			Epoch:      le.Epoch,
			Validators: vsd,
		})
	}

	var allPeers []types.NodeId
	for _, v := range vals {
		allPeers = append(allPeers, v.NodeId())
	}
	sort.Slice(allPeers, func(i, j int) bool { return allPeers[i].Cmp(allPeers[j]) < 0 })

	builders := make(swarm.SwarmBuilder, len(apps))
	for i, app := range apps {
		b, err := NewNodeBuilder(i, app, vals[i], allPeers, lockedEpochValidators, cfg)
		if err != nil {
			return nil, err
		}
		b.StateBuilder.Forkpoint = forkpoint
		builders[i] = *b
	}
	return builders, nil
}

// NewNodeBuilder — the per-node construction used by NewNodes, exported so
// tests can rebuild a single node mid-run (e.g. a wiped validator that
// must statesync to rejoin). The caller sets StateBuilder.Forkpoint to the
// boot point (ForkpointGenesis() for a fresh network, or a live peer's
// forkpoint for a rejoining node).
func NewNodeBuilder(i int, app *App, v Validator, allPeers []types.NodeId, lockedEpochValidators []glue.ValidatorSetDataWithEpoch, cfg Config) (*swarm.NodeBuilder, error) {
	var spec *SpecApp // nil → final-only execution
	if cfg.Speculative {
		spec = NewSpecApp(app)
	}
	ledger := NewLedger(app, spec)
	ledger.SetSyncCommit(true) // swarm = discrete-event sim: no background app work
	pool := NewTxPool(app)
	pool.SetLedger(ledger)
	valset, err := NewValSet(app, cfg.EpochLength)
	if err != nil {
		return nil, err
	}
	// Production validation in tests too: real round-signature checks +
	// proposal limits. The SDK decoder only exists for evmd apps.
	var decoder sdktypes.TxDecoder
	var ethChainID *big.Int
	if raw := app.Raw(); raw != nil {
		decoder = raw.TxConfig().TxDecoder()
		if cc := evmtypes.GetEthChainConfig(); cc != nil {
			ethChainID = cc.ChainID
		}
	}
	return &swarm.NodeBuilder{
		ID: swarm.NewID(v.NodeId()),
		StateBuilder: &monadstate.Builder{
			LeaderElection: validator.WeightedRoundRobin{},
			BlockValidator: NewEvmBlockValidator(decoder, ethChainID),
			BlockPolicy: newBlockPolicy(cfg.Speculative, cfg.ExecutionDelay,
				swarm.MinBaseFee, swarm.GenesisBaseFeeTrend, swarm.GenesisBaseFeeMoment),
			StateRead: NewStateRead(app, spec),

			LockedEpochValidators: lockedEpochValidators,

			Keypair:     v.Secp,
			CertKeypair: v.Bls,

			BlocksyncRngSeed: uint64Ptr(123456),

			ConsensusConfig: &consensusstate.Config{
				ExecutionDelay: cfg.ExecutionDelay,
				Delta:          cfg.Delta,
				ChainConfig:    cfg.ChainConfig,

				StatesyncToLiveThreshold:   cfg.StatesyncThreshold,
				LiveToStatesyncThreshold:   types.SeqNum(cfg.StatesyncThreshold.Uint64() * 3 / 2),
				StartExecutionThreshold:    types.SeqNum(cfg.StatesyncThreshold.Uint64() / 2),
				TimestampLatencyEstimateNs: types.U128FromUint64(10_000_000),
			},

			StatesyncExpandToGroup: true,
			ServeStatesync:         true,
		},
		RouterScheduler:   swarm.NewBytesRouterScheduler(allPeers, Evm),
		ValSetUpdater:     valset,
		TxPoolExecutor:    pool,
		Ledger:            ledger,
		StateSyncExecutor: NewStateSync(app, ledger, spec),
		OutboundPipeline:  swarm.TransformerPipeline{swarm.NewLatencyTransformer(cfg.Delta)},
		InboundPipeline:   swarm.TransformerPipeline{},
		TimestamperConfig: swarm.DefaultTimestamperConfig(),
		Seed:              swarm.DefaultSeed(i),
	}, nil
}

func uint64Ptr(v uint64) *uint64 { return &v }
