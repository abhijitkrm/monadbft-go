package bridge

import (
	"fmt"
	"sort"
	"time"

	"github.com/abhijitkrm/monadbft-go/blocktree"
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
	ExecutionDelay     types.SeqNum // delayed-exec window (≥2 for sync exec)
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
		valset, err := NewValSet(app, cfg.EpochLength)
		if err != nil {
			return nil, err
		}
		v := vals[i]
		builders[i] = swarm.NodeBuilder{
			ID: swarm.NewID(v.NodeId()),
			StateBuilder: &monadstate.Builder{
				LeaderElection: validator.WeightedRoundRobin{},
				BlockValidator: blocktree.MockValidator{},
				BlockPolicy:    blocktree.NewMockBlockPolicy(cfg.ExecutionDelay),
				StateRead:      NewStateRead(app),
				Forkpoint:      forkpoint,

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
			TxPoolExecutor:    NewTxPool(app),
			Ledger:            NewLedger(app),
			StateSyncExecutor: NopStateSync{},
			OutboundPipeline:  swarm.TransformerPipeline{swarm.NewLatencyTransformer(cfg.Delta)},
			InboundPipeline:   swarm.TransformerPipeline{},
			TimestamperConfig: swarm.DefaultTimestamperConfig(),
			Seed:              swarm.DefaultSeed(i),
		}
	}
	return builders, nil
}

func uint64Ptr(v uint64) *uint64 { return &v }
