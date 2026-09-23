package swarm

import (
	"sort"
	"time"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/chaincfg"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/monadstate"
	"github.com/abhijitkrm/monadbft-go/testutil"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// Default chain params — Rust CHAIN_PARAMS_LATEST (v0.12.0), used by
// MockChainConfig::DEFAULT.
func DefaultChainParams() chaincfg.Params {
	// max_reserve_balance = 10^19 (10 MON), big-endian U256.
	var maxReserve [32]byte
	copy(maxReserve[24:], []byte{0x8A, 0xC7, 0x23, 0x04, 0x89, 0xE8, 0x00, 0x00})
	return chaincfg.Params{
		TxLimit:           3_750,
		ProposalGasLimit:  150_000_000,
		ProposalByteLimit: 1_500_000,
		MaxReserveBalance: maxReserve,
		VotePace:          300 * time.Millisecond,
	}
}

// MockChainConfig — Rust MockChainConfig::DEFAULT: latest params, epoch_length
// = SeqNum::MAX, epoch_start_delay = Round::MAX, staking_activation = Epoch::MAX.
func MockChainConfig() chaincfg.StaticConfig {
	maxU64 := ^uint64(0)
	return chaincfg.StaticConfig{
		P:                 DefaultChainParams(),
		EpochLength:       types.SeqNum(maxU64),
		EpochStartDelay:   types.Round(maxU64),
		StakingActivation: types.Epoch(maxU64),
	}
}

// CreateKeysWithValidators — Rust create_keys_w_validators: n secp keys
// (get_key(i)), n BLS cert keys (get_certificate_key(i)), a validator set with
// Stake::ONE each, and the cert-pubkey mapping.
type GenesisValidators struct {
	Keys             []*crypto.SecpKeyPair
	CertKeys         []*crypto.BlsKeyPair
	Validators       *validator.ValidatorSet
	ValidatorMapping *validator.ValidatorMapping
	ValidatorData    glue.ValidatorSetData // sorted by NodeId, as upstream
}

func CreateKeysWithValidators(numNodes int) GenesisValidators {
	keys := make([]*crypto.SecpKeyPair, numNodes)
	certKeys := make([]*crypto.BlsKeyPair, numNodes)
	for i := 0; i < numNodes; i++ {
		keys[i] = testutil.GetKey(uint64(i))
		certKeys[i] = testutil.GetCertKey(uint64(i))
	}

	var valData []validator.ValidatorData
	var mapEntries []struct {
		NodeId     types.NodeId
		CertPubKey crypto.BlsPubKey
	}
	for i := 0; i < numNodes; i++ {
		nodeID := types.NewNodeId(keys[i].PubKey())
		valData = append(valData, validator.ValidatorData{
			NodeId:     nodeID,
			Stake:      types.StakeFromUint64(1),
			CertPubKey: certKeys[i].PubKey(),
		})
		mapEntries = append(mapEntries, struct {
			NodeId     types.NodeId
			CertPubKey crypto.BlsPubKey
		}{nodeID, certKeys[i].PubKey()})
	}

	vset, err := validator.NewValidatorSet(valData)
	if err != nil {
		panic(err)
	}
	vmap := validator.NewValidatorMapping(mapEntries)

	// ValidatorSetData::new iterates the BTreeMap — sorted by NodeId.
	var vd []glue.ValidatorData
	sorted := append([]validator.ValidatorData(nil), valData...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].NodeId.Cmp(sorted[j].NodeId) < 0 })
	for _, v := range sorted {
		var certPK [48]byte
		copy(certPK[:], v.CertPubKey.Compress())
		vd = append(vd, glue.ValidatorData{
			NodeId:     v.NodeId,
			Stake:      v.Stake,
			CertPubKey: certPK,
		})
	}

	return GenesisValidators{
		Keys:             keys,
		CertKeys:         certKeys,
		Validators:       vset,
		ValidatorMapping: vmap,
		ValidatorData:    glue.ValidatorSetData{Validators: vd},
	}
}

// StateConfigParams — the per-node knobs of make_state_configs.
type StateConfigParams struct {
	ExecutionDelay     types.SeqNum
	Delta              time.Duration
	ChainConfig        chaincfg.Config
	StatesyncThreshold types.SeqNum

	LeaderElection func() validator.LeaderElection
	BlockValidator func() blocktree.BlockValidator
	BlockPolicy    func() blocktree.BlockPolicy
	StateRead      func() blocktree.ExecutionStateRead
}

// MakeStateConfigs — Rust make_state_configs: one MonadStateBuilder per node
// sharing the genesis forkpoint and validator set.
func MakeStateConfigs(
	numNodes int,
	p StateConfigParams,
) (GenesisValidators, []monadstate.Builder) {
	gv := CreateKeysWithValidators(numNodes)

	forkpoint := monadstate.ForkpointGenesis()
	var lockedEpochValidators []glue.ValidatorSetDataWithEpoch
	for _, le := range forkpoint.Checkpoint.ValidatorSets {
		lockedEpochValidators = append(lockedEpochValidators, glue.ValidatorSetDataWithEpoch{
			Epoch:      le.Epoch,
			Validators: gv.ValidatorData,
		})
	}

	builders := make([]monadstate.Builder, numNodes)
	for i := range builders {
		builders[i] = monadstate.Builder{
			LeaderElection: p.LeaderElection(),
			BlockValidator: p.BlockValidator(),
			BlockPolicy:    p.BlockPolicy(),
			StateRead:      p.StateRead(),
			Forkpoint:      forkpoint,

			LockedEpochValidators: lockedEpochValidators,

			Keypair:     gv.Keys[i],
			CertKeypair: gv.CertKeys[i],

			BlockSyncOverridePeers: nil,
			BlocksyncRngSeed:       uint64Ptr(123456),

			ConsensusConfig: &consensusstate.Config{
				ExecutionDelay: p.ExecutionDelay,
				Delta:          p.Delta,
				ChainConfig:    p.ChainConfig,
				// StateSync -> Live transition
				StatesyncToLiveThreshold: p.StatesyncThreshold,
				// Live -> StateSync transition
				LiveToStatesyncThreshold: types.SeqNum(p.StatesyncThreshold.Uint64() * 3 / 2),
				// Live starts execution here
				StartExecutionThreshold: types.SeqNum(p.StatesyncThreshold.Uint64() / 2),

				TimestampLatencyEstimateNs: types.U128FromUint64(10_000_000),
			},

			WhitelistedStatesyncNodes: nil,
			StatesyncExpandToGroup:    true,
			ServeStatesync:            true,
		}
	}
	return gv, builders
}

func uint64Ptr(v uint64) *uint64 { return &v }

// ---------------------------------------------------------------------------
// BytesSwarm builder — the standard deterministic test swarm (RLP transport).
// ---------------------------------------------------------------------------

// SwarmConfig — one node's full config: MonadState builder + executor mocks +
// pipelines.
type SwarmConfig struct {
	Builders          []monadstate.Builder
	Genesis           GenesisValidators
	AllPeerIDs        []types.NodeId // sorted
	OutPipeline       func() Pipeline
	InPipeline        func() Pipeline
	EpochLength       types.SeqNum
	EP                *exec.Protocol
	Tick              time.Duration
	Timestamper       TimestamperConfig
	FinalizationDelay types.SeqNum
	Seeds             func(i int) [32]byte
}

// NewBytesSwarm — builds a SwarmBuilder of nodes using BytesRouterScheduler.
func NewBytesSwarm(cfg SwarmConfig) SwarmBuilder {
	out := make(SwarmBuilder, len(cfg.Builders))
	for i, sb := range cfg.Builders {
		stateRead, ok := sb.StateRead.(*InMemoryState)
		if !ok {
			panic("swarm: StateRead must be *InMemoryState")
		}
		var seed [32]byte
		if cfg.Seeds != nil {
			seed = cfg.Seeds(i)
		} else {
			seed = DefaultSeed(i)
		}
		nodeID := types.NewNodeId(sb.Keypair.PubKey())
		out[i] = NodeBuilder{
			ID:                NewID(nodeID),
			StateBuilder:      &sb,
			RouterScheduler:   NewBytesRouterScheduler(cfg.AllPeerIDs, cfg.EP),
			ValSetUpdater:     NewMockValSetUpdaterNop(cfg.Genesis.ValidatorData, cfg.EpochLength),
			TxPoolExecutor:    NewMockTxPoolExecutor(),
			Ledger:            NewMockLedger(stateRead).WithFinalizationDelay(cfg.FinalizationDelay),
			StateSyncExecutor: NewMockStateSyncExecutor(stateRead),
			OutboundPipeline:  cfg.OutPipeline(),
			InboundPipeline:   cfg.InPipeline(),
			TimestamperConfig: cfg.Timestamper,
			Seed:              seed,
		}
	}
	return out
}

// DefaultSeed — per-node deterministic rng seed.
func DefaultSeed(i int) [32]byte {
	var s [32]byte
	for j := 0; j < 8; j++ {
		s[j] = byte(uint64(i+1) >> (8 * j))
	}
	return s
}
