package swarm

import (
	"sort"
	"testing"
	"time"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/monadstate"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// restartParams — knobs for the crash-restart scenarios (Rust
// forkpoint_restart_one's epoch_length / statesync_threshold /
// statesync_service_window / finalization_delay).
type restartParams struct {
	execDelay          types.SeqNum
	epochLength        types.SeqNum
	epochStartDelay    types.Round
	statesyncThreshold types.SeqNum
	serviceWindow      types.SeqNum
	finalizationDelay  types.SeqNum
}

func defaultRestartParams() restartParams {
	return restartParams{
		execDelay:          4,
		epochLength:        200,
		epochStartDelay:    50,
		statesyncThreshold: 100,
		serviceWindow:      types.SeqNum(^uint64(0)), // SeqNum::MAX
	}
}

// testSwarmCrashRestart — port of Rust forkpoint_restart_one: a node is killed
// after finalizing blocksBeforeFailure blocks. If timeBeforeNewForkpoint > 0
// the network runs ahead that far and the node restarts from a LIVE peer's
// fresh forkpoint (operator-supplied checkpoint); otherwise it restarts from
// its own persisted forkpoint on disk. The network then runs to recover_block
// before the node rejoins. Surviving state: forkpoint + validators + block
// store + execution state (the WAL is waltrace-only, matching Rust).
func testSwarmCrashRestart(t *testing.T, p restartParams, blocksBeforeFailure, timeBeforeNewForkpoint, recoveryTime types.SeqNum) {
	t.Helper()
	if timeBeforeNewForkpoint > recoveryTime {
		t.Fatal("time_before_new_forkpoint must be <= recovery_time")
	}
	const numNodes = 4
	delta := 10 * time.Millisecond

	dirs := make([]string, numNodes)
	for i := range dirs {
		dirs[i] = t.TempDir()
	}

	cc := MockChainConfig()
	cc.EpochLength = p.epochLength
	cc.EpochStartDelay = p.epochStartDelay

	gv, builders := MakeStateConfigs(numNodes, StateConfigParams{
		ExecutionDelay:     p.execDelay,
		Delta:              delta,
		ChainConfig:        cc,
		StatesyncThreshold: p.statesyncThreshold,
		LeaderElection:     func() validator.LeaderElection { return validator.WeightedRoundRobin{} },
		BlockValidator:     func() blocktree.BlockValidator { return blocktree.MockValidator{} },
		BlockPolicy:        func() blocktree.BlockPolicy { return blocktree.NewMockBlockPolicy(p.execDelay) },
		StateRead:          func() blocktree.ExecutionStateRead { return NewInMemoryStateGenesis(p.execDelay) },
	})
	allPeers := make([]types.NodeId, numNodes)
	for i, k := range gv.Keys {
		allPeers[i] = types.NewNodeId(k.PubKey())
	}
	sort.Slice(allPeers, func(i, j int) bool { return allPeers[i].Cmp(allPeers[j]) < 0 })

	nodes := NewBytesSwarm(SwarmConfig{
		Builders:   builders,
		Genesis:    gv,
		AllPeerIDs: allPeers,
		OutPipeline: func() Pipeline {
			return TransformerPipeline{NewLatencyTransformer(delta)}
		},
		InPipeline:        func() Pipeline { return TransformerPipeline{} },
		EpochLength:       p.epochLength,
		EP:                exec.Mock,
		Timestamper:       DefaultTimestamperConfig(),
		FinalizationDelay: p.finalizationDelay,
		PersistDirs:       dirs,
	}).Build().CanFailDeliver()

	runUntilBlock := func(n int) {
		term := NewUntilTerminator().UntilBlock(n)
		for {
			if _, _, _, ok := nodes.StepUntil(term); !ok {
				break
			}
		}
	}
	finalized := func(id ID) int {
		return nodes.Node(id).Executor.Ledger().(*MockLedger).FinalizedBlocksLen()
	}

	// phase 1: everyone finalizes blocks_before_failure
	runUntilBlock(int(blocksBeforeFailure))
	for _, p := range allPeers {
		if got := finalized(NewID(p)); got < int(blocksBeforeFailure) {
			t.Fatalf("node finalized %d blocks, want >= %d", got, blocksBeforeFailure)
		}
	}
	// drain in-flight work at this tick so the crash boundary is clean
	if tick, ok := nodes.PeekTick(); ok {
		term := NewUntilTerminator().UntilTick(tick + time.Nanosecond)
		for {
			if _, _, _, ok := nodes.StepUntil(term); !ok {
				break
			}
		}
	}

	// kill node 0 — process dies; only its persistence dir + execution state survive
	failedID := NewID(allPeers[0])
	failedNode := nodes.RemoveState(failedID)
	failedNode.persist.Close() // flush handles; dir contents persist

	// find the failed node's builder (builders[i] keyed by gv.Keys[i], while
	// allPeers is ID-sorted — match by NodeId).
	failedPeer := allPeers[0]
	failedDir := ""
	var restartBuilder *monadstate.Builder
	for i := range builders {
		if types.NewNodeId(builders[i].Keypair.PubKey()) == failedPeer {
			b := builders[i]
			restartBuilder = &b
			failedDir = dirs[i]
		}
	}
	if restartBuilder == nil {
		t.Fatal("failed node builder not found")
	}

	var fp *monadstate.Forkpoint
	var lockedSets []glue.ValidatorSetDataWithEpoch
	if timeBeforeNewForkpoint == 0 {
		// restart from the dead node's own persisted forkpoint
		var err error
		fp, lockedSets, err = LoadPersistedState(failedDir, exec.Mock)
		if err != nil {
			t.Fatalf("LoadPersistedState: %v", err)
		}
	} else {
		// network advances; the restart uses a live peer's fresh forkpoint
		runUntilBlock(int(blocksBeforeFailure + timeBeforeNewForkpoint))
		liveID := NewID(allPeers[1])
		liveFp := nodes.Node(liveID).GetForkpoint()
		fp = &liveFp
		for _, le := range liveFp.Checkpoint.ValidatorSets {
			lockedSets = append(lockedSets, glue.ValidatorSetDataWithEpoch{
				Epoch:      le.Epoch,
				Validators: gv.ValidatorData,
			})
		}
	}

	// phase 2: network produces recovery_time blocks while the node is down
	recoverBlock := blocksBeforeFailure + recoveryTime
	runUntilBlock(int(recoverBlock))

	// rebuild: same identity, surviving execution state (state_read survives
	// the crash — restartBuilder.StateRead is the failed node's InMemoryState),
	// forkpoint + locked validator sets + block store loaded from disk.
	restartBuilder.Forkpoint = *fp
	restartBuilder.LockedEpochValidators = lockedSets

	restartID := failedID
	nodes.AddState(NodeBuilder{
		ID:              restartID,
		StateBuilder:    restartBuilder,
		RouterScheduler: NewBytesRouterScheduler(allPeers, exec.Mock),
		ValSetUpdater:   NewMockValSetUpdaterNop(gv.ValidatorData, p.epochLength),
		TxPoolExecutor:  NewMockTxPoolExecutor(),
		Ledger: NewMockLedger(restartBuilder.StateRead.(*InMemoryState)).
			WithFinalizationDelay(p.finalizationDelay),
		StateSyncExecutor: NewMockStateSyncExecutor(
			restartBuilder.StateRead.(*InMemoryState)).
			WithMaxServiceWindow(p.serviceWindow),
		OutboundPipeline:  TransformerPipeline{NewLatencyTransformer(delta)},
		InboundPipeline:   TransformerPipeline{},
		TimestamperConfig: DefaultTimestamperConfig(),
		Seed:              DefaultSeed(0),
		Persist:           &PersistSpec{Dir: failedDir},
	})

	// phase 3: run 3 epochs past recovery so epoch switching happens normally
	terminateBlock := recoverBlock + p.epochLength*3
	runUntilBlock(int(terminateBlock))

	restarted := nodes.Node(restartID)
	if restarted == nil {
		t.Fatal("restarted node missing")
	}
	if restarted.State.Consensus() == nil {
		t.Fatal("restarted node never went live")
	}

	// peers must have fully-converged contiguous ledgers (Rust asserts the
	// restarted node's tip only — its ledger legitimately has a hole across
	// the statesync gap).
	var peerLedgers [][]FinalizedBlock
	for _, nd := range nodes.OrderedNodes() {
		if nd.ID == restartID {
			continue
		}
		peerLedgers = append(peerLedgers, nd.Executor.Ledger().GetFinalizedBlocks())
	}
	// peers converge on a contiguous chain; each is within a few blocks of the
	// longest (ledger_verification's built-in lag tolerance is 5).
	LedgerVerification(peerLedgers, int(terminateBlock)-5)

	// Rust asserts: caught-up (last finalized >= terminate-2), voting again,
	// statesync only when the gap is close to/past the threshold, and target
	// reset only when the service window was exceeded.
	fbs := restarted.Executor.Ledger().GetFinalizedBlocks()
	lastSeq := fbs[len(fbs)-1].SeqNum
	if lastSeq < terminateBlock-2 {
		m := restarted.State.Metrics()
		var round interface{} = "syncing"
		if restarted.State.Consensus() != nil {
			round = restarted.State.Consensus().Consensus.Pacemaker.GetCurrentRound()
		}
		t.Fatalf("restarted node last finalized %d, want >= %d\n"+
			"  live=%v round=%v invalidEpoch=%d statesync=%d votes=%d",
			lastSeq, terminateBlock-2,
			restarted.State.Consensus() != nil,
			round,
			m.ValidationErrors.InvalidEpoch.Get(),
			m.ConsensusEvents.TriggerStateSync.Get(),
			m.ConsensusEvents.CreatedVote.Get())
	}
	m := restarted.State.Metrics()
	if m.ConsensusEvents.CreatedVote.Get() == 0 {
		t.Fatal("restarted node never voted after restart")
	}
	triggered := m.ConsensusEvents.TriggerStateSync.Get()
	closeToThreshold := p.statesyncThreshold.SaturatingSub(recoveryTime) < 5
	if triggered > 0 && !closeToThreshold {
		t.Fatalf("statesync triggered %d times but recovery %d << threshold %d",
			triggered, recoveryTime, p.statesyncThreshold)
	}
	shouldReset := recoveryTime.SaturatingSub(timeBeforeNewForkpoint) >= p.serviceWindow
	if triggered > 1 && !shouldReset {
		t.Fatalf("statesync target reset %d times but service window %d not exceeded",
			triggered-1, p.serviceWindow)
	}
}

func TestSwarmQuickRestart(t *testing.T) {
	// Rust test_quick_restart: restart immediately at the last forkpoint.
	// Tiny epochs exercise rapid epoch churn through the restart.
	p := defaultRestartParams()
	p.epochLength = 3
	p.epochStartDelay = 50
	p.statesyncThreshold = 5
	testSwarmCrashRestart(t, p, 10, 0, 0)
}

func TestSwarmRestartBlockSyncCatchUp(t *testing.T) {
	// Rust test_forkpoint_restart_f_simple_blocksync: network runs ahead
	// threshold/2 blocks while the node is down; it block-syncs the gap.
	p := scaledRestartParams()
	testSwarmCrashRestart(t, p, 10, 0, p.statesyncThreshold/2)
}

func TestSwarmRestartDelayedExecution(t *testing.T) {
	// Rust test_forkpoint_restart_f_delayed_execution_no_statesync: ledger
	// finalization delay exceeds state_root_delay; must NOT statesync.
	p := scaledRestartParams()
	p.finalizationDelay = 8 // state_root_delay is 4
	testSwarmCrashRestart(t, p, 10, 0, p.statesyncThreshold/2)
}

// scaledRestartParams — smaller epoch/threshold than the Rust defaults so the
// swarm tests run in reasonable time; ratios match forkpoint.rs.
func scaledRestartParams() restartParams {
	return restartParams{
		execDelay:          4,
		epochLength:        40,
		epochStartDelay:    10,
		statesyncThreshold: 20,
		serviceWindow:      types.SeqNum(^uint64(0)),
	}
}

func TestSwarmRestartStateSync(t *testing.T) {
	// Rust test_forkpoint_restart_f_simple_statesync: restart from a live
	// peer's forkpoint that is 1.5*threshold stale — the restarted node's
	// execution state can't cover the delay window, so it state-syncs.
	p := scaledRestartParams()
	tbnf := p.statesyncThreshold * 3 / 2
	testSwarmCrashRestart(t, p, 10, tbnf, tbnf)
}

func TestSwarmRestartTargetResetStateSync(t *testing.T) {
	// Rust test_forkpoint_restart_f_target_reset_statesync: service window is
	// smaller than the recovery gap — exercises statesync target refreshing.
	//
	// epoch_length must keep the rejoin inside the forkpoint's locked epochs:
	// the node restarts knowing only the forkpoint's base epoch, so peers must
	// still be in that epoch when it goes live (Rust: rejoin at ~170, epoch-1
	// boundary at 199). Crossing a boundary during the down+sync window is
	// unrecoverable — epoch-gated validation drops every peer message.
	p := scaledRestartParams()
	p.epochLength = 60 // bf+tbnf+recovery = 50 < boundary at 59
	p.serviceWindow = 10
	testSwarmCrashRestart(t, p, 10, 10, p.statesyncThreshold*3/2)
}

func TestSwarmRestartEpochBoundary(t *testing.T) {
	// Rust test_forkpoint_restart_f_epoch_boundary_statesync: fail mid-epoch-2,
	// restart from a fresh peer forkpoint and state-sync across the boundary.
	p := scaledRestartParams()
	tbnf := p.statesyncThreshold * 3 / 2
	testSwarmCrashRestart(t, p, p.epochLength+15, tbnf, tbnf)
}
