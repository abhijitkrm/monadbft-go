package node

import (
	"context"
	"testing"
	"time"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/swarm"
	"github.com/abhijitkrm/monadbft-go/types"
)

const testDelta = 20 * time.Millisecond

func testConsensusConfig(execDelay types.SeqNum) *consensusstate.Config {
	return &consensusstate.Config{
		ExecutionDelay:             execDelay,
		Delta:                      testDelta,
		ChainConfig:                swarm.MockChainConfig(),
		StatesyncToLiveThreshold:   types.SeqNum(100),
		LiveToStatesyncThreshold:   types.SeqNum(150),
		StartExecutionThreshold:    types.SeqNum(50),
		TimestampLatencyEstimateNs: types.U128FromUint64(10_000_000),
	}
}

// openTestNode — one node over swarm mocks; persistence under dir.
// Returns the node and its (freshly created) InMemoryState — kept by the
// caller across restarts since it models the app's durable execution state.
func openTestNode(t *testing.T, dir string, i int, gv swarm.GenesisValidators, sr *swarm.InMemoryState, transport Transport, execDelay types.SeqNum) (*Node, *swarm.MockLedger) {
	return openTestNodeCrash(t, dir, i, gv, sr, transport, execDelay, nil)
}

// openTestNodeCrash — openTestNode with a CrashHook armed (nil for the
// plain path).
func openTestNodeCrash(t *testing.T, dir string, i int, gv swarm.GenesisValidators, sr *swarm.InMemoryState, transport Transport, execDelay types.SeqNum, crash CrashHook) (*Node, *swarm.MockLedger) {
	t.Helper()
	persist, err := OpenPersistence(dir, exec.Mock, false, true)
	if err != nil {
		t.Fatalf("OpenPersistence: %v", err)
	}
	ledger := swarm.NewMockLedger(sr).WithBlockStore(persist.Blocks)
	maxU64 := ^uint64(0)
	n, err := Open(Config{
		Dir:                    dir,
		Protocol:               exec.Mock,
		Persistence:            persist,
		Keypair:                gv.Keys[i],
		CertKeypair:            gv.CertKeys[i],
		ConsensusConfig:        testConsensusConfig(execDelay),
		BlockValidator:         blocktree.MockValidator{},
		BlockPolicy:            blocktree.NewMockBlockPolicy(execDelay),
		StateRead:              sr,
		StatesyncExpandToGroup: true,
		ServeStatesync:         true,
		GenesisValidators:      gv.ValidatorData,
		Crash:                  crash,
		Executors: Executors{
			Ledger:    ledger,
			TxPool:    swarm.NewMockTxPoolExecutor(),
			ValSet:    swarm.NewMockValSetUpdaterNop(gv.ValidatorData, types.SeqNum(maxU64)),
			StateSync: swarm.NewMockStateSyncExecutor(sr),
			Transport: transport,
		},
	})
	if err != nil {
		persist.Close()
		t.Fatalf("Open: %v", err)
	}
	return n, ledger
}

// waitFinalized polls until the ledger reaches `want` finalized blocks.
func waitFinalized(t *testing.T, l *swarm.MockLedger, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if l.FinalizedBlocksLen() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("finalized %d blocks, want %d (timeout %s)", l.FinalizedBlocksLen(), want, timeout)
}

func TestNodeSingleValidator(t *testing.T) {
	gv := swarm.CreateKeysWithValidators(1)
	execDelay := types.SeqNum(4)
	sr := swarm.NewInMemoryStateGenesis(execDelay)
	mesh := NewMesh()
	self := types.NewNodeId(gv.Keys[0].PubKey())

	// Broadcast must loop back to self — the lone validator still votes on
	// its own proposal (same transport contract as multi-node).
	n, ledger := openTestNode(t, t.TempDir(), 0, gv, sr, mesh.Transport(self), execDelay)
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFinalized(t, ledger, 6, 30*time.Second)
	n.Stop()
	if err := n.Err(); err != nil {
		t.Fatalf("node error: %v", err)
	}
}

func TestNodeFourValidatorsMesh(t *testing.T) {
	const numNodes = 4
	const target = 8
	gv := swarm.CreateKeysWithValidators(numNodes)
	execDelay := types.SeqNum(4)
	mesh := NewMesh()

	nodes := make([]*Node, numNodes)
	ledgers := make([]*swarm.MockLedger, numNodes)
	for i := 0; i < numNodes; i++ {
		self := types.NewNodeId(gv.Keys[i].PubKey())
		sr := swarm.NewInMemoryStateGenesis(execDelay)
		nodes[i], ledgers[i] = openTestNode(t, t.TempDir(), i, gv, sr, mesh.Transport(self), execDelay)
	}
	for _, n := range nodes {
		if err := n.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
	}
	for i, l := range ledgers {
		waitFinalized(t, l, target, 60*time.Second)
		_ = i
	}
	for _, n := range nodes {
		n.Stop()
	}
	for i, n := range nodes {
		if err := n.Err(); err != nil {
			t.Fatalf("node %d error: %v", i, err)
		}
	}

	// convergence: every ledger's first `target` blocks identical
	ref := ledgers[0].GetFinalizedBlocks()
	for i := 1; i < numNodes; i++ {
		got := ledgers[i].GetFinalizedBlocks()
		for j := 0; j < target; j++ {
			gotID, refID := got[j].Block.GetId(), ref[j].Block.GetId()
			if gotID != refID {
				t.Fatalf("node %d block %d diverged: %x vs %x",
					i, j, gotID[:8], refID[:8])
			}
		}
	}
}

func TestNodeRestartResumes(t *testing.T) {
	// 4-node restart: kill one validator mid-run, reopen on the same data
	// dir (forkpoint + validators + safety + block store all load from
	// disk), and confirm it catches up and keeps finalizing with the
	// network — the crash-recovery contract a production daemon needs.
	// (Single-validator restart is unsupported: blocksync can only fall
	// back to peers when the local store can't serve the root window.)
	const numNodes = 4
	const firstTarget = 5
	const secondTarget = 10

	gv := swarm.CreateKeysWithValidators(numNodes)
	execDelay := types.SeqNum(4)
	mesh := NewMesh()

	nodes := make([]*Node, numNodes)
	ledgers := make([]*swarm.MockLedger, numNodes)
	states := make([]*swarm.InMemoryState, numNodes)
	dirs := make([]string, numNodes)
	for i := 0; i < numNodes; i++ {
		dirs[i] = t.TempDir()
		states[i] = swarm.NewInMemoryStateGenesis(execDelay)
		self := types.NewNodeId(gv.Keys[i].PubKey())
		nodes[i], ledgers[i] = openTestNode(t, dirs[i], i, gv, states[i], mesh.Transport(self), execDelay)
	}
	for _, n := range nodes {
		if err := n.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
	}
	for _, l := range ledgers {
		waitFinalized(t, l, firstTarget, 60*time.Second)
	}

	// kill node 0 — Stop() flushes handles; dir contents persist
	before := ledgers[0].FinalizedBlocksLen()
	nodes[0].Stop()
	if err := nodes[0].Err(); err != nil {
		t.Fatalf("node 0 error before restart: %v", err)
	}

	// peers advance while node 0 is down
	for i := 1; i < numNodes; i++ {
		waitFinalized(t, ledgers[i], secondTarget, 60*time.Second)
	}

	// reopen node 0 on the same dir — execution state (sr) persists in the
	// mock world, everything else reloads from disk
	self := types.NewNodeId(gv.Keys[0].PubKey())
	n0, l0 := openTestNode(t, dirs[0], 0, gv, states[0], mesh.Transport(self), execDelay)
	if got := l0.FinalizedBlocksLen(); got < before {
		t.Fatalf("restart lost finalized blocks: %d -> %d", before, got)
	}
	if err := n0.Start(context.Background()); err != nil {
		t.Fatalf("restart Start: %v", err)
	}
	func() {
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			if l0.FinalizedBlocksLen() >= secondTarget {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		cs := n0.State().Consensus()
		var round, epoch uint64
		live := cs != nil
		if live {
			round = cs.Consensus.Pacemaker.GetCurrentRound().Uint64()
			epoch = cs.Consensus.Pacemaker.GetCurrentEpoch().Uint64()
		}
		m := n0.Metrics().BlocksyncEvents
		t.Fatalf(`restarted node stalled: finalized=%d live=%v round=%d epoch=%d statesyncing=%v
  selfReq=%d selfRespOK=%d selfRespFail=%d peerReqOK=%d peerReqFail=%d noPeers=%d timeout=%d unexpected=%d`,
			l0.FinalizedBlocksLen(), live, round, epoch, n0.State().IsStatesyncing(),
			m.SelfHeadersRequest.Get(), m.SelfHeadersResponseSuccessful.Get(), m.SelfHeadersResponseFailed.Get(),
			m.PeerHeadersRequestSuccessful.Get(), m.PeerHeadersRequestFailed.Get(),
			m.RequestFailedNoPeers.Get(), m.RequestTimeout.Get(), m.HeadersResponseUnexpected.Get())
	}()
	n0.Stop()
	if err := n0.Err(); err != nil {
		t.Fatalf("restarted node error: %v", err)
	}

	// restarted node converged on the same chain as the live peers
	want := ledgers[1].GetFinalizedBlocks()
	got := l0.GetFinalizedBlocks()
	if len(got) < secondTarget {
		t.Fatalf("restarted ledger %d < %d", len(got), secondTarget)
	}
	for i := 0; i < secondTarget; i++ {
		g, w := got[i].Block.GetId(), want[i].Block.GetId()
		if g != w {
			t.Fatalf("restarted ledger diverged at block %d: %x vs %x", i, g[:8], w[:8])
		}
	}

	for i := 1; i < numNodes; i++ {
		nodes[i].Stop()
	}
}
