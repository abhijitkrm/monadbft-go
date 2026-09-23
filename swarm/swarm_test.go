package swarm

import (
	"sort"
	"testing"
	"time"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/sigcol"
	"github.com/abhijitkrm/monadbft-go/testutil"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// makeBlock builds a mock full block whose header QC points at parentID/
// parentRound — mirroring how the real pipeline links blocks.
func makeBlock(t *testing.T, seqNum types.SeqNum, round types.Round, parentID types.BlockId, parentRound types.Round, author types.NodeId, certKey *crypto.BlsKeyPair) *cstypes.ConsensusFullBlock {
	t.Helper()
	body := cstypes.ConsensusBlockBody{Inner: cstypes.ConsensusBlockBodyInner{
		ExecutionBody: &exec.MockBody{Data: []byte{byte(seqNum)}},
	}}
	qc := cstypes.QuorumCertificate{
		Info:       cstypes.Vote{ID: parentID, Round: parentRound, Epoch: types.Epoch(1)},
		Signatures: *sigcol.Empty(),
	}
	hdr := cstypes.NewConsensusBlockHeader(
		author, types.Epoch(1), round,
		nil, &exec.MockProposedHeader{}, body.GetId(), qc,
		seqNum, types.U128FromUint64(uint64(seqNum)*1_000_000),
		cstypes.NewRoundSignature(round, certKey),
		MinBaseFee, 0, 0,
	)
	fb, err := cstypes.NewFullBlock(hdr, body)
	if err != nil {
		t.Fatalf("NewFullBlock: %v", err)
	}
	return &fb
}

// makeChain builds seq 1..n blocks linked parent→child starting at genesis.
func makeChain(t *testing.T, n int, author types.NodeId, certKey *crypto.BlsKeyPair) []*cstypes.ConsensusFullBlock {
	blocks := make([]*cstypes.ConsensusFullBlock, n)
	var pid types.BlockId = types.GENESIS_BLOCK_ID
	var pr types.Round = types.GENESIS_ROUND
	for i := 0; i < n; i++ {
		blocks[i] = makeBlock(t, types.SeqNum(i+1), types.Round(i+1), pid, pr, author, certKey)
		pid, pr = blocks[i].GetId(), blocks[i].GetBlockRound()
	}
	return blocks
}

func drain(src EventSource) []glue.MonadEvent {
	var out []glue.MonadEvent
	for src.Ready() {
		out = append(out, src.Next())
	}
	return out
}

func proposeVoteFinalize(l *MockLedger, b *cstypes.ConsensusFullBlock) {
	l.Exec([]glue.LedgerCommand{
		glue.LedgerCommit{Commit: glue.OptimisticCommit{Kind: glue.CommitProposed, Block: b, IsCanonical: true}},
		glue.LedgerCommit{Commit: glue.OptimisticCommit{Kind: glue.CommitVoted, Block: b}},
		glue.LedgerCommit{Commit: glue.OptimisticCommit{Kind: glue.CommitFinalized, Block: b}},
	})
}

// ---------------------------------------------------------------------------
// InMemoryState
// ---------------------------------------------------------------------------

func TestInMemoryStateProposeCommitFinalize(t *testing.T) {
	delay := types.SeqNum(4)
	s := NewInMemoryStateGenesis(delay)
	kp := testutil.GetCertKey(0)
	author := types.NewNodeId(testutil.GetKey(0).PubKey())
	blocks := makeChain(t, 6, author, kp)

	for _, b := range blocks {
		s.LedgerPropose(b.GetId(), b.GetSeqNum(), b.GetBlockRound(), b.GetParentId(), nil)
	}

	// nothing committed yet; latest finalized = genesis
	if got := s.RawReadLatestFinalizedBlock(); got == nil || *got != types.GENESIS_SEQ_NUM {
		t.Fatalf("latest finalized = %v, want genesis", got)
	}
	if _, err := s.GetExecutionResult(blocks[0].GetId(), 1, true); err == nil {
		t.Fatal("expected error for uncommitted block")
	}
	if _, err := s.GetExecutionResult(blocks[0].GetId(), 1, false); err != nil {
		t.Fatalf("proposed GetExecutionResult: %v", err)
	}

	for _, b := range blocks {
		s.LedgerCommit(b.GetId(), b.GetSeqNum())
	}
	if got := s.RawReadLatestFinalizedBlock(); got == nil || *got != types.SeqNum(6) {
		t.Fatalf("latest finalized = %v, want 6", got)
	}
	if got := s.RawReadEarliestFinalizedBlock(); got == nil || *got != types.GENESIS_SEQ_NUM {
		t.Fatalf("earliest finalized = %v, want genesis", *got)
	}
	fh, err := s.GetExecutionResult(blocks[2].GetId(), 3, true)
	if err != nil {
		t.Fatalf("finalized GetExecutionResult: %v", err)
	}
	if fh.SeqNum() != types.SeqNum(3) {
		t.Fatalf("finalized header seq = %v, want 3", fh.SeqNum())
	}
	if s.CommittedState(4) == nil {
		t.Fatal("missing committed state for seq 4")
	}
}

func TestInMemoryStateProposedNotFinalized(t *testing.T) {
	s := NewInMemoryStateGenesis(4)
	kp := testutil.GetCertKey(0)
	author := types.NewNodeId(testutil.GetKey(0).PubKey())
	b := makeBlock(t, 1, 1, types.GENESIS_BLOCK_ID, types.GENESIS_ROUND, author, kp)
	s.LedgerPropose(b.GetId(), 1, 1, types.GENESIS_BLOCK_ID, nil)
	if _, err := s.GetExecutionResult(b.GetId(), 1, true); err == nil {
		t.Fatal("expected finalized error for merely-proposed block")
	}
}

// ---------------------------------------------------------------------------
// MockLedger
// ---------------------------------------------------------------------------

func TestMockLedgerCommitAndBlockSync(t *testing.T) {
	s := NewInMemoryStateGenesis(0)
	l := NewMockLedger(s)
	kp := testutil.GetCertKey(0)
	author := types.NewNodeId(testutil.GetKey(0).PubKey())
	blocks := makeChain(t, 3, author, kp)

	proposeVoteFinalize(l, blocks[0])
	if l.FinalizedBlocksLen() != 1 {
		t.Fatalf("finalized len = %d, want 1", l.FinalizedBlocksLen())
	}
	if got := s.RawReadLatestFinalizedBlock(); got == nil || *got != 1 {
		t.Fatalf("state latest finalized = %v, want 1", got)
	}
	fb := l.GetFinalizedBlocks()
	if fb[0].Block.GetId() != blocks[0].GetId() {
		t.Fatal("finalized block mismatch")
	}

	proposeVoteFinalize(l, blocks[1])
	proposeVoteFinalize(l, blocks[2])
	if l.FinalizedBlocksLen() != 3 {
		t.Fatalf("finalized len = %d, want 3", l.FinalizedBlocksLen())
	}

	// header fetch for a committed range → self response
	l.Exec([]glue.LedgerCommand{
		glue.LedgerFetchHeaders{Range: cstypes.BlockRange{LastBlockId: blocks[2].GetId(), NumBlocks: 2}},
	})
	evs := drain(l)
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	resp, ok := evs[0].(glue.EvBlockSyncSelfResponse)
	if !ok {
		t.Fatalf("expected EvBlockSyncSelfResponse, got %T", evs[0])
	}
	if resp.Response.IsPayload || !resp.Response.Headers.Found || len(resp.Response.Headers.Headers) != 2 {
		t.Fatalf("expected 2 headers, got %+v", resp.Response)
	}
	if resp.Response.Headers.Headers[1].GetId() != blocks[2].GetId() {
		t.Fatal("header chain order wrong")
	}

	// payload fetch by body id
	l.Exec([]glue.LedgerCommand{
		glue.LedgerFetchPayload{BodyID: blocks[1].GetBodyId()},
	})
	evs = drain(l)
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	resp2, ok := evs[0].(glue.EvBlockSyncSelfResponse)
	if !ok || !resp2.Response.IsPayload || !resp2.Response.Body.Found {
		t.Fatalf("expected payload response, got %+v", evs[0])
	}

	// unknown range → not available
	l.Exec([]glue.LedgerCommand{
		glue.LedgerFetchHeaders{Range: cstypes.BlockRange{LastBlockId: types.BlockId{0xde, 0xad}, NumBlocks: 1}},
	})
	evs = drain(l)
	if len(evs) != 1 || evs[0].(glue.EvBlockSyncSelfResponse).Response.Headers.Found {
		t.Fatal("expected Headers NotAvailable")
	}
}

func TestMockLedgerFinalizationDelay(t *testing.T) {
	delay := types.SeqNum(2)
	s := NewInMemoryStateGenesis(0)
	l := NewMockLedger(s).WithFinalizationDelay(delay)
	kp := testutil.GetCertKey(0)
	author := types.NewNodeId(testutil.GetKey(0).PubKey())
	blocks := makeChain(t, 4, author, kp)

	for _, b := range blocks[:2] {
		proposeVoteFinalize(l, b)
	}
	// seq 1,2 ≤ delay → not yet committed
	if l.FinalizedBlocksLen() != 0 {
		t.Fatalf("finalized len = %d, want 0 (delayed)", l.FinalizedBlocksLen())
	}
	proposeVoteFinalize(l, blocks[2]) // seq 3 → finalizes seq 1
	if l.FinalizedBlocksLen() != 1 {
		t.Fatalf("finalized len = %d, want 1", l.FinalizedBlocksLen())
	}
	proposeVoteFinalize(l, blocks[3]) // seq 4 → finalizes seq 2
	if l.FinalizedBlocksLen() != 2 {
		t.Fatalf("finalized len = %d, want 2", l.FinalizedBlocksLen())
	}
	if got := s.RawReadLatestFinalizedBlock(); got == nil || *got != 2 {
		t.Fatalf("state latest finalized = %v, want 2", got)
	}
}

// ---------------------------------------------------------------------------
// MockValSetUpdaterNop
// ---------------------------------------------------------------------------

func TestMockValSetUpdaterEpochBoundary(t *testing.T) {
	gv := CreateKeysWithValidators(4)
	epochLen := types.SeqNum(10)
	v := NewMockValSetUpdaterNop(gv.ValidatorData, epochLen)

	v.Exec([]glue.ValSetCommand{glue.ValSetNotifyFinalized{SeqNum: 5}})
	if v.Ready() {
		t.Fatal("unexpected valset event before boundary")
	}
	v.Exec([]glue.ValSetCommand{glue.ValSetNotifyFinalized{SeqNum: 9}}) // boundary for len 10
	if !v.Ready() {
		t.Fatal("expected valset event at boundary")
	}
	ev := v.Next()
	uv, ok := ev.(glue.EvUpdateValidators)
	if !ok {
		t.Fatalf("expected EvUpdateValidators, got %T", ev)
	}
	if uv.ValidatorSetDataWithEpoch.Epoch != types.Epoch(2) {
		t.Fatalf("locked epoch = %v, want 2", uv.ValidatorSetDataWithEpoch.Epoch)
	}
	if len(uv.ValidatorSetDataWithEpoch.Validators.Validators) != 4 {
		t.Fatalf("validator count = %d, want 4", len(uv.ValidatorSetDataWithEpoch.Validators.Validators))
	}

	v2 := NewMockValSetUpdaterNop(gv.ValidatorData, epochLen).WithUpdatesEnabled(false)
	v2.Exec([]glue.ValSetCommand{glue.ValSetNotifyFinalized{SeqNum: 9}})
	if v2.Ready() {
		t.Fatal("updates disabled but Ready() true")
	}
}

// ---------------------------------------------------------------------------
// LoopbackExecutor
// ---------------------------------------------------------------------------

func TestLoopbackFIFO(t *testing.T) {
	l := NewLoopbackExecutor()
	l.Exec([]glue.LoopbackCommand{
		glue.LoopbackForward{Event: glue.EvTimestampUpdate{Timestamp: types.U128FromUint64(1)}},
		glue.LoopbackForward{Event: glue.EvTimestampUpdate{Timestamp: types.U128FromUint64(2)}},
	})
	evs := drain(l)
	if len(evs) != 2 {
		t.Fatalf("expected 2 events, got %d", len(evs))
	}
	if evs[0].(glue.EvTimestampUpdate).Timestamp.Uint64() != 1 ||
		evs[1].(glue.EvTimestampUpdate).Timestamp.Uint64() != 2 {
		t.Fatal("loopback did not preserve FIFO order")
	}
}

// ---------------------------------------------------------------------------
// MockTxPoolExecutor
// ---------------------------------------------------------------------------

func TestMockTxPoolProposal(t *testing.T) {
	tp := NewMockTxPoolExecutor()
	kp := testutil.GetCertKey(0)
	author := types.NewNodeId(testutil.GetKey(0).PubKey())
	round := types.Round(1)

	tp.Exec([]glue.TxPoolCommand{
		glue.TxPoolCreateProposal{
			NodeId:                  author,
			Epoch:                   types.Epoch(1),
			Round:                   round,
			SeqNum:                  1,
			TxLimit:                 100,
			ProposalGasLimit:        1_000_000,
			ProposalByteLimit:       1_000_000,
			TimestampNs:             types.U128FromUint64(42),
			RoundSignature:          cstypes.NewRoundSignature(round, kp),
			DelayedExecutionResults: []exec.FinalizedHeader{&exec.MockFinalizedHeader{Number: 0}},
		},
	})
	evs := drain(tp)
	if len(evs) != 1 {
		t.Fatalf("expected 1 proposal event, got %d", len(evs))
	}
	prop, ok := evs[0].(glue.EvMempoolProposal)
	if !ok {
		t.Fatalf("expected EvMempoolProposal, got %T", evs[0])
	}
	if prop.Round != round || prop.SeqNum != 1 {
		t.Fatalf("proposal round/seq mismatch: %+v", prop)
	}
	if prop.BaseFee != MinBaseFee {
		t.Fatalf("base fee = %d, want %d", prop.BaseFee, MinBaseFee)
	}
	if len(prop.DelayedExecutionResults) != 1 {
		t.Fatal("delayed execution results not threaded through")
	}

	// tx submission unsupported → panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("SendTransaction did not panic")
		}
	}()
	tp.SendTransaction([]byte{1})
}

// ---------------------------------------------------------------------------
// MockStateSyncExecutor
// ---------------------------------------------------------------------------

func TestMockStateSyncGenesisShortCircuit(t *testing.T) {
	s := NewInMemoryStateGenesis(0)
	ss := NewMockStateSyncExecutor(s)
	ss.Exec([]glue.StateSyncCommand{
		glue.StateSyncRequestSync{Header: &exec.MockFinalizedHeader{Number: 0}},
	})
	evs := drain(ss)
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	ds, ok := evs[0].(glue.EvStateSyncDoneSync)
	if !ok || ds.SeqNum != types.GENESIS_SEQ_NUM {
		t.Fatalf("expected DoneSync(genesis), got %T %+v", evs[0], evs[0])
	}
}

func TestMockStateSyncRequestResponse(t *testing.T) {
	// server: execution started + committed state at seq 3
	serverState := NewInMemoryStateGenesis(0)
	kp := testutil.GetCertKey(0)
	author := types.NewNodeId(testutil.GetKey(0).PubKey())
	blocks := makeChain(t, 3, author, kp)
	server := NewMockStateSyncExecutor(serverState)
	server.Exec([]glue.StateSyncCommand{glue.StateSyncStartExecution{}})
	for _, b := range blocks {
		serverState.LedgerPropose(b.GetId(), b.GetSeqNum(), b.GetBlockRound(), b.GetParentId(), nil)
		serverState.LedgerCommit(b.GetId(), b.GetSeqNum())
	}
	serverID := types.NewNodeId(testutil.GetKey(100).PubKey())
	clientID := types.NewNodeId(testutil.GetKey(200).PubKey())

	// server receives a request for target 3 → emits response to client
	server.Exec([]glue.StateSyncCommand{
		glue.StateSyncMessage{To: clientID, Message: glue.StateSyncNetworkMessage{
			Kind:    glue.SSNRequest,
			Request: glue.StateSyncRequest{Version: glue.StateSyncVersionSelf, Target: 3, PrefixBytes: 1},
		}},
	})
	evs := drain(server)
	if len(evs) != 1 {
		t.Fatalf("expected 1 response, got %d", len(evs))
	}
	out, ok := evs[0].(glue.EvStateSyncOutbound)
	if !ok || out.To != clientID || out.Message.Kind != glue.SSNResponse {
		t.Fatalf("expected outbound response to client, got %+v", evs[0])
	}

	// client: request sync to 3 via server, then apply the response
	clientState := NewInMemoryStateGenesis(0)
	client := NewMockStateSyncExecutor(clientState)
	client.Exec([]glue.StateSyncCommand{
		glue.StateSyncExpandUpstreamPeers{Peers: []types.NodeId{serverID}},
		glue.StateSyncRequestSync{Header: &exec.MockFinalizedHeader{Number: 3}},
	})
	evs = drain(client)
	if len(evs) != 1 {
		t.Fatalf("expected 1 outbound request, got %d", len(evs))
	}
	reqOut := evs[0].(glue.EvStateSyncOutbound)
	if reqOut.To != serverID || reqOut.Message.Kind != glue.SSNRequest {
		t.Fatalf("expected outbound request to server, got %+v", reqOut)
	}

	// feed the server's response back to the client
	client.Exec([]glue.StateSyncCommand{
		glue.StateSyncMessage{To: serverID, Message: glue.StateSyncNetworkMessage{
			Kind:     glue.SSNResponse,
			Response: out.Message.Response,
		}},
	})
	evs = drain(client)
	if len(evs) != 1 {
		t.Fatalf("expected DoneSync, got %d events", len(evs))
	}
	ds, ok := evs[0].(glue.EvStateSyncDoneSync)
	if !ok || ds.SeqNum != 3 {
		t.Fatalf("expected DoneSync(3), got %T %+v", evs[0], evs[0])
	}
	// client state now mirrors server
	if got := clientState.RawReadLatestFinalizedBlock(); got == nil || *got != 3 {
		t.Fatalf("client latest finalized = %v, want 3", got)
	}
}

// ---------------------------------------------------------------------------
// Multi-node deterministic swarm — A2g
// ---------------------------------------------------------------------------

// buildTestSwarm wires an n-node BytesSwarm (full RLP transport) from genesis.
func buildTestSwarm(t *testing.T, numNodes int, delta time.Duration, execDelay types.SeqNum) (*Nodes, []types.NodeId) {
	t.Helper()
	gv, builders := MakeStateConfigs(numNodes, StateConfigParams{
		ExecutionDelay:     execDelay,
		Delta:              delta,
		ChainConfig:        MockChainConfig(),
		StatesyncThreshold: types.SeqNum(100),
		LeaderElection:     func() validator.LeaderElection { return validator.WeightedRoundRobin{} },
		BlockValidator:     func() blocktree.BlockValidator { return blocktree.MockValidator{} },
		BlockPolicy:        func() blocktree.BlockPolicy { return blocktree.PassthruBlockPolicy{} },
		StateRead:          func() blocktree.ExecutionStateRead { return NewInMemoryStateGenesis(execDelay) },
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
		EpochLength:       types.SeqNum(2000),
		EP:                exec.Mock,
		Timestamper:       DefaultTimestamperConfig(),
		FinalizationDelay: 0,
	}).Build()
	return nodes, allPeers
}

// TestSwarmConsensusProgress — 4 honest nodes, constant latency, must finalize
// ≥ target blocks each with identical ledgers. Mirrors Rust's two_nodes
// family of swarm tests.
func TestSwarmConsensusProgress(t *testing.T) {
	delta := 20 * time.Millisecond
	nodes, allPeers := buildTestSwarm(t, 4, delta, types.SeqNum(4))

	const target = 10
	monitor := map[ID]int{}
	for _, p := range allPeers {
		monitor[NewID(p)] = target
	}
	term := NewProgressTerminator(monitor, 10*time.Minute)

	for {
		if _, _, _, ok := nodes.StepUntil(term); !ok {
			break
		}
	}
	SwarmLedgerVerification(nodes, target)
}

// TestBlockSyncCatchUp — ports Rust bsync_timeout_recovery: partition node 0
// (its outbound dropped) while peers finalize ≥10 blocks; then unblock
// consensus traffic but keep dropping block-sync messages (node sees the
// new tip but cannot fetch it); finally unblock everything — node must
// blocksync the missing chain and converge.
func TestBlockSyncCatchUp(t *testing.T) {
	delta := 20 * time.Millisecond
	nodes, allPeers := buildTestSwarm(t, 4, delta, types.SeqNum(^uint64(0)))
	partitioned := NewID(allPeers[0])

	outbound := func(dropBlockSync, partition bool) Pipeline {
		var p TransformerPipeline
		if dropBlockSync {
			p = append(p, &BytesFilterTransformer{DropBlockSync: true, EP: exec.Mock})
		}
		p = append(p, NewLatencyTransformer(delta))
		if partition {
			p = append(p, NewPartitionTransformer(partitioned), NewDropTransformer())
		}
		return p
	}
	nodes.UpdateOutboundPipelineForAll(outbound(true, true))

	runFor := func(d time.Duration) {
		term := NewUntilTerminator().UntilTick(nodes.Tick() + d)
		for {
			if _, _, _, ok := nodes.StepUntil(term); !ok {
				break
			}
		}
	}
	finalized := func(id ID) int {
		return nodes.Node(id).Executor.Ledger().FinalizedBlocksLen()
	}

	// phase 1: partitioned — peers progress, node 0 stalls
	runFor(5 * time.Second)
	if got := finalized(partitioned); got != 0 {
		t.Fatalf("partitioned node finalized %d blocks, want 0", got)
	}
	for _, p := range allPeers[1:] {
		if got := finalized(NewID(p)); got < 10 {
			t.Fatalf("peer %v finalized %d blocks, want >=10", p.PubKey.String()[:8], got)
		}
	}

	// phase 2: unpartitioned but block-sync still filtered — node 0 sees the
	// tip but cannot fetch missing ancestors, stays behind
	nodes.UpdateOutboundPipelineForAll(outbound(true, false))
	runFor(5 * time.Second)
	if got := finalized(partitioned); got != 0 {
		t.Fatalf("filtered node finalized %d blocks, want 0", got)
	}

	// phase 3: everything flows — node 0 catches up via block-sync
	nodes.UpdateOutboundPipelineForAll(outbound(false, false))
	runFor(30 * time.Second)
	SwarmLedgerVerification(nodes, 10)
}

// TestSwarmEpochTransition — 4 nodes with a short epoch length must schedule
// the next epoch at the boundary block's round + epoch_start_delay and all
// cross into epoch 2+, with converged ledgers. Mirrors Rust epoch.rs.
func TestSwarmEpochTransition(t *testing.T) {
	const epochLen = 20
	const epochStartDelay = types.Round(5)
	delta := 10 * time.Millisecond

	cc := MockChainConfig()
	cc.EpochLength = types.SeqNum(epochLen)
	cc.EpochStartDelay = epochStartDelay

	gv, builders := MakeStateConfigs(4, StateConfigParams{
		ExecutionDelay:     types.SeqNum(^uint64(0)),
		Delta:              delta,
		ChainConfig:        cc,
		StatesyncThreshold: types.SeqNum(1000),
		LeaderElection:     func() validator.LeaderElection { return validator.WeightedRoundRobin{} },
		BlockValidator:     func() blocktree.BlockValidator { return blocktree.MockValidator{} },
		BlockPolicy:        func() blocktree.BlockPolicy { return blocktree.PassthruBlockPolicy{} },
		StateRead:          func() blocktree.ExecutionStateRead { return NewInMemoryStateGenesis(types.SeqNum(^uint64(0))) },
	})
	allPeers := make([]types.NodeId, 4)
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
		EpochLength:       types.SeqNum(epochLen),
		EP:                exec.Mock,
		Timestamper:       DefaultTimestamperConfig(),
		FinalizationDelay: 0,
	}).Build()

	// drive until every node reaches epoch >= 3 (two full transitions)
	term := NewUntilTerminator().UntilEpoch(types.Epoch(3)).UntilTick(10 * time.Minute)
	for {
		if _, _, _, ok := nodes.StepUntil(term); !ok {
			break
		}
	}

	for _, nd := range nodes.OrderedNodes() {
		cs := nd.State.Consensus()
		ep, ok := nd.State.EpochManager().GetEpoch(cs.Consensus.GetCurrentRound())
		if !ok {
			t.Fatalf("node %v: epoch lookup failed", nd.ID.PeerID.PubKey.String()[:8])
		}
		if ep < types.Epoch(3) {
			t.Fatalf("node %v stuck in epoch %v", nd.ID.PeerID.PubKey.String()[:8], ep)
		}
	}
	SwarmLedgerVerification(nodes, epochLen)
}

// TestSwarmVariableLatency — progress under non-uniform per-pair latency
// (XorLatency outbound). Mirrors Rust rand_lat-style coverage.
func TestSwarmVariableLatency(t *testing.T) {
	delta := 20 * time.Millisecond
	execDelay := types.SeqNum(4)
	gv, builders := MakeStateConfigs(4, StateConfigParams{
		ExecutionDelay:     execDelay,
		Delta:              delta,
		ChainConfig:        MockChainConfig(),
		StatesyncThreshold: types.SeqNum(100),
		LeaderElection:     func() validator.LeaderElection { return validator.WeightedRoundRobin{} },
		BlockValidator:     func() blocktree.BlockValidator { return blocktree.MockValidator{} },
		BlockPolicy:        func() blocktree.BlockPolicy { return blocktree.PassthruBlockPolicy{} },
		StateRead:          func() blocktree.ExecutionStateRead { return NewInMemoryStateGenesis(execDelay) },
	})
	allPeers := make([]types.NodeId, 4)
	for i, k := range gv.Keys {
		allPeers[i] = types.NewNodeId(k.PubKey())
	}
	sort.Slice(allPeers, func(i, j int) bool { return allPeers[i].Cmp(allPeers[j]) < 0 })

	nodes := NewBytesSwarm(SwarmConfig{
		Builders:   builders,
		Genesis:    gv,
		AllPeerIDs: allPeers,
		OutPipeline: func() Pipeline {
			return TransformerPipeline{
				NewXorLatencyTransformer(delta),
				NewRandLatencyTransformer(DefaultSeed(7), delta),
			}
		},
		InPipeline:        func() Pipeline { return TransformerPipeline{} },
		EpochLength:       types.SeqNum(2000),
		EP:                exec.Mock,
		Timestamper:       DefaultTimestamperConfig(),
		FinalizationDelay: 0,
	}).Build()

	const target = 8
	monitor := map[ID]int{}
	for _, p := range allPeers {
		monitor[NewID(p)] = target
	}
	term := NewProgressTerminator(monitor, 10*time.Minute)
	for {
		if _, _, _, ok := nodes.StepUntil(term); !ok {
			break
		}
	}
	SwarmLedgerVerification(nodes, target)
}
