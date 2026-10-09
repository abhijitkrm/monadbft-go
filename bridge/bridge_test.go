//go:build test

package bridge_test

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"sort"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/abhijitkrm/monadbft-go/bridge"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/swarm"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/ethereum/go-ethereum/common"

	"github.com/cosmos/evm/evmd"
	testconstants "github.com/cosmos/evm/testutil/constants"
	txtest "github.com/cosmos/evm/testutil/tx"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

const testEvmChainID = testconstants.EighteenDecimalsChainID

// buildTestnet — n in-process evmd apps sharing one genesis, wired into the
// deterministic swarm driver via bridge executors.
func buildTestnet(t *testing.T, n int) ([]*bridge.App, []*evmd.EVMD, *swarm.Nodes) {
	t.Helper()
	return buildTestnetDelay(t, n, bridge.DefaultConfig().ExecutionDelay)
}

// buildTestnetDelay — buildTestnet with an explicit execution-delay. With
// delay < the ~2-round finality lag, proposals can only embed
// delayed_execution_results when the spec index serves them — so the swarm
// stalling would mean the spec path regressed.
func buildTestnetDelay(t *testing.T, n int, delay types.SeqNum) ([]*bridge.App, []*evmd.EVMD, *swarm.Nodes) {
	t.Helper()
	vals := bridge.MakeValidators(n)
	apps := make([]*bridge.App, n)
	raws := make([]*evmd.EVMD, n)
	for i := range apps {
		// evmd keeps a global EVM chain config — reset between app
		// constructions (same chain ID, so the shared value stays consistent).
		// Requires -tags=test for ResetTestConfig.
		evmtypes.NewEVMConfigurator().ResetTestConfig()
		app, raw, err := bridge.NewEvmdApp(bridge.EvmdConfig{
			ChainID:    "monadbft-bridge-test",
			EVMChainID: testEvmChainID,
			Home:       t.TempDir(),
		}, vals)
		if err != nil {
			t.Fatalf("NewEvmdApp node %d: %v", i, err)
		}
		apps[i] = app
		raws[i] = raw
	}
	cfg := bridge.DefaultConfig()
	cfg.ExecutionDelay = delay
	builders, err := bridge.NewNodes(apps, vals, cfg)
	if err != nil {
		t.Fatalf("NewNodes: %v", err)
	}
	nodes := builders.Build()
	t.Cleanup(func() { closeLedgers(nodes) })
	return apps, raws, nodes
}

// closeLedgers — drain and stop every node's canonical-commit worker. The
// test EVM chain config is a process global: a later ResetTestConfig must
// not race a worker still executing FinalizeBlock in the background.
func closeLedgers(nodes *swarm.Nodes) {
	for _, id := range nodes.SortedKeys() {
		if l, ok := nodes.Node(id).Executor.Ledger().(*bridge.Ledger); ok {
			l.Close()
		}
	}
}

// runUntil — drive the swarm until every node has ≥ target finalized blocks.
func runUntil(t *testing.T, nodes *swarm.Nodes, ids []swarm.ID, target int) {
	t.Helper()
	monitor := map[swarm.ID]int{}
	for _, id := range ids {
		monitor[id] = target
	}
	term := swarm.NewProgressTerminator(monitor, 10*time.Minute)
	for {
		if _, _, _, ok := nodes.StepUntil(term); !ok {
			break
		}
	}
}

// assertSameChain — every app must have committed identical heights with
// identical app hashes (the real "produced finalized EVM blocks" assertion).
func assertSameChain(t *testing.T, apps []*bridge.App, minHeight int64) {
	t.Helper()
	for i, a := range apps {
		if a.Height() < minHeight {
			t.Fatalf("node %d only reached height %d (want >= %d)", i, a.Height(), minHeight)
		}
	}
	for h := int64(1); h <= minHeight; h++ {
		var ref []byte
		for i, a := range apps {
			ah := a.Result(h)
			if ah == nil {
				t.Fatalf("node %d missing result for height %d", i, h)
			}
			if ref == nil {
				ref = ah.AppHash
			} else if !bytes.Equal(ref, ah.AppHash) {
				t.Fatalf("apphash divergence at height %d: node0 %x vs node%d %x",
					h, ref[:8], i, ah.AppHash[:8])
			}
		}
		if len(ref) == 0 {
			t.Fatalf("empty apphash at height %d", h)
		}
	}
}

// TestBridgeOneNode — single-validator testnet: MonadBFT drives an in-process
// evmd app to produce finalized EVM blocks.
func TestBridgeOneNode(t *testing.T) {
	apps, _, nodes := buildTestnet(t, 1)
	ids := nodes.SortedKeys()
	runUntil(t, nodes, ids, 12)
	assertSameChain(t, apps, 10)
	t.Logf("1-node: reached height %d", apps[0].Height())
}

// TestBridgeFourNodes — 4 validators reaching BFT consensus over real EVM
// execution: identical app hashes on all nodes.
func TestBridgeFourNodes(t *testing.T) {
	apps, _, nodes := buildTestnet(t, 4)
	ids := nodes.SortedKeys()
	runUntil(t, nodes, ids, 12)
	assertSameChain(t, apps, 10)
	for i, a := range apps {
		fmt.Printf("node %d height=%d\n", i, a.Height())
	}
}

// TestBridgeTxInclusion — a real signed EVM transfer submitted via CheckTx →
// mempool → PrepareProposal → FinalizeBlock, and the app hash reflects the
// state change. Asserts the tx lands in a committed block and all nodes
// still agree byte-for-byte.
func TestBridgeTxInclusion(t *testing.T) {
	apps, raws, nodes := buildTestnet(t, 4)
	ids := nodes.SortedKeys()

	sender := bridge.GenesisSenderKey()
	from := common.BytesToAddress(sender.PubKey().Address().Bytes())
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	msg := evmtypes.NewTx(&evmtypes.EvmTxArgs{
		ChainID:  evmtypes.GetEthChainConfig().ChainID,
		Nonce:    0,
		To:       &to,
		Amount:   big.NewInt(1_000_000_000_000_000_000), // 1 coin
		GasLimit: 21_000,
		GasPrice: big.NewInt(1_000_000_000_000), // 1000 gwei — above base fee
	})
	msg.From = from.Bytes()

	txCfg := raws[0].TxConfig()
	sdkTx, err := txtest.PrepareEthTx(txCfg, sender, msg)
	if err != nil {
		t.Fatalf("PrepareEthTx: %v", err)
	}
	txBytes, err := txCfg.TxEncoder()(sdkTx)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	wantHash := msg.Hash()

	// produce a few blocks first — before the first Commit the app's check
	// state has no consensus params (block gas limit reads as 0) and the
	// mempool's height sync has no head to serve.
	runUntil(t, nodes, ids, 4)

	// inject into node 0's mempool — the swarm.TxPool seam (CheckTx+InsertTx)
	pool := bridge.NewTxPool(apps[0])
	pool.SendTransaction(txBytes)
	for _, e := range pool.LastErrs() {
		t.Logf("mempool insert: %v", e)
	}

	// drive until the tx is committed on every node (or height cap)
	found := false
	monitor := map[swarm.ID]int{}
	for _, id := range ids {
		monitor[id] = 40
	}
	term := swarm.NewProgressTerminator(monitor, 10*time.Minute)
	for {
		if _, _, _, ok := nodes.StepUntil(term); !ok {
			break
		}
		for h := int64(1); h <= apps[0].Height() && !found; h++ {
			for _, bz := range apps[0].Txs(h) {
				cand, err := txCfg.TxDecoder()(bz)
				if err != nil || len(cand.GetMsgs()) == 0 {
					continue
				}
				if etx, ok := cand.GetMsgs()[0].(*evmtypes.MsgEthereumTx); ok && etx.Hash() == wantHash {
					found = true
					break
				}
			}
		}
		if found && apps[0].Height() >= 12 {
			break
		}
	}
	if !found {
		t.Fatalf("tx %s never included (reached height %d)", wantHash, apps[0].Height())
	}
	assertSameChain(t, apps, 10)
	t.Logf("tx %s included; nodes at height %d", wantHash, apps[0].Height())
}

// TestBridgeDeferredExecParity — Phase-5 parity check: run the
// execution_delay=2 swarm (proposals embed *speculative* results — seq-2 is
// rarely finalized at proposal time) with a real tx injected, then replay
// every committed block through a fresh app on the canonical
// FinalizeBlock+Commit path. The committed app hashes are a mix of
// spec-produced results (reused by the ledger) and canonical fallbacks —
// all must equal independent re-execution.
func TestBridgeDeferredExecParity(t *testing.T) {
	t.Run("final", func(t *testing.T) { testDeferredExecParity(t, false, 3) })
	t.Run("speculative", func(t *testing.T) { testDeferredExecParity(t, true, 2) })
}

func testDeferredExecParity(t *testing.T, speculative bool, delay types.SeqNum) {
	const minHeight = 14

	vals := bridge.MakeValidators(4)
	apps := make([]*bridge.App, 4)
	raws := make([]*evmd.EVMD, 4)
	for i := range apps {
		evmtypes.NewEVMConfigurator().ResetTestConfig()
		app, raw, err := bridge.NewEvmdApp(bridge.EvmdConfig{
			ChainID:    "monadbft-bridge-test",
			EVMChainID: testEvmChainID,
			Home:       t.TempDir(),
		}, vals)
		if err != nil {
			t.Fatalf("NewEvmdApp node %d: %v", i, err)
		}
		apps[i], raws[i] = app, raw
	}
	cfg := bridge.DefaultConfig()
	cfg.ExecutionDelay = delay
	cfg.Speculative = speculative
	builders, err := bridge.NewNodes(apps, vals, cfg)
	if err != nil {
		t.Fatalf("NewNodes: %v", err)
	}
	nodes := builders.Build()
	t.Cleanup(func() { closeLedgers(nodes) })
	ids := nodes.SortedKeys()

	runUntil(t, nodes, ids, 4)
	nodes.SendTransaction(ids[0], signTx(t, raws[0], 0,
		common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
		big.NewInt(1_000_000_000_000_000_000)))
	runUntil(t, nodes, ids, minHeight+2)
	assertSameChain(t, apps, minHeight)

	// canonical replay: fresh app, execute the committed blocks in order.
	// Quiesce the swarm's commit workers first (shared EVM config global).
	closeLedgers(nodes)
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	replay, _, err := bridge.NewEvmdApp(bridge.EvmdConfig{
		ChainID:    "monadbft-bridge-test",
		EVMChainID: testEvmChainID,
		Home:       t.TempDir(),
	}, vals)
	if err != nil {
		t.Fatalf("NewEvmdApp replay: %v", err)
	}
	node0 := nodes.Node(ids[0])
	fbs := node0.Executor.Ledger().GetFinalizedBlocks()
	sort.Slice(fbs, func(i, j int) bool { return fbs[i].SeqNum < fbs[j].SeqNum })
	replayed := 0
	for _, fb := range fbs {
		h := fb.Block.Header
		seq := int64(h.SeqNum.Uint64())
		if seq > minHeight {
			break
		}
		body, ok := fb.Block.Body.Inner.ExecutionBody.(*bridge.EvmBody)
		if !ok {
			t.Fatalf("seq %d: unexpected body %T", seq, fb.Block.Body.Inner.ExecutionBody)
		}
		blockID := h.GetId()
		res, err := replay.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
			Txs:                body.Txs,
			Height:             seq,
			Time:               time.Unix(0, int64(h.TimestampNs.Uint64())),
			ProposerAddress:    replay.ConsAddr(h.Author),
			DecidedLastCommit:  replay.LastCommit(h.QC),
			Hash:               blockID[:],
			NextValidatorsHash: replay.ValidatorsHash(),
		})
		if err != nil {
			t.Fatalf("replay FinalizeBlock h=%d: %v", seq, err)
		}
		if err := replay.Commit(context.Background()); err != nil {
			t.Fatalf("replay Commit h=%d: %v", seq, err)
		}
		want := apps[0].Result(seq)
		if want == nil {
			t.Fatalf("node 0 missing result at height %d", seq)
		}
		if !bytes.Equal(res.AppHash, want.AppHash) {
			t.Fatalf("replay divergence at height %d: swarm %x vs canonical %x",
				seq, want.AppHash[:8], res.AppHash[:8])
		}
		replayed++
	}
	if replayed < minHeight {
		t.Fatalf("replayed only %d of %d committed blocks", replayed, minHeight)
	}
	t.Logf("canonical replay matches committed apphash across %d heights", replayed)
}

// TestBridgeDeferredExec — execution_delay=2 < finality lag (~3 rounds in
// this swarm): most proposals' delayed_execution_results must come from the
// speculative index (seq-delay is rarely finalized at proposal time). If
// spec were broken the swarm would stall on RxExecutionLagging; reaching
// height 10 proves the pipeline. (delay=1 is unsupported: seq-1 can't be
// spec-executed — see Ledger.speculate's floor.)
func TestBridgeDeferredExec(t *testing.T) {
	apps, _, nodes := buildTestnetDelay(t, 4, types.SeqNum(2))
	ids := nodes.SortedKeys()
	runUntil(t, nodes, ids, 10)
	assertSameChain(t, apps, 8)
	for i, a := range apps {
		t.Logf("deferred-exec node %d height=%d", i, a.Height())
	}
}

// TestBridgeStatesyncRejoin — end-to-end statesync: node 0 is wiped
// mid-run (fresh app at genesis), boots from a live peer's forkpoint, and
// its missing delayed-execution results trigger CmdRequestStateSync. The
// bridge StateSync executor pulls the canonical committed blocks from a
// serving peer, replays them through FinalizeBlock+Commit, reports
// DoneSync, and the node rejoins live consensus — ending with the same
// committed app hashes as its peers.
func TestBridgeStatesyncRejoin(t *testing.T) {
	vals := bridge.MakeValidators(4)
	cfg := bridge.DefaultConfig()
	cfg.ExecutionDelay = 2

	apps := make([]*bridge.App, 4)
	for i := range apps {
		evmtypes.NewEVMConfigurator().ResetTestConfig()
		app, _, err := bridge.NewEvmdApp(bridge.EvmdConfig{
			ChainID:    "monadbft-bridge-test",
			EVMChainID: testEvmChainID,
			Home:       t.TempDir(),
		}, vals)
		if err != nil {
			t.Fatalf("NewEvmdApp node %d: %v", i, err)
		}
		apps[i] = app
	}
	builders, err := bridge.NewNodes(apps, vals, cfg)
	if err != nil {
		t.Fatalf("NewNodes: %v", err)
	}
	nodes := builders.Build()
	ids := nodes.SortedKeys()
	nodes.CanFailDeliver() // node 0's messages drop while it is wiped
	runUntil(t, nodes, ids, 6)

	// map the failed swarm ID back to its validator
	failedID := ids[0]
	var failedIdx int
	for i := range vals {
		if vals[i].NodeId() == failedID.PeerID {
			failedIdx = i
		}
	}
	liveID := ids[1]
	nodes.RemoveState(failedID)

	// remaining 3 validators still meet 2/3 quorum — the network advances
	// while node 0 is wiped.
	runUntil(t, nodes, ids[1:], 12)

	// boot the wiped node at a live peer's forkpoint over a fresh app
	liveFp := nodes.Node(liveID).GetForkpoint()
	genesisVals, err := apps[1].ValidatorSetData()
	if err != nil {
		t.Fatalf("ValidatorSetData: %v", err)
	}
	var locked []glue.ValidatorSetDataWithEpoch
	for _, le := range liveFp.Checkpoint.ValidatorSets {
		locked = append(locked, glue.ValidatorSetDataWithEpoch{
			Epoch:      le.Epoch,
			Validators: genesisVals,
		})
	}
	// evmd global config reset between constructions — safe here: the swarm
	// is driven synchronously on this goroutine, so no app is mid-execution.
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	freshApp, _, err := bridge.NewEvmdApp(bridge.EvmdConfig{
		ChainID:    "monadbft-bridge-test",
		EVMChainID: testEvmChainID,
		Home:       t.TempDir(),
	}, vals)
	if err != nil {
		t.Fatalf("NewEvmdApp rejoin: %v", err)
	}
	var allPeers []types.NodeId
	for _, v := range vals {
		allPeers = append(allPeers, v.NodeId())
	}
	nb, err := bridge.NewNodeBuilder(failedIdx, freshApp, vals[failedIdx], allPeers, locked, cfg)
	if err != nil {
		t.Fatalf("NewNodeBuilder: %v", err)
	}
	nb.StateBuilder.Forkpoint = liveFp
	nodes.AddState(*nb)

	// all four validators live again; node 0 must catch up and agree.
	runUntil(t, nodes, ids, 18)
	apps[failedIdx] = freshApp
	assertSameChain(t, apps, 15)
	for i, a := range apps {
		t.Logf("rejoin: node %d height=%d", i, a.Height())
	}
}

// TestBridgeEpochBoundary — a short epoch length forces the consensus
// epoch machinery to roll (valset lock boundaries at epochLength) while
// the bridge keeps finalizing. Asserts committed-height/apptash parity
// across nodes past several epoch transitions.
func TestBridgeEpochBoundary(t *testing.T) {
	vals := bridge.MakeValidators(4)
	cfg := bridge.DefaultConfig()
	cfg.EpochLength = 6 // boundary every 6 seqs; lock window inside it

	apps := make([]*bridge.App, 4)
	for i := range apps {
		evmtypes.NewEVMConfigurator().ResetTestConfig()
		app, _, err := bridge.NewEvmdApp(bridge.EvmdConfig{
			ChainID:    "monadbft-bridge-test",
			EVMChainID: testEvmChainID,
			Home:       t.TempDir(),
		}, vals)
		if err != nil {
			t.Fatalf("NewEvmdApp node %d: %v", i, err)
		}
		apps[i] = app
	}
	builders, err := bridge.NewNodes(apps, vals, cfg)
	if err != nil {
		t.Fatalf("NewNodes: %v", err)
	}
	nodes := builders.Build()
	ids := nodes.SortedKeys()
	runUntil(t, nodes, ids, 20) // well past the epoch-2 boundary at 6
	assertSameChain(t, apps, 18)
	for i, a := range apps {
		t.Logf("epoch-boundary node %d height=%d", i, a.Height())
	}
}
