//go:build test

package bridge_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/abhijitkrm/monadbft-go/bridge"
	"github.com/abhijitkrm/monadbft-go/swarm"
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
	builders, err := bridge.NewNodes(apps, vals, bridge.DefaultConfig())
	if err != nil {
		t.Fatalf("NewNodes: %v", err)
	}
	return apps, raws, builders.Build()
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
