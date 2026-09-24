//go:build test

package bridge_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/abhijitkrm/monadbft-go/bridge"
	"github.com/abhijitkrm/monadbft-go/swarm"

	testconstants "github.com/cosmos/evm/testutil/constants"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

const testEvmChainID = testconstants.EighteenDecimalsChainID

// buildTestnet — n in-process evmd apps sharing one genesis, wired into the
// deterministic swarm driver via bridge executors.
func buildTestnet(t *testing.T, n int) ([]*bridge.App, *swarm.Nodes) {
	t.Helper()
	vals := bridge.MakeValidators(n)
	apps := make([]*bridge.App, n)
	for i := range apps {
		// evmd keeps a global EVM chain config — reset between app
		// constructions (same chain ID, so the shared value stays consistent).
		// Requires -tags=test for ResetTestConfig.
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
	builders, err := bridge.NewNodes(apps, vals, bridge.DefaultConfig())
	if err != nil {
		t.Fatalf("NewNodes: %v", err)
	}
	return apps, builders.Build()
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
	apps, nodes := buildTestnet(t, 1)
	ids := nodes.SortedKeys()
	runUntil(t, nodes, ids, 12)
	assertSameChain(t, apps, 10)
	t.Logf("1-node: reached height %d", apps[0].Height())
}

// TestBridgeFourNodes — 4 validators reaching BFT consensus over real EVM
// execution: identical app hashes on all nodes.
func TestBridgeFourNodes(t *testing.T) {
	apps, nodes := buildTestnet(t, 4)
	ids := nodes.SortedKeys()
	runUntil(t, nodes, ids, 12)
	assertSameChain(t, apps, 10)
	for i, a := range apps {
		fmt.Printf("node %d height=%d\n", i, a.Height())
	}
}
