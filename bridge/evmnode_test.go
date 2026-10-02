//go:build test

package bridge_test

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/bridge"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/node"
	"github.com/abhijitkrm/monadbft-go/types"

	"github.com/cosmos/evm/evmd"
	txtest "github.com/cosmos/evm/testutil/tx"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// TestEvmOverNodeRuntime — the production node.Node runtime drives real evmd
// apps: wall-clock timers, WAL+forkpoint+safety persistence, real TCP
// sockets — the wiring a multi-process evmd devnet uses, minus the process
// boundary (SDK apps are in-process by nature). Complements the swarm tests,
// which drive the same executors under a discrete-event scheduler.
func TestEvmOverNodeRuntime(t *testing.T) {
	const numNodes = 4
	cfg := bridge.DefaultConfig()
	// evmd FinalizeBlock takes tens of ms on this loop — the blocksync
	// request timeout (7*delta) must exceed it or requests livelock.
	cfg.Delta = 150 * time.Millisecond
	vals := bridge.MakeValidators(numNodes)

	// Static peer map: pre-allocate a port per validator.
	addrs := make([]string, numNodes)
	for i := range addrs {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = ln.Addr().String()
		_ = ln.Close()
	}
	peerMap := map[types.NodeId]string{}
	for i, a := range addrs {
		peerMap[vals[i].NodeId()] = a
	}

	apps := make([]*bridge.App, numNodes)
	raws := make([]*evmd.EVMD, numNodes)
	nodes := make([]*node.Node, numNodes)
	logPaths := make([]string, numNodes)

	// Genesis validator set — identical on every node (same vals table).
	var genesisVals glue.ValidatorSetData

	for i := 0; i < numNodes; i++ {
		// evmd keeps a global EVM chain config — reset between app
		// constructions (same chain ID, so the shared value stays consistent).
		evmtypes.NewEVMConfigurator().ResetTestConfig()
		app, raw, err := bridge.NewEvmdApp(bridge.EvmdConfig{
			ChainID:    "monadbft-node-test",
			EVMChainID: testEvmChainID,
			Home:       t.TempDir(),
		}, vals)
		if err != nil {
			t.Fatalf("NewEvmdApp node %d: %v", i, err)
		}
		apps[i], raws[i] = app, raw

		if i == 0 {
			genesisVals, err = app.ValidatorSetData()
			if err != nil {
				t.Fatalf("ValidatorSetData: %v", err)
			}
		}

		dir := t.TempDir()
		persist, err := node.OpenPersistence(dir, bridge.Evm, false, true)
		if err != nil {
			t.Fatalf("OpenPersistence node %d: %v", i, err)
		}
		valset, err := bridge.NewValSet(app, cfg.EpochLength)
		if err != nil {
			t.Fatalf("NewValSet node %d: %v", i, err)
		}
		transport := node.NewTCPTransport(vals[i].NodeId(), node.TCPConfig{
			Listen: addrs[i],
			Peers:  peerMap,
		})

		logPaths[i] = filepath.Join(dir, "node.log")
		logFile, _ := os.Create(logPaths[i])
		n, err := node.Open(node.Config{
			Logger:      slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug})),
			Dir:         dir,
			Protocol:    bridge.Evm,
			Persistence: persist,
			Keypair:     vals[i].Secp,
			CertKeypair: vals[i].Bls,
			ConsensusConfig: &consensusstate.Config{
				ExecutionDelay:             cfg.ExecutionDelay,
				Delta:                      cfg.Delta,
				ChainConfig:                cfg.ChainConfig,
				StatesyncToLiveThreshold:   cfg.StatesyncThreshold,
				LiveToStatesyncThreshold:   types.SeqNum(cfg.StatesyncThreshold.Uint64() * 3 / 2),
				StartExecutionThreshold:    types.SeqNum(cfg.StatesyncThreshold.Uint64() / 2),
				TimestampLatencyEstimateNs: types.U128FromUint64(10_000_000),
			},
			BlockValidator:         blocktree.MockValidator{},
			BlockPolicy:            blocktree.NewMockBlockPolicy(cfg.ExecutionDelay),
			StateRead:              bridge.NewStateRead(app),
			StatesyncExpandToGroup: true,
			ServeStatesync:         true,
			GenesisValidators:      genesisVals,
			Executors: node.Executors{
				Ledger:    bridge.NewLedger(app),
				TxPool:    bridge.NewTxPool(app),
				ValSet:    valset,
				StateSync: bridge.NopStateSync{},
				Transport: transport,
			},
		})
		if err != nil {
			t.Fatalf("node.Open %d: %v", i, err)
		}
		nodes[i] = n
	}

	ctx := context.Background()
	for i, n := range nodes {
		if err := n.Start(ctx); err != nil {
			t.Fatalf("Start node %d: %v", i, err)
		}
	}
	defer func() {
		for _, n := range nodes {
			if n != nil {
				n.Stop()
			}
		}
	}()

	waitAppHeight(t, apps, 4, 60*time.Second, logPaths)

	// Inject a real signed EVM transfer into node 0's mempool; it should be
	// reaped into a proposal and finalized on every node.
	sender := bridge.GenesisSenderKey()
	from := common.BytesToAddress(sender.PubKey().Address().Bytes())
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	msg := evmtypes.NewTx(&evmtypes.EvmTxArgs{
		ChainID:  evmtypes.GetEthChainConfig().ChainID,
		Nonce:    0,
		To:       &to,
		Amount:   big.NewInt(1_000_000_000_000_000_000),
		GasLimit: 21_000,
		GasPrice: big.NewInt(1_000_000_000_000),
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

	nodes[0].SendTransaction(txBytes)

	deadline := time.Now().Add(90 * time.Second)
	found := false
	for time.Now().Before(deadline) && !found {
		for h := int64(1); h <= apps[0].Height(); h++ {
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
			if found {
				break
			}
		}
		if !found {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !found {
		t.Fatalf("tx %s never included (reached height %d)", wantHash, apps[0].Height())
	}

	waitAppHeight(t, apps, 10, 60*time.Second, logPaths)
	assertSameChain(t, apps, 10)
	t.Logf("tx %s included; nodes at height %d", wantHash, apps[0].Height())
}

// waitAppHeight polls until every app's committed height reaches target.
func waitAppHeight(t *testing.T, apps []*bridge.App, target int64, timeout time.Duration, logPaths []string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok := true
		for _, a := range apps {
			if a.Height() < target {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	var b strings.Builder
	for i, a := range apps {
		fmt.Fprintf(&b, "node %d height=%d\n", i, a.Height())
		if data, err := os.ReadFile(logPaths[i]); err == nil {
			lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
			if len(lines) > 10 {
				lines = lines[len(lines)-10:]
			}
			fmt.Fprintf(&b, "--- node %d log tail:\n%s\n", i, strings.Join(lines, "\n"))
		}
	}
	t.Fatalf("apps never all reached height %d:\n%s", target, b.String())
}
