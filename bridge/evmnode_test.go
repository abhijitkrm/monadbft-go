//go:build test

package bridge_test

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
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
	"github.com/abhijitkrm/monadbft-go/net/peerdisc"
	"github.com/abhijitkrm/monadbft-go/node"
	"github.com/abhijitkrm/monadbft-go/swarm"
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
func TestEvmOverNodeRuntime(t *testing.T)           { testEvmOverNodeRuntime(t, "tcp") }
func TestEvmOverNodeRuntimeRaptorcast(t *testing.T) { testEvmOverNodeRuntime(t, "raptorcast") }

func testEvmOverNodeRuntime(t *testing.T, transportKind string) {
	const numNodes = 4
	cfg := bridge.DefaultConfig()
	// evmd FinalizeBlock takes tens of ms on this loop — the blocksync
	// request timeout (7*delta) must exceed it or requests livelock.
	cfg.Delta = 150 * time.Millisecond
	vals := bridge.MakeValidators(numNodes)

	// Static peer map: pre-allocate a port per validator.
	addrs := make([]string, numNodes)
	udpAddrs := make([]netip.AddrPort, numNodes)
	authAddrs := make([]netip.AddrPort, numNodes)
	allocPort := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		return port
	}
	allocUDPPort := func() int {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		port := c.LocalAddr().(*net.UDPAddr).Port
		_ = c.Close()
		return port
	}
	for i := range addrs {
		addrs[i] = fmt.Sprintf("127.0.0.1:%d", allocPort())
		if transportKind == "raptorcast" {
			udpAddrs[i] = netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", allocUDPPort()))
			authAddrs[i] = netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", allocUDPPort()))
		}
	}
	peerMap := map[types.NodeId]string{}
	for i, a := range addrs {
		peerMap[vals[i].NodeId()] = a
	}

	apps := make([]*bridge.App, numNodes)
	raws := make([]*evmd.EVMD, numNodes)
	nodes := make([]*node.Node, numNodes)
	pools := make([]*bridge.TxPool, numNodes)
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
		spec := bridge.NewAsyncSpecApp(app)
		t.Cleanup(spec.Close)
		var transport node.Transport
		switch transportKind {
		case "tcp":
			transport = node.NewTCPTransport(vals[i].NodeId(), node.TCPConfig{
				Listen: addrs[i],
				Peers:  peerMap,
			})
		case "raptorcast":
			transport = newRCTransport(t, vals, addrs, udpAddrs, authAddrs, i)
		}

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
			BlockValidator: blocktree.MockValidator{},
			BlockPolicy: blocktree.NewEvmBlockPolicy(cfg.ExecutionDelay,
				swarm.MinBaseFee, swarm.GenesisBaseFeeTrend, swarm.GenesisBaseFeeMoment),
			StateRead:              bridge.NewStateRead(app, spec),
			StatesyncExpandToGroup: true,
			ServeStatesync:         true,
			GenesisValidators:      genesisVals,
			Executors: node.Executors{
				Ledger:    bridge.NewLedger(app, spec),
				TxPool:    newPoolBridge(app, &pools[i]),
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

	// Inject a real signed EVM transfer into the LAST node's mempool; the
	// ForwardTxs leader-forwarding path carries it to upcoming leaders, where
	// it gets reaped into a proposal and finalized on every node.
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

	nodes[numNodes-1].SendTransaction(txBytes)

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
	// The submitter never re-forwards: at least one *other* node must have
	// received the forwarded batch for inclusion to have happened via a
	// different leader.
	fwd := 0
	for i := 0; i < numNodes-1; i++ {
		fwd += pools[i].ForwardedBatches()
	}
	if fwd == 0 {
		t.Fatal("tx included but no peer saw a forwarded batch — leader-forwarding broken")
	}
	t.Logf("forwarded batches received by peers: %d", fwd)

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

// newRCTransport — in-process RaptorCast wiring mirroring cmd/monadbft-node's
// raptorcastTransportOrDie: signed name records, all peers as bootstrap
// records, epoch-1 validator map.
func newRCTransport(t *testing.T, vals []bridge.Validator, addrs []string, udpAddrs, authAddrs []netip.AddrPort, i int) node.Transport {
	t.Helper()
	self := vals[i].NodeId()
	tcpAddr := netip.MustParseAddrPort(addrs[i])

	records := map[types.NodeId]peerdisc.MonadNameRecord{}
	epochVals := map[types.Epoch]map[types.NodeId]struct{}{1: {}}
	for j := range vals {
		id := vals[j].NodeId()
		epochVals[1][id] = struct{}{}
		if j == i {
			continue
		}
		records[id] = peerdisc.NewMonadNameRecord(
			peerdisc.NewNameRecordWithPorts(
				netip.MustParseAddrPort(addrs[j]).Addr(),
				tcpAddrFrom(t, addrs[j]), udpAddrs[j].Port(), authAddrs[j].Port(), 0, 0, 1),
			vals[j].Secp)
	}
	tr, err := node.NewRaptorcastTransport(node.RaptorcastTransportConfig{
		SelfID:   self,
		Key:      vals[i].Secp,
		AuthUDP:  authAddrs[i],
		PlainUDP: udpAddrs[i],
		TCPAddr:  tcpAddr,
		PeerDisc: peerdisc.PeerDiscoveryBuilder{
			SelfID:          self,
			SelfRecord:      peerdisc.NewMonadNameRecord(peerdisc.NewNameRecordWithPorts(tcpAddr.Addr(), tcpAddr.Port(), udpAddrs[i].Port(), authAddrs[i].Port(), 0, 0, 1), vals[i].Secp),
			CurrentEpoch:    1,
			EpochValidators: epochVals,
			BootstrapPeers:  records,
			// upstream devnet node.toml values
			RefreshPeriod:                   120 * time.Second,
			RequestTimeout:                  5 * time.Second,
			UnresponsivePruneThreshold:      5,
			LastParticipationPruneThreshold: types.Round(5000),
			MinNumPeers:                     0,
			MaxNumPeers:                     200,
			MaxGroupSize:                    10,
			PingRateLimitPerSecond:          100,
			RngSeed:                         uint64(i)*2654435761 + 1,
		},
	})
	if err != nil {
		t.Fatalf("NewRaptorcastTransport %d: %v", i, err)
	}
	return tr
}

func tcpAddrFrom(t *testing.T, a string) uint16 {
	t.Helper()
	ap, err := netip.ParseAddrPort(a)
	if err != nil {
		t.Fatal(err)
	}
	return ap.Port()
}

// newPoolBridge — retain a handle to the pool so the test can assert on
// forwarding counters.
func newPoolBridge(app *bridge.App, out **bridge.TxPool) *bridge.TxPool {
	p := bridge.NewTxPool(app)
	*out = p
	return p
}
