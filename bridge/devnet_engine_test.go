//go:build test

package bridge

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	cmtcfg "github.com/cometbft/cometbft/config"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"

	"github.com/abhijitkrm/monadbft-go/node"

	"github.com/cosmos/evm/engine"
	testconstants "github.com/cosmos/evm/testutil/constants"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// devnetNode — on-disk identity + dirs for one engine-managed validator.
type devnetNode struct {
	root     string
	appDir   string
	tcpAddr  string
	udpPort  int
	authPort int
	eng      engine.Engine
	me       *monadEngine
	db       dbm.DB
}

func allocTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func allocUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// writeNodeConfig — the per-node file set the engine consumes: monad key
// file, comet priv_validator, monadbft.json, shared validators+peers files.
func writeNodeConfig(t *testing.T, dn *devnetNode, transport string, v Validator, vals []Validator, peers []node.BootstrapPeerConfig) {
	writeNodeConfigSS(t, dn, transport, v, vals, peers, 0)
}

func writeNodeConfigSS(t *testing.T, dn *devnetNode, transport string, v Validator, vals []Validator, peers []node.BootstrapPeerConfig, ssThreshold uint64) {
	t.Helper()
	cfgDir := filepath.Join(dn.root, "config")
	if err := os.MkdirAll(filepath.Join(dn.root, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sk := v.Secp.SecretKey()
	keyJSON, _ := json.Marshal(MonadKeyFile{
		SecpSecretKey: hex.EncodeToString(sk[:]),
		BlsSecretKey:  hex.EncodeToString(v.Bls.IKM()),
	})
	if err := os.WriteFile(filepath.Join(cfgDir, "monad.key.json"), keyJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	privval.NewFilePV(cmted25519.PrivKey(v.ConsPriv),
		filepath.Join(cfgDir, "priv_validator_key.json"),
		filepath.Join(dn.root, "data", "priv_validator_state.json")).Save()

	var bindings validatorsFile
	for _, pv := range vals {
		bindings.Validators = append(bindings.Validators, ValidatorBinding{
			ConsPubKey: hex.EncodeToString(pv.ConsPub),
			SecpPubKey: hex.EncodeToString(pv.SecpPub.Bytes()),
			BlsPubKey:  hex.EncodeToString(pv.BlsPub[:]),
		})
	}
	vraw, _ := json.Marshal(bindings)
	if err := os.WriteFile(filepath.Join(cfgDir, "validators.json"), vraw, 0o644); err != nil {
		t.Fatal(err)
	}
	praw, _ := json.Marshal(peers)
	if err := os.WriteFile(filepath.Join(cfgDir, "peers.json"), praw, 0o644); err != nil {
		t.Fatal(err)
	}
	ecfg := DefaultEngineConfig()
	ecfg.Transport = transport
	ecfg.TCPAddress = dn.tcpAddr
	ecfg.UDPPort = dn.udpPort
	ecfg.AuthPort = dn.authPort
	ecfg.BindIP = "127.0.0.1"
	ecfg.PeersFile = "peers.json"
	ecfg.PeerdiscRefreshMs = 1000
	if ssThreshold > 0 {
		ecfg.StatesyncThreshold = ssThreshold
	}
	ecfg.ValidatorsFile = "validators.json"
	mcfg, _ := json.Marshal(ecfg)
	if err := os.WriteFile(filepath.Join(cfgDir, "monadbft.json"), mcfg, 0o644); err != nil {
		t.Fatal(err)
	}
}

// startDevnetNode — build the raw app on disk and Start the engine.
func startDevnetNode(t *testing.T, cfg EvmdConfig, dn *devnetNode, genDoc *cmttypes.GenesisDoc) {
	t.Helper()
	db, err := dbm.NewPebbleDB("application", dn.appDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	dn.db = db
	raw := newRawEvmdDB(cfg, db)
	pv := privval.LoadFilePV(
		filepath.Join(dn.root, "config", "priv_validator_key.json"),
		filepath.Join(dn.root, "data", "priv_validator_state.json"))
	cmtCfg := cmtcfg.DefaultConfig()
	cmtCfg.SetRoot(dn.root)
	eng, err := Start(engine.Options{
		App:           raw,
		Config:        cmtCfg,
		PrivValidator: pv,
		GenDocProvider: func() (*cmttypes.GenesisDoc, error) {
			return genDoc, nil
		},
		Logger: cmtlog.NewNopLogger(),
	})
	if err != nil {
		t.Fatalf("start %s: %v", dn.root, err)
	}
	dn.eng, dn.me = eng, eng.(*monadEngine)
}

func (dn *devnetNode) stop(t *testing.T) {
	t.Helper()
	if dn.eng != nil {
		if err := dn.eng.Stop(); err != nil {
			t.Fatalf("stop %s: %v", dn.root, err)
		}
		dn.eng, dn.me = nil, nil
	}
	if dn.db != nil {
		if err := dn.db.Close(); err != nil {
			t.Fatal(err)
		}
		dn.db = nil
	}
}

// TestEngineMultiNodeRestart — the devnet restart matrix at engine scope:
// 4 validators on TCP; stop node 0 mid-run, let quorum advance, restart
// node 0 on the same dirs — it must catch up over blocksync and resume
// committing, ending level with the peers.
func TestEngineMultiNodeRestart(t *testing.T) {
	runMultiNodeRestart(t, "tcp")
}

// TestEngineMultiNodeRestartRaptorcast — same restart matrix over the
// production dataplane (wireauth UDP + raptorcast fanout + TCP fallback).
func TestEngineMultiNodeRestartRaptorcast(t *testing.T) {
	runMultiNodeRestart(t, "raptorcast")
}

func runMultiNodeRestart(t *testing.T, transport string) {
	const n = 4
	vals := MakeValidators(n)
	cfg := EvmdConfig{ChainID: "probe-devnet", EVMChainID: testconstants.EighteenDecimalsChainID, Home: t.TempDir()}

	// Shared genesis: identical app state + all four cons keys.
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	genesisRaw := newRawEvmdDB(cfg, dbm.NewMemDB())
	stateBytes, err := evmdGenesisState(genesisRaw, cfg, vals)
	if err != nil {
		t.Fatal(err)
	}
	var genVals []cmttypes.GenesisValidator
	for _, v := range vals {
		pub := cmted25519.PubKey(v.ConsPub)
		genVals = append(genVals, cmttypes.GenesisValidator{
			Address: pub.Address(), PubKey: pub, Power: 1, Name: "v",
		})
	}
	genDoc := &cmttypes.GenesisDoc{
		ChainID:         cfg.ChainID,
		GenesisTime:     time.Now(),
		ConsensusParams: cmttypes.DefaultConsensusParams(),
		Validators:      genVals,
		AppState:        stateBytes,
	}

	// Ports first: the peers file embeds every node's signed name record.
	nodes := make([]*devnetNode, n)
	var peers []node.BootstrapPeerConfig
	for i := range nodes {
		tcp := allocTCP(t)
		_, portStr, _ := net.SplitHostPort(tcp)
		port, _ := strconv.Atoi(portStr)
		nodes[i] = &devnetNode{
			root: t.TempDir(), appDir: t.TempDir(), tcpAddr: tcp,
			udpPort: allocUDP(t), authPort: allocUDP(t),
		}
		peers = append(peers, node.SelfBootstrapPeer(vals[i].Secp,
			netip.MustParseAddr("127.0.0.1"),
			uint16(port), uint16(nodes[i].udpPort), uint16(nodes[i].authPort), 0, 0, 1))
	}
	for i := range nodes {
		writeNodeConfig(t, nodes[i], transport, vals[i], vals, peers)
	}

	for i := range nodes {
		startDevnetNode(t, cfg, nodes[i], genDoc)
		t.Cleanup(func() {
			if nodes[i].eng != nil {
				nodes[i].stop(t)
			}
		})
	}
	defer func() {
		for i, dn := range nodes {
			if dn.me != nil {
				id := dn.me.curNode().NodeID()
				t.Logf("node%d peers=%d id=%x…", i, len(dn.me.curNode().Peers()), id.PubKey[:4])
			}
		}
	}()
	for i := range nodes {
		probeWaitHeight(t, nodes[i].me, 4, 60*time.Second)
	}

	// Kill node 0 mid-run; remaining 3 keep quorum.
	nodes[0].stop(t)
	for i := 1; i < n; i++ {
		probeWaitHeight(t, nodes[i].me, 10, 60*time.Second)
	}
	tip := nodes[1].me.app.Height()

	// Restart node 0 on the same dirs — forkpoint+blockstore resume, then
	// blocksync from live peers to the moving tip.
	startDevnetNode(t, cfg, nodes[0], genDoc)
	probeWaitHeight(t, nodes[0].me, tip+2, 90*time.Second)
	for i := range nodes {
		t.Logf("node %d height=%d", i, nodes[i].me.app.Height())
	}
}

// TestEngineStatesyncRejoin — a validator that loses its chain state
// rejoins a live net: with a low statesync threshold it must sync via the
// statesync executor (replay-sync responses over the datapath) rather than
// crawling blocksync, then resume live consensus.
//
// Two wipe profiles, exercising both recovery arcs:
//   - keep_safety: ops wipe preserving monadbft/safety.rlp — the node must
//     NOT go live below its vote watermark; it holds in Sync mode until
//     observed certs advance the high certificate past it, then syncs.
//   - wipe_safety: full state loss — the node goes live at genesis, the
//     high QC races ahead of the buffer root, maybe_statesync panics into
//     ErrNeedStatesync, and the supervisor restarts onto the persisted
//     statesync-target forkpoint.
func TestEngineStatesyncRejoin(t *testing.T) {
	for _, wipeSafety := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep_safety", true: "wipe_safety"}[wipeSafety],
			func(t *testing.T) { testEngineStatesyncRejoin(t, wipeSafety) })
	}
}

func testEngineStatesyncRejoin(t *testing.T, wipeSafety bool) {
	const n = 4
	vals := MakeValidators(n)
	cfg := EvmdConfig{ChainID: "probe-statesync", EVMChainID: testconstants.EighteenDecimalsChainID, Home: t.TempDir()}

	evmtypes.NewEVMConfigurator().ResetTestConfig()
	genesisRaw := newRawEvmdDB(cfg, dbm.NewMemDB())
	stateBytes, err := evmdGenesisState(genesisRaw, cfg, vals)
	if err != nil {
		t.Fatal(err)
	}
	var genVals []cmttypes.GenesisValidator
	for _, v := range vals {
		pub := cmted25519.PubKey(v.ConsPub)
		genVals = append(genVals, cmttypes.GenesisValidator{
			Address: pub.Address(), PubKey: pub, Power: 1, Name: "v",
		})
	}
	genDoc := &cmttypes.GenesisDoc{
		ChainID:         cfg.ChainID,
		GenesisTime:     time.Now(),
		ConsensusParams: cmttypes.DefaultConsensusParams(),
		Validators:      genVals,
		AppState:        stateBytes,
	}

	nodes := make([]*devnetNode, n)
	var peers []node.BootstrapPeerConfig
	for i := range nodes {
		tcp := allocTCP(t)
		_, portStr, _ := net.SplitHostPort(tcp)
		port, _ := strconv.Atoi(portStr)
		nodes[i] = &devnetNode{
			root: t.TempDir(), appDir: t.TempDir(), tcpAddr: tcp,
			udpPort: allocUDP(t), authPort: allocUDP(t),
		}
		peers = append(peers, node.SelfBootstrapPeer(vals[i].Secp,
			netip.MustParseAddr("127.0.0.1"),
			uint16(port), uint16(nodes[i].udpPort), uint16(nodes[i].authPort), 0, 0, 1))
	}
	for i := range nodes {
		// Low threshold: a node >6 behind statesyncs instead of blocksyncing.
		writeNodeConfigSS(t, nodes[i], "tcp", vals[i], vals, peers, 6)
	}
	for i := range nodes {
		startDevnetNode(t, cfg, nodes[i], genDoc)
		t.Cleanup(func() {
			if nodes[i].eng != nil {
				nodes[i].stop(t)
			}
		})
	}
	defer func() {
		for i, dn := range nodes {
			if dn.me != nil {
				t.Logf("node%d peers=%d", i, len(dn.me.curNode().Peers()))
			}
		}
	}()
	for i := range nodes {
		probeWaitHeight(t, nodes[i].me, 6, 60*time.Second)
	}

	// Wipe node 0's chain state: blocks/WAL/forkpoint/app DB gone. Signing
	// watermarks survive — priv_validator_state.json (needed by LoadFilePV)
	// and, unless wipeSafety, monadbft/safety.rlp (the vote watermark — an
	// ops wipe keeps it precisely to avoid equivocation after a mid-epoch
	// vote).
	nodes[0].stop(t)
	wiped := []string{
		filepath.Join(nodes[0].root, "data", "monadbft", "wal"),
		filepath.Join(nodes[0].root, "data", "monadbft", "blocks"),
		filepath.Join(nodes[0].root, "data", "monadbft", "forkpoint.rlp"),
		filepath.Join(nodes[0].root, "data", "monadbft", "validators.rlp"),
		filepath.Join(nodes[0].root, "data", "bridge-results"),
	}
	if wipeSafety {
		wiped = append(wiped, filepath.Join(nodes[0].root, "data", "monadbft", "safety.rlp"))
	}
	for _, p := range wiped {
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
	}
	os.RemoveAll(nodes[0].appDir)
	nodes[0].appDir = t.TempDir()
	for i := 1; i < n; i++ {
		probeWaitHeight(t, nodes[i].me, 12, 60*time.Second)
	}
	tip := nodes[1].me.app.Height()

	startDevnetNode(t, cfg, nodes[0], genDoc)
	probeWaitHeight(t, nodes[0].me, tip+2, 120*time.Second)
	for i := range nodes {
		t.Logf("node %d height=%d", i, nodes[i].me.app.Height())
	}
	// Assert the real statesync path ran — not mere blocksync catch-up:
	// Sync mode must have emitted StateSyncRequestSync (trigger_state_sync).
	// In wipe_safety mode that additionally routes through maybe_statesync's
	// ErrNeedStatesync panic, the persisted statesync-target forkpoint, and
	// a supervisor restart; in keep_safety mode the watermark hold keeps the
	// node in Sync mode until certs advance past the vote watermark.
	if got := nodes[0].me.curNode().Metrics().ConsensusEvents.TriggerStateSync.Get(); got == 0 {
		t.Fatalf("node0 rejoined without triggering statesync")
	}
}
