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
	root    string
	appDir  string
	tcpAddr string
	eng     engine.Engine
	me      *monadEngine
	db      dbm.DB
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

// writeNodeConfig — the per-node file set the engine consumes: monad key
// file, comet priv_validator, monadbft.json, shared validators+peers files.
func writeNodeConfig(t *testing.T, dn *devnetNode, v Validator, vals []Validator, peers []node.BootstrapPeerConfig) {
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
	ecfg.Transport = "tcp"
	ecfg.TCPAddress = dn.tcpAddr
	ecfg.PeersFile = "peers.json"
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
		nodes[i] = &devnetNode{root: t.TempDir(), appDir: t.TempDir(), tcpAddr: tcp}
		// TCP mode only consumes TCPSocket from the record; auth is set
		// nonzero to satisfy the record's validation.
		peers = append(peers, node.SelfBootstrapPeer(vals[i].Secp,
			netip.MustParseAddr("127.0.0.1"),
			uint16(port), 0, uint16(port), 0, 0, 1))
	}
	for i := range nodes {
		writeNodeConfig(t, nodes[i], vals[i], vals, peers)
	}

	for i := range nodes {
		evmtypes.NewEVMConfigurator().ResetTestConfig()
		startDevnetNode(t, cfg, nodes[i], genDoc)
		t.Cleanup(func() {
			if nodes[i].eng != nil {
				nodes[i].stop(t)
			}
		})
	}
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
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	startDevnetNode(t, cfg, nodes[0], genDoc)
	probeWaitHeight(t, nodes[0].me, tip+2, 90*time.Second)
	for i := range nodes {
		t.Logf("node %d height=%d", i, nodes[i].me.app.Height())
	}
}
