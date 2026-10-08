//go:build test

package bridge

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmtcfg "github.com/cometbft/cometbft/config"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/node"
	"github.com/abhijitkrm/monadbft-go/types"

	"github.com/ethereum/go-ethereum/common"

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

// bringUpDevnet — shared 4-validator devnet bring-up: genesis doc with the
// full valset, per-node dirs/ports, bootstrap peer records, configs, then
// sequential engine starts. Returns nodes+vals+genDoc for tests that then
// exercise restart/crash/statesync scenarios.
func bringUpDevnet(t *testing.T, chainID string, transport string, ssThreshold int, fundedSenders ...int) ([]*devnetNode, []Validator, EvmdConfig, *cmttypes.GenesisDoc) {
	const n = 4
	vals := MakeValidators(n)
	cfg := EvmdConfig{ChainID: chainID, EVMChainID: testconstants.EighteenDecimalsChainID, Home: t.TempDir()}
	if len(fundedSenders) > 0 {
		cfg.FundedSenders = fundedSenders[0]
	}

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
		if ssThreshold > 0 {
			writeNodeConfigSS(t, nodes[i], transport, vals[i], vals, peers, uint64(ssThreshold))
		} else {
			writeNodeConfig(t, nodes[i], transport, vals[i], vals, peers)
		}
	}

	for i := range nodes {
		startDevnetNode(t, cfg, nodes[i], genDoc)
		t.Cleanup(func() {
			if nodes[i].eng != nil {
				nodes[i].stop(t)
			}
		})
	}
	return nodes, vals, cfg, genDoc
}

// logPeerCounts — failure-path diag: per-node peer count + id prefix.
func logPeerCounts(t *testing.T, nodes []*devnetNode) {
	t.Helper()
	for i, dn := range nodes {
		if dn.me != nil {
			id := dn.me.curNode().NodeID()
			t.Logf("node%d peers=%d id=%x…", i, len(dn.me.curNode().Peers()), id.PubKey[:4])
		}
	}
}

func runMultiNodeRestart(t *testing.T, transport string) {
	const n = 4
	nodes, _, cfg, genDoc := bringUpDevnet(t, "probe-devnet", transport, 0)
	defer logPeerCounts(t, nodes)
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

// TestEngineMultiNodeRestartUnderLoad — the soak-observed stall: a node
// restarted under sustained tx load must blocksync-fill the missed-block
// gap and resume committing. The plain restart test only lags ~6 empty
// blocks; here the fleet runs ~30 loaded blocks ahead so the rejoin
// exercises the coherence/blocksync path under real execution pressure.
func TestEngineMultiNodeRestartUnderLoad(t *testing.T) {
	const n = 4
	blocktree.DebugCoherency = func(seq types.SeqNum, err error) {
		t.Logf("COHERENCY-FAIL seq=%d err=%v", seq, err)
	}
	consensusstate.DebugProposal = func(tag, detail string) {
		t.Logf("PROPOSE-GATE %s %s", tag, detail)
	}
	specFails := 0
	DebugSpec = func(blockID types.BlockId, seq int64, err error) {
		if err != nil && specFails < 40 {
			specFails++
			t.Logf("SPEC-FAIL seq=%d id=%x err=%v", seq, blockID[:4], err)
		}
	}
	t.Cleanup(func() { blocktree.DebugCoherency = nil; consensusstate.DebugProposal = nil; DebugSpec = nil })
	nodes, _, cfg, genDoc := bringUpDevnet(t, "probe-restartload", "tcp", 0, 8)
	defer logPeerCounts(t, nodes)
	for i := range nodes {
		probeWaitHeight(t, nodes[i].me, 4, 60*time.Second)
	}

	txCfg := nodes[0].me.app.Raw().TxConfig()
	to := common.HexToAddress("0x00000000000000000000000000000000aa55aa55")

	// Snapshot node0's result hashes before the kill — the post-restart
	// divergence check distinguishes live-exec nondeterminism from
	// replay/restore pollution.
	preKill := map[int64][]byte{}
	{
		h := nodes[0].me.app.Height()
		for x := int64(1); x <= h; x++ {
			if r := nodes[0].me.app.Result(x); r != nil {
				preKill[x] = r.AppHash
			}
		}
		for i := 1; i < n; i++ {
			if r := nodes[i].me.app.Result(h); r != nil && !bytes.Equal(preKill[h], r.AppHash) {
				t.Fatalf("pre-kill divergence at h=%d", h)
			}
		}
	}

	// Stop node0; drive continuous load through node1 while peers advance.
	nodes[0].stop(t)
	stopLoad := make(chan struct{})
	go func() {
		senders := 8
		per := make([]uint64, senders)
		var i uint64
		// ~150 tx/s — soak-realistic; unthrottled blasting starves the
		// consensus loop on mempool/exec contention (fleet freeze).
		tick := time.NewTicker(7 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stopLoad:
				return
			case <-tick.C:
			}
			si := int(i % uint64(senders))
			i++
			bz, _ := makeEthTx(t, txCfg, DerivedSenderKey(si), per[si], to, 1)
			per[si]++
			if _, err := nodes[1].me.client.BroadcastTxSync(
				context.Background(), bz); err != nil {
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()
	defer close(stopLoad)

	for i := 1; i < n; i++ {
		probeWaitHeight(t, nodes[i].me, 100, 180*time.Second)
	}
	tip := nodes[1].me.app.Height()

	// Restart node0: resume, blocksync the ~95-block gap, rejoin.
	startDevnetNode(t, cfg, nodes[0], genDoc)
	probeWaitHeight(t, nodes[0].me, tip+2, 180*time.Second)
	// Stronger than tip+2: the node must close to the LIVE moving tip —
	// the soak stall signature was "caught up most of the way then froze".
	live := nodes[1].me.app.Height()
	// manual wait so a stall can dump per-node result divergence at the
	// stuck height before probeWaitHeight's Fatalf fires
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) && nodes[0].me.app.Height() < live {
		time.Sleep(200 * time.Millisecond)
	}
	if nodes[0].me.app.Height() < live {
		stuck := nodes[0].me.app.Height()
		// find first divergent height across the committed range
		var firstDiverged int64 = -1
		for h := int64(1); h <= stuck && firstDiverged < 0; h++ {
			var ref0 []byte
			for i := range nodes {
				r := nodes[i].me.app.Result(h)
				if r == nil {
					break
				}
				if ref0 == nil {
					ref0 = r.AppHash
				} else if !bytes.Equal(ref0, r.AppHash) {
					firstDiverged = h
					// request diff — which ABCI input field differed per node
					var reqs []*abcitypes.RequestFinalizeBlock
					for j := range nodes {
						nodes[j].me.ledger.reqMu.Lock()
						reqs = append(reqs, nodes[j].me.ledger.reqCaps[h])
						nodes[j].me.ledger.reqMu.Unlock()
					}
					for j := range reqs {
						nodes[j].me.ledger.reqMu.Lock()
						sr := nodes[j].me.ledger.reqCapsSpec[h]
						nodes[j].me.ledger.reqMu.Unlock()
						var vdesc string
						if sr != nil {
							var fl []string
							for _, v := range sr.DecidedLastCommit.Votes {
								fl = append(fl, fmt.Sprintf("%s:%x", v.BlockIdFlag.String()[13:], v.Validator.Address[:4]))
							}
							vdesc = fmt.Sprintf(" votes=[%s] prop=%x nvh=%x", strings.Join(fl, ","), sr.ProposerAddress[:6], sr.NextValidatorsHash[:6])
						}
						t.Logf("REQCAP h=%d n%d direct=%v spec=%v%s", h, j, reqs[j] != nil, sr != nil, vdesc)
					}
					if reqs[0] != nil && reqs[1] != nil {
						r0, r1 := reqs[0], reqs[1]
						t.Logf("REQDIFF h=%d: proposer %x vs %x | time %d vs %d | nvHash %x vs %x | votes %d vs %d | commitRound %d vs %d | txs %d vs %d",
							h, r0.ProposerAddress, r1.ProposerAddress,
							r0.Time.UnixNano(), r1.Time.UnixNano(),
							r0.NextValidatorsHash[:8], r1.NextValidatorsHash[:8],
							len(r0.DecidedLastCommit.Votes), len(r1.DecidedLastCommit.Votes),
							r0.DecidedLastCommit.Round, r1.DecidedLastCommit.Round,
							len(r0.Txs), len(r1.Txs))
						for vi := 0; vi < len(r0.DecidedLastCommit.Votes) && vi < len(r1.DecidedLastCommit.Votes); vi++ {
							v0, v1 := r0.DecidedLastCommit.Votes[vi], r1.DecidedLastCommit.Votes[vi]
							same := v0.BlockIdFlag == v1.BlockIdFlag && bytes.Equal(v0.Validator.Address, v1.Validator.Address) && v0.Validator.Power == v1.Validator.Power
							t.Logf("REQDIFF h=%d vote[%d] n0=%s@%x p%d | n1=%s@%x p%d same=%v", h, vi,
								v0.BlockIdFlag, v0.Validator.Address[:6], v0.Validator.Power,
								v1.BlockIdFlag, v1.Validator.Address[:6], v1.Validator.Power, same)
						}
					}
					for j := range nodes {
						_, bid, _, _, _, _, _ := nodes[j].me.app.CommittedEntry(h)
						cb := nodes[j].me.ledger.committedBlock(types.SeqNum(h))
						var qcSig string
						var flags string
						if cb != nil {
							q := cb.Header.QC
							qcSig = fmt.Sprintf("signers=%v len=%d", q.Signatures.Signers.Bits, q.Signatures.Signers.Len())
							ci := nodes[j].me.app.LastCommit(q)
							var f []string
							for _, v := range ci.Votes {
								f = append(f, v.BlockIdFlag.String())
							}
							flags = strings.Join(f, ",")
						}
						t.Logf("BLOCKID h=%d n%d=%x qc[%s] votes=[%s]", h, j, bid[:12], qcSig, flags)
					}
				}
			}
		}
		for h := int64(1); h <= stuck; h++ {
			var row string
			diverged := false
			var ref []byte
			for i := range nodes {
				r := nodes[i].me.app.Result(h)
				if r == nil {
					row += fmt.Sprintf(" n%d=nil", i)
					continue
				}
				row += fmt.Sprintf(" n%d=%x", i, r.AppHash[:6])
				if ref == nil {
					ref = r.AppHash
				} else if !bytes.Equal(ref, r.AppHash) {
					diverged = true
				}
			}
			if diverged {
				// tx-result comparison — if tx exec matches, divergence is
				// in begin/end-block module state (rewards, liveness), not txs
				if h == firstDiverged {
					for i := range nodes {
						if _, _, _, txr, ev, _, ok := nodes[i].me.app.CommittedEntry(h); ok {
							var tr []string
							for _, r := range txr {
								tr = append(tr, fmt.Sprintf("%d:%d", r.Code, r.GasUsed))
							}
							evs := map[string]int{}
							for _, e := range ev {
								evs[e.Type]++
							}
							var types_ []string
							for et, c := range evs {
								types_ = append(types_, fmt.Sprintf("%s x%d", et, c))
							}
							sort.Strings(types_)
							t.Logf("TXRES h=%d n%d codes/gas=[%s] events=%d [%s]", h, i, strings.Join(tr, ","), len(ev), strings.Join(types_, "; "))
						}
					}
				}
				// per-store commit hash — localize which module's state diverged
				if h == firstDiverged {
					for i := range nodes {
						raw := nodes[i].me.app.Raw()
						if rms, ok := raw.CommitMultiStore().(interface {
							GetCommitInfo(int64) (*storetypes.CommitInfo, error)
						}); ok {
							if ci, err := rms.GetCommitInfo(h); err == nil && ci != nil {
								var sr []string
								for _, si := range ci.StoreInfos {
									sr = append(sr, fmt.Sprintf("%s=%x", si.Name, si.CommitId.Hash[:4]))
								}
								t.Logf("STORES h=%d n%d %s", h, i, strings.Join(sr, " "))
							}
						}
					}
				}
				var vrow string
				for i := range nodes {
					if vs := nodes[i].me.app.ValSetAt(h); vs != nil {
						vrow += fmt.Sprintf(" n%d=%x", i, vs.Hash()[:6])
					} else {
						vrow += fmt.Sprintf(" n%d=nil", i)
					}
				}
				row += " | valset" + vrow
				if pk, ok := preKill[h]; ok {
					row += fmt.Sprintf(" prekill=%x sameaspre=%v", pk[:6], bytes.Equal(pk, nodes[0].me.app.Result(h).AppHash))
				}
				t.Logf("DIVERGENCE h=%d%s", h, row)
			}
		}
	}
	probeWaitHeight(t, nodes[0].me, live, 10*time.Second)
	for i := range nodes {
		t.Logf("node %d height=%d", i, nodes[i].me.app.Height())
	}
}

// TestEngineMultiNodeCrashWindows — Phase-6 crash matrix at engine scope:
// kill node 0 at three intra-round points — right after a peer's commit
// boundary (post-commit), ~500ms in (proposal/vote window), and ~1100ms in
// (near the next commit) on the ~1.3s devnet cadence — then restart on the
// same dirs and rejoin, three times over one live devnet. Each kill keeps
// safety.rlp/WAL/forkpoint, so this exercises resume-from-crash, not
// statesync.
func TestEngineMultiNodeCrashWindows(t *testing.T) {
	const n = 4
	nodes, _, cfg, genDoc := bringUpDevnet(t, "probe-crashwin", "tcp", 0)
	defer logPeerCounts(t, nodes)
	for i := range nodes {
		probeWaitHeight(t, nodes[i].me, 5, 60*time.Second)
	}

	for _, off := range []time.Duration{0, 500 * time.Millisecond, 1100 * time.Millisecond} {
		// Anchor at a fresh commit boundary on a peer, then sleep into the
		// intra-round offset before the kill.
		h := nodes[1].me.app.Height()
		probeWaitHeight(t, nodes[1].me, h+1, 60*time.Second)
		time.Sleep(off)

		nodes[0].stop(t)
		for i := 1; i < n; i++ {
			probeWaitHeight(t, nodes[i].me, nodes[i].me.app.Height()+2, 60*time.Second)
		}
		tip := nodes[1].me.app.Height()

		startDevnetNode(t, cfg, nodes[0], genDoc)
		// 180s: each successive window carries a bigger sync gap; under
		// suite load the blocksync re-anchor is the slow part, and the
		// assertion is liveness (eventually rejoins), not latency.
		probeWaitHeight(t, nodes[0].me, tip+1, 180*time.Second)
		t.Logf("offset=%v: node0 rejoined height=%d tip≈%d peers=%d",
			off, nodes[0].me.app.Height(), tip, len(nodes[0].me.curNode().Peers()))
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
	// Low threshold: a node >6 behind statesyncs instead of blocksyncing.
	nodes, _, cfg, genDoc := bringUpDevnet(t, "probe-statesync", "tcp", 6)
	defer logPeerCounts(t, nodes)
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
