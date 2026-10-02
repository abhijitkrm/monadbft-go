//go:build test

package bridge

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cmtcfg "github.com/cometbft/cometbft/config"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"

	"github.com/abhijitkrm/monadbft-go/metrics"

	"github.com/cosmos/evm/engine"
	testconstants "github.com/cosmos/evm/testutil/constants"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

func probeStart(t *testing.T, cfg EvmdConfig, vals []Validator, appDB dbm.DB, root string, genDoc *cmttypes.GenesisDoc) (engine.Engine, error) {
	t.Helper()
	raw := newRawEvmdDB(cfg, appDB)
	pv := privval.NewFilePV(cmted25519.PrivKey(vals[0].ConsPriv),
		filepath.Join(root, "config", "priv_validator_key.json"),
		filepath.Join(root, "data", "priv_validator_state.json"))
	cmtCfg := cmtcfg.DefaultConfig()
	cmtCfg.SetRoot(root)
	return Start(engine.Options{
		App:           raw,
		Config:        cmtCfg,
		PrivValidator: pv,
		GenDocProvider: func() (*cmttypes.GenesisDoc, error) {
			return genDoc, nil
		},
		Logger: cmtlog.NewNopLogger(),
	})
}

func probeWaitHeight(t *testing.T, me *monadEngine, h int64, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if me.app.Height() >= h {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	st := me.curNode().State()
	var round uint64
	if cs := st.Consensus(); cs != nil && cs.Consensus != nil {
		round = uint64(cs.Consensus.GetCurrentRound())
	}
	var specTip int64 = -1
	if me.ledger != nil && me.ledger.spec != nil {
		specTip = me.ledger.spec.SpecTip()
	}
	var mbuf strings.Builder
	rec := httptest.NewRecorder()
	metrics.PrometheusHandler(me.curNode().Metrics()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	mbuf.WriteString(rec.Body.String())
	var nonzero []string
	for _, ln := range strings.Split(mbuf.String(), "\n") {
		if strings.HasPrefix(ln, "#") || strings.HasSuffix(ln, " 0") {
			continue
		}
		nonzero = append(nonzero, ln)
	}
	var treeSize, rootSeq int
	if cs := st.Consensus(); cs != nil && cs.Consensus != nil && cs.Consensus.PendingBlockTree != nil {
		treeSize = cs.Consensus.PendingBlockTree.Size()
		rootSeq = int(cs.Consensus.PendingBlockTree.RootSeqNum())
	}
	t.Fatalf("height %d not reached in %s: appH=%d storeH=%d specTip=%d committed=%d round=%d tree=%d rootSeq=%d err=%v\n%s",
		h, d, me.app.Height(), me.app.StoreTip(), specTip, me.ledger.FinalizedBlocksLen(), round, treeSize, rootSeq, me.curNode().Err(),
		strings.Join(nonzero, "\n"))
}

// TestEngineRestart — kill the engine after commits, rebuild the app over the
// same data dir, restart: consensus must resume committing from the persisted
// forkpoint without replaying already-applied heights.
func TestEngineRestart(t *testing.T) {
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	cfg := EvmdConfig{ChainID: "probe-restart", EVMChainID: testconstants.EighteenDecimalsChainID, Home: t.TempDir()}
	vals := MakeValidators(1)

	appDir := t.TempDir()
	db1, err := dbm.NewPebbleDB("application", appDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw1 := newRawEvmdDB(cfg, db1)
	stateBytes, err := evmdGenesisState(raw1, cfg, vals)
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	pv := privval.NewFilePV(cmted25519.PrivKey(vals[0].ConsPriv),
		filepath.Join(root, "config", "priv_validator_key.json"),
		filepath.Join(root, "data", "priv_validator_state.json"))
	pub, _ := pv.GetPubKey()
	genDoc := &cmttypes.GenesisDoc{
		ChainID: cfg.ChainID, GenesisTime: time.Now(),
		ConsensusParams: cmttypes.DefaultConsensusParams(),
		Validators:      []cmttypes.GenesisValidator{{Address: pub.Address(), PubKey: pub, Power: 1}},
		AppState:        stateBytes,
	}

	eng1, err := probeStart(t, cfg, vals, db1, root, genDoc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng1.Stop() })
	me1 := eng1.(*monadEngine)
	probeWaitHeight(t, me1, 6, 90*time.Second)
	tip1 := me1.app.Height()
	t.Logf("first run tip=%d", tip1)
	if err := eng1.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := db1.Close(); err != nil {
		t.Fatal(err)
	}

	// the EVM configurator globals are a sync.Once — reset before building
	// the second in-process app instance.
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	db2, err := dbm.NewPebbleDB("application", appDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	eng2, err := probeStart(t, cfg, vals, db2, root, genDoc)
	if err != nil {
		t.Fatal(err)
	}
	me2 := eng2.(*monadEngine)
	t.Cleanup(func() { eng2.Stop() })

	probeWaitHeight(t, me2, tip1+5, 90*time.Second)
	qr, err := me2.client.ABCIQuery(context.Background(), "/cosmos.evm.vm.v1.Query/Params", nil)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("restart ok: tip1=%d tip2=%d qHeight=%d\n", tip1, me2.app.Height(), qr.Response.Height)
}

// TestEngineRestartMatrix — the same kill/restart cycle at several stop
// heights, sampling different crash windows: app-commit vs result-index vs
// forkpoint ordering shifts with the stop point, and low heights exercise
// the delay-gated spec pipeline boundary.
func TestEngineRestartMatrix(t *testing.T) {
	for _, stopAt := range []int64{2, 5, 8} {
		t.Run(fmt.Sprintf("h=%d", stopAt), func(t *testing.T) {
			runRestartOnce(t, stopAt, stopAt+4)
		})
	}
}

// runRestartOnce — one kill/restart cycle on fresh dirs: commit to stopAt,
// stop, rebuild on the same app DB + node root, require progress to
// resumeTo.
func runRestartOnce(t *testing.T, stopAt, resumeTo int64) {
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	cfg := EvmdConfig{ChainID: "probe-restart", EVMChainID: testconstants.EighteenDecimalsChainID, Home: t.TempDir()}
	vals := MakeValidators(1)

	appDir := t.TempDir()
	db1, err := dbm.NewPebbleDB("application", appDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw1 := newRawEvmdDB(cfg, db1)
	stateBytes, err := evmdGenesisState(raw1, cfg, vals)
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "config"), 0o755)
	os.MkdirAll(filepath.Join(root, "data"), 0o755)
	pv := privval.NewFilePV(cmted25519.PrivKey(vals[0].ConsPriv),
		filepath.Join(root, "config", "priv_validator_key.json"),
		filepath.Join(root, "data", "priv_validator_state.json"))
	pv.Save()
	pub, _ := pv.GetPubKey()
	genDoc := &cmttypes.GenesisDoc{
		ChainID: cfg.ChainID, GenesisTime: time.Now(),
		ConsensusParams: cmttypes.DefaultConsensusParams(),
		Validators:      []cmttypes.GenesisValidator{{Address: pub.Address(), PubKey: pub, Power: 1}},
		AppState:        stateBytes,
	}

	eng1, err := probeStart(t, cfg, vals, db1, root, genDoc)
	if err != nil {
		t.Fatal(err)
	}
	me1 := eng1.(*monadEngine)
	probeWaitHeight(t, me1, stopAt, 60*time.Second)
	if err := eng1.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := db1.Close(); err != nil {
		t.Fatal(err)
	}

	evmtypes.NewEVMConfigurator().ResetTestConfig()
	db2, err := dbm.NewPebbleDB("application", appDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	eng2, err := probeStart(t, cfg, vals, db2, root, genDoc)
	if err != nil {
		t.Fatal(err)
	}
	defer eng2.Stop()
	me2 := eng2.(*monadEngine)

	probeWaitHeight(t, me2, resumeTo, 60*time.Second)
	if got := me2.app.Height(); got < resumeTo {
		t.Fatalf("post-restart tip %d < %d", got, resumeTo)
	}
}
