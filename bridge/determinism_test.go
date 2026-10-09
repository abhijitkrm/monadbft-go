package bridge

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/ethereum/go-ethereum/common"

	testconstants "github.com/cosmos/evm/testutil/constants"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// TestParallelExecDeterminism — identical blocks executed on independent
// apps must produce identical app hashes. The workload is the worst case for
// BlockSTM: every tx credits ONE recipient (a single hot bank balance key)
// and each sender has several nonces in the same block. A devnet soak hit a
// bank-store-only app-hash divergence on one node under exactly this load.
func TestParallelExecDeterminism(t *testing.T) { testParallelExecDeterminism(t, false) }

// TestParallelExecDeterminismConcurrentCheckTx — same, but CheckTx+InsertTx
// run concurrently with FinalizeBlock/Commit on the same app (the CometBFT
// path's local-client concurrency; the monadbft bridge serializes these
// under App.opMu).
func TestParallelExecDeterminismConcurrentCheckTx(t *testing.T) { testParallelExecDeterminism(t, true) }

func testParallelExecDeterminism(t *testing.T, noise bool) {
	const (
		apps     = 4
		senders  = 64
		perSendr = 8 // nonces per sender per block
		heights  = 30
	)
	hot := common.HexToAddress("0x00000000000000000000000000000000c0ffee01")
	cfg := EvmdConfig{
		ChainID: "det-evm", EVMChainID: testconstants.EighteenDecimalsChainID,
		FundedSenders: senders + 32, // 32 extra senders feed the CheckTx noise
	}
	vals := MakeValidators(1)
	type node struct {
		app *App
	}
	nodes := make([]node, apps)
	var txCfgBuilt bool
	var blocks [][][]byte
	genesisTime := time.Unix(1_700_000_000, 0)
	for i := range nodes {
		evmtypes.NewEVMConfigurator().ResetTestConfig()
		app, raw, err := NewEvmdApp(cfg, vals)
		if err != nil {
			t.Fatal(err)
		}
		nodes[i].app = app
		// Stop the app's EVM mempool (background reorg/recheck goroutines)
		// at test end: they read the process-global test EVM config, which
		// the next test's ResetTestConfig clears.
		t.Cleanup(func() { _ = raw.Close() })
		if !txCfgBuilt {
			txCfg := raw.TxConfig()
			for h := 0; h < heights; h++ {
				var txs [][]byte
				for n := 0; n < perSendr; n++ {
					for s := 0; s < senders; s++ {
						bz, _ := makeEthTx(t, txCfg, DerivedSenderKey(s), uint64(h*perSendr+n), hot, int64(1+s))
						txs = append(txs, bz)
					}
				}
				blocks = append(blocks, txs)
			}
			txCfgBuilt = true
		}
	}
	for h := 1; h <= heights; h++ {
		var want []byte
		for i, n := range nodes {
			stop := make(chan struct{})
			done := make(chan struct{})
			if noise {
				go checkTxNoise(t, n.app, senders, h, hot, stop, done)
			} else {
				close(done)
			}
			res, err := n.app.FinalizeBlock(context.Background(), &abci.RequestFinalizeBlock{
				Txs: blocks[h-1], Height: int64(h),
				Time: genesisTime.Add(time.Duration(h) * time.Second),
				Hash: []byte(fmt.Sprintf("det-block-%d", h)),
			})
			if err != nil {
				t.Fatalf("app %d FinalizeBlock h=%d: %v", i, h, err)
			}
			failed := 0
			for _, r := range res.TxResults {
				if r.Code != 0 {
					failed++
				}
			}
			if failed > 0 {
				t.Fatalf("app %d h=%d: %d/%d txs failed (first: %s)", i, h, failed, len(res.TxResults), firstFail(res.TxResults))
			}
			if err := n.app.Commit(context.Background()); err != nil {
				t.Fatalf("app %d Commit h=%d: %v", i, h, err)
			}
			close(stop)
			<-done
			if i == 0 {
				want = res.AppHash
			} else if !bytes.Equal(res.AppHash, want) {
				t.Fatalf("NON-DETERMINISM at h=%d: app %d hash %X != app 0 hash %X", h, i, res.AppHash, want)
			}
		}
	}
	t.Logf("%d apps agree across %d heights × %d txs (single hot recipient)", apps, heights, senders*perSendr)
}

// checkTxNoise — CheckTx+InsertTx of fresh txs (extra senders → the hot
// recipient) in a loop until stop, unserialized against block execution.
func checkTxNoise(t *testing.T, app *App, firstSender, h int, hot common.Address, stop, done chan struct{}) {
	defer close(done)
	txCfg := app.Raw().TxConfig()
	nonce := uint64(h * 1000)
	for {
		for s := firstSender; s < firstSender+32; s++ {
			select {
			case <-stop:
				return
			default:
			}
			bz, _ := makeEthTx(t, txCfg, DerivedSenderKey(s), nonce, hot, 7)
			if res, err := app.app.CheckTx(context.Background(), &abci.RequestCheckTx{Tx: bz, Type: abci.CheckTxType_New}); err == nil && res.Code == 0 {
				_, _ = app.app.InsertTx(context.Background(), &abci.RequestInsertTx{Tx: bz})
			}
		}
		nonce++
	}
}

func firstFail(rs []*abci.ExecTxResult) string {
	for _, r := range rs {
		if r.Code != 0 {
			return r.Log
		}
	}
	return ""
}
