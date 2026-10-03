package bridge

// e2e_test.go — production-review coverage: real-EVM-tx integrity across a
// live 4-node TCP devnet, plus the FinalizeBlock throughput benchmark the
// "EVM TPS" budget is measured against.

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	"github.com/ethereum/go-ethereum/common"

	"github.com/cosmos/cosmos-sdk/client"
	ethsecp256k1 "github.com/cosmos/evm/crypto/ethsecp256k1"
	testconstants "github.com/cosmos/evm/testutil/constants"
	txtest "github.com/cosmos/evm/testutil/tx"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

func TestEvmIntegrityTransfers(t *testing.T) {
	const senders, per = 8, 3
	nodes, _, _, _ := bringUpDevnet(t, "e2e-integrity", "tcp", 0, senders)
	defer func() {
		for _, dn := range nodes {
			if dn.eng != nil {
				dn.stop(t)
			}
		}
	}()

	// Chain live before injecting txs.
	for _, dn := range nodes {
		probeWaitHeight(t, dn.me, 4, 90*time.Second)
	}

	raw := nodes[0].me.app.Raw()
	txCfg := raw.TxConfig()
	amount := int64(1_000_000_000_000_000) // 0.001 native
	to := common.HexToAddress("0x00000000000000000000000000000000aa55aa55")

	type want struct {
		sender common.Address
		nonces int
	}
	wants := make([]want, senders)
	txHashes := make(map[common.Hash]bool)
	for i := 0; i < senders; i++ {
		key := DerivedSenderKey(i)
		from := common.BytesToAddress(key.PubKey().Address().Bytes())
		wants[i] = want{sender: from, nonces: per}
		for n := 0; n < per; n++ {
			bz, hash := makeEthTx(t, txCfg, key, uint64(n), to, amount)
			txHashes[hash] = true
			res, err := nodes[len(nodes)-1].me.client.BroadcastTxSync(context.Background(), bz)
			if err != nil {
				t.Fatalf("broadcast sender %d nonce %d: %v", i, n, err)
			}
			if res != nil && res.Code != 0 {
				t.Fatalf("CheckTx rejected sender %d nonce %d: %s", i, n, res.Log)
			}
		}
	}

	// Inclusion: every tx hash lands in a committed block on node 0.
	deadline := time.Now().Add(120 * time.Second)
	seen := make(map[common.Hash]int64)
	for len(seen) < len(txHashes) && time.Now().Before(deadline) {
		app := nodes[0].me.app
		for h := int64(1); h <= app.Height(); h++ {
			for _, bz := range app.Txs(h) {
				if hsh := committedEthHash(txCfg, bz); hsh != (common.Hash{}) && txHashes[hsh] {
					seen[hsh] = h
				}
			}
		}
		if len(seen) < len(txHashes) {
			time.Sleep(150 * time.Millisecond)
		}
	}
	if len(seen) != len(txHashes) {
		t.Fatalf("included %d/%d txs by height %d", len(seen), len(txHashes), nodes[0].me.app.Height())
	}

	// Result integrity: every included tx executed successfully with gas.
	for hash, h := range seen {
		_, _, txs, res, _, _, ok := nodes[0].me.app.CommittedEntry(h)
		if !ok {
			t.Fatalf("missing CommittedEntry at %d", h)
		}
		for i, bz := range txs {
			if committedEthHash(txCfg, bz) == hash {
				if res[i].Code != 0 {
					t.Fatalf("tx %s failed: %s", hash, res[i].Log)
				}
				if res[i].GasUsed <= 0 {
					t.Fatalf("tx %s: zero gas used", hash)
				}
			}
		}
	}

	// All nodes past the last inclusion height before checking state.
	var maxH int64
	for _, h := range seen {
		if h > maxH {
			maxH = h
		}
	}
	for _, dn := range nodes {
		probeWaitHeight(t, dn.me, maxH+1, 60*time.Second)
	}

	// State integrity: recipient balance + sender nonces on EVERY node,
	// read from the committed branch (isCheckTx=false).
	wantBal := uint64(senders*per) * uint64(amount)
	for i, dn := range nodes {
		r := dn.me.app.Raw()
		ctx := r.NewUncachedContext(false, cmtproto.Header{Height: dn.me.app.Height()})
		got := r.EVMKeeper.GetBalance(ctx, to)
		if got == nil || got.Uint64() != wantBal {
			t.Fatalf("node %d: recipient balance %v, want %d", i, got, wantBal)
		}
		for si, w := range wants {
			if n := r.EVMKeeper.GetNonce(ctx, w.sender); n != uint64(w.nonces) {
				t.Fatalf("node %d sender %d: nonce %d, want %d", i, si, n, w.nonces)
			}
		}
	}

	// Cross-node determinism: identical app hashes at every height.
	for h := int64(1); h <= nodes[0].me.app.Height(); h++ {
		ref := nodes[0].me.app.Result(h).AppHash
		for i := 1; i < len(nodes); i++ {
			if got := nodes[i].me.app.Result(h).AppHash; !bytes.Equal(ref, got) {
				t.Fatalf("apphash divergence h=%d: node0 %x vs node%d %x", h, ref[:8], i, got[:8])
			}
		}
	}
}

// makeEthTx — sign a LegacyTx transfer and wrap it as an SDK tx.
func makeEthTx(t testing.TB, txCfg client.TxConfig, key *ethsecp256k1.PrivKey, nonce uint64, to common.Address, amount int64) ([]byte, common.Hash) {
	t.Helper()
	msg := evmtypes.NewTx(&evmtypes.EvmTxArgs{
		ChainID:  evmtypes.GetEthChainConfig().ChainID,
		Nonce:    nonce,
		To:       &to,
		Amount:   big.NewInt(amount),
		GasLimit: 21_000,
		GasPrice: big.NewInt(1_000_000_000_000),
	})
	msg.From = common.BytesToAddress(key.PubKey().Address().Bytes()).Bytes()
	sdkTx, err := txtest.PrepareEthTx(txCfg, key, msg)
	if err != nil {
		t.Fatalf("PrepareEthTx: %v", err)
	}
	bz, err := txCfg.TxEncoder()(sdkTx)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return bz, msg.Hash()
}

// committedEthHash — the eth tx hash if bz decodes to a single
// MsgEthereumTx SDK tx (what the bridge puts on the wire).
func committedEthHash(txCfg client.TxConfig, bz []byte) common.Hash {
	tx, err := txCfg.TxDecoder()(bz)
	if err != nil || len(tx.GetMsgs()) != 1 {
		return common.Hash{}
	}
	if m, ok := tx.GetMsgs()[0].(*evmtypes.MsgEthereumTx); ok {
		return m.Hash()
	}
	return common.Hash{}
}

// BenchmarkFinalizeBlockEvm — FinalizeBlock+Commit throughput on a single
// real evmd app: the floor for achievable EVM TPS (consensus/networking can
// only subtract from this). Reports monadbft_evm_txs_per_sec.
func BenchmarkFinalizeBlockEvm(b *testing.B) {
	const senders = 32 // enough parallel nonces to fill blocks
	cfg := EvmdConfig{
		ChainID: "bench-evm", EVMChainID: testconstants.EighteenDecimalsChainID,
		FundedSenders: senders,
	}
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	app, raw, err := NewEvmdApp(cfg, MakeValidators(1))
	if err != nil {
		b.Fatal(err)
	}
	txCfg := raw.TxConfig()
	to := common.HexToAddress("0x00000000000000000000000000000000be11c4")

	const blockTxs = 512 // ~10.7M gas — fits the 150M proposal gas limit
	b.ReportAllocs()
	b.ResetTimer()

	var height int64
	txCount := int64(0)
	var fbDur, cmDur time.Duration
	start := time.Now()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		height++
		txs := make([][]byte, 0, blockTxs)
		for j := 0; j < blockTxs; j++ {
			k := DerivedSenderKey(j % senders)
			bz, _ := makeEthTx(b, txCfg, k, uint64(j/senders)+(uint64(i)*uint64(blockTxs/senders)), to, 1)
			txs = append(txs, bz)
		}
		b.StartTimer()
		fbStart := time.Now()
		res, err := app.FinalizeBlock(context.Background(), &abci.RequestFinalizeBlock{
			Txs: txs, Height: height, Time: time.Now(),
			Hash: []byte(fmt.Sprintf("bench-block-%d", height)),
		})
		fbDur += time.Since(fbStart)
		if err != nil {
			b.Fatalf("FinalizeBlock %d: %v", height, err)
		}
		for _, r := range res.TxResults {
			if r.Code != 0 {
				b.Fatalf("tx failed at height %d: %s", height, r.Log)
			}
		}
		cmStart := time.Now()
		if err := app.Commit(context.Background()); err != nil {
			b.Fatalf("commit %d: %v", height, err)
		}
		cmDur += time.Since(cmStart)
		txCount += int64(len(res.TxResults))
	}
	b.StopTimer()
	b.Logf("split: finalize=%v commit=%v", fbDur, cmDur)
	secs := time.Since(start).Seconds()
	b.ReportMetric(float64(txCount)/secs, "evm_tx/s")
	b.Logf("finalized %d txs in %d blocks: %.0f tx/s (%.1f blk/s)",
		txCount, b.N, float64(txCount)/secs, float64(b.N)/secs)
}

// BenchmarkConsensusCommit — engine-side commit throughput with empty blocks:
// how fast the ledger→app pipeline settles, so the block budget available to
// EVM exec is visible. Reports blocks/s.
func BenchmarkConsensusCommit(b *testing.B) {
	vals := MakeValidators(1)
	cfg := EvmdConfig{ChainID: "bench-cons", EVMChainID: testconstants.EighteenDecimalsChainID}
	evmtypes.NewEVMConfigurator().ResetTestConfig()
	app, _, err := NewEvmdApp(cfg, vals)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	var h int64
	for i := 0; i < b.N; i++ {
		h++
		res, err := app.FinalizeBlock(context.Background(), &abci.RequestFinalizeBlock{
			Height: h, Time: time.Now(),
			Hash: []byte(fmt.Sprintf("bench-empty-%d", h)),
		})
		if err != nil {
			b.Fatalf("FinalizeBlock %d: %v", h, err)
		}
		if len(res.TxResults) != 0 {
			b.Fatalf("expected empty block, got %d results", len(res.TxResults))
		}
		if err := app.Commit(context.Background()); err != nil {
			b.Fatalf("commit %d: %v", h, err)
		}
	}
}
