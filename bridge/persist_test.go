package bridge

import (
	"fmt"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/abhijitkrm/monadbft-go/types"
)

func TestResultStoreRoundTrip(t *testing.T) {
	s, err := OpenResultStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var bid types.BlockId
	bid[0] = 0xAB
	entry := resultEntry{
		header:  &EvmFinalizedHeader{Number: types.SeqNum(7), AppHash: []byte{1, 2, 3}},
		blockID: bid,
		txs:     [][]byte{{0xde, 0xad}, {0xbe, 0xef}},
		txResults: []*abcitypes.ExecTxResult{
			{Code: 0, GasUsed: 21000, Events: []abcitypes.Event{{Type: "transfer"}}},
			{Code: 11, Log: "out of gas"},
		},
		events: []abcitypes.Event{{Type: "fee_market"}},
		valUpdates: []abcitypes.ValidatorUpdate{
			{Power: 5},
		},
	}
	if err := s.Put(7, entry); err != nil {
		t.Fatal(err)
	}

	vs := cmttypes.NewValidatorSet([]*cmttypes.Validator{
		cmttypes.NewValidator(cmted25519.GenPrivKey().PubKey(), 1),
	})
	if err := s.SaveValSet(vs); err != nil {
		t.Fatal(err)
	}

	tip, res, gotVS, err := s.LoadRecent(0)
	if err != nil {
		t.Fatal(err)
	}
	if tip != 7 {
		t.Fatalf("tip=%d want 7", tip)
	}
	e, ok := res[7]
	if !ok {
		t.Fatal("res[7] missing")
	}
	if string(e.header.AppHash) != string([]byte{1, 2, 3}) || e.blockID != bid {
		t.Fatalf("entry mismatch: %+v", e.header)
	}
	if len(e.txResults) != 2 || e.txResults[1].Code != 11 || e.txResults[0].GasUsed != 21000 {
		t.Fatalf("txResults mismatch: %+v", e.txResults)
	}
	if len(e.events) != 1 || len(e.valUpdates) != 1 || e.valUpdates[0].Power != 5 {
		t.Fatal("events/updates mismatch")
	}
	// tx index is store-resident
	for _, tx := range entry.txs {
		h, ok, err := s.TxHeight(fmt.Sprintf("%X", tmhash.Sum(tx)))
		if err != nil || !ok || h != 7 {
			t.Fatalf("TxHeight(%x)=%d,%v,%v want 7,true", tx, h, ok, err)
		}
	}
	if _, ok, _ := s.TxHeight("DEADBEEF"); ok {
		t.Fatal("TxHeight found unknown hash")
	}
	if gotVS == nil || len(gotVS.Validators) != 1 ||
		string(gotVS.Validators[0].Address) != string(vs.Validators[0].Address) {
		t.Fatal("valset roundtrip mismatch")
	}
}

func TestResultStoreWindowAndIndexes(t *testing.T) {
	s, err := OpenResultStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// 20 committed heights, a valset change at 10, cmt-hash + tx indexes.
	vs0 := cmttypes.NewValidatorSet([]*cmttypes.Validator{
		cmttypes.NewValidator(cmted25519.GenPrivKey().PubKey(), 1),
	})
	vs1 := cmttypes.NewValidatorSet([]*cmttypes.Validator{
		cmttypes.NewValidator(cmted25519.GenPrivKey().PubKey(), 1),
	})
	if err := s.PutValSetChange(0, vs0); err != nil {
		t.Fatal(err)
	}
	if err := s.PutValSetChange(10, vs1); err != nil {
		t.Fatal(err)
	}
	for h := int64(1); h <= 20; h++ {
		var bid types.BlockId
		bid[0] = byte(h)
		e := resultEntry{
			header:  &EvmFinalizedHeader{Number: types.SeqNum(h), AppHash: []byte{byte(h)}},
			blockID: bid,
			txs:     [][]byte{{byte(h)}},
		}
		if err := s.Put(h, e); err != nil {
			t.Fatal(err)
		}
		if err := s.PutCmtHash([]byte(fmt.Sprintf("blockhash-%02d", h)), h); err != nil {
			t.Fatal(err)
		}
	}

	// windowed load: only heights ≥ from come back
	_, res, _, err := s.LoadRecent(15)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 6 || res[14].header != nil {
		t.Fatalf("window load got %d entries, res[14]=%v", len(res), res[14].header)
	}

	// per-height Get
	e, ok, err := s.Get(3)
	if err != nil || !ok || e.header == nil || e.header.AppHash[0] != 3 {
		t.Fatalf("Get(3)=%v,%v,%v", e.header, ok, err)
	}
	if _, ok, _ := s.Get(99); ok {
		t.Fatal("Get(99) found")
	}

	// cmt hash index
	if h, ok, _ := s.CmtHeight([]byte("blockhash-07")); !ok || h != 7 {
		t.Fatalf("CmtHeight=%d,%v want 7,true", h, ok)
	}

	// valset change log: ≤9 → vs0, ≥10 → vs1
	got, err := s.ValSetBefore(9)
	if err != nil || got == nil ||
		string(got.Validators[0].Address) != string(vs0.Validators[0].Address) {
		t.Fatalf("ValSetBefore(9): %v %v", got, err)
	}
	got, err = s.ValSetBefore(20)
	if err != nil || got == nil ||
		string(got.Validators[0].Address) != string(vs1.Validators[0].Address) {
		t.Fatalf("ValSetBefore(20): %v %v", got, err)
	}

	// prune below 10: res rows gone, tx index retained
	if err := s.PruneBefore(10); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(5); ok {
		t.Fatal("Get(5) still present after prune")
	}
	if _, ok, _ := s.Get(12); !ok {
		t.Fatal("Get(12) pruned unexpectedly")
	}
	if _, ok, _ := s.TxHeight(fmt.Sprintf("%X", tmhash.Sum([]byte{5}))); !ok {
		t.Fatal("tx index lost on prune")
	}
}
