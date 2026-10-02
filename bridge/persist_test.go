package bridge

import (
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
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

	tip, res, txIdx, gotVS, err := s.Load()
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
	if len(txIdx) != 2 {
		t.Fatalf("txIndex=%d want 2", len(txIdx))
	}
	if gotVS == nil || len(gotVS.Validators) != 1 ||
		string(gotVS.Validators[0].Address) != string(vs.Validators[0].Address) {
		t.Fatal("valset roundtrip mismatch")
	}
}
