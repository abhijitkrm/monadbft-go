package glue

import (
	"bytes"
	"testing"
	"time"

	"github.com/abhijitkrm/monadbft-go/blocksync"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/testutil"
	"github.com/abhijitkrm/monadbft-go/types"
)

func sampleQC() cstypes.QuorumCertificate {
	return cstypes.GenesisQC()
}

func sampleBlock() cstypes.ConsensusFullBlock {
	kp := testutil.GetKey(1)
	cert := testutil.GetCertKey(1)
	round := types.Round(7)
	sig := cstypes.NewRoundSignature(round, cert)
	body := cstypes.ConsensusBlockBody{Inner: cstypes.ConsensusBlockBodyInner{
		ExecutionBody: &exec.MockBody{Data: []byte{9, 9, 9}},
	}}
	hdr := cstypes.NewConsensusBlockHeader(
		types.NewNodeId(kp.PubKey()),
		types.Epoch(1), round,
		nil, &exec.MockProposedHeader{}, body.GetId(),
		sampleQC(), types.SeqNum(1), types.U128FromUint64(12345),
		sig, 100, 50, 3,
	)
	fb, err := cstypes.NewFullBlock(hdr, body)
	if err != nil {
		panic(err)
	}
	return fb
}

func roundTrip(t *testing.T, ev MonadEvent) MonadEvent {
	t.Helper()
	if !IsWalLogged(ev) {
		t.Fatalf("test event %T should be wal-logged", ev)
	}
	enc, err := EncodeMonadEvent(ev)
	if err != nil {
		t.Fatalf("encode %T: %v", ev, err)
	}
	dec, err := DecodeMonadEvent(enc, exec.Mock)
	if err != nil {
		t.Fatalf("decode %T: %v", ev, err)
	}
	return dec
}

func TestEventCodecConsensus(t *testing.T) {
	kp := testutil.GetKey(1)
	sender := types.NewNodeId(kp.PubKey())

	vote := messages.NewVoteMessage(cstypes.Vote{
		ID: types.BlockId{1}, Round: types.Round(3), Epoch: types.Epoch(1),
	}, testutil.GetCertKey(1))
	msg := messages.ConsensusMessage{
		Version: 1,
		Message: messages.ProtocolMessage{Kind: messages.PMVote, Vote: &vote},
	}
	sig := kp.Sign([]byte("x"), msg.EncodeRLP(nil))
	unverified := messages.Unverified{Obj: msg, AuthorSignature: sig}

	got := roundTrip(t, EvConsensusMessage{Sender: sender, UnverifiedMessage: unverified})
	m, ok := got.(EvConsensusMessage)
	if !ok {
		t.Fatalf("decoded %T", got)
	}
	if m.Sender != sender || m.UnverifiedMessage.Obj.Version != 1 ||
		m.UnverifiedMessage.Obj.Message.Kind != messages.PMVote {
		t.Fatal("consensus message mismatch")
	}

	got = roundTrip(t, EvConsensusTimeout{Round: types.Round(42)})
	if got.(EvConsensusTimeout).Round != 42 {
		t.Fatal("timeout mismatch")
	}

	fb := sampleBlock()
	got = roundTrip(t, EvConsensusBlockSync{
		BlockRange: cstypes.BlockRange{LastBlockId: fb.GetId(), NumBlocks: 1},
		FullBlocks: []cstypes.ConsensusFullBlock{fb},
	})
	bs := got.(EvConsensusBlockSync)
	if len(bs.FullBlocks) != 1 || bs.FullBlocks[0].GetId() != fb.GetId() {
		t.Fatal("blocksync blocks mismatch")
	}

	got = roundTrip(t, EvConsensusSendVote{Round: types.Round(11)})
	if got.(EvConsensusSendVote).Round != 11 {
		t.Fatal("sendvote mismatch")
	}
}

func TestEventCodecBlockSync(t *testing.T) {
	kp := testutil.GetKey(2)
	sender := types.NewNodeId(kp.PubKey())
	fb := sampleBlock()

	req := blocksync.RequestHeaders(cstypes.BlockRange{LastBlockId: fb.GetId(), NumBlocks: 3})

	got := roundTrip(t, EvBlockSyncRequest{Sender: sender, Request: req})
	r := got.(EvBlockSyncRequest)
	if r.Sender != sender || r.Request.Range != req.Range || r.Request.IsPayload {
		t.Fatal("blocksync request mismatch")
	}

	got = roundTrip(t, EvBlockSyncTimeout{Request: req})
	if got.(EvBlockSyncTimeout).Request.Range != req.Range {
		t.Fatal("blocksync timeout mismatch")
	}

	got = roundTrip(t, EvBlockSyncSelfRequest{
		Requester: blocksync.SelfRequesterConsensus, BlockRange: req.Range})
	if got.(EvBlockSyncSelfRequest).BlockRange != req.Range ||
		got.(EvBlockSyncSelfRequest).Requester != blocksync.SelfRequesterConsensus {
		t.Fatal("self request mismatch")
	}
	got = roundTrip(t, EvBlockSyncSelfCancelRequest{
		Requester: blocksync.SelfRequesterStateSync, BlockRange: req.Range})
	if got.(EvBlockSyncSelfCancelRequest).Requester != blocksync.SelfRequesterStateSync {
		t.Fatal("self cancel mismatch")
	}

	resp := blocksync.ResponseHeaders(req.Range, []cstypes.ConsensusBlockHeader{fb.Header})
	got = roundTrip(t, EvBlockSyncResponse{Sender: sender, Response: resp})
	rr := got.(EvBlockSyncResponse)
	if !rr.Response.Headers.Found || len(rr.Response.Headers.Headers) != 1 {
		t.Fatal("blocksync response mismatch")
	}
	pr := blocksync.ResponsePayload(fb.Body)
	got = roundTrip(t, EvBlockSyncSelfResponse{Response: pr})
	if !got.(EvBlockSyncSelfResponse).Response.Body.Found {
		t.Fatal("self response mismatch")
	}
}

func TestEventCodecValidator(t *testing.T) {
	cert := testutil.GetCertKey(3)
	kp := testutil.GetKey(3)
	pk := cert.PubKey()
	var cpk [48]byte
	copy(cpk[:], pk.Compress())
	vset := ValidatorSetDataWithEpoch{
		Epoch: types.Epoch(5),
		Validators: ValidatorSetData{Validators: []ValidatorData{
			{NodeId: types.NewNodeId(kp.PubKey()), Stake: types.StakeFromUint64(9), CertPubKey: cpk},
		}},
	}
	got := roundTrip(t, EvUpdateValidators{ValidatorSetDataWithEpoch: vset})
	v := got.(EvUpdateValidators)
	if v.ValidatorSetDataWithEpoch.Epoch != 5 ||
		len(v.ValidatorSetDataWithEpoch.Validators.Validators) != 1 ||
		v.ValidatorSetDataWithEpoch.Validators.Validators[0].CertPubKey != cpk {
		t.Fatal("validator event mismatch")
	}
}

func TestEventCodecMempool(t *testing.T) {
	cert := testutil.GetCertKey(4)
	sig := cstypes.NewRoundSignature(types.Round(8), cert)
	prop := EvMempoolProposal{
		Epoch: types.Epoch(2), Round: types.Round(8), SeqNum: types.SeqNum(44),
		HighQC:         sampleQC(),
		TimestampNs:    types.U128FromUint64(999),
		RoundSignature: sig,
		BaseFee:        100, BaseFeeTrend: 50, BaseFeeMoment: 3,
		DelayedExecutionResults: []exec.FinalizedHeader{
			&exec.MockFinalizedHeader{Number: types.SeqNum(40)},
		},
		ProposedExecutionInputs: ProposedExecutionInputs{
			Header: &exec.MockProposedHeader{},
			Body:   &exec.MockBody{Data: []byte{5}},
		},
	}
	got := roundTrip(t, prop)
	p := got.(EvMempoolProposal)
	if p.Round != 8 || p.SeqNum != 44 || p.BaseFee != 100 {
		t.Fatal("mempool proposal scalar mismatch")
	}
	if len(p.DelayedExecutionResults) != 1 || p.DelayedExecutionResults[0].SeqNum() != 40 {
		t.Fatal("delayed execution results mismatch")
	}
	if p.LastRoundTC != nil || p.FreshProposalCertificate != nil {
		t.Fatal("optional fields should be nil")
	}
	if !bytes.Equal(p.RoundSignature.Compress(), sig.Compress()) {
		t.Fatal("round signature mismatch")
	}

	got = roundTrip(t, EvTimestampUpdate{Timestamp: types.U128FromUint64(777)})
	if got.(EvTimestampUpdate).Timestamp.Lo() != 777 {
		t.Fatal("timestamp mismatch")
	}
}

func TestEventCodecStateSync(t *testing.T) {
	fb := sampleBlock()
	got := roundTrip(t, EvStateSyncDoneSync{SeqNum: types.SeqNum(33)})
	if got.(EvStateSyncDoneSync).SeqNum != 33 {
		t.Fatal("donesync mismatch")
	}
	got = roundTrip(t, EvStateSyncBlockSync{
		BlockRange: cstypes.BlockRange{LastBlockId: fb.GetId(), NumBlocks: 1},
		FullBlocks: []cstypes.ConsensusFullBlock{fb},
	})
	if len(got.(EvStateSyncBlockSync).FullBlocks) != 1 {
		t.Fatal("statesync blocksync mismatch")
	}
	got = roundTrip(t, EvStateSyncRequestSync{Root: fb.Header, HighQC: sampleQC()})
	if got.(EvStateSyncRequestSync).Root.GetId() != fb.GetId() {
		t.Fatal("requestsync mismatch")
	}
}

func TestIsWalLogged(t *testing.T) {
	logged := []MonadEvent{
		EvConsensusTimeout{Round: 1},
		EvBlockSyncTimeout{Request: blocksync.RequestMessage{}},
		EvUpdateValidators{},
		EvMempoolProposal{},
		EvStateSyncDoneSync{},
		EvTimestampUpdate{},
	}
	for _, e := range logged {
		if !IsWalLogged(e) {
			t.Fatalf("%T should be wal-logged", e)
		}
	}
	notLogged := []MonadEvent{
		EvMempoolForwardedTxs{},
		EvMempoolForwardTxs{},
		EvStateSyncInbound{},
		EvStateSyncOutbound{},
		EvGetMetrics{},
		EvConfigUpdate{},
		EvSecondaryRaptorcastPeersUpdate{},
	}
	for _, e := range notLogged {
		if IsWalLogged(e) {
			t.Fatalf("%T should NOT be wal-logged", e)
		}
	}
}

func TestLogFriendlyMonadEvent(t *testing.T) {
	ev := EvConsensusTimeout{Round: types.Round(99)}
	ts := time.Unix(1700000000, 123456789).UTC()
	lfe := LogFriendlyMonadEvent{Timestamp: ts, Event: ev}
	data, err := lfe.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	gotTs, err := DeserializeTimestamp(data)
	if err != nil {
		t.Fatal(err)
	}
	if !gotTs.Equal(ts) {
		t.Fatalf("timestamp %v != %v", gotTs, ts)
	}
	got, err := DeserializeLogFriendly(data, exec.Mock)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Timestamp.Equal(ts) {
		t.Fatal("timestamp mismatch")
	}
	if got.Event.(EvConsensusTimeout).Round != 99 {
		t.Fatal("event mismatch")
	}
}
