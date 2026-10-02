package store

import (
	"testing"

	"github.com/abhijitkrm/monadbft-go/consensus"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/testutil"
	"github.com/abhijitkrm/monadbft-go/types"
)

func mkTip(t *testing.T, seed uint64, round types.Round) *cstypes.ConsensusTip {
	t.Helper()
	kp := testutil.GetKey(seed)
	cert := testutil.GetCertKey(seed)
	hdr := cstypes.NewConsensusBlockHeader(
		types.NewNodeId(kp.PubKey()), types.Epoch(1), round,
		nil, &exec.MockProposedHeader{}, cstypes.ConsensusBlockBodyId{}, cstypes.GenesisQC(),
		types.SeqNum(1), types.U128FromUint64(1),
		cstypes.NewRoundSignature(round, cert), 0, 0, 0,
	)
	tip := cstypes.NewConsensusTip(kp, hdr, nil)
	return &tip
}

func TestSafetyRoundTrip(t *testing.T) {
	dir := t.TempDir()

	tip := mkTip(t, 3, 8)
	saved := &consensus.SafetySnapshot{
		MaybeHighTip:           tip,
		HighCertificateQcRound: 7,
		HighestVote:            9,
		HighestNoEndorseRound:  4,
		HighestNoEndorseTip:    tip.BlockHeader.GetId(),
		HighestPropose:         8,
		HighestRecoveryRequest: 2,
	}
	if err := WriteSafety(dir, saved); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSafety(dir, exec.Mock)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected snapshot")
	}
	if got.HighestVote != 9 || got.HighCertificateQcRound != 7 || got.HighestPropose != 8 {
		t.Fatalf("watermarks mismatch: %+v", got)
	}
	if got.MaybeHighTip == nil || got.MaybeHighTip.BlockHeader.GetId() != tip.BlockHeader.GetId() {
		t.Fatal("tip round-trip mismatch")
	}
	if got.HighestNoEndorseTip != tip.BlockHeader.GetId() {
		t.Fatal("no-endorse tip mismatch")
	}

	absent, err := LoadSafety(t.TempDir(), exec.Mock)
	if err != nil || absent != nil {
		t.Fatal("missing file should give nil snapshot")
	}
}

func TestSafetyMergeMonotone(t *testing.T) {
	hi := &consensus.SafetySnapshot{HighestVote: 9, HighCertificateQcRound: 7,
		MaybeHighTip: mkTip(t, 3, 8)}
	lo := &consensus.SafetySnapshot{HighestVote: 4, HighCertificateQcRound: 2,
		MaybeHighTip: mkTip(t, 3, 3)}

	hiS := consensus.SafetyFromSnapshot(hi)
	hiS.Merge(consensus.SafetyFromSnapshot(lo))
	m := hiS.Snapshot()
	if m.HighestVote != 9 || m.HighCertificateQcRound != 7 {
		t.Fatal("merge should keep max watermark")
	}
	if m.MaybeHighTip == nil || m.MaybeHighTip.BlockHeader.BlockRound != 8 {
		t.Fatal("merge should keep the fresher high tip")
	}

	loS := consensus.SafetyFromSnapshot(lo)
	loS.Merge(consensus.SafetyFromSnapshot(hi))
	m = loS.Snapshot()
	if m.HighestVote != 9 || m.MaybeHighTip.BlockHeader.BlockRound != 8 {
		t.Fatal("merge should pull lower state up (reversed)")
	}
}
