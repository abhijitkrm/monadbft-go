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

// TestSafetyRestoreRefusesResign — the CometBFT CheckHRS analogue: a Safety
// rebuilt from durable watermarks must refuse to re-vote/re-propose a round
// it already signed, while still allowing the next round.
func TestSafetyRestoreRefusesResign(t *testing.T) {
	neTip := mkTip(t, 2, 6).BlockHeader.GetId()

	s := consensus.DefaultSafety()
	s.Propose(4)                    // proposed round 4
	s.Vote(5, nil, *mkTip(t, 1, 5)) // voted round 5
	s.NoEndorse(6, neTip)           // NE'd round 6 against neTip
	snap := s.Snapshot()

	// Process death: only the snapshot survives.
	restored := consensus.SafetyFromSnapshot(snap)

	if restored.IsSafeToVote(5, nil) {
		t.Fatal("restored Safety must refuse re-vote at signed round")
	}
	if restored.IsSafeToPropose(4) {
		t.Fatal("restored Safety must refuse re-propose at signed round")
	}
	if restored.IsSafeToNoEndorse(6) {
		t.Fatal("restored Safety must refuse re-NE at signed round")
	}
	// The NE rule survives restore: at the NE'd round a vote is allowed only
	// when the proposal carries the NE'd tip — nil or a different tip is
	// refused (round == highestNoEndorse.round is the gated case).
	if restored.IsSafeToVote(6, nil) {
		t.Fatal("vote at NE'd round must require the NE'd tip")
	}
	if other := mkTip(t, 9, 6).BlockHeader.GetId(); restored.IsSafeToVote(6, &other) {
		t.Fatal("vote at NE'd round must refuse a different tip")
	}
	if !restored.IsSafeToVote(6, &neTip) {
		t.Fatal("vote at NE'd round must allow the NE'd tip")
	}
	if !restored.IsSafeToVote(7, nil) {
		t.Fatal("the NE gate applies only at the NE'd round — 7 must be free")
	}

	// A conflicting sign attempt must panic — the watermark is the guard.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("re-vote at signed round must panic")
		}
	}()
	restored.Vote(5, nil, *mkTip(t, 4, 5))
}

// TestSafetyRoundPersistence — a watermark written between Update and the
// wire send must be on disk (fsync'd) and reload identically.
func TestSafetyRoundPersistence(t *testing.T) {
	dir := t.TempDir()
	s := consensus.DefaultSafety()
	s.Vote(5, nil, *mkTip(t, 1, 5))
	if err := WriteSafety(dir, s.Snapshot()); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSafety(dir, exec.Mock)
	if err != nil || got == nil {
		t.Fatalf("reload: %v %v", got, err)
	}
	if got.HighestVote != 5 {
		t.Fatalf("highestVote = %d, want 5", got.HighestVote)
	}
}
