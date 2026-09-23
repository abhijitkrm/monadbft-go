package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/testutil"
	"github.com/abhijitkrm/monadbft-go/types"
)

func mkBlock(t *testing.T, seed uint64, seq types.SeqNum, parentQC cstypes.QuorumCertificate) cstypes.ConsensusFullBlock {
	t.Helper()
	kp := testutil.GetKey(seed)
	cert := testutil.GetCertKey(seed)
	round := types.Round(100 + seq.Uint64())
	body := cstypes.ConsensusBlockBody{Inner: cstypes.ConsensusBlockBodyInner{
		ExecutionBody: &exec.MockBody{Data: []byte{byte(seq)}},
	}}
	hdr := cstypes.NewConsensusBlockHeader(
		types.NewNodeId(kp.PubKey()), types.Epoch(1), round,
		nil, &exec.MockProposedHeader{}, body.GetId(),
		parentQC, seq, types.U128FromUint64(uint64(seq)),
		cstypes.NewRoundSignature(round, cert), 0, 0, 0,
	)
	fb, err := cstypes.NewFullBlock(hdr, body)
	if err != nil {
		t.Fatal(err)
	}
	return fb
}

func TestBlockStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	bs, err := OpenBlockStore(dir, exec.Mock)
	if err != nil {
		t.Fatal(err)
	}
	b1 := mkBlock(t, 1, 1, cstypes.GenesisQC())
	b2 := mkBlock(t, 2, 2, cstypes.GenesisQC())
	for _, b := range []*cstypes.ConsensusFullBlock{&b1, &b2} {
		if err := bs.PutBlock(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := bs.PutFinalized(b1.GetSeqNum(), b1.GetId()); err != nil {
		t.Fatal(err)
	}

	got, err := bs.GetBlock(b1.GetId())
	if err != nil || got == nil {
		t.Fatalf("GetBlock: %v %v", got, err)
	}
	if got.GetId() != b1.GetId() {
		t.Fatal("block id mismatch")
	}
	bySeq, err := bs.GetBySeqNum(2)
	if err != nil || bySeq == nil || bySeq.GetId() != b2.GetId() {
		t.Fatal("GetBySeqNum mismatch")
	}
	payload, err := bs.GetPayload(b2.GetBodyId())
	if err != nil || payload == nil || payload.GetId() != b2.GetBodyId() {
		t.Fatal("GetPayload mismatch")
	}
	fins, err := bs.FinalizedBlocks()
	if err != nil || len(fins) != 1 || fins[0].GetId() != b1.GetId() {
		t.Fatal("FinalizedBlocks mismatch")
	}
	all, err := bs.AllBlocks()
	if err != nil || len(all) != 2 {
		t.Fatalf("AllBlocks = %d, %v", len(all), err)
	}
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	// reopen — durable
	bs2, err := OpenBlockStore(dir, exec.Mock)
	if err != nil {
		t.Fatal(err)
	}
	defer bs2.Close()
	got, err = bs2.GetBlock(b1.GetId())
	if err != nil || got == nil {
		t.Fatal("block lost across reopen")
	}
}

func TestForkpointWriteLoad(t *testing.T) {
	dir := t.TempDir()
	cf := NewConfigFile(dir, exec.Mock)

	cp := cstypes.Checkpoint{
		Root:            types.BlockId{7},
		HighCertificate: cstypes.RoundCertificate{IsQC: true, QC: ptr(cstypes.GenesisQC())},
		ValidatorSets:   []cstypes.LockedEpoch{{Epoch: 1, Round: 0}, {Epoch: 2, Round: 50}},
	}
	cf.WriteCheckpoint(types.SeqNum(9), cp)

	// backup file exists
	matches, _ := filepath.Glob(filepath.Join(dir, "forkpoint.rlp.9.*"))
	if len(matches) != 1 {
		t.Fatalf("expected checkpoint backup, got %v", matches)
	}
	// no .wip residue
	if _, err := os.Stat(filepath.Join(dir, "forkpoint.rlp.wip")); !os.IsNotExist(err) {
		t.Fatal("wip file should be renamed away")
	}

	loaded, err := LoadCheckpoint(dir, exec.Mock)
	if err != nil || loaded == nil {
		t.Fatalf("LoadCheckpoint: %v %v", loaded, err)
	}
	if loaded.Root != cp.Root || len(loaded.ValidatorSets) != 2 || loaded.ValidatorSets[1].Epoch != 2 {
		t.Fatal("checkpoint mismatch")
	}

	// validator sets
	vset := glue.ValidatorSetDataWithEpoch{Epoch: 2, Validators: glue.ValidatorSetData{
		Validators: []glue.ValidatorData{
			{NodeId: types.NewNodeId(testutil.GetKey(1).PubKey()), Stake: types.StakeFromUint64(1)},
		},
	}}
	cf.WriteValidatorSet(vset)
	vset3 := glue.ValidatorSetDataWithEpoch{Epoch: 3, Validators: vset.Validators}
	cf.WriteValidatorSet(vset3)

	sets, err := LoadValidatorSets(dir)
	if err != nil || len(sets) != 2 {
		t.Fatalf("LoadValidatorSets = %v, %v", sets, err)
	}
	if sets[0].Epoch != 2 || sets[1].Epoch != 3 {
		t.Fatal("trailing validator sets mismatch")
	}
	if _, err := os.Stat(filepath.Join(dir, "validators.3")); err != nil {
		t.Fatal("validators.3 backup missing")
	}
}

func ptr(q cstypes.QuorumCertificate) *cstypes.QuorumCertificate { return &q }
