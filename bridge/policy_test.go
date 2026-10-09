package bridge

import (
	"errors"
	"testing"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/types"
)

// fakeResults — ExecutionStateRead over a seq→apphash map; `executed` is
// the finalized-execution tip (results above it are not available yet).
type fakeResults struct {
	executed types.SeqNum
	ids      map[types.SeqNum]types.BlockId
}

func (f *fakeResults) hash(s types.SeqNum) []byte { return []byte{byte(s), 0xAB} }

func (f *fakeResults) GetExecutionResult(id types.BlockId, s types.SeqNum, fin bool) (exec.FinalizedHeader, error) {
	if !fin || s > f.executed {
		return nil, blocktree.ErrNotAvailableYet
	}
	if want, ok := f.ids[s]; ok && want != id {
		return nil, blocktree.ErrNotAvailableYet
	}
	return &EvmFinalizedHeader{Number: s, AppHash: f.hash(s)}, nil
}
func (f *fakeResults) RawReadEarliestFinalizedBlock() *types.SeqNum { z := types.SeqNum(0); return &z }
func (f *fakeResults) RawReadLatestFinalizedBlock() *types.SeqNum   { e := f.executed; return &e }
func (f *fakeResults) ReadValsetAtBlock(types.SeqNum, types.Epoch) []blocktree.ValidatorReadData {
	return nil
}

var testBls = MakeValidators(1)[0].Bls

func mkBlock(seq types.SeqNum, embed *types.SeqNum, f *fakeResults) *cstypes.ConsensusFullBlock {
	h := cstypes.ConsensusBlockHeader{
		BlockRound:      types.Round(seq),
		QC:              cstypes.GenesisQC(),
		SeqNum:          seq,
		TimestampNs:     types.U128FromUint64(uint64(seq)),
		RoundSignature:  cstypes.NewRoundSignature(types.Round(seq), testBls),
		ExecutionInputs: &EvmProposedHeader{},
	}
	if embed != nil {
		h.DelayedExecutionResults = []exec.FinalizedHeader{&EvmFinalizedHeader{Number: *embed, AppHash: f.hash(*embed)}}
	}
	return &cstypes.ConsensusFullBlock{Header: h}
}

func sp(s types.SeqNum) *types.SeqNum { return &s }

// commitChain — finalize 1..tip, each block embedding max-lag results.
func commitChain(p *FinalOnlyPolicy, f *fakeResults, tip types.SeqNum) {
	f.ids = map[types.SeqNum]types.BlockId{0: types.GENESIS_BLOCK_ID}
	for s := types.SeqNum(1); s <= tip; s++ {
		var e *types.SeqNum
		if s >= p.delay {
			e = sp(s - p.delay)
		}
		b := mkBlock(s, e, f)
		f.ids[s] = b.GetId()
		p.UpdateCommittedBlock(b)
	}
}

func TestFinalOnlyPolicy(t *testing.T) {
	const delay = 3
	newP := func() (*FinalOnlyPolicy, *fakeResults) {
		p := NewFinalOnlyPolicy(delay, 0, 0, 0)
		f := &fakeResults{}
		commitChain(p, f, 6) // root = 6, embeds 3
		f.executed = 6
		return p, f
	}
	root := blocktree.RootInfo{SeqNum: 6, TimestampNs: types.U128FromUint64(6)}
	check := func(p *FinalOnlyPolicy, f *fakeResults, b *cstypes.ConsensusFullBlock, ext ...*cstypes.ConsensusFullBlock) error {
		return p.CheckCoherency(b, ext, root, f, nil)
	}

	t.Run("happy path embeds exactly N-delay", func(t *testing.T) {
		p, f := newP()
		res, err := p.GetExpectedExecutionResults(7, nil, f)
		if err != nil || len(res) != 1 || res[0].SeqNum() != 4 {
			t.Fatalf("proposer pick: %v %v", res, err)
		}
		if err := check(p, f, mkBlock(7, sp(4), f)); err != nil {
			t.Fatalf("valid block rejected: %v", err)
		}
	})

	t.Run("lagging final tip embeds an older finalized seq", func(t *testing.T) {
		p, f := newP()
		// N=10 extends unfinalized 7,8,9: N-delay=7 > final tip 6 → pick 6
		b7, b8 := mkBlock(7, sp(4), f), mkBlock(8, sp(5), f)
		b9 := mkBlock(9, sp(6), f)
		ext := []*cstypes.ConsensusFullBlock{b7, b8, b9}
		res, err := p.GetExpectedExecutionResults(10, ext, f)
		if err != nil || res[0].SeqNum() != 6 {
			t.Fatalf("proposer pick: %v %v", res, err)
		}
		if err := check(p, f, mkBlock(10, sp(6), f), ext...); err != nil {
			t.Fatalf("lagging-but-final result rejected: %v", err)
		}
		// beyond the local final tip: wait, don't reject
		if err := check(p, f, mkBlock(10, sp(7), f), ext...); !errors.Is(err, blocktree.ErrNotAvailableYet) {
			t.Fatalf("unfinalized s: want NotAvailableYet, got %v", err)
		}
	})

	t.Run("range bounds reject", func(t *testing.T) {
		p, f := newP()
		if err := check(p, f, mkBlock(7, sp(5), f)); !errors.Is(err, blocktree.ErrExecutionResultMismatch) {
			t.Fatalf("s > N-delay: got %v", err)
		}
		// root (6) embedded 3 → lower bound 3
		if err := check(p, f, mkBlock(7, sp(2), f)); !errors.Is(err, blocktree.ErrExecutionResultMismatch) {
			t.Fatalf("s < r(parent): got %v", err)
		}
		if err := check(p, f, mkBlock(7, nil, f)); !errors.Is(err, blocktree.ErrExecutionResultMismatch) {
			t.Fatalf("missing result: got %v", err)
		}
	})

	t.Run("wrong app hash rejects", func(t *testing.T) {
		p, f := newP()
		b := mkBlock(7, sp(4), f)
		b.Header.DelayedExecutionResults = []exec.FinalizedHeader{&EvmFinalizedHeader{Number: 4, AppHash: []byte{9}}}
		if err := check(p, f, b); !errors.Is(err, blocktree.ErrExecutionResultMismatch) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("execution lag waits validator, throttles proposer", func(t *testing.T) {
		p, f := newP()
		f.executed = 3 // finalized to 6, executed only to 3
		if err := check(p, f, mkBlock(7, sp(4), f)); !errors.Is(err, blocktree.ErrNotAvailableYet) {
			t.Fatalf("validator: want NotAvailableYet, got %v", err)
		}
		// proposer may fall back to the lower bound (3 = r(root)) it has executed
		res, err := p.GetExpectedExecutionResults(7, nil, f)
		if err != nil || res[0].SeqNum() != 3 {
			t.Fatalf("proposer fallback: %v %v", res, err)
		}
		f.executed = 2 // below r(parent): nothing embeddable yet
		if _, err := p.GetExpectedExecutionResults(7, nil, f); !errors.Is(err, blocktree.ErrNotAvailableYet) {
			t.Fatalf("proposer below lower bound: got %v", err)
		}
	})

	t.Run("pre-delay heights embed nothing", func(t *testing.T) {
		p := NewFinalOnlyPolicy(delay, 0, 0, 0)
		f := &fakeResults{executed: 1}
		commitChain(p, f, 1)
		r := blocktree.RootInfo{SeqNum: 1, TimestampNs: types.U128FromUint64(1)}
		if err := p.CheckCoherency(mkBlock(2, sp(0), f), nil, r, f, nil); !errors.Is(err, blocktree.ErrExecutionResultMismatch) {
			t.Fatalf("result below delay: got %v", err)
		}
		if err := p.CheckCoherency(mkBlock(2, nil, f), nil, r, f, nil); err != nil {
			t.Fatalf("empty result below delay rejected: %v", err)
		}
	})

	t.Run("prune keeps the embedded seq reachable", func(t *testing.T) {
		p := NewFinalOnlyPolicy(delay, 0, 0, 0)
		f := &fakeResults{}
		commitChain(p, f, 40)
		lo := p.committed[p.lastCommit].rSeq
		if _, ok := p.committed[lo]; !ok {
			t.Fatalf("r(lastCommit)=%d pruned", lo)
		}
		if len(p.committed) > int(2*delay)+2 {
			t.Fatalf("index not bounded: %d entries", len(p.committed))
		}
	})
}
