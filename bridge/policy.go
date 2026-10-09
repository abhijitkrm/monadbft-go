package bridge

import (
	"bytes"
	"fmt"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/chaincfg"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/types"
)

// FinalOnlyPolicy — block policy for final-only execution: the app executes
// finalized blocks exclusively (FinalizeBlock+Commit means final, as the SDK
// assumes), so delayed_execution_results can only ever reference finalized
// heights.
//
// Upstream embeds the result of exactly seq-delay, which after a run of
// timeouts may be unfinalized — upstream executes speculatively to cover
// that. Here block N embeds the result of a finalized seq s with
//
//	r(parent) <= s <= N - delay
//
// where r(parent) is the seq the parent embedded (monotonic, so the lag can
// never regress). Validators check the result against their own finalized
// execution of s; a validator that hasn't executed s yet answers
// ErrNotAvailableYet (wait, don't reject) — s is final, so it will. An
// honest proposer embeds min(N-delay, its executed final tip), which on the
// happy path is exactly N-delay (upstream-identical); only after timeout
// streaks does the lag widen, and it can never deadlock because r(parent)
// is always already executed.
//
// Base-fee checks mirror blocktree.EvmBlockPolicy.
type FinalOnlyPolicy struct {
	delay                         types.SeqNum
	baseFee, baseTrend, baseMomnt uint64

	lastCommit types.SeqNum
	// committed — finalized seq → (id, embedded result seq). Bounded below
	// by min(lastCommit-2*delay, r(lastCommit)) so every honest lookup in
	// [r(parent), N-delay] resolves.
	committed map[types.SeqNum]committedRef
}

type committedRef struct {
	id   types.BlockId
	rSeq types.SeqNum // seq the block embedded; 0 when it embedded none
}

var _ blocktree.BlockPolicy = (*FinalOnlyPolicy)(nil)

func NewFinalOnlyPolicy(delay types.SeqNum, baseFee, baseFeeTrend, baseFeeMoment uint64) *FinalOnlyPolicy {
	if delay < 2 {
		panic(fmt.Sprintf("bridge: final-only policy needs execution_delay >= 2, got %d", delay))
	}
	return &FinalOnlyPolicy{
		delay:      delay,
		baseFee:    baseFee,
		baseTrend:  baseFeeTrend,
		baseMomnt:  baseFeeMoment,
		lastCommit: types.GENESIS_SEQ_NUM,
		committed:  map[types.SeqNum]committedRef{},
	}
}

// embeddedSeq — the seq a block's delayed result refers to (0 when none).
func embeddedSeq(b *cstypes.ConsensusFullBlock) types.SeqNum {
	if res := b.Header.DelayedExecutionResults; len(res) == 1 {
		return res[0].SeqNum()
	}
	return 0
}

// lowerBound — r(parent): the parent is the last extending block, else the
// blocktree root, which is always the last committed block.
func (p *FinalOnlyPolicy) lowerBound(extending []*cstypes.ConsensusFullBlock) types.SeqNum {
	if len(extending) > 0 {
		return embeddedSeq(extending[len(extending)-1])
	}
	return p.committed[p.lastCommit].rSeq // genesis/missing → 0
}

// finalizedID — canonical block id at a finalized seq.
func (p *FinalOnlyPolicy) finalizedID(s types.SeqNum) (types.BlockId, bool) {
	if s == types.GENESIS_SEQ_NUM {
		return types.GENESIS_BLOCK_ID, true
	}
	ref, ok := p.committed[s]
	return ref.id, ok
}

// finalizedResult — this node's finalized execution result for seq s.
func (p *FinalOnlyPolicy) finalizedResult(s types.SeqNum, sr blocktree.ExecutionStateRead) (exec.FinalizedHeader, error) {
	if s > p.lastCommit {
		return nil, blocktree.ErrNotAvailableYet // not final here yet
	}
	id, ok := p.finalizedID(s)
	if !ok {
		// below the retained window: only reachable for s < r(parent),
		// which the range check rejects first
		return nil, blocktree.ErrNeverAvailable
	}
	return sr.GetExecutionResult(id, s, true)
}

func (p *FinalOnlyPolicy) CheckCoherency(
	block *cstypes.ConsensusFullBlock,
	extending []*cstypes.ConsensusFullBlock,
	root blocktree.RootInfo,
	stateRead blocktree.ExecutionStateRead,
	_ chaincfg.Config,
) error {
	var extSeqNum types.SeqNum
	var extTs types.U128
	if len(extending) > 0 {
		extSeqNum = extending[len(extending)-1].Header.SeqNum
		extTs = extending[len(extending)-1].Header.TimestampNs
	} else {
		extSeqNum = root.SeqNum // extending_timestamp = 0 like upstream
	}
	if block.Header.SeqNum != extSeqNum+1 {
		return blocktree.ErrBlockNotCoherent
	}
	if block.Header.TimestampNs.Cmp(extTs) <= 0 {
		return blocktree.ErrTimestamp
	}

	seq := block.Header.SeqNum
	res := block.Header.DelayedExecutionResults
	if seq < p.delay {
		if len(res) != 0 {
			return blocktree.ErrExecutionResultMismatch
		}
	} else {
		if len(res) != 1 {
			return blocktree.ErrExecutionResultMismatch
		}
		s := res[0].SeqNum()
		if s < p.lowerBound(extending) || s > seq-p.delay {
			return blocktree.ErrExecutionResultMismatch
		}
		expected, err := p.finalizedResult(s, stateRead)
		if err != nil {
			return err
		}
		if !bytes.Equal(res[0].EncodeRLP(nil), expected.EncodeRLP(nil)) {
			return blocktree.ErrExecutionResultMismatch
		}
	}

	if block.Header.BaseFee != p.baseFee ||
		block.Header.BaseFeeTrend != p.baseTrend ||
		block.Header.BaseFeeMoment != p.baseMomnt {
		return blocktree.ErrBaseFee
	}
	return nil
}

// GetExpectedExecutionResults — proposer side: the highest finalized seq in
// [r(parent), N-delay] this node has executed.
func (p *FinalOnlyPolicy) GetExpectedExecutionResults(
	blockSeqNum types.SeqNum,
	extending []*cstypes.ConsensusFullBlock,
	stateRead blocktree.ExecutionStateRead,
) ([]exec.FinalizedHeader, error) {
	if blockSeqNum < p.delay {
		return nil, nil
	}
	hi := blockSeqNum - p.delay
	if hi > p.lastCommit {
		hi = p.lastCommit
	}
	if latest := stateRead.RawReadLatestFinalizedBlock(); latest == nil {
		return nil, blocktree.ErrNotAvailableYet
	} else if *latest < hi {
		hi = *latest
	}
	if hi < p.lowerBound(extending) {
		return nil, blocktree.ErrNotAvailableYet // execution lagging
	}
	res, err := p.finalizedResult(hi, stateRead)
	if err != nil {
		return nil, err
	}
	return []exec.FinalizedHeader{res}, nil
}

// UpdateCommittedBlock — index a finalized block (strict +1 order, as
// upstream asserts) and prune below the lookup window.
func (p *FinalOnlyPolicy) UpdateCommittedBlock(block *cstypes.ConsensusFullBlock) {
	if block.GetSeqNum() != p.lastCommit+1 {
		panic(fmt.Sprintf("bridge: committed seq %d does not follow %d", block.GetSeqNum(), p.lastCommit))
	}
	p.record(block)
	p.prune()
}

// Reset — reseed from the committed blocks below the root (restart and
// statesync path; monadstate widens the window to cover r(root)).
func (p *FinalOnlyPolicy) Reset(lastDelayCommitted []*cstypes.ConsensusFullBlock) {
	p.committed = map[types.SeqNum]committedRef{}
	p.lastCommit = types.GENESIS_SEQ_NUM
	for _, blk := range lastDelayCommitted {
		p.record(blk)
	}
}

func (p *FinalOnlyPolicy) record(block *cstypes.ConsensusFullBlock) {
	p.lastCommit = block.GetSeqNum()
	p.committed[block.GetSeqNum()] = committedRef{id: block.GetId(), rSeq: embeddedSeq(block)}
}

func (p *FinalOnlyPolicy) prune() {
	floor := p.lastCommit.SaturatingSub(p.delay.Mul(2))
	if r := p.committed[p.lastCommit].rSeq; r < floor {
		floor = r
	}
	for seq := range p.committed {
		if seq < floor {
			delete(p.committed, seq)
		}
	}
}
