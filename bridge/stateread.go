package bridge

import (
	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/types"
)

// StateRead — blocktree.ExecutionStateRead over the app's committed results.
//
// Synchronous execution means a block only has an execution result once it
// is finalized; proposed-but-unfinalized blocks return ErrNotAvailableYet
// (the upstream proposals-fallback would need speculative execution, which
// the bridge defers).
type StateRead struct {
	app *App
}

var _ blocktree.ExecutionStateRead = (*StateRead)(nil)

func NewStateRead(app *App) *StateRead { return &StateRead{app: app} }

// GetExecutionResult — the finalized result for (blockID, seqNum).
func (s *StateRead) GetExecutionResult(
	blockID types.BlockId, seqNum types.SeqNum, isFinalized bool,
) (exec.FinalizedHeader, error) {
	entry, ok := s.app.results[int64(seqNum.Uint64())]
	if !ok {
		return nil, blocktree.ErrNotAvailableYet
	}
	if isFinalized && entry.blockID != blockID {
		return nil, blocktree.ErrNotAvailableYet
	}
	return entry.header, nil
}

// RawReadEarliestFinalizedBlock — lowest committed seq (genesis = 0).
func (s *StateRead) RawReadEarliestFinalizedBlock() *types.SeqNum {
	var min *types.SeqNum
	for seq := range s.app.results {
		sn := types.SeqNum(seq)
		if min == nil || sn < *min {
			cp := sn
			min = &cp
		}
	}
	return min
}

// RawReadLatestFinalizedBlock — highest committed seq.
func (s *StateRead) RawReadLatestFinalizedBlock() *types.SeqNum {
	var max *types.SeqNum
	for seq := range s.app.results {
		sn := types.SeqNum(seq)
		if max == nil || sn > *max {
			cp := sn
			max = &cp
		}
	}
	return max
}

// ReadValsetAtBlock — the validator set for `requestedEpoch`. The bridge's
// validator registry is the app's canonical set (genesis + applied
// ValidatorUpdates); per-epoch history is kept by the ValSet executor.
func (s *StateRead) ReadValsetAtBlock(
	blockNum types.SeqNum, requestedEpoch types.Epoch,
) []blocktree.ValidatorReadData {
	data, err := s.app.ValidatorSetData()
	if err != nil {
		return nil
	}
	out := make([]blocktree.ValidatorReadData, 0, len(data.Validators))
	for _, vd := range data.Validators {
		out = append(out, blocktree.ValidatorReadData{
			PubKey:     [33]byte(vd.NodeId.PubKey),
			CertPubKey: vd.CertPubKey,
			Stake:      vd.Stake,
		})
	}
	return out
}
