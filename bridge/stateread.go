package bridge

import (
	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/types"
)

// StateRead — blocktree.ExecutionStateRead over the app's results.
//
// Finalized lookups serve the canonical committed-result index (seq +
// blockID verified). Non-finalized lookups serve the speculative index —
// blocks executed by SpecApp ahead of finalization — which is what lets
// execution_delay>0 proposals embed delayed_execution_results. A nil spec
// index degrades to the old synchronous behavior (ErrNotAvailableYet for
// unfinalized blocks).
type StateRead struct {
	app  *App
	spec *SpecApp
}

var _ blocktree.ExecutionStateRead = (*StateRead)(nil)

func NewStateRead(app *App, spec *SpecApp) *StateRead {
	return &StateRead{app: app, spec: spec}
}

// GetExecutionResult — the result for (blockID, seqNum): committed index
// when isFinalized, speculative index otherwise.
func (s *StateRead) GetExecutionResult(
	blockID types.BlockId, seqNum types.SeqNum, isFinalized bool,
) (exec.FinalizedHeader, error) {
	if !isFinalized {
		if s.spec == nil {
			return nil, blocktree.ErrNotAvailableYet
		}
		seq, appHash, _, ok := s.spec.SpecResultID(blockID)
		if !ok || seq != int64(seqNum.Uint64()) {
			return nil, blocktree.ErrNotAvailableYet
		}
		return &EvmFinalizedHeader{Number: seqNum, AppHash: appHash}, nil
	}
	s.app.mu.Lock()
	entry, ok := s.app.results[int64(seqNum.Uint64())]
	s.app.mu.Unlock()
	if !ok || entry.blockID != blockID {
		return nil, blocktree.ErrNotAvailableYet
	}
	return entry.header, nil
}

// RawReadEarliestFinalizedBlock — lowest committed seq (genesis = 0).
func (s *StateRead) RawReadEarliestFinalizedBlock() *types.SeqNum {
	s.app.mu.Lock()
	defer s.app.mu.Unlock()
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

// RawReadLatestFinalizedBlock — highest committed seq (O(1): a.height is
// written with the result entry). The final-only proposer reads it on
// every proposal.
func (s *StateRead) RawReadLatestFinalizedBlock() *types.SeqNum {
	s.app.mu.Lock()
	defer s.app.mu.Unlock()
	if len(s.app.results) == 0 {
		return nil
	}
	h := types.SeqNum(s.app.height)
	return &h
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
