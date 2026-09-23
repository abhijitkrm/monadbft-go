package swarm

import (
	"errors"
	"fmt"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/types"
)

// In-memory execution state — port of
// monad-execution-state-read::in_memory::{InMemoryStateInner, InMemoryBlockState}.
//
// The Rust mock tracks full EVM account state; the swarm drives it with
// MockExecutionProtocol whose bodies carry no transactions, so accounts are
// always empty. This port keeps the block bookkeeping (proposals/commits,
// earliest/latest finalized reads, statesync reset) and drops the account
// model — ledger_propose is always invoked with an empty txn list upstream.

// InMemoryBlockState — Rust InMemoryBlockState.
type InMemoryBlockState struct {
	BlockID  types.BlockId
	SeqNum   types.SeqNum
	Round    types.Round
	ParentID types.BlockId
}

// GenesisInMemoryBlockState — Rust InMemoryBlockState::genesis.
func GenesisInMemoryBlockState() *InMemoryBlockState {
	return &InMemoryBlockState{
		BlockID:  types.GENESIS_BLOCK_ID,
		SeqNum:   types.GENESIS_SEQ_NUM,
		Round:    types.GENESIS_ROUND,
		ParentID: types.GENESIS_BLOCK_ID,
	}
}

var (
	ErrNotAvailableYet = errors.New("execution result not available yet")
	ErrNeverAvailable  = errors.New("execution result never available")
)

// InMemoryState — Rust InMemoryStateInner: the in-memory ExecutionStateRead +
// MockExecution impl shared by MockLedger/MockStateSyncExecutor and consumed by
// MonadState as blocktree.ExecutionStateRead.
type InMemoryState struct {
	commits   map[types.SeqNum]*InMemoryBlockState
	proposals map[types.BlockId]*InMemoryBlockState

	executionDelay types.SeqNum
}

var _ blocktree.ExecutionStateRead = (*InMemoryState)(nil)

// NewInMemoryStateGenesis — Rust InMemoryStateInner::genesis.
func NewInMemoryStateGenesis(executionDelay types.SeqNum) *InMemoryState {
	g := GenesisInMemoryBlockState()
	return &InMemoryState{
		commits:        map[types.SeqNum]*InMemoryBlockState{g.SeqNum: g},
		proposals:      map[types.BlockId]*InMemoryBlockState{},
		executionDelay: executionDelay,
	}
}

// NewInMemoryState — Rust InMemoryStateInner::new(execution_delay, last_commit).
func NewInMemoryState(executionDelay types.SeqNum, lastCommit *InMemoryBlockState) *InMemoryState {
	return &InMemoryState{
		commits:        map[types.SeqNum]*InMemoryBlockState{lastCommit.SeqNum: lastCommit},
		proposals:      map[types.BlockId]*InMemoryBlockState{},
		executionDelay: executionDelay,
	}
}

// CommittedState — Rust InMemoryStateInner::committed_state.
func (s *InMemoryState) CommittedState(seq types.SeqNum) *InMemoryBlockState {
	return s.commits[seq]
}

// ResetState — Rust InMemoryStateInner::reset_state (statesync install).
func (s *InMemoryState) ResetState(state *InMemoryBlockState) {
	s.proposals = map[types.BlockId]*InMemoryBlockState{}
	s.commits = map[types.SeqNum]*InMemoryBlockState{state.SeqNum: state}
}

func (s *InMemoryState) earliestFinalized() (types.SeqNum, bool) {
	var best types.SeqNum
	ok := false
	for seq := range s.commits {
		if !ok || seq < best {
			best, ok = seq, true
		}
	}
	return best, ok
}

func (s *InMemoryState) latestFinalized() (types.SeqNum, bool) {
	var best types.SeqNum
	ok := false
	for seq := range s.commits {
		if !ok || seq > best {
			best, ok = seq, true
		}
	}
	return best, ok
}

// LedgerPropose — Rust MockExecution::ledger_propose. `txns` is always empty in
// the swarm (MockExecutionProtocol bodies carry no real transactions).
func (s *InMemoryState) LedgerPropose(blockID types.BlockId, seqNum types.SeqNum, round types.Round, parentID types.BlockId, txns [][]byte) {
	if committed, ok := s.commits[seqNum]; ok && committed.BlockID == blockID {
		// we can repropose already-finalized blocks on startup
		// this is part of the statesync process
		return
	}
	if latest, ok := s.latestFinalized(); ok && seqNum.Uint64() <= latest.Uint64() {
		return // already finalized
	}

	// get parent block state; execute on top of it
	var parent *InMemoryBlockState
	if p, ok := s.proposals[parentID]; ok {
		parent = p
	} else if seqNum.Uint64() > 0 {
		parent = s.commits[seqNum.Sub(types.SeqNum(1))]
	}
	if parent == nil {
		panic(fmt.Sprintf("parent block not found for proposed block, proposed_seq_num=%d, round=%d", seqNum.Uint64(), round.Uint64()))
	}
	_ = parent // accounts are always empty under MockExecutionProtocol

	s.proposals[blockID] = &InMemoryBlockState{
		BlockID:  blockID,
		SeqNum:   seqNum,
		Round:    round,
		ParentID: parentID,
	}
}

// LedgerCommit — Rust MockExecution::ledger_commit.
func (s *InMemoryState) LedgerCommit(blockID types.BlockId, seqNum types.SeqNum) {
	if committed, ok := s.commits[seqNum]; ok && committed.BlockID == blockID {
		// we can refinalize already-finalized blocks on startup
		return
	}
	if latest, ok := s.latestFinalized(); ok && seqNum.Uint64() <= latest.Uint64() {
		return // already finalized
	}

	committedProposal, ok := s.proposals[blockID]
	if !ok {
		panic(fmt.Sprintf("committed proposal that doesn't exist, block_id=%x", blockID[:8]))
	}
	delete(s.proposals, blockID)

	lastSeq, lastOk := s.latestFinalized()
	if !lastOk {
		panic("latest_finalized doesn't exist")
	}
	lastCommit := s.commits[lastSeq]
	if lastCommit.SeqNum.Add(types.SeqNum(1)) != committedProposal.SeqNum {
		panic(fmt.Sprintf("ledger_commit seq gap: last=%d proposal=%d", lastCommit.SeqNum.Uint64(), committedProposal.SeqNum.Uint64()))
	}
	if lastCommit.BlockID != committedProposal.ParentID {
		panic("ledger_commit parent mismatch")
	}

	s.commits[committedProposal.SeqNum] = committedProposal
}

// GetExecutionResult — Rust ExecutionStateRead::get_execution_result.
// Under MockExecutionProtocol the finalized header only carries the seq_num.
func (s *InMemoryState) GetExecutionResult(blockID types.BlockId, seqNum types.SeqNum, isFinalized bool) (exec.FinalizedHeader, error) {
	var block *InMemoryBlockState
	if isFinalized {
		latest, ok := s.latestFinalized()
		if !ok || latest.Uint64() < seqNum.Uint64() {
			return nil, ErrNotAvailableYet
		}
		if earliest, ok := s.earliestFinalized(); ok && earliest.Uint64() > seqNum.Uint64() {
			return nil, ErrNeverAvailable
		}
		block = s.commits[seqNum]
		if block == nil {
			panic("finalized block missing from commits")
		}
	} else {
		p, ok := s.proposals[blockID]
		if !ok {
			return nil, ErrNotAvailableYet
		}
		block = p
	}

	if block.BlockID != blockID {
		panic("get_execution_result block_id mismatch")
	}
	if block.SeqNum != seqNum {
		panic("get_execution_result seq_num mismatch")
	}
	return &exec.MockFinalizedHeader{Number: block.SeqNum}, nil
}

// RawReadEarliestFinalizedBlock — Rust raw_read_earliest_finalized_block.
func (s *InMemoryState) RawReadEarliestFinalizedBlock() *types.SeqNum {
	if seq, ok := s.earliestFinalized(); ok {
		return &seq
	}
	return nil
}

// RawReadLatestFinalizedBlock — Rust raw_read_latest_finalized_block.
func (s *InMemoryState) RawReadLatestFinalizedBlock() *types.SeqNum {
	if seq, ok := s.latestFinalized(); ok {
		return &seq
	}
	return nil
}

// ReadValsetAtBlock — Rust read_valset_at_block is unimplemented!() in
// InMemoryState (validator-set updates for tests are driven by
// MockValSetUpdater instead). Returns nil; the locked-epoch assert in
// maybeStartConsensus never runs under MockChainConfig.
func (s *InMemoryState) ReadValsetAtBlock(blockNum types.SeqNum, requestedEpoch types.Epoch) []blocktree.ValidatorReadData {
	return nil
}
