package bridge

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/abhijitkrm/monadbft-go/blocksync"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/swarm"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Ledger — swarm.Ledger backed by an ABCI app: every finalized consensus
// block drives FinalizeBlock+Commit synchronously, and the resulting app hash
// is recorded as the block's finalized execution result (which later headers
// bind via delayed_execution_results).
//
// Height convention: consensus seq_num n ↔ app height n (seq 0 is genesis —
// no FinalizeBlock; InitChain covers it).
type Ledger struct {
	app  *App
	spec *SpecApp // nil → synchronous finalize-only execution

	blocks    map[types.BlockId]*cstypes.ConsensusFullBlock // proposed+voted+finalized
	committed map[types.SeqNum]*cstypes.ConsensusFullBlock  // finalized, in seq order

	// pendingSpec — blocks awaiting speculative execution. A commit event
	// can arrive before the spec frontier reaches the block's parent (a
	// proposed block may be coherent before its parent is canonically
	// committed), so submits retry on later commits until they chain or
	// canonicalize.
	pendingSpec map[types.BlockId]*cstypes.ConsensusFullBlock

	events []glue.MonadEvent // queued EvBlockSyncSelfResponse
}

var _ swarm.Ledger = (*Ledger)(nil)

func NewLedger(app *App, spec *SpecApp) *Ledger {
	return &Ledger{
		app:         app,
		spec:        spec,
		blocks:      map[types.BlockId]*cstypes.ConsensusFullBlock{},
		committed:   map[types.SeqNum]*cstypes.ConsensusFullBlock{},
		pendingSpec: map[types.BlockId]*cstypes.ConsensusFullBlock{},
	}
}

// Exec — LedgerCommand dispatch (mirrors MockLedger, Finalized executes).
func (l *Ledger) Exec(cmds []glue.LedgerCommand) {
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.LedgerCommit:
			switch c.Commit.Kind {
			case glue.CommitProposed, glue.CommitVoted:
				l.blocks[c.Commit.Block.GetId()] = c.Commit.Block
				l.speculate(c.Commit.Block)
			case glue.CommitFinalized:
				l.commitFinalized(c.Commit.Block)
			}
		case glue.LedgerFetchHeaders:
			l.events = append(l.events, glue.EvBlockSyncSelfResponse{
				Response: l.getHeaders(c.Range),
			})
		case glue.LedgerFetchPayload:
			l.events = append(l.events, glue.EvBlockSyncSelfResponse{
				Response: l.getPayload(c.BodyID),
			})
		}
	}
}

// commitFinalized — on a Finalized commit, commit the block and any
// still-uncommitted ancestors in seq order through the app.
func (l *Ledger) commitFinalized(block *cstypes.ConsensusFullBlock) {
	l.blocks[block.GetId()] = block

	// collect the uncommitted tail (walk parents until already-committed)
	var pending []*cstypes.ConsensusFullBlock
	for b := block; b != nil; {
		seq := b.GetSeqNum()
		if seq == types.GENESIS_SEQ_NUM {
			break
		}
		if _, done := l.committed[seq]; done {
			break
		}
		pending = append(pending, b)
		if b.GetParentId() == types.GENESIS_BLOCK_ID {
			break // parent is genesis — nothing further to commit
		}
		par := l.blocks[b.GetParentId()]
		if par == nil {
			// ancestor not yet seen — the commit chain is contiguous by
			// consensus construction, so this only happens if the parent was
			// pruned; treat as an invariant violation.
			panic(fmt.Sprintf("bridge: finalized block seq %d missing parent", seq.Uint64()))
		}
		b = par
	}
	// commit oldest → newest
	for i := len(pending) - 1; i >= 0; i-- {
		l.finalizeOne(pending[i])
	}
	// canonicalized parents may have unblocked pending spec work
	l.drainSpec()
}

// speculate — queue a block for speculative execution and drain the backlog
// in seq order. Safe for both Proposed and Voted commits; dedup by ID.
func (l *Ledger) speculate(block *cstypes.ConsensusFullBlock) {
	if l.spec == nil {
		return
	}
	// Spec floor: never spec-execute height 1 — its orphan would need a
	// rewind to version 0, which doesn't exist (genesis writes land in v1).
	// Height 1 always finalizes canonically; the spec frontier picks it up
	// via CommittedResult. Consequence: execution_delay must be ≥2 — a
	// smaller delay needs result(1) before seq-1 could ever finalize.
	if block.Header.SeqNum.Uint64() <= 1 {
		return
	}
	l.pendingSpec[block.GetId()] = block
	l.drainSpec()
}

// drainSpec — submit pending blocks to the spec frontier in seq order.
// Non-chaining submissions stay queued (their parent may arrive or commit
// later); real execution failures drop out (the canonical path re-executes
// and surfaces the error there).
func (l *Ledger) drainSpec() {
	if len(l.pendingSpec) == 0 {
		return
	}
	seqs := make([]*cstypes.ConsensusFullBlock, 0, len(l.pendingSpec))
	for _, b := range l.pendingSpec {
		seqs = append(seqs, b)
	}
	sort.Slice(seqs, func(i, j int) bool {
		return seqs[i].Header.SeqNum < seqs[j].Header.SeqNum
	})
	committed := l.app.committedHeight()
	for _, b := range seqs {
		h := b.Header
		seq := int64(h.SeqNum.Uint64())
		blockID := h.GetId()
		if seq <= committed {
			delete(l.pendingSpec, blockID)
			continue
		}
		if _, _, _, ok := l.spec.SpecResultID(blockID); ok {
			delete(l.pendingSpec, blockID)
			continue
		}
		body, ok := b.Body.Inner.ExecutionBody.(*EvmBody)
		if !ok {
			delete(l.pendingSpec, blockID)
			continue
		}
		_, err := l.spec.SpecFinalize(context.Background(), l.finalizeRequest(h, body.Txs), blockID, h.GetParentId())
		if err == nil || errors.Is(err, ErrSpecNotChaining) {
			if err == nil {
				delete(l.pendingSpec, blockID)
			}
			continue
		}
		// genuine execution error — drop; canonical finalize re-surfaces it
		delete(l.pendingSpec, blockID)
	}
	// bound the backlog — dead branches never chain
	for len(l.pendingSpec) > 512 {
		var lowest types.BlockId
		var minSeq types.SeqNum = ^types.SeqNum(0)
		for id, b := range l.pendingSpec {
			if b.Header.SeqNum < minSeq {
				minSeq, lowest = b.Header.SeqNum, id
			}
		}
		delete(l.pendingSpec, lowest)
	}
}

// finalizeRequest — the deterministic ABCI request for one consensus block
// (identical for spec and canonical execution — that equality is what makes
// delayed_execution_results verifiable).
func (l *Ledger) finalizeRequest(h cstypes.ConsensusBlockHeader, txs [][]byte) *abcitypes.RequestFinalizeBlock {
	blockID := h.GetId()
	return &abcitypes.RequestFinalizeBlock{
		Txs:                txs,
		Height:             int64(h.SeqNum.Uint64()),
		Time:               time.Unix(0, int64(h.TimestampNs.Uint64())),
		ProposerAddress:    l.app.ConsAddr(h.Author),
		DecidedLastCommit:  l.app.LastCommit(h.QC),
		Hash:               blockID[:],
		NextValidatorsHash: l.app.ValidatorsHash(),
	}
}

// finalizeOne — commit one consensus block through the app: reuse the spec
// result when this block was already executed (execution-delay pipeline),
// else FinalizeBlock+Commit synchronously.
func (l *Ledger) finalizeOne(block *cstypes.ConsensusFullBlock) {
	h := block.Header
	seq := int64(h.SeqNum.Uint64())
	if height := l.app.committedHeight(); seq <= height {
		return // already committed (e.g. re-emit after restart)
	} else if height != 0 && seq != height+1 {
		panic(fmt.Sprintf("bridge: finalize height %d after %d — gaps", seq, height))
	}

	body, ok := block.Body.Inner.ExecutionBody.(*EvmBody)
	if !ok {
		panic(fmt.Sprintf("bridge: unexpected body type %T", block.Body.Inner.ExecutionBody))
	}
	blockID := h.GetId()

	var appHash []byte
	var updates []abcitypes.ValidatorUpdate
	if l.spec != nil {
		appHash, updates, ok = l.spec.CommittedResult(seq, blockID, l.committedID)
		if !ok {
			appHash = nil
		}
	}
	if appHash == nil {
		l.app.opMu.Lock()
		res, err := l.app.FinalizeBlock(context.Background(), l.finalizeRequest(h, body.Txs))
		if err != nil {
			panic(fmt.Sprintf("bridge: FinalizeBlock h=%d: %v", seq, err))
		}
		if err := l.app.Commit(context.Background()); err != nil {
			panic(fmt.Sprintf("bridge: Commit h=%d: %v", seq, err))
		}
		l.app.opMu.Unlock()
		appHash, updates = res.AppHash, res.ValidatorUpdates
	}

	l.app.recordCommit(seq, resultEntry{
		header:  &EvmFinalizedHeader{Number: h.SeqNum, AppHash: appHash},
		blockID: blockID,
		txs:     body.Txs,
	})
	l.committed[h.SeqNum] = block
	if err := l.app.applyUpdates(updates); err != nil {
		panic(err)
	}
}

// committedID — the canonical block ID at a committed seq (genesis → zero ID).
func (l *Ledger) committedID(seq int64) types.BlockId {
	b := l.committed[types.SeqNum(seq)]
	if b == nil {
		return types.GENESIS_BLOCK_ID
	}
	return b.GetId()
}

// getHeaders / getPayload — blocksync self-fetch over the local block store
// (same semantics as MockLedger: proposed+voted+finalized blocks all serve).
func (l *Ledger) getHeaders(blockRange cstypes.BlockRange) blocksync.ResponseMessage {
	nextID := blockRange.LastBlockId
	var headers []cstypes.ConsensusBlockHeader
	for uint64(len(headers)) < blockRange.NumBlocks.Uint64() {
		if nextID == types.GENESIS_BLOCK_ID {
			break // chain terminus — no stored genesis block
		}
		block, ok := l.blocks[nextID]
		if !ok {
			return blocksync.ResponseHeadersNotAvailable(blockRange)
		}
		headers = append([]cstypes.ConsensusBlockHeader{block.Header}, headers...)
		nextID = block.Header.GetParentId()
	}
	if len(headers) == 0 {
		return blocksync.ResponseHeadersNotAvailable(blockRange)
	}
	return blocksync.ResponseHeaders(blockRange, headers)
}

func (l *Ledger) getPayload(payloadID cstypes.ConsensusBlockBodyId) blocksync.ResponseMessage {
	for _, fullBlock := range l.blocks {
		if fullBlock.GetBodyId() == payloadID {
			return blocksync.ResponsePayload(fullBlock.Body)
		}
	}
	return blocksync.ResponsePayloadNotAvailable(payloadID)
}

// Ready / Next — EventSource.
func (l *Ledger) Ready() bool { return len(l.events) > 0 }
func (l *Ledger) Next() glue.MonadEvent {
	if len(l.events) == 0 {
		return nil
	}
	ev := l.events[0]
	l.events = l.events[1:]
	return ev
}

// GetFinalizedBlocks / FinalizedBlocksLen — swarm verifier seam.
func (l *Ledger) GetFinalizedBlocks() []swarm.FinalizedBlock {
	out := make([]swarm.FinalizedBlock, 0, len(l.committed))
	for seq, b := range l.committed {
		out = append(out, swarm.FinalizedBlock{SeqNum: seq, Block: b})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SeqNum < out[j].SeqNum })
	return out
}

func (l *Ledger) FinalizedBlocksLen() int { return len(l.committed) }
