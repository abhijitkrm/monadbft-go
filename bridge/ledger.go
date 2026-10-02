package bridge

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/abhijitkrm/monadbft-go/blocksync"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/store"
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

	// mu guards the block maps for external readers (RPC server runs off
	// the node loop); Exec holds it for the whole batch — all map writes
	// happen inside Exec.
	mu sync.RWMutex

	blocks    map[types.BlockId]*cstypes.ConsensusFullBlock // proposed+voted+finalized
	committed map[types.SeqNum]*cstypes.ConsensusFullBlock  // finalized, in seq order

	// pendingSpec — blocks awaiting speculative execution. A commit event
	// can arrive before the spec frontier reaches the block's parent (a
	// proposed block may be coherent before its parent is canonically
	// committed), so submits retry on later commits until they chain or
	// canonicalize.
	pendingSpec map[types.BlockId]*cstypes.ConsensusFullBlock

	events []glue.MonadEvent // queued EvBlockSyncSelfResponse

	bs *store.BlockStore // durable block persistence; nil until AttachBlockStore

	// commitHook — optional per-commit callback (engine event publication).
	// Runs after l.mu is released (the hook reads back through the ledger).
	commitHook   func(seq int64)
	pendingHooks []int64
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

// AttachBlockStore wires durable persistence: persists every observed block
// and the finalized index, and rebuilds the in-memory block maps from what
// was persisted (restart path). Call before the node starts.
func (l *Ledger) AttachBlockStore(bs *store.BlockStore) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bs = bs
	all, err := bs.AllBlocks()
	if err != nil {
		return fmt.Errorf("bridge: load blocks: %w", err)
	}
	for _, b := range all {
		l.blocks[b.GetId()] = b
	}
	fin, err := bs.FinalizedBlocks()
	if err != nil {
		return fmt.Errorf("bridge: load finalized: %w", err)
	}
	for _, b := range fin {
		l.blocks[b.GetId()] = b
		l.committed[b.GetSeqNum()] = b
	}
	// The app's result index records the exact winner per committed height
	// (written post-app-commit); prefer it over the fin/ index, which a
	// crash can leave one commit behind.
	for h := int64(1); h <= l.app.committedHeight(); h++ {
		if _, bid, _, _, _, _, ok := l.app.CommittedEntry(h); ok {
			if b := l.blocks[bid]; b != nil {
				l.committed[b.GetSeqNum()] = b
			}
		}
	}
	return nil
}

// SetCommitHook registers the per-commit callback (engine event bus).
func (l *Ledger) SetCommitHook(fn func(seq int64)) { l.commitHook = fn }

// persistBlock — durable write of an observed block (idempotent on id).
// A failed write means a later finalized commit can reference a lost
// ancestor — unrecoverable, so it's fatal.
func (l *Ledger) persistBlock(b *cstypes.ConsensusFullBlock) {
	if l.bs == nil {
		return
	}
	id := b.GetId()
	if err := l.bs.PutBlock(b); err != nil {
		panic(fmt.Sprintf("bridge: persist block %x seq %d: %v",
			id[:8], b.GetSeqNum(), err))
	}
}

// Exec — LedgerCommand dispatch (mirrors MockLedger, Finalized executes).
func (l *Ledger) Exec(cmds []glue.LedgerCommand) {
	l.mu.Lock()
	l.execLocked(cmds)
	l.mu.Unlock()
	l.runCommitHooks()
}

func (l *Ledger) execLocked(cmds []glue.LedgerCommand) {
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.LedgerCommit:
			switch c.Commit.Kind {
			case glue.CommitProposed, glue.CommitVoted:
				l.blocks[c.Commit.Block.GetId()] = c.Commit.Block
				l.persistBlock(c.Commit.Block)
				l.speculate(c.Commit.Block)
			case glue.CommitFinalized:
				l.blocks[c.Commit.Block.GetId()] = c.Commit.Block
				l.persistBlock(c.Commit.Block)
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
	var txResults []*abcitypes.ExecTxResult
	var events []abcitypes.Event
	if l.spec != nil {
		appHash, updates, txResults, events, ok = l.spec.CommittedResult(seq, blockID, l.committedID)
		if !ok {
			appHash = nil
		}
	}
	if appHash == nil {
		appHash, updates, txResults, events = l.finalizeDirect(block, body)
	}
	l.recordCommitted(block, appHash, updates, txResults, events)
}

// finalizeDirect — synchronous FinalizeBlock+Commit for one block (opMu
// serializes the store-touching pair against the spec worker).
func (l *Ledger) finalizeDirect(block *cstypes.ConsensusFullBlock, body *EvmBody) ([]byte, []abcitypes.ValidatorUpdate, []*abcitypes.ExecTxResult, []abcitypes.Event) {
	h := block.Header
	seq := int64(h.SeqNum.Uint64())
	l.app.opMu.Lock()
	defer l.app.opMu.Unlock()
	res, err := l.app.FinalizeBlock(context.Background(), l.finalizeRequest(h, body.Txs))
	if err != nil {
		panic(fmt.Sprintf("bridge: FinalizeBlock h=%d: %v", seq, err))
	}
	if err := l.app.Commit(context.Background()); err != nil {
		panic(fmt.Sprintf("bridge: Commit h=%d: %v", seq, err))
	}
	return res.AppHash, res.ValidatorUpdates, res.TxResults, res.Events
}

// recordCommitted — canonical bookkeeping after a block commits.
func (l *Ledger) recordCommitted(block *cstypes.ConsensusFullBlock, appHash []byte, updates []abcitypes.ValidatorUpdate,
	txResults []*abcitypes.ExecTxResult, events []abcitypes.Event) {
	h := block.Header
	body := block.Body.Inner.ExecutionBody.(*EvmBody)
	l.app.recordCommit(int64(h.SeqNum.Uint64()), resultEntry{
		header:     &EvmFinalizedHeader{Number: h.SeqNum, AppHash: appHash},
		blockID:    h.GetId(),
		txs:        body.Txs,
		txResults:  txResults,
		events:     events,
		valUpdates: updates,
	})
	l.committed[h.SeqNum] = block
	if l.commitHook != nil {
		l.pendingHooks = append(l.pendingHooks, int64(h.SeqNum.Uint64()))
	}
	if l.bs != nil {
		if err := l.bs.PutFinalized(h.SeqNum, h.GetId()); err != nil {
			panic(fmt.Sprintf("bridge: persist finalized %d: %v", h.SeqNum, err))
		}
	}
	if err := l.app.applyUpdates(int64(h.SeqNum.Uint64()), updates); err != nil {
		panic(err)
	}
}

// applySyncedBlock — replay one statesync-served block through the direct
// commit path. Spec consultation is deliberately skipped: during a sync the
// spec index holds the stale pre-sync lineage, and treating the canonical
// replay as an "orphan" would roll back the just-synced store. The spec
// frontier is re-anchored wholesale via SpecApp.ResetToHeight at DoneSync.
func (l *Ledger) applySyncedBlock(block *cstypes.ConsensusFullBlock) {
	l.mu.Lock()
	l.applySyncedBlockLocked(block)
	l.mu.Unlock()
	l.runCommitHooks()
}

func (l *Ledger) applySyncedBlockLocked(block *cstypes.ConsensusFullBlock) {
	seq := int64(block.GetSeqNum().Uint64())
	if seq <= l.app.committedHeight() {
		return
	}
	l.blocks[block.GetId()] = block
	body, ok := block.Body.Inner.ExecutionBody.(*EvmBody)
	if !ok {
		panic(fmt.Sprintf("bridge: synced block seq %d unexpected body %T",
			seq, block.Body.Inner.ExecutionBody))
	}
	if height := l.app.committedHeight(); seq != height+1 {
		panic(fmt.Sprintf("bridge: synced block seq %d at height %d — gaps", seq, height))
	}
	appHash, updates, txResults, events := l.finalizeDirect(block, body)
	l.recordCommitted(block, appHash, updates, txResults, events)
}

// committedBlock — canonical finalized block at seq (statesync serving).
func (l *Ledger) committedBlock(seq types.SeqNum) *cstypes.ConsensusFullBlock {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.committed[seq]
}

// committedBlockByID — canonical block lookup by ID (RPC /block_by_hash).
func (l *Ledger) committedBlockByID(id types.BlockId) *cstypes.ConsensusFullBlock {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, b := range l.committed {
		if b.GetId() == id {
			return b
		}
	}
	return nil
}

// committedSeq — highest committed seq (statesync service window).
func (l *Ledger) committedSeq() types.SeqNum {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var max types.SeqNum
	for seq := range l.committed {
		if seq > max {
			max = seq
		}
	}
	return max
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

// runCommitHooks — drain queued commit seqs and invoke the hook outside
// l.mu (the hook calls back into ledger/app read paths).
func (l *Ledger) runCommitHooks() {
	l.mu.Lock()
	hooks := l.pendingHooks
	l.pendingHooks = nil
	hook := l.commitHook
	l.mu.Unlock()
	for _, seq := range hooks {
		hook(seq)
	}
}
