package bridge

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmttypes "github.com/cometbft/cometbft/types"

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

	// Block lookup indexes — the maps above are bounded to a retention
	// window around the committed tip; older seqs resolve through bs.
	committedByID map[types.BlockId]types.SeqNum   // committed id → seq
	maxCommitted  types.SeqNum                     // O(1) committedSeq
	certifiers    map[types.BlockId]certifierEntry // certified id → best QC
	retain        types.SeqNum                     // mem window; 0 = all
	pruneKeep     types.SeqNum                     // disk retention; 0 = all

	// lastPrune — last tip the disk pruner ran at (amortized every 512).
	lastPrune types.SeqNum

	// specInFlight — blockIDs with a job queued on the spec worker. Kept
	// separate from pendingSpec: a queued job can still fail (chain check
	// raced by a canonical commit), and the worker's OnDone clears the flag
	// so the block becomes re-drainable. Deleting a pendingSpec entry only
	// once SpecResultID confirms — never on enqueue — closes the hole where
	// a lost job permanently froze the spec frontier.
	specInFlight map[types.BlockId]bool
	// pendingSpec — blocks awaiting speculative execution. A commit event
	// can arrive before the spec frontier reaches the block's parent (a
	// proposed block may be coherent before its parent is canonically
	// committed), so submits retry on later commits until they chain or
	// canonicalize.
	pendingSpec map[types.BlockId]*cstypes.ConsensusFullBlock

	events []glue.MonadEvent // queued EvBlockSyncSelfResponse

	// reqCaps — diagnostic ring of the last-canonical FinalizeBlock requests
	// per height, used by restart-replay tests to diff ABCI inputs across
	// nodes. Populated in finalizeDirect only.
	reqMu       sync.Mutex // guards reqCaps/reqCapsSpec (diag — own lock, not l.mu)
	reqCaps     map[int64]*abcitypes.RequestFinalizeBlock
	reqCapsSpec map[int64]*abcitypes.RequestFinalizeBlock

	bs *store.BlockStore // durable block persistence; nil until AttachBlockStore

	// commitHook — optional per-commit callback (engine event publication).
	// Runs after l.mu is released (the hook reads back through the ledger).
	commitHook   func(seq int64)
	pendingHooks []int64

	// commitQ feeds the canonical-commit worker: FinalizeBlock+Commit latency
	// must not serialize inside the node loop or proposal/vote timers starve.
	// FIFO preserves seq order; l.committed is marked at enqueue so readers
	// see the consensus-finalized chain even while the app commit is in
	// flight. close() drains the buffer before the worker exits.
	commitQ    chan *cstypes.ConsensusFullBlock
	commitWg   sync.WaitGroup
	commitOnce sync.Once
	commitDone chan struct{}
}

// certifierEntry — the lowest-round observed QC certifying a block id, with
// the certifying block's timestamp (synthesized commit for the tip height).
type certifierEntry struct {
	qc cstypes.QuorumCertificate
	ts types.U128
}

var _ swarm.Ledger = (*Ledger)(nil)

func NewLedger(app *App, spec *SpecApp) *Ledger {
	l := &Ledger{
		app:           app,
		spec:          spec,
		blocks:        map[types.BlockId]*cstypes.ConsensusFullBlock{},
		committed:     map[types.SeqNum]*cstypes.ConsensusFullBlock{},
		committedByID: map[types.BlockId]types.SeqNum{},
		certifiers:    map[types.BlockId]certifierEntry{},
		pendingSpec:   map[types.BlockId]*cstypes.ConsensusFullBlock{},
		specInFlight:  map[types.BlockId]bool{},
		commitQ:       make(chan *cstypes.ConsensusFullBlock, 1024),
		commitDone:    make(chan struct{}),
	}
	if spec != nil {
		spec.OnDone = l.onSpecDone
	}
	return l
}

// onSpecDone — spec worker finished a job (any outcome): release the
// in-flight mark and re-drive the pending queue. A successful job shows up
// via SpecResultID on the drain; a failed one gets re-submitted — either
// way the frontier can never be left waiting on a job that no longer exists.
func (l *Ledger) onSpecDone(blockID types.BlockId) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.specInFlight, blockID)
	l.drainSpec()
}

// SetRetain — bound the in-memory block maps to the last `keep` committed
// seqs; pruneKeep bounds the durable stores (0 = retain everything on disk).
func (l *Ledger) SetRetain(keep, pruneKeep types.SeqNum) {
	l.retain = keep
	l.pruneKeep = pruneKeep
}

// Close — drain the canonical-commit queue and stop the worker. Callers must
// guarantee no further Ledger/StateSync Exec calls first (the node loop owns
// both dispatch paths, so after Node.Stop it is safe).
func (l *Ledger) Close() {
	if l.commitQ == nil {
		return
	}
	l.commitOnce.Do(func() {}) // never started → nothing to drain
	select {
	case <-l.commitDone:
		return
	default:
	}
	close(l.commitQ)
	l.commitWg.Wait()
	close(l.commitDone)
}

// AttachBlockStore wires durable persistence: persists every observed block
// and the finalized index, and rebuilds the in-memory block maps from what
// was persisted (restart path). cp is the persisted forkpoint checkpoint
// (nil on a fresh chain) — its Root names the canonical committed tip, used
// to reconcile the crash window between app Commit and index writes.
func (l *Ledger) AttachBlockStore(bs *store.BlockStore, cp *cstypes.Checkpoint) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bs = bs
	// Bounded rebuild: the fin/ tip names the canonical committed height;
	// only the last `retain` seqs are materialized into memory — everything
	// older resolves through the store on demand (blocksync/RPC fallbacks).
	finTip, err := bs.FinalizedTip()
	if err != nil {
		return fmt.Errorf("bridge: load finalized tip: %w", err)
	}
	floor := types.SeqNum(0)
	if l.retain > 0 && finTip > l.retain {
		floor = finTip - l.retain + 1
	}
	all, err := bs.BlocksSince(floor)
	if err != nil {
		return fmt.Errorf("bridge: load blocks: %w", err)
	}
	for _, b := range all {
		l.indexBlock(b)
	}
	fin, err := bs.FinalizedSince(floor)
	if err != nil {
		return fmt.Errorf("bridge: load finalized: %w", err)
	}
	for _, b := range fin {
		l.indexBlock(b)
		l.markCommitted(b)
	}
	// The app's result index records the exact winner per committed height
	// (written post-app-commit); prefer it over the fin/ index, which a
	// crash can leave one commit behind. Only the recent window can diverge
	// (the gap is a few heights at most).
	appTip := l.app.committedHeight()
	lo := int64(1)
	if appTip > 64 {
		lo = appTip - 64
	}
	for h := lo; h <= appTip; h++ {
		if _, bid, _, _, _, _, ok := l.app.CommittedEntry(h); ok {
			if b := l.getBlock(bid); b != nil {
				l.markCommitted(b)
			}
		}
	}
	l.reconcileStoreTip(cp)
	return nil
}

// reconcileStoreTip — restore consistency between three stores after a kill:
// the app store (which spec commits run ahead), the result index (written
// post-commit, so it can lag), and the persisted forkpoint checkpoint (the
// authoritative canonical tip — consensus resumes there).
//
//   - store tip above the checkpoint root = speculative tail or
//     uncheckpointed commits: roll the store back to the root; consensus
//     re-finalizes anything real.
//   - checkpoint root above the index tip = tail commits lost to the
//     recordCommit write window: backfill index/finalized entries walking
//     the root's ancestry through the block index.
func (l *Ledger) reconcileStoreTip(cp *cstypes.Checkpoint) {
	idxTip := l.app.committedHeight()
	rootSeq := idxTip
	var rootID types.BlockId
	if cp != nil {
		rootID = cp.Root
		if root := l.getBlock(cp.Root); root != nil {
			rootSeq = int64(root.GetSeqNum().Uint64())
		}
	}
	if idxTip > rootSeq {
		l.app.truncateIndex(rootSeq)
		idxTip = rootSeq
	}
	if tip := l.app.StoreTip(); tip > rootSeq && rootSeq > 0 {
		if err := l.app.RollbackTo(rootSeq); err != nil {
			panic(fmt.Sprintf("bridge: rollback to forkpoint %d: %v", rootSeq, err))
		}
	}
	// Re-anchor the spec frontier at the canonical tip: restart leaves the
	// spec index empty and its tip tracking at zero, so without this every
	// SpecFinalize fails chaining and delayed-execution results never
	// materialize — consensus stalls proposing.
	if l.spec != nil && rootSeq > 0 {
		l.spec.ResetToHeight(rootSeq, rootID)
	}
	if rootSeq <= idxTip {
		return
	}
	// Collect the winning blocks for (idxTip, rootSeq] walking back from
	// the forkpoint root.
	var gap []*cstypes.ConsensusFullBlock
	for id := cp.Root; ; {
		b := l.getBlock(id)
		if b == nil {
			break
		}
		seq := int64(b.GetSeqNum().Uint64())
		if seq <= idxTip {
			break
		}
		gap = append(gap, b)
		id = b.Header.GetParentId()
	}
	if len(gap) == 0 || int64(gap[0].GetSeqNum().Uint64()) != rootSeq {
		// Winners unavailable — committedHeight() still reports the index
		// tip, so the ledger re-finalizes from there and recordCommit
		// overwrites; only the interim RPC surface is incomplete.
		return
	}
	for i := len(gap) - 1; i >= 0; i-- {
		b := gap[i]
		h := b.Header
		seq := int64(h.SeqNum.Uint64())
		body, ok := b.Body.Inner.ExecutionBody.(*EvmBody)
		if !ok {
			continue
		}
		l.app.recordCommit(seq, resultEntry{
			header:  &EvmFinalizedHeader{Number: h.SeqNum, AppHash: l.app.StoreAppHash(seq)},
			blockID: h.GetId(),
			txs:     body.Txs,
		})
		l.markCommitted(b)
		l.app.fillValSetGap(seq)
		if err := l.bs.PutFinalized(h.SeqNum, h.GetId()); err != nil {
			if errors.Is(err, store.ErrClosed) {
				return
			}
			panic(fmt.Sprintf("bridge: persist reconciled finalized %d: %v", seq, err))
		}
	}
}

// SetCommitHook registers the per-commit callback (engine event bus).
func (l *Ledger) SetCommitHook(fn func(seq int64)) {
	l.mu.Lock()
	l.commitHook = fn
	l.mu.Unlock()
}

// persistBlock — durable write of an observed block (idempotent on id).
// A failed write means a later finalized commit can reference a lost
// ancestor — unrecoverable, so it's fatal.
func (l *Ledger) persistBlock(b *cstypes.ConsensusFullBlock) {
	if l.bs == nil {
		return
	}
	id := b.GetId()
	if err := l.bs.PutBlock(b); err != nil {
		if errors.Is(err, store.ErrClosed) {
			return // store closed mid-shutdown; index self-heals on reopen
		}
		panic(fmt.Sprintf("bridge: persist block %x seq %d: %v",
			id[:8], b.GetSeqNum(), err))
	}
}

// insertBlock — record an observed block: memory index, certifier index
// (its header QC certifies the parent — used to serve tip-height commits
// before the certifier itself is committed), and the durable store.
// Callers must hold l.mu.
func (l *Ledger) insertBlock(b *cstypes.ConsensusFullBlock) {
	l.indexBlock(b)
	l.persistBlock(b)
}

// indexBlock — memory indexes only (AttachBlockStore rebuild: the blocks
// came from the store, so re-persisting is wasted fsyncs).
func (l *Ledger) indexBlock(b *cstypes.ConsensusFullBlock) {
	id := b.GetId()
	l.blocks[id] = b
	qc := b.Header.QC
	if parent := qc.GetBlockId(); parent != types.GENESIS_BLOCK_ID {
		if cur, ok := l.certifiers[parent]; !ok || qc.Info.Round < cur.qc.Info.Round {
			l.certifiers[parent] = certifierEntry{qc: qc, ts: b.Header.TimestampNs}
		}
	}
}

// markCommitted — index a block as the canonical committed block at its
// seq (memory maps; durable fin/ row is written by the commit worker).
// Callers must hold l.mu.
func (l *Ledger) markCommitted(b *cstypes.ConsensusFullBlock) {
	seq := b.GetSeqNum()
	l.committed[seq] = b
	l.committedByID[b.GetId()] = seq
	if seq > l.maxCommitted {
		l.maxCommitted = seq
	}
}

// getBlock — in-memory first, then the durable store (below-floor serving).
// Callers must hold l.mu.
func (l *Ledger) getBlock(id types.BlockId) *cstypes.ConsensusFullBlock {
	if b := l.blocks[id]; b != nil {
		return b
	}
	if l.bs != nil {
		if b, err := l.bs.GetBlock(id); err == nil {
			return b
		}
	}
	return nil
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
				l.insertBlock(c.Commit.Block)
				l.speculate(c.Commit.Block)
			case glue.CommitFinalized:
				l.insertBlock(c.Commit.Block)
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
		par := l.getBlock(b.GetParentId())
		if par == nil {
			// ancestor not yet seen — the commit chain is contiguous by
			// consensus construction, so this only happens if the parent was
			// never persisted; treat as an invariant violation.
			panic(fmt.Sprintf("bridge: finalized block seq %d missing parent", seq.Uint64()))
		}
		b = par
	}
	// enqueue oldest → newest; marking committed at enqueue keeps later
	// walks from re-queuing and lets self-blocksync/header readers see the
	// canonical chain while app-commit is still in flight on the worker.
	for i := len(pending) - 1; i >= 0; i-- {
		b := pending[i]
		if _, done := l.committed[b.GetSeqNum()]; done {
			continue
		}
		l.markCommitted(b)
		l.commitOnce.Do(func() {
			l.commitWg.Add(1)
			go l.commitLoop()
		})
		l.commitQ <- b
	}
	l.drainSpec()
}

// commitLoop — the canonical-commit worker: applies each finalized block to
// the app (opMu-serialized against the spec worker) and records the result,
// off the node loop so consensus timers are never blocked by app latency.
func (l *Ledger) commitLoop() {
	defer l.commitWg.Done()
	for b := range l.commitQ {
		l.execCanonical(b)
	}
}

// execCanonical — worker-side apply of one finalized block: spec-result
// reuse when the spec frontier already executed this exact block, else a
// direct FinalizeBlock+Commit. Lock discipline: l.mu and app.opMu are never
// held together — bookkeeping takes l.mu briefly; store commits take opMu.
func (l *Ledger) execCanonical(block *cstypes.ConsensusFullBlock) {
	h := block.Header
	seq := int64(h.SeqNum.Uint64())
	if seq <= l.app.committedHeight() {
		return // already applied (restart re-emit or duplicate)
	}
	if height := l.app.committedHeight(); height != 0 && seq != height+1 {
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
		l.mu.Lock()
		parent := l.committedID(seq - 1)
		l.mu.Unlock()
		a, u, t, e, hit := l.spec.CommittedResult(seq, blockID,
			func(int64) types.BlockId { return parent })
		if hit {
			appHash, updates, txResults, events = a, u, t, e
		}
	}
	if appHash == nil {
		appHash, updates, txResults, events = l.finalizeDirect(block, body)
	}
	l.mu.Lock()
	l.recordCommitted(block, appHash, updates, txResults, events)
	l.drainSpec()
	l.mu.Unlock()
	l.runCommitHooks()
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
			delete(l.specInFlight, blockID)
			continue
		}
		if _, _, _, ok := l.spec.SpecResultID(blockID); ok {
			delete(l.pendingSpec, blockID)
			delete(l.specInFlight, blockID)
			continue
		}
		if l.specInFlight[blockID] {
			continue // job already on the worker — OnDone re-drives us
		}
		if !l.spec.WouldChain(seq, h.GetParentId()) {
			continue // can't chain at the current tip — retry on next drain
		}
		body, ok := b.Body.Inner.ExecutionBody.(*EvmBody)
		if !ok {
			delete(l.pendingSpec, blockID)
			continue
		}
		votesSet, nextSet := l.finalizeSets(seq, l.spec)
		if votesSet == nil || nextSet == nil {
			continue // sets not resolvable yet — retry on the next drain
		}
		req := l.finalizeRequest(h, body.Txs, votesSet, nextSet)
		l.reqMu.Lock()
		if l.reqCapsSpec == nil {
			l.reqCapsSpec = map[int64]*abcitypes.RequestFinalizeBlock{}
		}
		l.reqCapsSpec[seq] = req
		for old := range l.reqCapsSpec { // bounded diagnostic window
			if old < seq-256 {
				delete(l.reqCapsSpec, old)
			}
		}
		l.reqMu.Unlock()
		_, err := l.spec.SpecFinalize(context.Background(), req, blockID, h.GetParentId())
		switch {
		case err == nil:
			// accepted by the async worker (or executed inline, in which
			// case the SpecResultID check above confirms it next drain).
			// Keep the entry pending — deleting here was the lost-job bug.
			l.specInFlight[blockID] = true
		case errors.Is(err, ErrSpecNotChaining), errors.Is(err, ErrSpecQueueFull):
			// parent not spec'd yet, or worker busy — retry on next drain
		default:
			// genuine execution error — drop; canonical finalize re-surfaces it
			delete(l.pendingSpec, blockID)
		}
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
		delete(l.specInFlight, lowest)
	}
}

// finalizeRequest — the deterministic ABCI request for one consensus block
// (identical for spec and canonical execution — that equality is what makes
// delayed_execution_results verifiable).
//
// votesSet/nextSet must resolve the app validator set at the block's own
// height, not the mutable tip: DecidedLastCommit is indexed by the set that
// validated the parent (valSets[seq-2]), NextValidatorsHash by the set
// validating this block (valSets[seq-1]). Callers pass the committed-side
// ValSetAt or the spec lineage's valSetAfter — both resolve identically
// for the same canonical height.
func (l *Ledger) finalizeRequest(h cstypes.ConsensusBlockHeader, txs [][]byte,
	votesSet, nextSet *cmttypes.ValidatorSet) *abcitypes.RequestFinalizeBlock {
	blockID := h.GetId()
	var nvHash []byte
	if nextSet != nil {
		nvHash = nextSet.Hash()
	}
	return &abcitypes.RequestFinalizeBlock{
		Txs:                txs,
		Height:             int64(h.SeqNum.Uint64()),
		Time:               time.Unix(0, int64(h.TimestampNs.Uint64())),
		ProposerAddress:    l.app.ConsAddr(h.Author),
		DecidedLastCommit:  l.app.LastCommitWith(h.QC, votesSet),
		Hash:               blockID[:],
		NextValidatorsHash: nvHash,
	}
}

// finalizeSets — the height-scoped validator sets for a request at seq:
// the set that validated seq-1 (QC signers, DecidedLastCommit) and the set
// validating seq (NextValidatorsHash). Canonical commits resolve from the
// app's valSets; spec resolves across the canonical↔spec boundary via the
// spec lineage's fold.
func (l *Ledger) finalizeSets(seq int64, spec *SpecApp) (votesSet, nextSet *cmttypes.ValidatorSet) {
	if spec != nil {
		return spec.valSetAfter(seq - 2), spec.valSetAfter(seq - 1)
	}
	return l.app.ValSetAt(seq - 1), l.app.ValSetAt(seq)
}

// finalizeDirect — synchronous FinalizeBlock+Commit for one block (opMu
// serializes the store-touching pair against the spec worker).
func (l *Ledger) finalizeDirect(block *cstypes.ConsensusFullBlock, body *EvmBody) ([]byte, []abcitypes.ValidatorUpdate, []*abcitypes.ExecTxResult, []abcitypes.Event) {
	h := block.Header
	seq := int64(h.SeqNum.Uint64())
	l.app.opMu.Lock()
	defer l.app.opMu.Unlock()
	votesSet, nextSet := l.finalizeSets(seq, l.spec)
	req := l.finalizeRequest(h, body.Txs, votesSet, nextSet)
	l.reqMu.Lock()
	if l.reqCaps == nil {
		l.reqCaps = map[int64]*abcitypes.RequestFinalizeBlock{}
	}
	l.reqCaps[seq] = req
	for old := range l.reqCaps { // bounded diagnostic window
		if old < seq-256 {
			delete(l.reqCaps, old)
		}
	}
	l.reqMu.Unlock()
	res, err := l.app.FinalizeBlock(context.Background(), req)
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
	seq := int64(h.SeqNum.Uint64())
	body := block.Body.Inner.ExecutionBody.(*EvmBody)
	l.app.recordCommit(seq, resultEntry{
		header:     &EvmFinalizedHeader{Number: h.SeqNum, AppHash: appHash},
		blockID:    h.GetId(),
		txs:        body.Txs,
		txResults:  txResults,
		events:     events,
		valUpdates: updates,
	})
	l.markCommitted(block)
	// Index the synthesized comet hash once per commit (post-applyUpdates so
	// nextValidatorsHash is final) — block_by_hash stays O(1).
	if l.commitHook != nil {
		l.pendingHooks = append(l.pendingHooks, int64(h.SeqNum.Uint64()))
	}
	if l.bs != nil {
		if err := l.bs.PutFinalized(h.SeqNum, h.GetId()); err != nil {
			if errors.Is(err, store.ErrClosed) {
				return // shutdown raced the commit worker; app already committed
			}
			panic(fmt.Sprintf("bridge: persist finalized %d: %v", h.SeqNum, err))
		}
	}
	if err := l.app.applyUpdates(seq, updates); err != nil {
		panic(err)
	}
	hdr := l.app.synthHeader(block)
	l.app.RecordCmtHash(hdr.Hash(), seq)
	l.pruneLocked(h.SeqNum)
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
	l.insertBlock(block)
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

// pruneLocked — drop in-memory map entries below tip-retain (they stay
// durable in the store; readers fall back). Optional disk pruning runs
// every 512 commits when pruneKeep is set. Callers must hold l.mu.
func (l *Ledger) pruneLocked(tip types.SeqNum) {
	if l.retain > 0 && tip > l.retain {
		floor := tip - l.retain
		for id, b := range l.blocks {
			if b.GetSeqNum() < floor {
				delete(l.blocks, id)
				delete(l.certifiers, id)
			}
		}
		for seq, b := range l.committed {
			if seq < floor {
				delete(l.committed, seq)
				delete(l.committedByID, b.GetId())
			}
		}
	}
	if l.pruneKeep > 0 && l.bs != nil &&
		tip > l.pruneKeep+l.retain && tip-l.lastPrune >= 512 {
		l.lastPrune = tip
		cutoff := tip - l.pruneKeep
		if err := l.bs.PruneBelow(cutoff); err != nil && !errors.Is(err, store.ErrClosed) {
			panic(fmt.Sprintf("bridge: prune blockstore below %d: %v", cutoff, err))
		}
		if a := l.app; a.store != nil {
			if err := a.store.PruneBefore(int64(cutoff)); err != nil {
				panic(fmt.Sprintf("bridge: prune result store below %d: %v", cutoff, err))
			}
		}
	}
}

// committedBlock — canonical finalized block at seq (statesync serving).
// In-memory window first, then the durable fin/ index.
func (l *Ledger) committedBlock(seq types.SeqNum) *cstypes.ConsensusFullBlock {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if b := l.committed[seq]; b != nil {
		return b
	}
	if l.bs != nil {
		if b, err := l.bs.GetFinalized(seq); err == nil {
			return b
		}
	}
	return nil
}

// committedBlockByID — canonical block lookup by ID (RPC /block_by_hash):
// O(1) via committedByID, store fallback for below-window heights.
func (l *Ledger) committedBlockByID(id types.BlockId) *cstypes.ConsensusFullBlock {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if seq, ok := l.committedByID[id]; ok {
		return l.committed[seq]
	}
	if l.bs == nil {
		return nil
	}
	b, err := l.bs.GetBlock(id)
	if err != nil || b == nil {
		return nil
	}
	fid, ok, err := l.bs.GetFinalizedID(b.GetSeqNum())
	if err != nil || !ok || fid != id {
		return nil
	}
	return b
}

// certifierQC — an observed (proposed/voted/committed) child block whose
// header QC certifies (seq, id): lets Commit serve the tip height before
// the certifying block is itself committed. Deterministic: lowest round,
// maintained incrementally in the certifiers index.
func (l *Ledger) certifierQC(id types.BlockId) (cstypes.QuorumCertificate, types.U128, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if e, ok := l.certifiers[id]; ok {
		return e.qc, e.ts, true
	}
	// Below the window the certifier is the committed successor's QC.
	if l.bs == nil {
		return cstypes.QuorumCertificate{}, types.U128{}, false
	}
	b, err := l.bs.GetBlock(id)
	if err != nil || b == nil {
		return cstypes.QuorumCertificate{}, types.U128{}, false
	}
	next, err := l.bs.GetFinalized(b.GetSeqNum() + 1)
	if err != nil || next == nil {
		return cstypes.QuorumCertificate{}, types.U128{}, false
	}
	return next.Header.QC, next.Header.TimestampNs, true
}

// committedSeq — highest committed seq (statesync service window).
func (l *Ledger) committedSeq() types.SeqNum {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.maxCommitted
}

// committedID — the canonical block ID at a committed seq (genesis → zero ID).
// Callers must hold l.mu.
func (l *Ledger) committedID(seq int64) types.BlockId {
	if b := l.committed[types.SeqNum(seq)]; b != nil {
		return b.GetId()
	}
	if l.bs != nil {
		if id, ok, err := l.bs.GetFinalizedID(types.SeqNum(seq)); err == nil && ok {
			return id
		}
	}
	return types.GENESIS_BLOCK_ID
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
		block := l.getBlock(nextID)
		if block == nil {
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
	if l.bs != nil {
		// pld/ index is O(1) — prefer it over the bounded in-memory scan.
		if body, err := l.bs.GetPayload(payloadID); err == nil && body != nil {
			return blocksync.ResponsePayload(*body)
		}
		return blocksync.ResponsePayloadNotAvailable(payloadID)
	}
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

// GetFinalizedBlocks / FinalizedBlocksLen — swarm verifier seam. Called
// from harness goroutines, so read under l.mu like the other accessors.
func (l *Ledger) GetFinalizedBlocks() []swarm.FinalizedBlock {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]swarm.FinalizedBlock, 0, len(l.committed))
	for seq, b := range l.committed {
		out = append(out, swarm.FinalizedBlock{SeqNum: seq, Block: b})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SeqNum < out[j].SeqNum })
	return out
}

func (l *Ledger) FinalizedBlocksLen() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.committed)
}

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
