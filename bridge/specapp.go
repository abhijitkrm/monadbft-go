package bridge

import (
	"context"
	"fmt"
	"sync"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/evm/evmd"

	"github.com/abhijitkrm/monadbft-go/types"
)

// SpecApp — speculative-execution bookkeeping over the canonical App: the
// block pipeline (FinalizeBlock+Commit) runs on the real app at
// proposal/QC-commit time — ahead of the ledger's 2-chain finalization — so
// `execution_delay>0` proposals can embed delayed_execution_results and the
// canonical commit path reuses the already-computed result instead of
// re-executing (the WS-4b "commit the pre-computed branch" shape).
//
// This design executes speculatively on the app's own store rather than a
// shadow instance or an SDK-internal branch: BaseApp's execModeFinalize seam
// can't host caller-chosen parents without an SDK patch, while the store's
// commit history is identical either way (proven byte-for-byte by the
// shadow-app variant in specapp_test).
//
//   - app.height / app.results stay ledger-canonical (only finalization
//     records them); the spec index is separate.
//   - CheckTx/ReapTxs/PrepareProposal run against the speculative tip —
//     mempool accounting actually improves (txs consumed by in-flight
//     blocks are no longer re-accepted).
//   - Orphaned spec lineages rewind the app store via
//     rootmulti.RollbackToVersion — never below the ledger's finalized
//     height (finalized heights are QC-safe by consensus).
//
// All methods are serialized on an internal mutex; the node loop drives it
// through the ledger executor seam.
type SpecApp struct {
	app *App
	raw *evmd.EVMD // for CommitMultiStore().RollbackToVersion

	mu    sync.Mutex
	tip   int64         // store's spec-executed height (≥ app.finalized height)
	tipID types.BlockId // block ID at the spec tip (lineage for orphans)
	bySeq map[int64]specEntry
	byID  map[types.BlockId]int64

	// valSets — the app validator set *after* each spec-executed height's
	// updates (same indexing as App.valSets: valSets[h] validates h+1).
	// DecidedLastCommit/NextValidatorsHash in a spec request must resolve
	// the set at the block's own height, not the committed tip's: validator
	// updates (jailing) applied between the tip and the spec depth
	// otherwise produce timing-dependent requests and divergent app hashes.
	valSets map[int64]*cmttypes.ValidatorSet

	// async worker (NewAsyncSpecApp): SpecFinalize submits run off the
	// caller's goroutine — FinalizeBlock is expensive enough to starve a
	// consensus loop. Nil jobs channel = synchronous mode.
	jobs      chan specJob
	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	// OnDone — invoked by the worker after every job completes (success or
	// failure). Lets the ledger re-drive its pending queue: a failed job is
	// retried on the next drain instead of leaving a permanent hole in the
	// spec frontier, which would stall delayed-execution lookups forever.
	OnDone func(blockID types.BlockId)
}

type specJob struct {
	req      *abcitypes.RequestFinalizeBlock
	blockID  types.BlockId
	parentID types.BlockId
}

// specEntry — one speculatively-executed block's durable outputs.
type specEntry struct {
	appHash   []byte
	updates   []abcitypes.ValidatorUpdate
	txResults []*abcitypes.ExecTxResult
	events    []abcitypes.Event
	blockID   types.BlockId
}

// NewSpecApp wraps an initialized app (InitChain'd, height 0 committed) in
// synchronous mode — SpecFinalize runs inline (the deterministic-swarm
// path). Returns nil when the app's raw isn't *evmd.EVMD — the rollback
// seam needs CommitMultiStore, so non-evmd apps run finalize-only.
func NewSpecApp(app *App) *SpecApp {
	return newSpecApp(app, false)
}

// NewAsyncSpecApp — SpecApp with a worker goroutine: SpecFinalize enqueues
// and returns immediately; results land in the spec index as the worker
// drains (FIFO — jobs recheck chaining at execution, so a gap skips that
// job but later jobs re-evaluate fresh).
func NewAsyncSpecApp(app *App) *SpecApp {
	s := newSpecApp(app, true)
	if s == nil {
		return nil
	}
	s.jobs = make(chan specJob, 256)
	s.stop = make(chan struct{})
	s.wg.Add(1)
	go s.loop()
	return s
}

func newSpecApp(app *App, _ bool) *SpecApp {
	raw := app.Raw()
	if raw == nil {
		return nil
	}
	return &SpecApp{
		app:     app,
		raw:     raw,
		bySeq:   map[int64]specEntry{},
		byID:    map[types.BlockId]int64{},
		valSets: map[int64]*cmttypes.ValidatorSet{},
	}
}

// Close — stop the async worker (drains pending jobs first, since they're
// ordered). Idempotent; no-op in sync mode.
func (s *SpecApp) Close() {
	if s.stop == nil {
		return
	}
	s.closeOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
	})
}

func (s *SpecApp) loop() {
	defer s.wg.Done()
	for {
		select {
		case j := <-s.jobs:
			s.runSpec(context.Background(), j.req, j.blockID, j.parentID)
			if s.OnDone != nil {
				s.OnDone(j.blockID)
			}
		case <-s.stop:
			for {
				select {
				case j := <-s.jobs:
					s.runSpec(context.Background(), j.req, j.blockID, j.parentID)
				default:
					return
				}
			}
		}
	}
}

// ErrSpecNotChaining — submitted block does not extend the spec tip (gap or
// fork); callers fall back to synchronous execution on finalization.
var ErrSpecNotChaining = fmt.Errorf("bridge: block does not chain onto spec tip")

// ErrSpecQueueFull — async SpecFinalize could not enqueue the job. Callers
// keep the block pending and retry on the next drain.
var ErrSpecQueueFull = fmt.Errorf("bridge: spec job queue full")

// SpecFinalize — execute req on the app at the spec tip. Must chain:
// height == tip+1 and parentID == tipID. Caller supplies the consensus block
// IDs (req.Hash is the block's own ID as the ledger already encodes). Async
// mode enqueues and returns nil immediately (result lands via the index).
func (s *SpecApp) SpecFinalize(ctx context.Context, req *abcitypes.RequestFinalizeBlock, blockID, parentID types.BlockId) ([]byte, error) {
	if s.jobs != nil {
		select {
		case s.jobs <- specJob{req, blockID, parentID}:
			return nil, nil
		default:
			return nil, ErrSpecQueueFull
		}
	}
	return s.runSpec(ctx, req, blockID, parentID)
}

func (s *SpecApp) runSpec(ctx context.Context, req *abcitypes.RequestFinalizeBlock, blockID, parentID types.BlockId) ([]byte, error) {
	// opMu serializes the store-touching call pair against the node loop's
	// PrepareProposal/CheckTx; mu guards the spec index.
	s.app.opMu.Lock()
	defer s.app.opMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.Height != s.tip+1 {
		if DebugSpec != nil {
			DebugSpec(blockID, req.Height, fmt.Errorf("h %d after tip %d", req.Height, s.tip))
		}
		return nil, fmt.Errorf("%w (height %d after tip %d)", ErrSpecNotChaining, req.Height, s.tip)
	}
	// tipID == GENESIS_BLOCK_ID (zero value) at the genesis tip, so the
	// equality check covers height-1 parenting without a special case.
	if parentID != s.tipID {
		if DebugSpec != nil {
			DebugSpec(blockID, req.Height, fmt.Errorf("parent %x vs tip %x", parentID[:4], s.tipID[:4]))
		}
		return nil, fmt.Errorf("%w (parent %x vs tip %x)", ErrSpecNotChaining, parentID[:4], s.tipID[:4])
	}
	// Revalidate against the live store tip: statesync replay advances the
	// canonical store behind the spec index's back, and a stale queued job
	// must not double-commit an old height.
	if storeTip := s.raw.LastBlockHeight(); req.Height != storeTip+1 {
		return nil, fmt.Errorf("%w (height %d after store tip %d)", ErrSpecNotChaining, req.Height, storeTip)
	}
	res, err := s.app.FinalizeBlock(ctx, req)
	if err != nil {
		if DebugSpec != nil {
			DebugSpec(blockID, req.Height, err)
		}
		return nil, fmt.Errorf("bridge: spec FinalizeBlock h=%d: %w", req.Height, err)
	}
	if err := s.app.Commit(ctx); err != nil {
		return nil, fmt.Errorf("bridge: spec Commit h=%d: %w", req.Height, err)
	}
	s.tip = req.Height
	s.tipID = blockID
	e := specEntry{appHash: res.AppHash, updates: res.ValidatorUpdates,
		txResults: res.TxResults, events: res.Events, blockID: blockID}
	s.bySeq[req.Height] = e
	s.byID[blockID] = req.Height
	if base := s.valSetAfterLocked(req.Height - 1); base != nil {
		if next, err := applyValUpdates(base, res.ValidatorUpdates); err == nil {
			s.valSets[req.Height] = next
		}
	}
	return res.AppHash, nil
}

// valSetAfter — the app validator set after height h's updates, resolved
// across the canonical↔spec boundary: h ≤ committed comes from the app's
// committed valSets, h > committed comes from the spec lineage's own fold.
func (s *SpecApp) valSetAfter(h int64) *cmttypes.ValidatorSet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.valSetAfterLocked(h)
}

func (s *SpecApp) valSetAfterLocked(h int64) *cmttypes.ValidatorSet {
	if h <= s.app.committedHeight() {
		return s.app.ValSetAt(h + 1)
	}
	return s.valSets[h]
}

// WouldChain — pre-flight chain check for the ledger's pending queue:
// a job can only execute when the spec tip is exactly seq-1 and parented by
// parentID. Submitting earlier only spins the worker (dequeue → reject →
// re-queue), starving chainable jobs behind it in the FIFO.
func (s *SpecApp) WouldChain(seq int64, parentID types.BlockId) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return seq == s.tip+1 && parentID == s.tipID
}

// SpecResultSeq — spec result at height h.
func (s *SpecApp) SpecResultSeq(h int64) (appHash []byte, updates []abcitypes.ValidatorUpdate, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.bySeq[h]
	return e.appHash, e.updates, ok
}

// SpecResultID — spec result keyed by consensus block ID (what StateRead's
// !isFinalized path and the ledger's commit fast-path query).
func (s *SpecApp) SpecResultID(blockID types.BlockId) (seq int64, appHash []byte, updates []abcitypes.ValidatorUpdate, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.byID[blockID]
	if !ok {
		return 0, nil, nil, false
	}
	e := s.bySeq[h]
	if e.blockID != blockID {
		// bySeq[h] was overwritten by a different block at this height (fork
		// lineage spec'd after this one) — the result for blockID is gone,
		// so report a miss rather than another block's appHash.
		delete(s.byID, blockID)
		return 0, nil, nil, false
	}
	return h, e.appHash, e.updates, true
}

// SpecTip — spec-executed height.
func (s *SpecApp) SpecTip() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tip
}

// CommittedResult — called by the ledger as each finalized block is
// canonicalized, in seq order. Returns the spec result when this exact
// block was spec-executed (the common path: store already holds it).
//
// If the spec tip carried a different block at this seq, the branch is
// orphaned — the store is rolled back to seq-1 (parentID supplies the
// canonical ID there) so the caller's synchronous FinalizeBlock replays the
// winner. Canonicalized entries ≤ seq are pruned from the spec index;
// app.results owns them from here.
// Lock order is always opMu → mu (the rewind path writes the store while
// the async worker may hold opMu mid-Commit).
func (s *SpecApp) CommittedResult(seq int64, blockID types.BlockId, parentID func(h int64) types.BlockId) ([]byte, []abcitypes.ValidatorUpdate, []*abcitypes.ExecTxResult, []abcitypes.Event, bool) {
	s.app.opMu.Lock()
	defer s.app.opMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, specd := s.bySeq[seq]
	if specd && e.blockID == blockID {
		// canonical winner == what we executed — prune ≤ seq, serve it.
		for h, pr := range s.bySeq {
			if h <= seq {
				delete(s.byID, pr.blockID)
				delete(s.bySeq, h)
				delete(s.valSets, h)
			}
		}
		return e.appHash, e.updates, e.txResults, e.events, true
	}
	if specd {
		if err := s.rewindLocked(seq-1, parentID(seq-1)); err != nil {
			panic(fmt.Sprintf("bridge: orphan rewind at seq %d: %v", seq, err))
		}
	}
	// The caller's synchronous commit will advance the store to seq — keep
	// the spec frontier in step so later SpecFinalize calls chain.
	if seq > s.tip {
		s.tip = seq
		s.tipID = blockID
	}
	for h, pr := range s.bySeq {
		if h <= seq {
			delete(s.byID, pr.blockID)
			delete(s.bySeq, h)
			delete(s.valSets, h)
		}
	}
	return nil, nil, nil, nil, false
}

// Rewind — discard spec heights above h and roll the store back
// (rootmulti.RollbackToVersion removes versions > target). h=0 (orphan at
// the first post-genesis height) is rejected: the canonical store cannot
// rebuild — that path is statesync's job.
func (s *SpecApp) Rewind(h int64) error {
	s.app.opMu.Lock()
	defer s.app.opMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if h > s.tip {
		return fmt.Errorf("bridge: rewind target %d above tip %d", h, s.tip)
	}
	if h == 0 {
		return fmt.Errorf("bridge: rewind to genesis requires statesync")
	}
	e, ok := s.bySeq[h]
	if !ok {
		return fmt.Errorf("bridge: rewind target %d never spec-executed", h)
	}
	return s.rewindLocked(h, e.blockID)
}

func (s *SpecApp) rewindLocked(h int64, tipID types.BlockId) error {
	if h == 0 {
		return fmt.Errorf("bridge: rewind to genesis requires statesync")
	}
	raw := s.app.Raw()
	rms, ok := raw.CommitMultiStore().(interface {
		RollbackToVersion(int64) error
	})
	if !ok {
		return fmt.Errorf("bridge: store %T cannot rollback", raw.CommitMultiStore())
	}
	// RollbackToVersion deletes versions > h — a query context built
	// concurrently can resolve LatestVersion ahead of the materialized
	// IAVL trees and hit ErrVersionDoesNotExist (the mempool rechecker
	// panic seen in soak). SpecLock serializes version deletion against
	// CreateQueryContext, which the mempool's ctx callback also holds.
	sl := raw.SpecLock()
	sl.Lock()
	err := rms.RollbackToVersion(h)
	sl.Unlock()
	if err != nil {
		return err
	}
	for seq, e := range s.bySeq {
		if seq > h {
			delete(s.byID, e.blockID)
			delete(s.bySeq, seq)
			delete(s.valSets, seq)
		}
	}
	s.tip = h
	s.tipID = tipID
	return nil
}

// ResetToHeight — re-anchor the spec frontier at a synced canonical tip.
// Statesync replay replaces the store with a canonical lineage that bears
// no relation to the pre-sync speculative branch: every spec entry is stale
// (keeping them would make CommittedResult treat canonical commits as
// orphans and roll back synced state). The caller supplies the canonical
// block ID at h so the next SpecFinalize chains correctly.
func (s *SpecApp) ResetToHeight(h int64, tipID types.BlockId) {
	// Drain queued jobs first — they were submitted against the stale
	// lineage and must not observe the reset tip.
	if s.jobs != nil {
	drain:
		for {
			select {
			case <-s.jobs:
			default:
				break drain
			}
		}
	}
	s.app.opMu.Lock()
	defer s.app.opMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bySeq = map[int64]specEntry{}
	s.byID = map[types.BlockId]int64{}
	s.valSets = map[int64]*cmttypes.ValidatorSet{}
	s.tip = h
	s.tipID = tipID
}

// DebugSpec — test-only hook for spec job outcomes (nil err = executed).
var DebugSpec func(blockID types.BlockId, seq int64, err error)
