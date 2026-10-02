package bridge

import (
	"context"
	"fmt"
	"sync"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/evm/evmd"
)

// SpecApp — a shadow evmd instance that executes FinalizeBlock for
// consensus-blocks whose commitment hasn't landed yet. This is the bridge's
// implementation of MonadBFT's deferred-execution primitive: with
// execution_delay>0 a proposal at seq N embeds the execution results of seq
// N-delay, so results must be computed before the canonical FinalizeBlock
// runs them.
//
// Rather than branching app.cms in place (SDK BaseApp couples execModeFinalize
// to a single slot + unexported internals — the seam PORTING-PLAN WS-4b calls
// out as requiring an SDK patch), SpecApp is a second app instance over its
// own in-memory store. The FinalizeBlock request is fully determined by the
// consensus block (txs, height, time, proposer, commit votes, hash) so the
// shadow produces byte-identical results; on an orphaned branch the shadow
// rewinds via LoadVersion and re-executes the winning lineage.
//
// All methods are serialized on an internal mutex; the node loop calls into
// it only from the executor seam.
type SpecApp struct {
	*App
	raw  *evmd.EVMD
	cfg  EvmdConfig
	vals []Validator

	mu      sync.Mutex
	tip     int64            // shadow's committed height (== last spec seq)
	lastID  [32]byte         // block ID of the spec tip (orphan detection)
	results map[int64][]byte // height → AppHash of the spec-executed block
}

// NewSpecApp — shadow instance sharing cfg/vals; InitChain'd identically so
// genesis state (and thus all heights' execution) matches the canonical app.
func NewSpecApp(cfg EvmdConfig, vals []Validator) (*SpecApp, error) {
	app, raw, err := NewEvmdApp(cfg, vals)
	if err != nil {
		return nil, err
	}
	return &SpecApp{
		App:     app,
		raw:     raw,
		cfg:     cfg,
		vals:    vals,
		results: map[int64][]byte{},
	}, nil
}

// SpecFinalize — execute req on the shadow at its current tip; the request
// must be the same FinalizeBlock request the canonical path will build for
// this consensus block. Returns the resulting AppHash.
//
// If req.Height doesn't chain onto the shadow tip the caller must Rewind
// first — SpecFinalize errors rather than guessing.
func (s *SpecApp) SpecFinalize(ctx context.Context, req *abcitypes.RequestFinalizeBlock) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.Height != s.tip+1 {
		return nil, fmt.Errorf("bridge: spec finalize height %d after tip %d", req.Height, s.tip)
	}
	res, err := s.App.FinalizeBlock(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("bridge: spec FinalizeBlock h=%d: %w", req.Height, err)
	}
	if err := s.App.Commit(ctx); err != nil {
		return nil, fmt.Errorf("bridge: spec Commit h=%d: %w", req.Height, err)
	}
	s.tip = req.Height
	copy(s.lastID[:], req.Hash)
	s.results[req.Height] = res.AppHash
	return res.AppHash, nil
}

// SpecResult — the shadow's result for height h, if executed.
func (s *SpecApp) SpecResult(h int64) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[h]
	return r, ok
}

// SpecTip — shadow's committed spec height.
func (s *SpecApp) SpecTip() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tip
}

// Rewind — discard all spec heights above h and roll the shadow store back
// to h (rootmulti RollbackToVersion: IAVL LoadVersionForOverwriting removes
// versions > target). h must have been spec-executed (or 0 = genesis, which
// rebuilds the shadow — orphan-at-height-1 is rare enough to pay the cost).
func (s *SpecApp) Rewind(h int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h > s.tip {
		return fmt.Errorf("bridge: rewind target %d above tip %d", h, s.tip)
	}
	if h == 0 {
		app, raw, err := NewEvmdApp(s.cfg, s.vals)
		if err != nil {
			return fmt.Errorf("bridge: spec rebuild: %w", err)
		}
		s.App, s.raw = app, raw
		s.tip, s.results = 0, map[int64][]byte{}
		return nil
	}
	if _, ok := s.results[h]; !ok {
		return fmt.Errorf("bridge: rewind target %d never spec-executed", h)
	}
	rms, ok := s.raw.CommitMultiStore().(interface {
		RollbackToVersion(int64) error
	})
	if !ok {
		return fmt.Errorf("bridge: shadow store %T cannot rollback", s.raw.CommitMultiStore())
	}
	if err := rms.RollbackToVersion(h); err != nil {
		return fmt.Errorf("bridge: spec rewind to %d: %w", h, err)
	}
	for k := range s.results {
		if k > h {
			delete(s.results, k)
		}
	}
	s.tip = h
	return nil
}
