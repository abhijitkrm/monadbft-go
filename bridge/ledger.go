package bridge

import (
	"context"
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
	app *App

	blocks    map[types.BlockId]*cstypes.ConsensusFullBlock // proposed+voted+finalized
	committed map[types.SeqNum]*cstypes.ConsensusFullBlock  // finalized, in seq order

	events []glue.MonadEvent // queued EvBlockSyncSelfResponse
}

var _ swarm.Ledger = (*Ledger)(nil)

func NewLedger(app *App) *Ledger {
	return &Ledger{
		app:       app,
		blocks:    map[types.BlockId]*cstypes.ConsensusFullBlock{},
		committed: map[types.SeqNum]*cstypes.ConsensusFullBlock{},
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
}

// finalizeOne — FinalizeBlock + Commit one consensus block through the app.
func (l *Ledger) finalizeOne(block *cstypes.ConsensusFullBlock) {
	h := block.Header
	seq := int64(h.SeqNum.Uint64())
	if seq <= l.app.height {
		return // already committed (e.g. re-emit after restart)
	}
	if l.app.height != 0 && seq != l.app.height+1 {
		panic(fmt.Sprintf("bridge: finalize height %d after %d — gaps", seq, l.app.height))
	}

	body, ok := block.Body.Inner.ExecutionBody.(*EvmBody)
	if !ok {
		panic(fmt.Sprintf("bridge: unexpected body type %T", block.Body.Inner.ExecutionBody))
	}
	blockID := h.GetId()

	res, err := l.app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
		Txs:                body.Txs,
		Height:             seq,
		Time:               time.Unix(0, int64(h.TimestampNs.Uint64())),
		ProposerAddress:    l.app.ConsAddr(h.Author),
		DecidedLastCommit:  l.app.LastCommit(h.QC),
		Hash:               blockID[:],
		NextValidatorsHash: l.app.ValidatorsHash(),
	})
	if err != nil {
		panic(fmt.Sprintf("bridge: FinalizeBlock h=%d: %v", seq, err))
	}
	if err := l.app.Commit(context.Background()); err != nil {
		panic(fmt.Sprintf("bridge: Commit h=%d: %v", seq, err))
	}

	l.app.height = seq
	l.app.results[seq] = resultEntry{
		header:  &EvmFinalizedHeader{Number: h.SeqNum, AppHash: res.AppHash},
		blockID: h.GetId(),
		txs:     body.Txs,
	}
	l.committed[h.SeqNum] = block
	if err := l.app.applyUpdates(res.ValidatorUpdates); err != nil {
		panic(err)
	}
}

// getHeaders / getPayload — blocksync self-fetch over the local block store
// (same semantics as MockLedger: proposed+voted+finalized blocks all serve).
func (l *Ledger) getHeaders(blockRange cstypes.BlockRange) blocksync.ResponseMessage {
	nextID := blockRange.LastBlockId
	var headers []cstypes.ConsensusBlockHeader
	for uint64(len(headers)) < blockRange.NumBlocks.Uint64() {
		block, ok := l.blocks[nextID]
		if !ok {
			return blocksync.ResponseHeadersNotAvailable(blockRange)
		}
		headers = append([]cstypes.ConsensusBlockHeader{block.Header}, headers...)
		nextID = block.Header.GetParentId()
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
