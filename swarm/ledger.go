package swarm

import (
	"fmt"
	"sort"

	"github.com/abhijitkrm/monadbft-go/blocksync"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/store"
	"github.com/abhijitkrm/monadbft-go/types"
)

// MockLedger — port of monad-updaters::ledger::MockLedger.
//
// Stores every proposed/voted block, tracks finalized blocks by seq_num with a
// configurable finalization delay, serves block-sync requests out of the
// in-memory store, and mirrors commits into a shared InMemoryState.
type MockLedger struct {
	blocks          map[types.BlockId]*cstypes.ConsensusFullBlock
	committedBlocks map[types.SeqNum]*cstypes.ConsensusFullBlock

	events []glue.MonadEvent // queued BlockSyncEvent::SelfResponse

	finalizationDelay types.SeqNum
	stateRead         *InMemoryState
	blockStore        *store.BlockStore // optional durable mirror
}

var _ EventSource = (*MockLedger)(nil)

func NewMockLedger(stateRead *InMemoryState) *MockLedger {
	return &MockLedger{
		blocks:          map[types.BlockId]*cstypes.ConsensusFullBlock{},
		committedBlocks: map[types.SeqNum]*cstypes.ConsensusFullBlock{},
		stateRead:       stateRead,
	}
}

// WithFinalizationDelay — Rust with_finalization_delay.
func (l *MockLedger) WithFinalizationDelay(d types.SeqNum) *MockLedger {
	l.finalizationDelay = d
	return l
}

// WithBlocks — Rust with_blocks (carry another ledger's contents, e.g. restart).
func (l *MockLedger) WithBlocks(old *MockLedger) *MockLedger {
	l.blocks = old.blocks
	l.committedBlocks = old.committedBlocks
	return l
}

// WithBlockStore mirrors every ledger block write into the durable store and
// seeds the in-memory maps from it — the restart path that replaces
// with_blocks when the process is actually killed.
func (l *MockLedger) WithBlockStore(bs *store.BlockStore) *MockLedger {
	l.blockStore = bs
	if bs == nil {
		return l
	}
	if blocks, err := bs.AllBlocks(); err == nil {
		for _, b := range blocks {
			l.blocks[b.GetId()] = b
		}
	}
	if fins, err := bs.FinalizedBlocks(); err == nil {
		for _, b := range fins {
			l.committedBlocks[b.GetSeqNum()] = b
		}
	}
	return l
}

func (l *MockLedger) putBlock(b *cstypes.ConsensusFullBlock) {
	l.blocks[b.GetId()] = b
	if l.blockStore != nil {
		if err := l.blockStore.PutBlock(b); err != nil {
			panic(fmt.Sprintf("mockledger: block store write: %v", err))
		}
	}
}

// Exec — Rust Executor::exec(LedgerCommand).
func (l *MockLedger) Exec(cmds []glue.LedgerCommand) {
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.LedgerCommit:
			switch c.Commit.Kind {
			case glue.CommitProposed:
				b := c.Commit.Block
				l.stateRead.LedgerPropose(b.GetId(), b.GetSeqNum(), b.GetBlockRound(), b.GetParentId(), nil)
				l.putBlock(b)
			case glue.CommitVoted:
				b := c.Commit.Block
				l.putBlock(b)
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

func (l *MockLedger) commitFinalized(block *cstypes.ConsensusFullBlock) {
	if block.GetSeqNum().Uint64() <= l.finalizationDelay.Uint64() {
		return
	}
	finalizeSeqNum := block.GetSeqNum().Sub(l.finalizationDelay)
	for {
		if block.GetSeqNum() == finalizeSeqNum {
			l.committedBlocks[block.GetSeqNum()] = block
			l.stateRead.LedgerCommit(block.GetId(), block.GetSeqNum())
			if l.blockStore != nil {
				if err := l.blockStore.PutBlock(block); err != nil {
					panic(fmt.Sprintf("mockledger: block store write: %v", err))
				}
				if err := l.blockStore.PutFinalized(block.GetSeqNum(), block.GetId()); err != nil {
					panic(fmt.Sprintf("mockledger: finalized write: %v", err))
				}
			}
			return
		}
		next, ok := l.blocks[block.GetParentId()]
		if !ok {
			return
		}
		block = next
	}
}

// getHeaders — Rust get_headers: walk back from range.last_block_id collecting
// up to num_blocks headers; NotAvailable if any link is missing.
func (l *MockLedger) getHeaders(blockRange cstypes.BlockRange) blocksync.ResponseMessage {
	nextID := blockRange.LastBlockId
	var headers []cstypes.ConsensusBlockHeader // push_front order
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

// getPayload — Rust get_payload: find block by body id.
func (l *MockLedger) getPayload(payloadID cstypes.ConsensusBlockBodyId) blocksync.ResponseMessage {
	for _, fullBlock := range l.blocks {
		if fullBlock.GetBodyId() == payloadID {
			return blocksync.ResponsePayload(fullBlock.Body)
		}
	}
	return blocksync.ResponsePayloadNotAvailable(payloadID)
}

// Ready — Rust MockableLedger::ready.
func (l *MockLedger) Ready() bool { return len(l.events) > 0 }

// Next — Rust Stream::next → MonadEvent::BlockSyncEvent(SelfResponse).
func (l *MockLedger) Next() glue.MonadEvent {
	if len(l.events) == 0 {
		return nil
	}
	ev := l.events[0]
	l.events = l.events[1:]
	return ev
}

// GetFinalizedBlocks — Rust get_finalized_blocks (BTreeMap → ordered slice of
// (seq, block) pairs).
func (l *MockLedger) GetFinalizedBlocks() []FinalizedBlock {
	out := make([]FinalizedBlock, 0, len(l.committedBlocks))
	for seq, b := range l.committedBlocks {
		out = append(out, FinalizedBlock{SeqNum: seq, Block: b})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SeqNum < out[j].SeqNum })
	return out
}

// FinalizedBlocksLen — number of committed blocks (BTreeMap::len()).
func (l *MockLedger) FinalizedBlocksLen() int { return len(l.committedBlocks) }

// FinalizedBlock — a (seq_num, block) entry of the finalized BTreeMap.
type FinalizedBlock struct {
	SeqNum types.SeqNum
	Block  *cstypes.ConsensusFullBlock
}

// Blocks — the raw block store (test inspection).
func (l *MockLedger) Blocks() map[types.BlockId]*cstypes.ConsensusFullBlock { return l.blocks }
