package monadstate

import (
	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/types"
)

// BlockBuffer — Rust monad-state::statesync::BlockBuffer. Tracks pending
// blocks mid-statesync: a lightweight blocktree used only while Sync.
type BlockBuffer struct {
	maxBufferedProposals int

	// trigger resync once passively observed new_root > root + resync_threshold
	resyncThreshold types.SeqNum
	// TFM reserve-balance checking needs N-2*state_root_delay blocks for N
	minNumBlocks types.SeqNum
	// executionDelay — fallback target offset when the root embeds no result.
	executionDelay types.SeqNum

	root types.BlockId
	// blocks <= root
	fullBlocks   map[types.BlockId]*cstypes.ConsensusFullBlock
	payloadCache map[cstypes.ConsensusBlockBodyId]*cstypes.ConsensusBlockBody
	// block headers >= root
	blockHeaders map[types.BlockId]*cstypes.ConsensusBlockHeader

	// last max_buffered_proposals proposals
	proposalBuffer []bufferedProposal
}

type bufferedProposal struct {
	author   types.NodeId
	proposal messages.ProposalMessage
}

// NewBlockBuffer — Rust BlockBuffer::new(execution_delay, root, resync_threshold).
func NewBlockBuffer(executionDelay types.SeqNum, root types.BlockId, resyncThreshold types.SeqNum) *BlockBuffer {
	return &BlockBuffer{
		maxBufferedProposals: int(resyncThreshold),
		resyncThreshold:      resyncThreshold,
		minNumBlocks:         types.SeqNum(uint64(executionDelay) * 2),
		executionDelay:       executionDelay,
		root:                 root,
		fullBlocks:           make(map[types.BlockId]*cstypes.ConsensusFullBlock),
		payloadCache:         make(map[cstypes.ConsensusBlockBodyId]*cstypes.ConsensusBlockBody),
		blockHeaders:         make(map[types.BlockId]*cstypes.ConsensusBlockHeader),
	}
}

func (b *BlockBuffer) PayloadCache() map[cstypes.ConsensusBlockBodyId]*cstypes.ConsensusBlockBody {
	return b.payloadCache
}

// RootHeader — the buffered root block's header; nil until blocksync lands it.
func (b *BlockBuffer) RootHeader() *cstypes.ConsensusBlockHeader {
	fb, ok := b.fullBlocks[b.root]
	if !ok {
		return nil
	}
	return &fb.Header
}

func (b *BlockBuffer) RootSeqNum() (types.SeqNum, bool) {
	ri := b.RootInfo()
	if ri == nil {
		return 0, false
	}
	return ri.SeqNum, true
}

// RootInfo — Rust BlockBuffer::root_info.
func (b *BlockBuffer) RootInfo() *blocktree.RootInfo {
	if b.root == types.GENESIS_BLOCK_ID {
		return &blocktree.RootInfo{
			SeqNum:      types.GENESIS_SEQ_NUM,
			Round:       types.GENESIS_ROUND,
			Epoch:       types.GENESIS_EPOCH,
			BlockId:     types.GENESIS_BLOCK_ID,
			TimestampNs: types.U128{}, // GENESIS_TIMESTAMP
		}
	}
	root, ok := b.fullBlocks[b.root]
	if !ok {
		return nil
	}
	return &blocktree.RootInfo{
		Round:       root.GetBlockRound(),
		SeqNum:      root.GetSeqNum(),
		Epoch:       root.GetEpoch(),
		BlockId:     root.GetId(),
		TimestampNs: root.GetTimestamp(),
	}
}

// ExecutionTarget — the seq whose execution result the root embeds: the
// DB/statesync target. Upstream's fixed-delay policy makes this always
// root-delay; reading it from the root header instead keeps variable-lag
// block policies (results of the latest *finalized* block ≤ seq-delay)
// correct, with identical behavior under a fixed delay. Falls back to
// root-delay (clamped) when the root embeds no result (seq < delay).
func (b *BlockBuffer) ExecutionTarget() (types.SeqNum, bool) {
	ri := b.RootInfo()
	if ri == nil {
		return 0, false
	}
	if root, ok := b.fullBlocks[b.root]; ok {
		if res := root.GetExecutionResults(); len(res) == 1 {
			return res[0].SeqNum(), true
		}
	}
	return ri.SeqNum.SaturatingSub(b.executionDelay), true
}

// RequiredChainLen — root-parent blocks to hold: 2*delay (upstream), widened
// to reach the root's embedded result seq when its lag exceeds that.
func (b *BlockBuffer) RequiredChainLen() types.SeqNum {
	root, ok := b.fullBlocks[b.root]
	if !ok {
		return b.minNumBlocks
	}
	return b.chainLenFor(root.GetSeqNum(), root.GetExecutionResults())
}

func (b *BlockBuffer) chainLenFor(rootSeq types.SeqNum, res []exec.FinalizedHeader) types.SeqNum {
	n := b.minNumBlocks
	if len(res) == 1 && res[0].SeqNum() < rootSeq {
		if need := rootSeq - res[0].SeqNum() + 1; need > n {
			n = need
		}
	}
	return n
}

// RootDelayedExecutionResult — Rust root_delayed_execution_result.
func (b *BlockBuffer) RootDelayedExecutionResult() []exec.FinalizedHeader {
	root, ok := b.fullBlocks[b.root]
	if !ok {
		return nil
	}
	return root.GetExecutionResults()
}

// HandleProposal — Rust BlockBuffer::handle_proposal: buffers the proposal,
// returns (new_root, new_high_qc) if it advanced root past the threshold.
func (b *BlockBuffer) HandleProposal(
	author types.NodeId,
	proposal messages.ProposalMessage,
) (*cstypes.ConsensusBlockHeader, *cstypes.QuorumCertificate) {
	rootSeqNum, ok := b.RootSeqNum()
	if !ok {
		return nil, nil
	}
	if proposal.Tip.BlockHeader.SeqNum < rootSeqNum {
		return nil, nil
	}
	proposalQC := proposal.Tip.BlockHeader.QC
	hdr := proposal.Tip.BlockHeader
	b.blockHeaders[hdr.GetId()] = &hdr

	b.proposalBuffer = append(b.proposalBuffer, bufferedProposal{author, proposal})
	if len(b.proposalBuffer) > b.maxBufferedProposals {
		b.proposalBuffer = b.proposalBuffer[1:]
	}

	qcParent := b.blockHeaders[proposalQC.GetBlockId()]
	if qcParent == nil {
		return nil, nil
	}
	finalizedID := proposalQC.GetCommittableIdForHeader(qcParent)
	if finalizedID == nil {
		return nil, nil
	}
	finalized := b.blockHeaders[*finalizedID]
	if finalized == nil {
		return nil, nil
	}
	if finalized.SeqNum <= rootSeqNum+b.resyncThreshold {
		return nil, nil
	}
	return finalized, &proposalQC
}

// HandleBlocksync — Rust BlockBuffer::handle_blocksync.
func (b *BlockBuffer) HandleBlocksync(block cstypes.ConsensusFullBlock) {
	if rs, ok := b.RootSeqNum(); ok && block.GetSeqNum() > rs {
		return
	}
	b.payloadCache[block.GetBodyId()] = &block.Body
	fb := block
	b.fullBlocks[block.GetId()] = &fb
}

// ReRoot — Rust BlockBuffer::re_root: advance the root and prune.
func (b *BlockBuffer) ReRoot(newRoot cstypes.ConsensusBlockHeader) {
	keep := b.chainLenFor(newRoot.SeqNum, newRoot.DelayedExecutionResults)
	for id, blk := range b.fullBlocks {
		if blk.GetSeqNum()+keep < newRoot.SeqNum {
			delete(b.fullBlocks, id)
		}
	}
	for _, bp := range b.proposalBuffer {
		if bp.proposal.Tip.BlockHeader.SeqNum <= newRoot.SeqNum {
			if fb, err := cstypes.NewFullBlock(bp.proposal.Tip.BlockHeader, bp.proposal.BlockBody); err == nil {
				fbc := fb
				b.fullBlocks[fbc.GetId()] = &fbc
			}
		}
	}
	for id, h := range b.blockHeaders {
		if h.SeqNum < newRoot.SeqNum {
			delete(b.blockHeaders, id)
		}
	}
	b.root = newRoot.GetId()
	b.payloadCache = make(map[cstypes.ConsensusBlockBodyId]*cstypes.ConsensusBlockBody)
	for _, fb := range b.fullBlocks {
		b.payloadCache[fb.GetBodyId()] = &fb.Body
	}
}

// Proposals — Rust BlockBuffer::proposals.
func (b *BlockBuffer) Proposals() []bufferedProposal {
	return b.proposalBuffer
}

// RootParentChain — Rust root_parent_chain: chain from root, newest-first.
func (b *BlockBuffer) RootParentChain() []*cstypes.ConsensusFullBlock {
	next := b.root
	var out []*cstypes.ConsensusFullBlock
	for {
		blk, ok := b.fullBlocks[next]
		if !ok {
			break
		}
		out = append(out, blk)
		next = blk.GetParentId()
	}
	return out
}

// NeedsBlocksync — Rust needs_blocksync: the range still missing under root.
func (b *BlockBuffer) NeedsBlocksync() *cstypes.BlockRange {
	if b.root == types.GENESIS_BLOCK_ID {
		return nil
	}
	chain := b.RootParentChain()
	if len(chain) == 0 {
		return &cstypes.BlockRange{LastBlockId: b.root, NumBlocks: b.minNumBlocks}
	}
	required := b.RequiredChainLen()
	last := chain[len(chain)-1]
	// Chain terminates at genesis — no earlier full block exists to fetch.
	if last.GetSeqNum() <= types.SeqNum(1) {
		return nil
	}
	if uint64(len(chain)) < uint64(required) {
		// Clamp so the range can't dip below seq 1 — genesis (seq 0) is a
		// sentinel id with no stored block; verifyBlockHeaders accepts the
		// resulting genesis-terminated shortfall.
		want := required - types.SeqNum(len(chain))
		if avail := last.GetSeqNum() - 1; want > avail {
			want = avail
		}
		return &cstypes.BlockRange{
			LastBlockId: last.GetParentId(),
			NumBlocks:   want,
		}
	}
	return nil
}
