// Package blocktree ports monad-blocktree: the pending block tree with
// coherency tracking, pruning/commit, and canonical-tip selection.
package blocktree

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/abhijitkrm/monadbft-go/chaincfg"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/metrics"
	"github.com/abhijitkrm/monadbft-go/types"
)

// RootInfo — Rust checkpoint::RootInfo.
type RootInfo struct {
	Round       types.Round
	SeqNum      types.SeqNum
	Epoch       types.Epoch
	BlockId     types.BlockId
	TimestampNs types.U128
}

// ExecutionStateRead — seam for reading execution state (Rust
// monad-execution-state-read::ExecutionStateRead).
type ExecutionStateRead interface {
	// GetExecutionResult — Rust get_execution_result: the finalized execution
	// result for block (block_id, seq_num), ErrNotAvailableYet if unknown.
	GetExecutionResult(blockID types.BlockId, seqNum types.SeqNum, isFinalized bool) (exec.FinalizedHeader, error)
	// RawReadEarliestFinalizedBlock — Rust raw_read_earliest_finalized_block.
	RawReadEarliestFinalizedBlock() *types.SeqNum
	// RawReadLatestFinalizedBlock — Rust raw_read_latest_finalized_block.
	RawReadLatestFinalizedBlock() *types.SeqNum
	// ReadValsetAtBlock — Rust read_valset_at_block: (secp pubkey, cert pubkey,
	// stake) entries for `requestedEpoch` as observed at `blockNum`.
	ReadValsetAtBlock(blockNum types.SeqNum, requestedEpoch types.Epoch) []ValidatorReadData
}

// ValidatorReadData — a read_valset_at_block entry: (node pubkey, cert pubkey,
// stake). Kept in blocktree to avoid a validator->blocktree import cycle.
type ValidatorReadData struct {
	PubKey     [33]byte // secp256k1 compressed
	CertPubKey [48]byte // BLS (compressed)
	Stake      types.Stake
}

// BlockPolicy — Rust BlockPolicy trait.
type BlockPolicy interface {
	// CheckCoherency validates block against extending chain + root.
	CheckCoherency(
		block *cstypes.ConsensusFullBlock,
		extendingBlocks []*cstypes.ConsensusFullBlock,
		root RootInfo,
		stateRead ExecutionStateRead,
		chainConfig chaincfg.Config,
	) error
	GetExpectedExecutionResults(
		blockSeqNum types.SeqNum,
		extendingBlocks []*cstypes.ConsensusFullBlock,
		stateRead ExecutionStateRead,
	) ([]exec.FinalizedHeader, error)
	UpdateCommittedBlock(block *cstypes.ConsensusFullBlock)
	Reset(lastDelayCommittedBlocks []*cstypes.ConsensusFullBlock)
}

// Policy errors — Rust BlockPolicyError.
var (
	ErrBlockNotCoherent        = errors.New("blocktree: block not coherent")
	ErrTimestamp               = errors.New("blocktree: timestamp not monotonic")
	ErrExecutionResultMismatch = errors.New("blocktree: execution result mismatch")
	ErrNotAvailableYet         = errors.New("blocktree: execution state not available yet")
	ErrNeverAvailable          = errors.New("blocktree: execution state never available")
	ErrBaseFee                 = errors.New("blocktree: base fee error")
)

// PassthruBlockPolicy — Rust PassthruBlockPolicy: seqnum+timestamp+exec-results
// coherency only (no tx-level validation).
type PassthruBlockPolicy struct{}

func (p PassthruBlockPolicy) CheckCoherency(
	block *cstypes.ConsensusFullBlock,
	extending []*cstypes.ConsensusFullBlock,
	root RootInfo,
	stateRead ExecutionStateRead,
	_ chaincfg.Config,
) error {
	// check coherency against the block being extended or against the root of
	// the blocktree if there is no extending branch
	var extSeqNum types.SeqNum
	var extTs types.U128
	if len(extending) > 0 {
		extSeqNum = extending[len(extending)-1].Header.SeqNum
		extTs = extending[len(extending)-1].Header.TimestampNs
	} else {
		extSeqNum = root.SeqNum // extending_timestamp = 0 like Rust (TODO upstream)
	}
	if block.Header.SeqNum != extSeqNum+1 {
		return ErrBlockNotCoherent
	}
	if block.Header.TimestampNs.Cmp(extTs) <= 0 {
		return ErrTimestamp
	}
	expected, err := p.GetExpectedExecutionResults(block.Header.SeqNum, extending, stateRead)
	if err != nil {
		return err
	}
	if !finalizedHeadersEqual(block.Header.DelayedExecutionResults, expected) {
		return ErrExecutionResultMismatch
	}
	return nil
}

// finalizedHeadersEqual — Rust `block.get_execution_results() != &expected`.
func finalizedHeadersEqual(a, b []exec.FinalizedHeader) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].EncodeRLP(nil), b[i].EncodeRLP(nil)) {
			return false
		}
	}
	return true
}

func (PassthruBlockPolicy) GetExpectedExecutionResults(types.SeqNum, []*cstypes.ConsensusFullBlock, ExecutionStateRead) ([]exec.FinalizedHeader, error) {
	return nil, nil
}
func (PassthruBlockPolicy) UpdateCommittedBlock(*cstypes.ConsensusFullBlock) {}
func (PassthruBlockPolicy) Reset([]*cstypes.ConsensusFullBlock)              {}

// MockBlockPolicy — minimal EthBlockPolicy port for tests: tracks a committed
// seq→block-id index so get_expected_execution_results resolves the block at
// `seq - execution_delay` exactly like Rust's committed_cache+extending lookup.
// Proposals then embed that delayed result, which is what restart/state-sync
// recovery reads from the forkpoint root block.
type MockBlockPolicy struct {
	ExecutionDelay types.SeqNum
	lastCommit     types.SeqNum
	committed      map[types.SeqNum]types.BlockId
}

func NewMockBlockPolicy(executionDelay types.SeqNum) *MockBlockPolicy {
	return &MockBlockPolicy{
		ExecutionDelay: executionDelay,
		lastCommit:     types.GENESIS_SEQ_NUM,
		committed:      map[types.SeqNum]types.BlockId{},
	}
}

func (p *MockBlockPolicy) CheckCoherency(
	block *cstypes.ConsensusFullBlock,
	extending []*cstypes.ConsensusFullBlock,
	root RootInfo,
	stateRead ExecutionStateRead,
	_ chaincfg.Config,
) error {
	var extSeqNum types.SeqNum
	var extTs types.U128
	if len(extending) > 0 {
		extSeqNum = extending[len(extending)-1].Header.SeqNum
		extTs = extending[len(extending)-1].Header.TimestampNs
	} else {
		extSeqNum = root.SeqNum
	}
	if block.Header.SeqNum != extSeqNum+1 {
		return ErrBlockNotCoherent
	}
	if block.Header.TimestampNs.Cmp(extTs) <= 0 {
		return ErrTimestamp
	}
	expected, err := p.GetExpectedExecutionResults(block.Header.SeqNum, extending, stateRead)
	if err != nil {
		return err
	}
	if !finalizedHeadersEqual(block.Header.DelayedExecutionResults, expected) {
		return ErrExecutionResultMismatch
	}
	return nil
}

// GetExpectedExecutionResults — Rust EthBlockPolicy::get_expected_execution_
// results: the execution result for block_seq_num - execution_delay, resolved
// via the extending branch first then the committed index.
func (p *MockBlockPolicy) GetExpectedExecutionResults(
	blockSeqNum types.SeqNum,
	extending []*cstypes.ConsensusFullBlock,
	stateRead ExecutionStateRead,
) ([]exec.FinalizedHeader, error) {
	if blockSeqNum.Uint64() < p.ExecutionDelay.Uint64() {
		return nil, nil
	}
	baseSeqNum := blockSeqNum.Sub(p.ExecutionDelay)

	// get_block_index: committed chain first (base <= last_commit, genesis
	// special-cased), else the extending branch (unfinalized).
	var blockID types.BlockId
	isFinalized := false
	if baseSeqNum <= p.lastCommit {
		isFinalized = true
		if baseSeqNum == types.GENESIS_SEQ_NUM {
			blockID = types.GENESIS_BLOCK_ID
		} else {
			id, ok := p.committed[baseSeqNum]
			if !ok {
				panic(fmt.Sprintf("blocktree: queried recently committed block that doesn't exist, base=%d last_commit=%d", baseSeqNum, p.lastCommit))
			}
			blockID = id
		}
	} else {
		if extending == nil {
			return nil, ErrNotAvailableYet
		}
		found := false
		for _, blk := range extending {
			if blk.GetSeqNum() == baseSeqNum {
				blockID = blk.GetId()
				found = true
				break
			}
		}
		if !found {
			return nil, ErrNotAvailableYet
		}
	}
	res, err := stateRead.GetExecutionResult(blockID, baseSeqNum, isFinalized)
	if err != nil {
		return nil, err
	}
	return []exec.FinalizedHeader{res}, nil
}

// UpdateCommittedBlock — Rust update_committed_block: index the canonical
// commit, keeping a window of 2*execution_delay for base-seq lookups.
func (p *MockBlockPolicy) UpdateCommittedBlock(block *cstypes.ConsensusFullBlock) {
	if block.GetSeqNum() != p.lastCommit+1 {
		// Rust asserts strict +1 ordering on commits.
		panic(fmt.Sprintf("blocktree: committed seq %d does not follow %d", block.GetSeqNum(), p.lastCommit))
	}
	p.lastCommit = block.GetSeqNum()
	p.committed[block.GetSeqNum()] = block.GetId()
	minSeq := block.GetSeqNum().SaturatingSub(p.ExecutionDelay.Mul(2))
	for seq := range p.committed {
		if seq < minSeq {
			delete(p.committed, seq)
		}
	}
}

// Reset — Rust reset: reseed the committed index from the last 2*delay
// committed blocks (restart path).
func (p *MockBlockPolicy) Reset(lastDelayCommitted []*cstypes.ConsensusFullBlock) {
	p.committed = map[types.SeqNum]types.BlockId{}
	p.lastCommit = types.GENESIS_SEQ_NUM
	for _, blk := range lastDelayCommitted {
		p.committed[blk.GetSeqNum()] = blk.GetId()
		p.lastCommit = blk.GetSeqNum()
	}
}

// BlockValidator — Rust BlockValidator trait: validates a proposed
// header+body into a policy-validated block.
type BlockValidator interface {
	Validate(
		header cstypes.ConsensusBlockHeader,
		body cstypes.ConsensusBlockBody,
		authorPubKey *crypto.BlsPubKey,
		chainConfig chaincfg.Config,
		metrics *metrics.Metrics,
	) (*cstypes.ConsensusFullBlock, error)
}

// MockValidator — Rust MockValidator: only checks header/body payload-id
// consistency.
type MockValidator struct{}

func (MockValidator) Validate(
	header cstypes.ConsensusBlockHeader,
	body cstypes.ConsensusBlockBody,
	_ *crypto.BlsPubKey,
	_ chaincfg.Config,
	_ *metrics.Metrics,
) (*cstypes.ConsensusFullBlock, error) {
	b, err := cstypes.NewFullBlock(header, body)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// BlockTreeEntry — Rust BlockTreeEntry.
type BlockTreeEntry struct {
	ValidatedBlock *cstypes.ConsensusFullBlock
	IsCoherent     bool
	ChildrenBlocks []types.BlockId
}

type blockBodyIndex struct {
	body         cstypes.ConsensusBlockBody
	activeBlocks map[types.BlockId]struct{}
}

// BlockTree — Rust BlockTree. ValidatedBlock = *ConsensusFullBlock.
type BlockTree struct {
	root     RootInfo
	rootKids []types.BlockId
	tree     map[types.BlockId]*BlockTreeEntry
	payloads map[cstypes.ConsensusBlockBodyId]*blockBodyIndex
}

func New(root RootInfo) *BlockTree {
	return &BlockTree{
		root:     root,
		tree:     make(map[types.BlockId]*BlockTreeEntry),
		payloads: make(map[cstypes.ConsensusBlockBodyId]*blockBodyIndex),
	}
}

func (t *BlockTree) Root() RootInfo { return t.root }

// Prune — Rust prune: commit path to new_root; returns committed blocks in
// increasing round. Caller must ensure new_root is coherent.
func (t *BlockTree) Prune(newRoot types.BlockId) []*cstypes.ConsensusFullBlock {
	if !t.IsCoherent(newRoot) {
		panic("blocktree: prune on incoherent block")
	}
	var commit []*cstypes.ConsensusFullBlock
	if newRoot == t.root.BlockId {
		return commit
	}
	newRootEntry, ok := t.remove(newRoot)
	if !ok {
		panic("blocktree: new root not in tree")
	}
	entryToCommit := newRootEntry
	for {
		if !entryToCommit.IsCoherent {
			panic("blocktree: incoherent block on commit path")
		}
		vb := entryToCommit.ValidatedBlock
		parentId := vb.Header.QC.GetBlockId()
		commit = append(commit, vb)
		if parentId == t.root.BlockId {
			break
		}
		entryToCommit, ok = t.remove(parentId)
		if !ok {
			panic("blocktree: path to root broken")
		}
	}

	// GC: drop blocks whose parent round < new_root's block round
	var toDelete []types.BlockId
	for id, e := range t.tree {
		if e.ValidatedBlock.Header.QC.GetRound() < newRootEntry.ValidatedBlock.Header.BlockRound {
			toDelete = append(toDelete, id)
		}
	}
	for _, id := range toDelete {
		t.remove(id)
	}

	t.root = RootInfo{
		Round:       newRootEntry.ValidatedBlock.Header.BlockRound,
		SeqNum:      newRootEntry.ValidatedBlock.Header.SeqNum,
		Epoch:       newRootEntry.ValidatedBlock.Header.Epoch,
		BlockId:     newRootEntry.ValidatedBlock.GetId(),
		TimestampNs: newRootEntry.ValidatedBlock.Header.TimestampNs,
	}
	t.rootKids = newRootEntry.ChildrenBlocks

	// reverse commit → increasing round
	for i, j := 0, len(commit)-1; i < j; i, j = i+1, j-1 {
		commit[i], commit[j] = commit[j], commit[i]
	}
	return commit
}

// Add — Rust add: insert if not present and round > root round.
func (t *BlockTree) Add(block *cstypes.ConsensusFullBlock) {
	if !t.IsValidToInsert(&block.Header) {
		return
	}
	newId := block.GetId()
	parentId := block.Header.QC.GetBlockId()
	t.insert(block)
	if parentId == t.root.BlockId {
		t.rootKids = append(t.rootKids, newId)
	}
}

// insert — Rust Tree::insert (is_coherent=false, wires children/parent,
// payload index).
func (t *BlockTree) insert(block *cstypes.ConsensusFullBlock) {
	newId := block.GetId()
	parentId := block.Header.QC.GetBlockId()
	bodyId := block.Header.BlockBodyId

	var children []types.BlockId
	for id, e := range t.tree {
		if e.ValidatedBlock.Header.QC.GetBlockId() == newId {
			children = append(children, id)
		}
	}
	t.tree[newId] = &BlockTreeEntry{
		ValidatedBlock: block,
		IsCoherent:     false,
		ChildrenBlocks: children,
	}
	if pe, ok := t.tree[parentId]; ok {
		pe.ChildrenBlocks = append(pe.ChildrenBlocks, newId)
	}
	idx, ok := t.payloads[bodyId]
	if !ok {
		idx = &blockBodyIndex{body: block.Body, activeBlocks: make(map[types.BlockId]struct{})}
		t.payloads[bodyId] = idx
	}
	idx.activeBlocks[newId] = struct{}{}
}

func (t *BlockTree) remove(id types.BlockId) (*BlockTreeEntry, bool) {
	e, ok := t.tree[id]
	if !ok {
		return nil, false
	}
	delete(t.tree, id)
	pid := e.ValidatedBlock.Header.BlockBodyId
	if idx, ok := t.payloads[pid]; ok {
		delete(idx.activeBlocks, id)
		if len(idx.activeBlocks) == 0 {
			delete(t.payloads, pid)
		}
	}
	return e, true
}

// TryUpdateCoherency — Rust try_update_coherency.
func (t *BlockTree) TryUpdateCoherency(
	blockId types.BlockId,
	blockPolicy BlockPolicy,
	stateRead ExecutionStateRead,
	chainConfig chaincfg.Config,
) []*cstypes.ConsensusFullBlock {
	path := t.GetBlocksOnPathFromRoot(blockId)
	if path == nil {
		return nil
	}
	var incoherent *cstypes.ConsensusFullBlock
	for _, b := range path {
		if e := t.tree[b.GetId()]; e == nil || !e.IsCoherent {
			incoherent = b
			break
		}
	}
	if incoherent == nil {
		return nil // already coherent
	}
	var out []*cstypes.ConsensusFullBlock
	queue := []types.BlockId{incoherent.GetId()}
	for len(queue) > 0 {
		nextId := queue[0]
		queue = queue[1:]
		extending := t.GetBlocksOnPathFromRoot(nextId)
		if extending == nil {
			continue
		}
		nextBlock := extending[len(extending)-1]
		extending = extending[:len(extending)-1]
		if err := blockPolicy.CheckCoherency(nextBlock, extending, t.root, stateRead, chainConfig); err == nil {
			t.tree[nextId].IsCoherent = true
			out = append(out, nextBlock)
			queue = append(queue, t.tree[nextId].ChildrenBlocks...)
		}
	}
	return out
}

// GetHighCommittableQc — Rust get_high_committable_qc (BFS over tree).
func (t *BlockTree) GetHighCommittableQc() *cstypes.QuorumCertificate {
	var high *cstypes.QuorumCertificate
	queue := append([]types.BlockId{}, t.rootKids...)
	for len(queue) > 0 {
		bid := queue[0]
		queue = queue[1:]
		entry := t.tree[bid]
		if entry == nil {
			continue
		}
		queue = append(queue, entry.ChildrenBlocks...)
		qc := &entry.ValidatedBlock.Header.QC
		if high != nil && high.GetRound() >= qc.GetRound() {
			continue
		}
		parent, ok := t.tree[qc.GetBlockId()]
		if !ok {
			continue
		}
		cid := committableId(qc, parent.ValidatedBlock)
		if cid == nil {
			continue
		}
		if *cid == t.root.BlockId {
			continue
		}
		if !t.IsCoherent(*cid) {
			continue
		}
		high = qc
	}
	return high
}

// committableId — Rust QuorumCertificate::get_committable_id.
func committableId(qc *cstypes.QuorumCertificate, qcParent *cstypes.ConsensusFullBlock) *types.BlockId {
	return qc.GetCommittableId(qcParent)
}

// MaybeFillPathToRoot — Rust maybe_fill_path_to_root.
func (t *BlockTree) MaybeFillPathToRoot(qc *cstypes.QuorumCertificate) *cstypes.BlockRange {
	if t.root.Round >= qc.GetRound() || t.root.BlockId == qc.GetBlockId() {
		return nil
	}
	maybeUnknown := qc.GetBlockId()
	numBlocks := types.SeqNum(1)
	for {
		e, ok := t.tree[maybeUnknown]
		if !ok {
			break
		}
		if e.ValidatedBlock.Header.QC.GetBlockId() == t.root.BlockId {
			return nil
		}
		maybeUnknown = e.ValidatedBlock.Header.QC.GetBlockId()
		diff := e.ValidatedBlock.Header.SeqNum - t.root.SeqNum
		if diff < 2 {
			diff = 2
		}
		numBlocks = diff - 1
	}
	return &cstypes.BlockRange{LastBlockId: maybeUnknown, NumBlocks: numBlocks}
}

// IsCoherent — Rust is_coherent.
func (t *BlockTree) IsCoherent(b types.BlockId) bool {
	if b == t.root.BlockId {
		return true
	}
	if e, ok := t.tree[b]; ok {
		return e.IsCoherent
	}
	return false
}

// GetBlocksOnPathFromRoot — Rust get_blocks_on_path_from_root (low→high
// order). Returns nil if there's no path to root.
func (t *BlockTree) GetBlocksOnPathFromRoot(b types.BlockId) []*cstypes.ConsensusFullBlock {
	if b == t.root.BlockId {
		return []*cstypes.ConsensusFullBlock{}
	}
	var blocks []*cstypes.ConsensusFullBlock
	visit := b
	for {
		e, ok := t.tree[visit]
		if !ok {
			return nil
		}
		vb := e.ValidatedBlock
		blocks = append(blocks, vb)
		if vb.Header.QC.GetBlockId() == t.root.BlockId {
			// reverse
			for i, j := 0, len(blocks)-1; i < j; i, j = i+1, j-1 {
				blocks[i], blocks[j] = blocks[j], blocks[i]
			}
			return blocks
		}
		visit = vb.Header.QC.GetBlockId()
	}
}

// GetHighestCoherentBlockOnPathFromRoot — Rust get_highest_coherent_block_on_path_from_root.
func (t *BlockTree) GetHighestCoherentBlockOnPathFromRoot(b types.BlockId) *cstypes.ConsensusFullBlock {
	path := t.GetBlocksOnPathFromRoot(b)
	if path == nil {
		return nil
	}
	for i := len(path) - 1; i >= 0; i-- {
		if t.IsCoherent(path[i].GetId()) {
			return path[i]
		}
	}
	return nil
}

func (t *BlockTree) GetSeqNumOfQc(qc *cstypes.QuorumCertificate) (types.SeqNum, bool) {
	bid := qc.GetBlockId()
	if bid == t.root.BlockId {
		return t.root.SeqNum, true
	}
	e, ok := t.tree[bid]
	if !ok {
		return 0, false
	}
	return e.ValidatedBlock.Header.SeqNum, true
}

func (t *BlockTree) GetTimestampOfQc(qc *cstypes.QuorumCertificate) (types.U128, bool) {
	bid := qc.GetBlockId()
	if bid == t.root.BlockId {
		return t.root.TimestampNs, true
	}
	e, ok := t.tree[bid]
	if !ok {
		return types.U128{}, false
	}
	return e.ValidatedBlock.Header.TimestampNs, true
}

func (t *BlockTree) GetBlockRoundOfQc(qc *cstypes.QuorumCertificate) (types.Round, bool) {
	bid := qc.GetBlockId()
	if bid == t.root.BlockId {
		return t.root.Round, true
	}
	e, ok := t.tree[bid]
	if !ok {
		return 0, false
	}
	return e.ValidatedBlock.Header.BlockRound, true
}

// IsValidToInsert — Rust is_valid_to_insert: not already in tree and newer
// than root.
func (t *BlockTree) IsValidToInsert(h *cstypes.ConsensusBlockHeader) bool {
	_, exists := t.tree[h.GetId()]
	return !exists && h.BlockRound > t.root.Round
}

func (t *BlockTree) Size() int                 { return len(t.tree) }
func (t *BlockTree) RootSeqNum() types.SeqNum  { return t.root.SeqNum }
func (t *BlockTree) RootTimestamp() types.U128 { return t.root.TimestampNs }

func (t *BlockTree) GetBlock(id types.BlockId) *cstypes.ConsensusFullBlock {
	if e, ok := t.tree[id]; ok {
		return e.ValidatedBlock
	}
	return nil
}

func (t *BlockTree) GetPayload(id cstypes.ConsensusBlockBodyId) *cstypes.ConsensusBlockBody {
	if idx, ok := t.payloads[id]; ok {
		return &idx.body
	}
	return nil
}

func (t *BlockTree) GetEntry(id types.BlockId) *BlockTreeEntry { return t.tree[id] }

// GetParentBlockChain — Rust get_parent_block_chain (low→high).
func (t *BlockTree) GetParentBlockChain(blockId types.BlockId) []*cstypes.ConsensusFullBlock {
	base, ok := t.tree[blockId]
	if !ok {
		return nil
	}
	chain := []*cstypes.ConsensusFullBlock{base.ValidatedBlock}
	for {
		parent, ok := t.tree[chain[len(chain)-1].Header.QC.GetBlockId()]
		if !ok {
			break
		}
		chain = append(chain, parent.ValidatedBlock)
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// highestRoundCoherentDescendant — Rust highest_round_coherent_descendant.
func (t *BlockTree) highestRoundCoherentDescendant(blockId types.BlockId) types.BlockId {
	bestId := blockId
	var bestRound types.Round
	if blockId == t.root.BlockId {
		bestRound = t.root.Round
	} else if e, ok := t.tree[blockId]; ok {
		bestRound = e.ValidatedBlock.Header.BlockRound
	} else {
		return blockId
	}
	queue := []types.BlockId{blockId}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		var children []types.BlockId
		if cur == t.root.BlockId {
			children = t.rootKids
		} else if e, ok := t.tree[cur]; ok {
			children = e.ChildrenBlocks
		} else {
			continue
		}
		for _, child := range children {
			if !t.IsCoherent(child) {
				continue
			}
			ce := t.tree[child]
			if ce == nil {
				continue
			}
			if ce.ValidatedBlock.Header.BlockRound > bestRound {
				bestId = child
				bestRound = ce.ValidatedBlock.Header.BlockRound
			}
			queue = append(queue, child)
		}
	}
	return bestId
}

// GetCanonicalCoherentTip — Rust get_canonical_coherent_tip.
func (t *BlockTree) GetCanonicalCoherentTip(highCertQc *cstypes.QuorumCertificate) types.BlockId {
	var coherentTip types.BlockId
	if path := t.GetBlocksOnPathFromRoot(highCertQc.GetBlockId()); path != nil {
		found := false
		for i := len(path) - 1; i >= 0; i-- {
			if t.IsCoherent(path[i].GetId()) {
				coherentTip = path[i].GetId()
				found = true
				break
			}
		}
		if !found {
			return t.root.BlockId
		}
	} else {
		return t.highestRoundCoherentDescendant(t.root.BlockId)
	}
	if coherentTip == highCertQc.GetBlockId() {
		return t.highestRoundCoherentDescendant(coherentTip)
	}
	return coherentTip
}
