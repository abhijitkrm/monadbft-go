package store

import (
	"encoding/binary"
	"fmt"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/cockroachdb/pebble"
	"sync"
)

// Key spaces:
//
//	blk/{id32}      → rlp(ConsensusFullBlock)          — every observed block
//	seq/{seq8be}    → id32                             — finalized seq index
//	pld/{bodyid32}  → id32                             — payload lookup
//	fin/{seq8be}    → id32                             — committed/finalized index
var (
	blkPrefix = []byte("blk/")
	seqPrefix = []byte("seq/")
	pldPrefix = []byte("pld/")
	finPrefix = []byte("fin/")
)

var syncWrite = &pebble.WriteOptions{Sync: true}

// ErrClosed — sentinel for ops racing Close (see BlockStore's doc).
var ErrClosed = pebble.ErrClosed

// BlockStore — the consensus block store: durable headers+bodies (+QC via
// headers) backing blocksync service and ledger reconstruction on restart.
//
// Ops take mu in read mode so Close never runs under an in-flight batch:
// pebble panics on use-after-close, and the engine's commit worker can
// outlive the node loop that owns Close. Post-close ops get ErrClosed —
// callers log and drop, which is the correct tail-commit semantics on
// shutdown (app state is already committed).
type BlockStore struct {
	db     *pebble.DB
	ep     *exec.Protocol
	mu     sync.RWMutex
	closed bool
}

func OpenBlockStore(dir string, ep *exec.Protocol) (*BlockStore, error) {
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		return nil, err
	}
	return &BlockStore{db: db, ep: ep}, nil
}

func (s *BlockStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

func blkKey(id types.BlockId) []byte {
	k := make([]byte, 4+32)
	copy(k, blkPrefix)
	copy(k[4:], id[:])
	return k
}

func seqKey(seq types.SeqNum) []byte {
	k := make([]byte, 4+8)
	copy(k, seqPrefix)
	binary.BigEndian.PutUint64(k[4:], seq.Uint64())
	return k
}

func finKey(seq types.SeqNum) []byte {
	k := make([]byte, 4+8)
	copy(k, finPrefix)
	binary.BigEndian.PutUint64(k[4:], seq.Uint64())
	return k
}

func pldKey(id cstypes.ConsensusBlockBodyId) []byte {
	k := make([]byte, 4+32)
	copy(k, pldPrefix)
	copy(k[4:], id[:])
	return k
}

// PutBlock — persist a full block with seq and payload indexes. Idempotent.
func (s *BlockStore) PutBlock(b *cstypes.ConsensusFullBlock) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	id := b.GetId()
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(blkKey(id), b.EncodeRLP(nil), nil); err != nil {
		return err
	}
	if err := batch.Set(seqKey(b.GetSeqNum()), id[:], nil); err != nil {
		return err
	}
	if err := batch.Set(pldKey(b.GetBodyId()), id[:], nil); err != nil {
		return err
	}
	return batch.Commit(syncWrite)
}

// PutFinalized — mark a block as committed (ledger-finalized).
func (s *BlockStore) PutFinalized(seq types.SeqNum, id types.BlockId) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	return s.db.Set(finKey(seq), id[:], syncWrite)
}

func (s *BlockStore) get(key []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	v, closer, err := s.db.Get(key)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	return append([]byte(nil), v...), nil
}

// prefixUpperBound — the exclusive iterator bound covering every key under
// prefix: the prefix with its final byte incremented. Appending 0xff would
// wrongly exclude keys whose payload starts with a 0xff byte.
func prefixUpperBound(prefix []byte) []byte {
	ub := append([]byte(nil), prefix...)
	ub[len(ub)-1]++
	return ub
}

// GetBlock — fetch a full block by id; nil if absent.
func (s *BlockStore) GetBlock(id types.BlockId) (*cstypes.ConsensusFullBlock, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	return s.getBlock(id)
}

// getBlock — GetBlock with mu already held (callers hold RLock through an
// iterator loop; nested RLock can deadlock against a pending writer).
func (s *BlockStore) getBlock(id types.BlockId) (*cstypes.ConsensusFullBlock, error) {
	v, closer, err := s.db.Get(blkKey(id))
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	var b cstypes.ConsensusFullBlock
	if err := b.DecodeRLP(rlp.NewStream(v), s.ep); err != nil {
		return nil, err
	}
	return &b, nil
}

// GetBySeqNum — fetch a block by sequence number; nil if absent.
func (s *BlockStore) GetBySeqNum(seq types.SeqNum) (*cstypes.ConsensusFullBlock, error) {
	idb, err := s.get(seqKey(seq))
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var id types.BlockId
	copy(id[:], idb)
	return s.GetBlock(id)
}

// GetPayload — fetch a block body by its payload id; nil if absent.
func (s *BlockStore) GetPayload(pid cstypes.ConsensusBlockBodyId) (*cstypes.ConsensusBlockBody, error) {
	idb, err := s.get(pldKey(pid))
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var id types.BlockId
	copy(id[:], idb)
	b, err := s.GetBlock(id)
	if err != nil || b == nil {
		return nil, err
	}
	return &b.Body, nil
}

// AllBlocks — every persisted block (for ledger rebuild on restart).
func (s *BlockStore) AllBlocks() ([]*cstypes.ConsensusFullBlock, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	it, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: blkPrefix,
		UpperBound: prefixUpperBound(blkPrefix),
	})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []*cstypes.ConsensusFullBlock
	for it.First(); it.Valid(); it.Next() {
		var b cstypes.ConsensusFullBlock
		if err := b.DecodeRLP(rlp.NewStream(it.Value()), s.ep); err != nil {
			return nil, fmt.Errorf("store: decode block %x: %w", it.Key(), err)
		}
		out = append(out, &b)
	}
	return out, it.Error()
}

// GetFinalizedID — the finalized canonical block id at seq; ok=false when
// no fin/ entry exists.
func (s *BlockStore) GetFinalizedID(seq types.SeqNum) (types.BlockId, bool, error) {
	idb, err := s.get(finKey(seq))
	if err == pebble.ErrNotFound {
		return types.BlockId{}, false, nil
	}
	if err != nil {
		return types.BlockId{}, false, err
	}
	var id types.BlockId
	copy(id[:], idb)
	return id, true, nil
}

// GetFinalized — the finalized block at seq via the fin/ index; nil if
// absent (unfinalized or pruned).
func (s *BlockStore) GetFinalized(seq types.SeqNum) (*cstypes.ConsensusFullBlock, error) {
	id, ok, err := s.GetFinalizedID(seq)
	if err != nil || !ok {
		return nil, err
	}
	return s.GetBlock(id)
}

// FinalizedTip — the highest finalized seq (iterator Last on fin/); 0 on an
// empty store.
func (s *BlockStore) FinalizedTip() (types.SeqNum, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, ErrClosed
	}
	it, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: finPrefix,
		UpperBound: prefixUpperBound(finPrefix),
	})
	if err != nil {
		return 0, err
	}
	defer it.Close()
	if !it.Last() {
		return 0, it.Error()
	}
	return types.SeqNum(binary.BigEndian.Uint64(it.Key()[4:])), it.Error()
}

// BlocksSince — every block whose seq index entry is ≥ floor, seq-ordered.
// The seq/ index maps a seq to the last-written block id, so forked siblings
// at the same seq are skipped — the windowed ledger rebuild only needs one
// canonical candidate per height.
func (s *BlockStore) BlocksSince(floor types.SeqNum) ([]*cstypes.ConsensusFullBlock, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	it, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: seqKey(floor),
		UpperBound: prefixUpperBound(seqPrefix),
	})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []*cstypes.ConsensusFullBlock
	for it.First(); it.Valid(); it.Next() {
		var id types.BlockId
		copy(id[:], it.Value())
		b, err := s.getBlock(id)
		if err != nil {
			return nil, err
		}
		if b != nil {
			out = append(out, b)
		}
	}
	return out, it.Error()
}

// PruneBelow — delete every store artifact for blocks below floorSeq:
// blk/, seq/, fin/ rows and their pld/ index entries. Iterates the seq/
// index to find ids, then ranges-deletes the height-keyed spaces.
func (s *BlockStore) PruneBelow(floor types.SeqNum) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	var ids []types.BlockId
	var bodies []cstypes.ConsensusBlockBodyId
	it, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: seqPrefix,
		UpperBound: seqKey(floor),
	})
	if err != nil {
		return err
	}
	var iterErr error
	for it.First(); it.Valid(); it.Next() {
		var id types.BlockId
		copy(id[:], it.Value())
		b, err := s.getBlock(id)
		if err != nil {
			iterErr = err
			break
		}
		if b != nil {
			ids = append(ids, id)
			bodies = append(bodies, b.GetBodyId())
		}
	}
	cerr := it.Close()
	if iterErr != nil {
		return iterErr
	}
	if cerr != nil {
		return cerr
	}
	if err := s.db.DeleteRange(seqPrefix, seqKey(floor), syncWrite); err != nil {
		return err
	}
	if err := s.db.DeleteRange(finPrefix, finKey(floor), syncWrite); err != nil {
		return err
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	for _, id := range ids {
		if err := batch.Delete(blkKey(id), nil); err != nil {
			return err
		}
	}
	for _, pid := range bodies {
		if err := batch.Delete(pldKey(pid), nil); err != nil {
			return err
		}
	}
	return batch.Commit(syncWrite)
}

// FinalizedSince — committed blocks at seq ≥ floor, in seq order.
func (s *BlockStore) FinalizedSince(floor types.SeqNum) ([]*cstypes.ConsensusFullBlock, error) {
	return s.finalizedRange(finKey(floor))
}

// FinalizedBlocks — committed (seq, block) pairs in seq order.
func (s *BlockStore) FinalizedBlocks() ([]*cstypes.ConsensusFullBlock, error) {
	return s.finalizedRange(finPrefix)
}

func (s *BlockStore) finalizedRange(lower []byte) ([]*cstypes.ConsensusFullBlock, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	it, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: lower,
		UpperBound: prefixUpperBound(finPrefix),
	})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []*cstypes.ConsensusFullBlock
	for it.First(); it.Valid(); it.Next() {
		var id types.BlockId
		copy(id[:], it.Value())
		b, err := s.getBlock(id)
		if err != nil {
			return nil, err
		}
		if b == nil {
			return nil, fmt.Errorf("store: finalized seq index references missing block %x", id)
		}
		out = append(out, b)
	}
	return out, it.Error()
}
