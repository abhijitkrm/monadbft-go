package store

import (
	"encoding/binary"
	"fmt"

	"github.com/cockroachdb/pebble"

	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
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

// BlockStore — the consensus block store: durable headers+bodies (+QC via
// headers) backing blocksync service and ledger reconstruction on restart.
type BlockStore struct {
	db *pebble.DB
	ep *exec.Protocol
}

func OpenBlockStore(dir string, ep *exec.Protocol) (*BlockStore, error) {
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		return nil, err
	}
	return &BlockStore{db: db, ep: ep}, nil
}

func (s *BlockStore) Close() error { return s.db.Close() }

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
	return s.db.Set(finKey(seq), id[:], syncWrite)
}

func (s *BlockStore) get(key []byte) ([]byte, error) {
	v, closer, err := s.db.Get(key)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	return append([]byte(nil), v...), nil
}

// GetBlock — fetch a full block by id; nil if absent.
func (s *BlockStore) GetBlock(id types.BlockId) (*cstypes.ConsensusFullBlock, error) {
	v, err := s.get(blkKey(id))
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
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
	it, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: blkPrefix,
		UpperBound: append(append([]byte(nil), blkPrefix...), 0xff),
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

// FinalizedBlocks — committed (seq, block) pairs in seq order.
func (s *BlockStore) FinalizedBlocks() ([]*cstypes.ConsensusFullBlock, error) {
	it, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: finPrefix,
		UpperBound: append(append([]byte(nil), finPrefix...), 0xff),
	})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []*cstypes.ConsensusFullBlock
	for it.First(); it.Valid(); it.Next() {
		var id types.BlockId
		copy(id[:], it.Value())
		b, err := s.GetBlock(id)
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
