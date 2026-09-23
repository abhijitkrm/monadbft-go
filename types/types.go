// Package types holds the core consensus domain types ported from
// monad-bft/monad-types. RLP encodings are byte-identical to the Rust
// implementation (alloy-rlp semantics: structs encode as lists, integer
// newtypes encode as minimal big-endian, fixed arrays as byte strings).
package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/rlp"
)

// Round is the consensus round number. Rust: pub struct Round(pub u64)
type Round uint64

// Epoch groups rounds under a locked validator set. Rust: pub struct Epoch(pub u64)
type Epoch uint64

// SeqNum is the committed block sequence number. Rust: pub struct SeqNum(pub u64)
type SeqNum uint64

// Hash is the global 32-byte hash output (blake3). Rust: pub struct Hash(pub [u8; 32])
type Hash [32]byte

// BlockId identifies a consensus block; wraps Hash transparently.
// Rust: pub struct BlockId(pub Hash)
type BlockId Hash

// Stake is validator weight. Rust: pub struct Stake(pub U256)
// Encoded as minimal big-endian (RLP integer).
type Stake struct {
	Bytes [32]byte // big-endian U256
}

var (
	GENESIS_SEQ_NUM  = SeqNum(0)
	GENESIS_ROUND    = Round(0)
	GENESIS_EPOCH    = Epoch(1)
	GENESIS_BLOCK_ID = BlockId{}
)

func (r Round) Uint64() uint64  { return uint64(r) }
func (e Epoch) Uint64() uint64  { return uint64(e) }
func (s SeqNum) Uint64() uint64 { return uint64(s) }

func (r Round) Add(o Round) Round    { return Round(uint64(r) + uint64(o)) }
func (r Round) Sub(o Round) Round    { return Round(uint64(r) - uint64(o)) }
func (s SeqNum) Add(o SeqNum) SeqNum { return SeqNum(uint64(s) + uint64(o)) }

func (s SeqNum) IsBoundaryBlock(epochLength SeqNum) bool {
	return s.Uint64()%epochLength.Uint64() == epochLength.Uint64()-1
}

// ToEpoch maps a sequence number to its epoch. Rust: SeqNum::to_epoch.
func (s SeqNum) ToEpoch(epochLength SeqNum) Epoch {
	return Epoch(s.Uint64()/epochLength.Uint64() + 1)
}

func (s SeqNum) IsEpochEnd(epochLength SeqNum) bool {
	return s.IsBoundaryBlock(epochLength)
}

// GetEpoch after n locked epochs. Rust: SeqNum::get_epoch
func (s SeqNum) GetEpoch(epochLength SeqNum, n uint64) Epoch {
	epoch := s.ToEpoch(epochLength)
	return Epoch(epoch.Uint64() + n - 1)
}

// ---- RLP ----

func (r Round) EncodeRLP(dst []byte) []byte  { return rlp.AppendUint64(dst, uint64(r)) }
func (e Epoch) EncodeRLP(dst []byte) []byte  { return rlp.AppendUint64(dst, uint64(e)) }
func (s SeqNum) EncodeRLP(dst []byte) []byte { return rlp.AppendUint64(dst, uint64(s)) }

func (r *Round) DecodeRLP(s *rlp.Stream) error {
	v, err := s.Uint64()
	*r = Round(v)
	return err
}
func (e *Epoch) DecodeRLP(s *rlp.Stream) error {
	v, err := s.Uint64()
	*e = Epoch(v)
	return err
}
func (s *SeqNum) DecodeRLP(st *rlp.Stream) error {
	v, err := st.Uint64()
	*s = SeqNum(v)
	return err
}

// EncodeRLP encodes Hash as a fixed 32-byte string (a0 + 32B).
func (h Hash) EncodeRLP(dst []byte) []byte { return rlp.AppendString(dst, h[:]) }
func (h *Hash) DecodeRLP(s *rlp.Stream) error {
	b, err := s.FixedBytes(32)
	if err != nil {
		return err
	}
	copy(h[:], b)
	return nil
}

func (b BlockId) EncodeRLP(dst []byte) []byte { return rlp.AppendString(dst, b[:]) }
func (b *BlockId) DecodeRLP(s *rlp.Stream) error {
	p, err := s.FixedBytes(32)
	if err != nil {
		return err
	}
	copy(b[:], p)
	return nil
}

func (s Stake) EncodeRLP(dst []byte) []byte {
	i := 0
	for i < 32 && s.Bytes[i] == 0 {
		i++
	}
	return rlp.AppendString(dst, s.Bytes[i:])
}

func (s *Stake) DecodeRLP(st *rlp.Stream) error {
	b, err := st.Bytes()
	if err != nil {
		return err
	}
	if len(b) > 32 {
		return fmt.Errorf("rlp: stake overflow")
	}
	if len(b) > 0 && b[0] == 0 {
		return rlp.ErrLeadingZero
	}
	copy(s.Bytes[32-len(b):], b)
	return nil
}

func StakeFromUint64(v uint64) Stake {
	var s Stake
	binary.BigEndian.PutUint64(s.Bytes[24:], v)
	return s
}

func StakeFromBig(v *big.Int) Stake {
	var s Stake
	b := v.Bytes()
	copy(s.Bytes[32-len(b):], b)
	return s
}

func (s Stake) Big() *big.Int { return new(big.Int).SetBytes(s.Bytes[:]) }
func (s Stake) Uint64() uint64 {
	return binary.BigEndian.Uint64(s.Bytes[24:])
}

// Add returns s + o (wraps mod 2^256; Rust uses U256 wrapping ops in tests).
func (s Stake) Add(o Stake) Stake {
	var out Stake
	carry := uint64(0)
	for i := 31; i >= 0; i-- {
		sum := uint64(s.Bytes[i]) + uint64(o.Bytes[i]) + carry
		out.Bytes[i] = byte(sum)
		carry = sum >> 8
	}
	return out
}

func (s Stake) Cmp(o Stake) int { return bytes.Compare(s.Bytes[:], o.Bytes[:]) }
func (s Stake) IsZero() bool    { return s == Stake{} }

func (h Hash) String() string { return fmt.Sprintf("0x%x", h[:]) }
func (b BlockId) String() string {
	return fmt.Sprintf("0x%x", [32]byte(b))
}

// NodeId identifies a validator by its secp256k1 node pubkey.
// Rust: pub struct NodeId<PT: PubKey>(PT) — encodes as the compressed pubkey.
type NodeId struct {
	PubKey crypto.SecpPubKey
}

func NewNodeId(pk crypto.SecpPubKey) NodeId { return NodeId{PubKey: pk} }

// Cmp orders by compressed pubkey bytes — identical to the Rust derived Ord
// (rust-secp256k1 PublicKey::cmp serializes before comparing).
func (n NodeId) Cmp(o NodeId) int { return n.PubKey.Cmp(o.PubKey) }

func (n NodeId) EncodeRLP(dst []byte) []byte {
	return rlp.AppendString(dst, n.PubKey[:])
}
func (n *NodeId) DecodeRLP(s *rlp.Stream) error {
	b, err := s.FixedBytes(crypto.SecpPubkeySize)
	if err != nil {
		return err
	}
	copy(n.PubKey[:], b)
	return nil
}
func (n NodeId) String() string { return n.PubKey.String() }

// LimitedVec mirrors Rust LimitedVec<T, N> — encodes as a plain RLP list.
type LimitedVec[T rlp.Encodable] struct {
	Items []T
}
