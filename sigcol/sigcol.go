// Package sigcol ports monad-bls::aggregation_tree — the BLS signature
// collection used for QCs, TCs, NECs and FPCs.
//
// SignerMap is a bitvec over validator indices (position in the sorted
// validator map). On the wire it encodes as [num_bits, bytes] where the
// bytes hold the bits in reversed Lsb0 order — see SignerMap.EncodeRLP.
package sigcol

import (
	"errors"
	"fmt"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

const MaxSignersLen = 1024 * 16

var (
	ErrNodeIdNotInMapping    = errors.New("sigcol: node id not in validator mapping")
	ErrConflictingSignatures = errors.New("sigcol: conflicting signatures")
	ErrInvalidSignatures     = errors.New("sigcol: invalid signatures")
	ErrSignersLenMismatch    = errors.New("sigcol: signer map length != validator count")
	ErrSignersLenExceeded    = errors.New("sigcol: signers count exceeds limit")
)

// InvalidSignaturesCreateError carries the (node_id, sig) pairs whose
// individual verification failed — Rust SignatureCollectionError::
// InvalidSignaturesCreate. Callers drop these voters and retry.
type InvalidSignaturesCreateError struct {
	Bad []NodeSig
}

func (e *InvalidSignaturesCreateError) Error() string {
	return fmt.Sprintf("sigcol: %d invalid signatures on create", len(e.Bad))
}

func (e *InvalidSignaturesCreateError) NodeIds() []types.NodeId {
	out := make([]types.NodeId, len(e.Bad))
	for i, s := range e.Bad {
		out[i] = s.NodeId
	}
	return out
}

// SignerMap is a BitVec<u8, Lsb0> over validator indices.
// Bit i refers to the i-th validator in ValidatorMapping's sorted order.
type SignerMap struct {
	Bits []bool
}

func NewSignerMap(n int) SignerMap { return SignerMap{Bits: make([]bool, n)} }

func (m SignerMap) Len() int { return len(m.Bits) }

func (m SignerMap) NumSignatures() int {
	n := 0
	for _, b := range m.Bits {
		if b {
			n++
		}
	}
	return n
}

// EncodeRLP — Rust SignerMap::encode:
//
//	[num_bits u32, buf] where buf[num_bytes-1-j/8] |= 1<<(j%8) for each
//	bit set at index num_bits-1-j (iter().rev().enumerate()).
func (m SignerMap) EncodeRLP(dst []byte) []byte {
	numBits := len(m.Bits)
	numBytes := (numBits + 7) / 8
	buf := make([]byte, numBytes)
	for j := 0; j < numBits; j++ {
		if m.Bits[numBits-1-j] {
			buf[numBytes-1-j/8] |= 1 << (j % 8)
		}
	}
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = rlp.AppendUint32(p, uint32(numBits))
		p = rlp.AppendString(p, buf)
		return p
	})
}

func (m *SignerMap) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	numBits64, err := l.Uint64()
	if err != nil {
		return err
	}
	if numBits64 > MaxSignersLen {
		return rlp.ErrCustom
	}
	numBits := int(numBits64)
	numBytes := (numBits + 7) / 8
	decoded, err := l.Bytes()
	if err != nil {
		return err
	}
	if len(decoded) != numBytes {
		return rlp.ErrUnexpectedLength
	}
	if err := l.Done(); err != nil {
		return err
	}
	// Rust decode: push byte[num_bytes-1-k/8] bit (k%8) for k in 0..num_bits,
	// then reverse — equivalent to logical bit i = back-indexed lookup.
	bits := make([]bool, numBits)
	for i := 0; i < numBits; i++ {
		k := numBits - 1 - i
		bits[i] = decoded[numBytes-1-k/8]>>(k%8)&1 == 1
	}
	m.Bits = bits
	return nil
}

// Empty returns the empty signature collection (0 signers, infinity sig) —
// used by GenesisQC.
func Empty() *BlsSignatureCollection {
	c := &BlsSignatureCollection{Signers: NewSignerMap(0)}
	inf := crypto.BlsSignatureInfinity()
	c.Sig = inf
	copy(c.RawSig[:], inf.Compress())
	return c
}

// BlsSignatureCollection mirrors Rust BlsSignatureCollection<PT>:
//
//	[signers: SignerMap, sig: LazyBlsSignature(96B), phantom(0 bytes)]
type BlsSignatureCollection struct {
	Signers SignerMap
	Sig     crypto.BlsSignature
	// raw compressed sig kept to survive decode->encode round-trips without
	// recompressing (LazyBlsSignature::Raw semantics)
	RawSig [crypto.BlsSignatureCompressdLen]byte
}

func (c BlsSignatureCollection) NumSignatures() int { return c.Signers.NumSignatures() }

func (c BlsSignatureCollection) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = c.Signers.EncodeRLP(p)
		p = rlp.AppendString(p, c.RawSig[:])
		return p
	})
}

func (c *BlsSignatureCollection) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := c.Signers.DecodeRLP(l); err != nil {
		return err
	}
	sigBytes, err := l.FixedBytes(crypto.BlsSignatureCompressdLen)
	if err != nil {
		return err
	}
	copy(c.RawSig[:], sigBytes)
	// lazy decode: keep raw bytes; parse point on demand
	sig, err := crypto.BlsSignatureUncompress(sigBytes)
	if err == nil {
		c.Sig = sig
	}
	return l.Done()
}

// NodeSig pairs a validator's node id with its BLS signature.
type NodeSig struct {
	NodeId types.NodeId
	Sig    crypto.BlsSignature
}

// New builds a signature collection from (node_id, sig) pairs, mirroring
// Rust SignatureCollection::new — including error behavior for unknown
// validators and conflicting signatures.
func New(
	domain []byte,
	sigs []NodeSig,
	mapping *validator.ValidatorMapping,
	msg []byte,
) (*BlsSignatureCollection, error) {
	// index validators in sorted (BTreeMap) order
	seen := make(map[types.NodeId]crypto.BlsSignature)
	var ordered []types.NodeId
	for _, s := range sigs {
		if !mapping.Has(s.NodeId) {
			return nil, fmt.Errorf("%w: %s", ErrNodeIdNotInMapping, s.NodeId)
		}
		if prev, ok := seen[s.NodeId]; ok {
			if !prev.Equal(s.Sig) {
				return nil, ErrConflictingSignatures
			}
			continue
		}
		seen[s.NodeId] = s.Sig
		ordered = append(ordered, s.NodeId)
	}
	_ = ordered

	out := &BlsSignatureCollection{Signers: NewSignerMap(mapping.Len())}
	agg := crypto.NewBlsAggregateSignature()
	var aggPk = crypto.NewBlsAggregatePubKeyInfinity()
	var any bool
	for nodeId, sig := range seen {
		idx := mapping.Index(nodeId)
		out.Signers.Bits[idx] = true
		agg.Add(sig)
		aggPk.Add(mapping.PubKey(nodeId))
		any = true
	}
	var compressed []byte
	if any {
		aggSig := agg.ToSignature()
		// verify aggregate; on failure localize invalid signers
		// (Rust uses the aggregation tree to bisect — we verify each signer)
		if !aggSig.FastAggregateVerifyPreAggregated(domain, msg, aggPk) {
			var bad []NodeSig
			for nodeId, sig := range seen {
				if !sig.Verify(domain, msg, mapping.PubKey(nodeId)) {
					bad = append(bad, NodeSig{NodeId: nodeId, Sig: sig})
				}
			}
			if len(bad) == 0 {
				// aggregate failure without individually-invalid sigs
				// (e.g. sum-to-infinity attack) — treat all as suspect
				return nil, ErrInvalidSignatures
			}
			return nil, &InvalidSignaturesCreateError{Bad: bad}
		}
		compressed = aggSig.Compress()
	} else {
		compressed = crypto.BlsSignatureInfinity().Compress()
	}
	copy(out.RawSig[:], compressed)
	out.Sig, _ = crypto.BlsSignatureUncompress(compressed)
	return out, nil
}

// Verify — Rust verify_aggregate_sig semantics.
func (c *BlsSignatureCollection) Verify(
	domain []byte,
	mapping *validator.ValidatorMapping,
	msg []byte,
) ([]types.NodeId, error) {
	if c.Signers.Len() != mapping.Len() {
		return nil, ErrSignersLenMismatch
	}
	if c.Signers.Len() > MaxSignersLen {
		return nil, ErrSignersLenExceeded
	}
	sig := c.Sig
	if sig.Inner() == nil {
		var err error
		sig, err = crypto.BlsSignatureUncompress(c.RawSig[:])
		if err != nil {
			return nil, ErrInvalidSignatures
		}
	}
	aggPk := crypto.NewBlsAggregatePubKeyInfinity()
	var signers []types.NodeId
	for i, b := range c.Signers.Bits {
		if b {
			nodeId, pk := mapping.At(i)
			aggPk.Add(pk)
			signers = append(signers, nodeId)
		}
	}
	if sig.IsInfinity() {
		if len(signers) == 0 && c.Signers.Len() == 0 {
			return signers, nil
		}
		return nil, ErrInvalidSignatures
	}
	if !sig.FastAggregateVerifyPreAggregated(domain, msg, aggPk) {
		return nil, ErrInvalidSignatures
	}
	return signers, nil
}

// Serialize — Rust SignatureCollection::serialize = RLP encode.
func (c *BlsSignatureCollection) Serialize() []byte {
	return c.EncodeRLP(nil)
}

func Deserialize(data []byte) (*BlsSignatureCollection, error) {
	var c BlsSignatureCollection
	err := rlp.DecodeExact(data, func(s *rlp.Stream) error {
		return c.DecodeRLP(s)
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}
