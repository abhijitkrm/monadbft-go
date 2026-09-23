package crypto

import (
	"bytes"
	"errors"
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

// BLS12-381 min_pk scheme (monad-bls port):
//   pubkey: G1, 48B compressed / 96B serialized
//   sig:    G2, 96B compressed / 192B serialized
//   signed msg = domainPrefix || msg   (domain applied by caller-facing sign/verify)
//   DST = BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_

var BLSDst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

const (
	BlsPubkeyCompressedLen   = 48
	BlsSignatureCompressdLen = 96
	BlsSecretKeyLen          = 32
)

var ErrBlsBadEncoding = errors.New("bls: bad encoding")

// blsKeygenKeyInfo is the key_info used by BlsKeyPairFromIkm
// (Rust: BlsKeyPair::from_ikm, dst = b"monad-bls-keygen").
var blsKeygenKeyInfo = []byte("monad-bls-keygen")

// BlsPubKey is a G1 public key.
type BlsPubKey struct {
	inner *blst.P1Affine
}

func BlsPubKeyInfinity() BlsPubKey {
	b := make([]byte, BlsPubkeyCompressedLen)
	b[0] = 0xc0
	pk, err := BlsPubKeyUncompress(b)
	if err != nil {
		panic(err)
	}
	return pk
}

// BlsPubKeyFromBytes parses a serialized (uncompressed, 96B) pubkey and
// validates subgroup membership. Rust: BlsPubKey::deserialize
func BlsPubKeyFromBytes(b []byte) (BlsPubKey, error) {
	if len(b) != 96 {
		return BlsPubKey{}, ErrBlsBadEncoding
	}
	pk := new(blst.P1Affine).Deserialize(b)
	if pk == nil {
		return BlsPubKey{}, ErrBlsBadEncoding
	}
	if !pk.KeyValidate() {
		return BlsPubKey{}, ErrBlsBadEncoding
	}
	return BlsPubKey{inner: pk}, nil
}

// BlsPubKeyUncompress parses a compressed (48B) pubkey. Rust: uncompress
func BlsPubKeyUncompress(b []byte) (BlsPubKey, error) {
	if len(b) != BlsPubkeyCompressedLen {
		return BlsPubKey{}, ErrBlsBadEncoding
	}
	pk := new(blst.P1Affine).Uncompress(b)
	if pk == nil {
		return BlsPubKey{}, ErrBlsBadEncoding
	}
	if !pk.KeyValidate() {
		return BlsPubKey{}, ErrBlsBadEncoding
	}
	return BlsPubKey{inner: pk}, nil
}

func (p BlsPubKey) Compress() []byte       { return p.inner.Compress() }
func (p BlsPubKey) Serialize() []byte      { return p.inner.Serialize() }
func (p BlsPubKey) Validate() bool         { return p.inner.KeyValidate() }
func (p BlsPubKey) Affine() *blst.P1Affine { return p.inner }

func (p BlsPubKey) Cmp(o BlsPubKey) int {
	// Rust: Ord by serialize() bytes
	return bytes.Compare(p.Serialize(), o.Serialize())
}

func (p BlsPubKey) Equal(o BlsPubKey) bool {
	return bytes.Equal(p.Compress(), o.Compress())
}

func (p BlsPubKey) String() string { return fmt.Sprintf("%x", p.Compress()) }

// BlsKeyPair is a BLS secret key + derived pubkey.
type BlsKeyPair struct {
	sk *blst.SecretKey
	pk BlsPubKey
}

// BlsKeyPairFromBytes: ikm -> key_gen(ikm, key_info=[]). Rust: from_bytes
func BlsKeyPairFromBytes(ikm []byte) (*BlsKeyPair, error) {
	if len(ikm) < 32 {
		return nil, errors.New("bls: secret key material must be at least 32 bytes")
	}
	sk := blst.KeyGen(ikm)
	if sk == nil {
		return nil, errors.New("bls: keygen failed")
	}
	return &BlsKeyPair{sk: sk, pk: BlsPubKey{inner: new(blst.P1Affine).From(sk)}}, nil
}

// BlsKeyPairFromIkm: key_gen(ikm, key_info="monad-bls-keygen"). Rust: from_ikm
func BlsKeyPairFromIkm(ikm []byte) (*BlsKeyPair, error) {
	if len(ikm) < 32 {
		return nil, errors.New("bls: ikm must be at least 32 bytes")
	}
	sk := blst.KeyGen(ikm, blsKeygenKeyInfo)
	if sk == nil {
		return nil, errors.New("bls: keygen failed")
	}
	return &BlsKeyPair{sk: sk, pk: BlsPubKey{inner: new(blst.P1Affine).From(sk)}}, nil
}

func (k *BlsKeyPair) PubKey() BlsPubKey { return k.pk }

// Sign signs (domain || msg). Rust: BlsKeyPair::sign<SD>
func (k *BlsKeyPair) Sign(domain, msg []byte) BlsSignature {
	full := withDomain(domain, msg)
	sig := new(blst.P2Affine).Sign(k.sk, full, BLSDst)
	return BlsSignature{inner: sig}
}

// BlsSignature is a G2 signature point.
type BlsSignature struct {
	inner *blst.P2Affine
}

func BlsSignatureFromBytes(b []byte) (BlsSignature, error) {
	// Rust deserialize = uncompress without subgroup check (checked at verify)
	return BlsSignatureUncompress(b)
}

func BlsSignatureUncompress(b []byte) (BlsSignature, error) {
	if len(b) != BlsSignatureCompressdLen {
		return BlsSignature{}, ErrBlsBadEncoding
	}
	sig := new(blst.P2Affine).Uncompress(b)
	if sig == nil {
		return BlsSignature{}, ErrBlsBadEncoding
	}
	return BlsSignature{inner: sig}, nil
}

func (s BlsSignature) Compress() []byte      { return s.inner.Compress() }
func (s BlsSignature) Serialize() []byte     { return s.Compress() }
func (s BlsSignature) Inner() *blst.P2Affine { return s.inner }

// Equal compares compressed encodings (Rust LazyBlsSignature semantics).
func (s BlsSignature) Equal(o BlsSignature) bool {
	return bytes.Equal(s.Compress(), o.Compress())
}

func (s BlsSignature) IsInfinity() bool {
	return bytes.Equal(s.Compress(), BlsSignatureInfinity().Compress())
}

// BlsSignatureInfinity is the G2 identity (0xc0 followed by 95 zeros).
func BlsSignatureInfinity() BlsSignature {
	b := make([]byte, BlsSignatureCompressdLen)
	b[0] = 0xc0
	sig, err := BlsSignatureUncompress(b)
	if err != nil {
		panic(err)
	}
	return sig
}

// BlsAggregateSignature is an efficient mutable G2 aggregate.
// Zero-value = identity (infinity).
type BlsAggregateSignature struct {
	inner *blst.P2Aggregate
}

func NewBlsAggregateSignature() *BlsAggregateSignature {
	return &BlsAggregateSignature{inner: new(blst.P2Aggregate)}
}

func NewBlsAggregateSignatureFrom(s BlsSignature) *BlsAggregateSignature {
	agg := new(blst.P2Aggregate)
	agg.Add(s.inner, false)
	return &BlsAggregateSignature{inner: agg}
}

func (a *BlsAggregateSignature) Add(s BlsSignature) { a.inner.Add(s.inner, false) }
func (a *BlsAggregateSignature) AddAggregate(o *BlsAggregateSignature) {
	a.inner.AddAggregate(o.inner)
}
func (a *BlsAggregateSignature) ToSignature() BlsSignature {
	return BlsSignature{inner: a.inner.ToAffine()}
}

// Verify checks sig over (domain || msg). Rust: verify(sig_groupcheck=true, pkValidate=true)
func (s BlsSignature) Verify(domain, msg []byte, pk BlsPubKey) bool {
	full := withDomain(domain, msg)
	return s.inner.Verify(true, pk.inner, true, full, BLSDst)
}

func (s BlsSignature) String() string { return fmt.Sprintf("%x", s.Compress()) }

// BlsAggregatePubKey is the faster aggregate representation of G1 pubkeys.
// A zero-value aggregate is the identity (infinity) — matching
// Rust BlsAggregatePubKey::infinity().
type BlsAggregatePubKey struct {
	inner *blst.P1Aggregate
}

func NewBlsAggregatePubKeyInfinity() *BlsAggregatePubKey {
	return &BlsAggregatePubKey{inner: new(blst.P1Aggregate)}
}

func NewBlsAggregatePubKey(pk BlsPubKey) *BlsAggregatePubKey {
	agg := new(blst.P1Aggregate)
	agg.Add(pk.inner, false)
	return &BlsAggregatePubKey{inner: agg}
}

func (a *BlsAggregatePubKey) Add(pk BlsPubKey) {
	a.inner.Add(pk.inner, false)
}

func (a *BlsAggregatePubKey) AddAggregate(o *BlsAggregatePubKey) {
	a.inner.AddAggregate(o.inner)
}

func (a *BlsAggregatePubKey) ToPubKey() BlsPubKey {
	return BlsPubKey{inner: a.inner.ToAffine()}
}

// FastAggregateVerifyPreAggregated — Rust: fast_aggregate_verify_pre_aggregated
func (s BlsSignature) FastAggregateVerifyPreAggregated(domain, msg []byte, aggPk *BlsAggregatePubKey) bool {
	full := withDomain(domain, msg)
	return s.inner.Verify(true, aggPk.inner.ToAffine(), false, full, BLSDst)
}
