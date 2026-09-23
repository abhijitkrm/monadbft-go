package crypto

import (
	"bytes"
	"errors"
	"fmt"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	gethsecp "github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/zeebo/blake3"
)

// Secp256k1 (monad-secp port):
//   digest = blake3(domainPrefix || msg)
//   sig    = ecdsa recoverable over digest, serialized as 64B compact (r||s, low-S) || recid(0..3)
//   pubkey = 33B compressed point — this is also the NodeId pubkey type

const (
	SecpPubkeySize    = 33 // compressed
	SecpSignatureSize = 65 // compact(64) + recid(1)
	SecpSecretKeySize = 32
)

var ErrInvalidSignature = errors.New("secp256k1: invalid signature")

// SecpPubKey is a compressed secp256k1 public key.
type SecpPubKey [SecpPubkeySize]byte

func (p SecpPubKey) Bytes() []byte { return p[:] }

func (p SecpPubKey) Cmp(o SecpPubKey) int { return bytes.Compare(p[:], o[:]) }

func (p SecpPubKey) String() string {
	return fmt.Sprintf("%x..%x", p[:4], p[29:])
}

// SecpPubKeyFromBytes parses a compressed (33B) or uncompressed (65B) pubkey.
// Rust: PubKey::from_slice
func SecpPubKeyFromBytes(b []byte) (SecpPubKey, error) {
	var out SecpPubKey
	switch len(b) {
	case SecpPubkeySize:
		if b[0] != 0x02 && b[0] != 0x03 {
			return out, errors.New("secp256k1: bad compressed pubkey prefix")
		}
		copy(out[:], b)
	case 65:
		if b[0] != 0x04 {
			return out, errors.New("secp256k1: bad uncompressed pubkey prefix")
		}
		x, y := gethsecp.S256().Unmarshal(b)
		if x == nil {
			return out, errors.New("secp256k1: invalid uncompressed pubkey")
		}
		copy(out[:], gethsecp.CompressPubkey(x, y))
	default:
		return out, fmt.Errorf("secp256k1: bad pubkey length %d", len(b))
	}
	return out, nil
}

// SecpKeyPair wraps a secp256k1 secret key.
type SecpKeyPair struct {
	sk [SecpSecretKeySize]byte
	pk SecpPubKey
}

// SecpKeyPairFromBytes derives a keypair from a raw 32-byte secret scalar.
// Rust: KeyPair::from_bytes
func SecpKeyPairFromBytes(secret []byte) (*SecpKeyPair, error) {
	priv, err := gethcrypto.ToECDSA(secret)
	if err != nil {
		return nil, fmt.Errorf("secp256k1: invalid secret key: %w", err)
	}
	var kp SecpKeyPair
	copy(kp.sk[:], secret)
	copy(kp.pk[:], gethsecp.CompressPubkey(priv.X, priv.Y))
	return &kp, nil
}

func (k *SecpKeyPair) PubKey() SecpPubKey { return k.pk }

// SecretKey returns a copy of the raw secret key bytes.
func (k *SecpKeyPair) SecretKey() [SecpSecretKeySize]byte { return k.sk }

// SecpSignature is a 65-byte recoverable ECDSA signature (r||s||recid).
type SecpSignature [SecpSignatureSize]byte

// msgHash = blake3(domain || msg) — matches Rust msg_hash<SD>.
func msgHash(domain, msg []byte) [32]byte {
	return blake3.Sum256(withDomain(domain, msg))
}

// Sign produces the recoverable signature over domain||msg.
// Rust: KeyPair::sign<SD> = sign_ecdsa_recoverable(msg_hash, sk)
func (k *SecpKeyPair) Sign(domain, msg []byte) SecpSignature {
	digest := msgHash(domain, msg)
	sig, err := gethsecp.Sign(digest[:], k.sk[:])
	if err != nil {
		panic(fmt.Sprintf("secp256k1: sign failed: %v", err))
	}
	var out SecpSignature
	copy(out[:], sig)
	return out
}

// RecoverPubKey recovers the signer pubkey. Rust: SecpSignature::recover_pubkey
func (s SecpSignature) RecoverPubKey(domain, msg []byte) (SecpPubKey, error) {
	var zero SecpPubKey
	digest := msgHash(domain, msg)
	pkBytes, err := gethsecp.RecoverPubkey(digest[:], s[:])
	if err != nil {
		return zero, ErrInvalidSignature
	}
	if len(pkBytes) != 65 {
		return zero, ErrInvalidSignature
	}
	x, y := gethsecp.S256().Unmarshal(pkBytes)
	if x == nil {
		return zero, ErrInvalidSignature
	}
	var out SecpPubKey
	copy(out[:], gethsecp.CompressPubkey(x, y))
	return out, nil
}

// Verify checks the signature against msg under domain.
// Rust: PubKey::verify<SD>
func (s SecpSignature) Verify(domain, msg []byte, pk SecpPubKey) bool {
	digest := msgHash(domain, msg)
	uncompressed, err := decompressToUncompressed(pk)
	if err != nil {
		return false
	}
	return gethsecp.VerifySignature(uncompressed, digest[:], s[:64])
}

func decompressToUncompressed(pk SecpPubKey) ([]byte, error) {
	x, y := gethsecp.DecompressPubkey(pk[:])
	if x == nil {
		return nil, ErrInvalidSignature
	}
	return gethsecp.S256().Marshal(x, y), nil
}

func (s SecpSignature) Serialize() []byte { return s[:] }

func SecpSignatureFromBytes(b []byte) (SecpSignature, error) {
	var out SecpSignature
	if len(b) != SecpSignatureSize {
		return out, fmt.Errorf("secp256k1: signature must be %d bytes", SecpSignatureSize)
	}
	if b[64] > 3 {
		return out, errors.New("secp256k1: invalid recovery id")
	}
	copy(out[:], b)
	return out, nil
}
