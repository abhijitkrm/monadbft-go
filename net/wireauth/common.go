// Package wireauth ports monad-bft/monad-wireauth — the WireGuard-derived
// authenticated-UDP protocol (Noise_IKpsk2_secp256k1_AEGIS128L_BLAKE3) used to
// protect RaptorCast traffic. Wire-identical with upstream: message layouts,
// handshake transcript, cookie and replay-filter semantics.
package wireauth

import (
	"encoding/binary"
	"time"

	"github.com/zeebo/blake3"

	"github.com/abhijitkrm/monadbft-go/crypto"
)

const (
	cipherTagSize = 16
	macTagSize    = 16
	publicKeySize = crypto.SecpPubkeySize // 33-byte compressed
)

// SessionIndex identifies a session slot on the wire (LE u32).
type SessionIndex uint32

func (s *SessionIndex) increment() { *s = SessionIndex(uint32(*s) + 1) } //nolint:gocritic

// cipherKey is the 16-byte AEGIS-128L key.
type cipherKey [16]byte

func cipherKeyFromHash(h hashOutput) cipherKey {
	var k cipherKey
	copy(k[:], h[:16])
	return k
}

// cipherNonce is the 16-byte AEGIS-128L nonce; data-packet nonces are a
// LE u64 zero-padded to 16 bytes.
type cipherNonce [16]byte

func cipherNonceFromU64(v uint64) cipherNonce {
	var n cipherNonce
	binary.LittleEndian.PutUint64(n[:8], v)
	return n
}

type hashOutput [32]byte

type macTag [16]byte

func macTagFromHash(h hashOutput) macTag {
	var t macTag
	copy(t[:], h[:16])
	return t
}

// sharedSecret is the 32-byte ECDH output.
type sharedSecret [32]byte

// transportKeys carries the two directions' AEAD keys.
type transportKeys struct {
	sendKey cipherKey
	recvKey cipherKey
}

// --- blake3 helpers (Rust hash! / keyed_hash! macros) ---

func blake3Hash(parts ...[]byte) hashOutput {
	h := blake3.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out hashOutput
	copy(out[:], h.Sum(nil))
	return out
}

func keyedHash(key []byte, parts ...[]byte) hashOutput {
	h, err := blake3.NewKeyed(key)
	if err != nil {
		panic(err) // 32-byte key is always valid
	}
	for _, p := range parts {
		h.Write(p)
	}
	var out hashOutput
	copy(out[:], h.Sum(nil))
	return out
}

// TAI64N timestamp: 8-byte BE seconds + 4-byte BE nanoseconds.
// TAI64 offset from Unix epoch: 2^62 + 37 (leap seconds).
const tai64UnixEpoch = 37 + (uint64(1) << 62)

type tai64n struct {
	seconds uint64
	nanos   uint32
}

func tai64nFromTime(t time.Time) tai64n {
	return tai64n{
		seconds: uint64(t.Unix()) + tai64UnixEpoch,
		nanos:   uint32(t.Nanosecond()),
	}
}

func tai64nFromBytes(b []byte) tai64n {
	return tai64n{
		seconds: binary.BigEndian.Uint64(b[:8]),
		nanos:   binary.BigEndian.Uint32(b[8:12]),
	}
}

func (t tai64n) bytes() [12]byte {
	var b [12]byte
	binary.BigEndian.PutUint64(b[:8], t.seconds)
	binary.BigEndian.PutUint32(b[8:], t.nanos)
	return b
}

func (t tai64n) valid() bool { return t.nanos < 1_000_000_000 }

func (t tai64n) cmp(o tai64n) int {
	if t.seconds != o.seconds {
		if t.seconds < o.seconds {
			return -1
		}
		return 1
	}
	switch {
	case t.nanos < o.nanos:
		return -1
	case t.nanos > o.nanos:
		return 1
	}
	return 0
}
