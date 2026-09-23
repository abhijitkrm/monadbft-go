// Package testutil ports monad-testutil::signing key derivation helpers:
// get_key(seed) = secp keypair from blake3(seed_le64); get_certificate_key =
// same seed -> BLS keypair (key_gen with empty key_info).
package testutil

import (
	"encoding/binary"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/zeebo/blake3"
)

func seedHash(seed uint64) [32]byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], seed)
	return blake3.Sum256(b[:])
}

// GetKey — Rust monad_testutil::signing::get_key.
func GetKey(seed uint64) *crypto.SecpKeyPair {
	h := seedHash(seed)
	kp, err := crypto.SecpKeyPairFromBytes(h[:])
	if err != nil {
		panic(err)
	}
	return kp
}

// GetCertKey — Rust get_certificate_key (BLS cert/voting key).
func GetCertKey(seed uint64) *crypto.BlsKeyPair {
	h := seedHash(seed)
	kp, err := crypto.BlsKeyPairFromBytes(h[:])
	if err != nil {
		panic(err)
	}
	return kp
}
