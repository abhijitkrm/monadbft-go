package wireauth

// Ported from monad-bft/monad-wireauth/src/protocol/crypto.rs.

import (
	"errors"

	"github.com/ericlagergren/aegis"

	"github.com/abhijitkrm/monadbft-go/crypto"
)

var (
	construction = []byte("Noise_IKpsk2_secp256k1_AEGIS128L_BLAKE3")
	identifier   = []byte("authenticated udp v1 -- monad")
	labelMAC1    = []byte("mac1----")
	labelCookie  = []byte("cookie--")
)

var errMACVerificationFailed = errors.New("MAC verification failed")

// encryptInPlace encrypts data in place with AEGIS-128L and returns the
// 16-byte detached tag. Rust: encrypt_in_place.
func encryptInPlace(key *cipherKey, nonce *cipherNonce, data []byte, ad []byte) [16]byte {
	aead, err := aegis.New(key[:])
	if err != nil {
		panic(err)
	}
	sealed := aead.Seal(nil, nonce[:], data, ad)
	copy(data, sealed[:len(data)])
	var tag [16]byte
	copy(tag[:], sealed[len(data):])
	return tag
}

// decryptInPlace verifies tag and decrypts data in place.
// Rust: decrypt_in_place.
func decryptInPlace(key *cipherKey, nonce *cipherNonce, data []byte, tag *[16]byte, ad []byte) error {
	aead, err := aegis.New(key[:])
	if err != nil {
		panic(err)
	}
	sealed := make([]byte, 0, len(data)+16)
	sealed = append(sealed, data...)
	sealed = append(sealed, tag[:]...)
	opened, err := aead.Open(nil, nonce[:], sealed, ad)
	if err != nil {
		return errMACVerificationFailed
	}
	copy(data, opened)
	return nil
}

// verifyKeyedHash compares a keyed blake3 MAC (first 16 bytes) against tag.
func verifyKeyedHash(key *hashOutput, data []byte, tag [16]byte) error {
	computed := macTagFromHash(keyedHash(key[:], data))
	if computed != macTag(tag) {
		return errMACVerificationFailed
	}
	return nil
}

// ecdh is libsecp256k1 SharedSecret: SHA-256(compressed shared point).
func ecdh(priv *crypto.SecpKeyPair, pub crypto.SecpPubKey) (sharedSecret, error) {
	secret, err := priv.ECDH(pub)
	return sharedSecret(secret), err
}

// verifyMAC1 checks message.mac1 under hash(LABEL_MAC1 || responder_static).
func verifyMAC1(m macMessage, staticPublic crypto.SecpPubKey) error {
	macKey := blake3Hash(labelMAC1, staticPublic.Bytes())
	return verifyKeyedHash(&macKey, m.mac1Input(), m.mac1Tag())
}

// verifyMAC2 checks message.mac2 under the cookie key and cookie value.
func verifyMAC2(m macMessage, staticPublic crypto.SecpPubKey, cookie [16]byte) error {
	cookieKey := blake3Hash(labelCookie, staticPublic.Bytes())
	expected := macTagFromHash(keyedHash(cookieKey[:], m.mac2Input(), cookie[:]))
	if m.mac2Tag() != expected {
		return errMACVerificationFailed
	}
	return nil
}
