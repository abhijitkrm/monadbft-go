package wireauth

// Ported from monad-bft/monad-wireauth/src/protocol/handshake.rs.
// Noise_IKpsk2_secp256k1_AEGIS128L_BLAKE3 handshake transcript.

import (
	"errors"

	"github.com/abhijitkrm/monadbft-go/crypto"
)

var (
	errStaticKeyDecryptionFailed = errors.New("static key decryption failed")
	errTimestampDecryptionFailed = errors.New("timestamp decryption failed")
	errInvalidTimestamp          = errors.New("invalid timestamp")
	errEmptyMessageDecryptFailed = errors.New("empty message decryption failed")
	errInvalidPublicKey          = errors.New("invalid public key")
)

// handshakeState is the running Noise transcript state.
type handshakeState struct {
	chainingKey      hashOutput
	hash             hashOutput
	ephemeralPrivate *crypto.SecpKeyPair
	remoteEphemeral  *crypto.SecpPubKey
	remoteStatic     *crypto.SecpPubKey
	senderIndex      uint32
	receiverIndex    uint32
}

func zeroHandshakeState() handshakeState {
	z := blake3Hash(nil)
	return handshakeState{chainingKey: z, hash: z}
}

// rng abstracts entropy for ephemeral keygen and jitter. crypto/rand.Reader
// satisfies io.Reader; the Uint64 side is used for timer jitter.
type rng interface {
	Read(b []byte) (int, error)
	Uint64() uint64
}

// generateKeyPair draws a 32-byte secret scalar from rng, retrying until
// valid — mirrors secp256k1::Keypair::new.
func generateKeyPair(r rng) (*crypto.SecpKeyPair, error) {
	return crypto.GenerateSecpKeyPair(r)
}

// kdf1 = ck' = keyed_hash(temp, 0x01); kdf2 adds keyed_hash(temp, ck', 0x02).
func kdfChain(chainingKey *hashOutput, input []byte) {
	temp := keyedHash(chainingKey[:], input)
	*chainingKey = keyedHash(temp[:], []byte{0x01})
}

func kdfChain2(chainingKey *hashOutput, input []byte) hashOutput {
	temp := keyedHash(chainingKey[:], input)
	*chainingKey = keyedHash(temp[:], []byte{0x01})
	return keyedHash(temp[:], append(chainingKey[:], 0x02))
}

func (s *handshakeState) mixHash(parts ...[]byte) {
	s.hash = blake3Hash(append([][]byte{s.hash[:]}, parts...)...)
}

func sendHandshakeInit(
	r rng,
	timestamp tai64n,
	localSessionIndex uint32,
	initiatorStaticKeypair *crypto.SecpKeyPair,
	responderStaticPublic crypto.SecpPubKey,
	storedCookie *[16]byte,
) (*handshakeInitiation, *handshakeState, error) {
	initiatorStaticPublic := initiatorStaticKeypair.PubKey()
	ephemeralKeypair, err := generateKeyPair(r)
	if err != nil {
		return nil, nil, err
	}
	ephemeralPublic := ephemeralKeypair.PubKey()

	msg := &handshakeInitiation{
		senderIndex:     localSessionIndex,
		ephemeralPublic: ephemeralPublic,
	}
	state := &handshakeState{
		chainingKey:      blake3Hash(construction),
		senderIndex:      localSessionIndex,
		ephemeralPrivate: ephemeralKeypair,
	}
	ckID := blake3Hash(state.chainingKey[:], identifier)
	state.hash = blake3Hash(ckID[:], responderStaticPublic.Bytes())

	// hash = h || eph_pub
	state.mixHash(ephemeralPublic[:])
	// ck = kdf(ck, eph_pub)
	kdfChain(&state.chainingKey, ephemeralPublic[:])

	// es = DH(eph_priv, responder_static)
	ecdhES, err := ecdh(ephemeralKeypair, responderStaticPublic)
	if err != nil {
		return nil, nil, err
	}
	key := kdfChain2(&state.chainingKey, ecdhES[:])

	msg.encryptedStatic = initiatorStaticPublic
	k := cipherKeyFromHash(key)
	msg.encryptedStaticTag = encryptInPlace(&k, ptrNonce(cipherNonceFromU64(0)), msg.encryptedStatic[:], state.hash[:])
	state.mixHash(msg.encryptedStatic[:], msg.encryptedStaticTag[:])

	// ss = DH(static_priv, responder_static)
	ecdhSS, err := ecdh(initiatorStaticKeypair, responderStaticPublic)
	if err != nil {
		return nil, nil, err
	}
	key = kdfChain2(&state.chainingKey, ecdhSS[:])

	ts := timestamp.bytes()
	copy(msg.encryptedTimestamp[:], ts[:])
	k = cipherKeyFromHash(key)
	msg.encryptedTimestampTag = encryptInPlace(&k, ptrNonce(cipherNonceFromU64(0)), msg.encryptedTimestamp[:], state.hash[:])
	state.mixHash(msg.encryptedTimestamp[:], msg.encryptedTimestampTag[:])

	macKey := blake3Hash(labelMAC1, responderStaticPublic.Bytes())
	msg.mac1 = macTagFromHash(keyedHash(macKey[:], msg.mac1Input()))
	if storedCookie != nil {
		cookieKey := blake3Hash(labelCookie, responderStaticPublic.Bytes())
		msg.mac2 = macTagFromHash(keyedHash(cookieKey[:], msg.mac2Input(), storedCookie[:]))
	}
	return msg, state, nil
}

func acceptHandshakeInit(
	responderStaticKeypair *crypto.SecpKeyPair,
	msg *handshakeInitiation,
) (*handshakeState, tai64n, error) {
	responderStaticPublic := responderStaticKeypair.PubKey()
	state := &handshakeState{chainingKey: blake3Hash(construction)}
	ckID := blake3Hash(state.chainingKey[:], identifier)
	state.hash = blake3Hash(ckID[:], responderStaticPublic.Bytes())

	state.mixHash(msg.ephemeralPublic[:])
	remoteEphemeral, err := crypto.SecpPubKeyFromBytes(msg.ephemeralPublic[:])
	if err != nil {
		return nil, tai64n{}, errStaticKeyDecryptionFailed
	}
	state.remoteEphemeral = &remoteEphemeral
	state.receiverIndex = msg.senderIndex

	kdfChain(&state.chainingKey, msg.ephemeralPublic[:])

	// ee = DH(responder_static_priv, remote_ephemeral)
	ecdhEE, err := ecdh(responderStaticKeypair, remoteEphemeral)
	if err != nil {
		return nil, tai64n{}, errStaticKeyDecryptionFailed
	}
	key := kdfChain2(&state.chainingKey, ecdhEE[:])

	prevHash := state.hash
	state.mixHash(msg.encryptedStatic[:], msg.encryptedStaticTag[:])
	k := cipherKeyFromHash(key)
	if err := decryptInPlace(&k, ptrNonce(cipherNonceFromU64(0)), msg.encryptedStatic[:], &msg.encryptedStaticTag, prevHash[:]); err != nil {
		return nil, tai64n{}, errStaticKeyDecryptionFailed
	}

	remoteStatic, err := crypto.SecpPubKeyFromBytes(msg.encryptedStatic[:])
	if err != nil {
		return nil, tai64n{}, errStaticKeyDecryptionFailed
	}
	state.remoteStatic = &remoteStatic

	// ss = DH(responder_static_priv, remote_static)
	ecdhSS, err := ecdh(responderStaticKeypair, remoteStatic)
	if err != nil {
		return nil, tai64n{}, errStaticKeyDecryptionFailed
	}
	key = kdfChain2(&state.chainingKey, ecdhSS[:])

	prevHash = state.hash
	state.mixHash(msg.encryptedTimestamp[:], msg.encryptedTimestampTag[:])
	k = cipherKeyFromHash(key)
	if err := decryptInPlace(&k, ptrNonce(cipherNonceFromU64(0)), msg.encryptedTimestamp[:], &msg.encryptedTimestampTag, prevHash[:]); err != nil {
		return nil, tai64n{}, errTimestampDecryptionFailed
	}

	timestamp := tai64nFromBytes(msg.encryptedTimestamp[:])
	if !timestamp.valid() {
		return nil, tai64n{}, errInvalidTimestamp
	}
	return state, timestamp, nil
}

func sendHandshakeResponse(
	r rng,
	localSessionIndex uint32,
	state *handshakeState,
	psk [32]byte,
	storedCookie *[16]byte,
) (*handshakeResponse, transportKeys, error) {
	ephemeralKeypair, err := generateKeyPair(r)
	if err != nil {
		return nil, transportKeys{}, err
	}
	ephemeralPublic := ephemeralKeypair.PubKey()
	state.senderIndex = localSessionIndex
	initiatorStaticPublic := *state.remoteStatic // set by acceptHandshakeInit

	msg := &handshakeResponse{
		senderIndex:     localSessionIndex,
		receiverIndex:   state.receiverIndex,
		ephemeralPublic: ephemeralPublic,
	}

	state.mixHash(ephemeralPublic[:])
	kdfChain(&state.chainingKey, ephemeralPublic[:])

	remoteEphemeral := *state.remoteEphemeral

	// ee = DH(resp_eph_priv, remote_eph)
	ecdhEE, err := ecdh(ephemeralKeypair, remoteEphemeral)
	if err != nil {
		return nil, transportKeys{}, err
	}
	kdfChain(&state.chainingKey, ecdhEE[:])

	// se = DH(resp_eph_priv, initiator_static)
	ecdhSE, err := ecdh(ephemeralKeypair, initiatorStaticPublic)
	if err != nil {
		return nil, transportKeys{}, err
	}
	kdfChain(&state.chainingKey, ecdhSE[:])

	// mix psk
	temp := keyedHash(state.chainingKey[:], psk[:])
	state.chainingKey = keyedHash(temp[:], []byte{0x01})
	temp2 := keyedHash(temp[:], append(state.chainingKey[:], 0x02))
	key := keyedHash(temp[:], append(temp2[:], 0x03))

	state.mixHash(temp2[:])

	k := cipherKeyFromHash(key)
	msg.encryptedNothingTag = encryptInPlace(&k, ptrNonce(cipherNonceFromU64(0)), nil, state.hash[:])
	state.mixHash(msg.encryptedNothingTag[:])

	macKey := blake3Hash(labelMAC1, initiatorStaticPublic.Bytes())
	msg.mac1 = macTagFromHash(keyedHash(macKey[:], msg.mac1Input()))
	if storedCookie != nil {
		cookieKey := blake3Hash(labelCookie, initiatorStaticPublic.Bytes())
		msg.mac2 = macTagFromHash(keyedHash(cookieKey[:], msg.mac2Input(), storedCookie[:]))
	}
	return msg, deriveTransportKeys(state.chainingKey, false), nil
}

func acceptHandshakeResponse(
	initiatorStaticKeypair *crypto.SecpKeyPair,
	initiatorEphemeralPrivate *crypto.SecpKeyPair,
	initiatorHash hashOutput,
	initiatorChainingKey hashOutput,
	msg *handshakeResponse,
	psk [32]byte,
) (transportKeys, error) {
	remoteEphemeral, err := crypto.SecpPubKeyFromBytes(msg.ephemeralPublic[:])
	if err != nil {
		return transportKeys{}, errStaticKeyDecryptionFailed
	}
	handshakeHash := blake3Hash(initiatorHash[:], msg.ephemeralPublic[:])

	temp := keyedHash(initiatorChainingKey[:], msg.ephemeralPublic[:])
	chainingKey := keyedHash(temp[:], []byte{0x01})

	ecdhEE, err := ecdh(initiatorEphemeralPrivate, remoteEphemeral)
	if err != nil {
		return transportKeys{}, errStaticKeyDecryptionFailed
	}
	temp = keyedHash(chainingKey[:], ecdhEE[:])
	chainingKey = keyedHash(temp[:], []byte{0x01})

	ecdhSE, err := ecdh(initiatorStaticKeypair, remoteEphemeral)
	if err != nil {
		return transportKeys{}, errStaticKeyDecryptionFailed
	}
	temp = keyedHash(chainingKey[:], ecdhSE[:])
	chainingKey = keyedHash(temp[:], []byte{0x01})

	temp = keyedHash(chainingKey[:], psk[:])
	chainingKey = keyedHash(temp[:], []byte{0x01})
	temp2 := keyedHash(temp[:], append(chainingKey[:], 0x02))
	key := keyedHash(temp[:], append(temp2[:], 0x03))
	handshakeHash = blake3Hash(handshakeHash[:], temp2[:])

	k := cipherKeyFromHash(key)
	var emptyTag = msg.encryptedNothingTag
	if err := decryptInPlace(&k, ptrNonce(cipherNonceFromU64(0)), nil, &emptyTag, handshakeHash[:]); err != nil {
		return transportKeys{}, errEmptyMessageDecryptFailed
	}
	return deriveTransportKeys(chainingKey, true), nil
}

// deriveTransportKeys — temp1 = K(ck, ""); T1 = K(temp1, 0x01); T2 = K(temp1, T1||0x02).
func deriveTransportKeys(chainingKey hashOutput, isInitiator bool) transportKeys {
	temp1 := keyedHash(chainingKey[:], nil)
	t1 := keyedHash(temp1[:], []byte{0x01})
	t2 := keyedHash(temp1[:], append(t1[:], 0x02))

	if isInitiator {
		return transportKeys{sendKey: cipherKeyFromHash(t1), recvKey: cipherKeyFromHash(t2)}
	}
	return transportKeys{sendKey: cipherKeyFromHash(t2), recvKey: cipherKeyFromHash(t1)}
}

func ptrNonce(n cipherNonce) *cipherNonce { return &n }

func (s *handshakeState) receiverIndexAsSessionIndex() SessionIndex {
	return SessionIndex(s.receiverIndex)
}
