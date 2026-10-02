package wireauth

// Ported from monad-bft/monad-wireauth/src/protocol/cookies.rs and src/cookie.rs.
// WireGuard-style cookie challenge/response for DoS mitigation.

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
)

var errCookieDecryptionFailed = errors.New("cookie decryption failed")

// sendCookieReply builds a CookieReply encrypting `cookie` under
// hash(LABEL_COOKIE || responder_static) with a nonce derived from the
// responder's nonce_secret + counter.
func sendCookieReply(
	nonceSecret *[32]byte,
	nonceCounter uint64, // upstream u128 counter, low 64 bits used in practice
	responderStaticPublic crypto.SecpPubKey,
	msgSenderIndex uint32,
	msgMAC1 [16]byte,
	cookie [16]byte,
) *cookieReply {
	var nonceLE [16]byte
	binary.LittleEndian.PutUint64(nonceLE[:8], nonceCounter)
	binary.LittleEndian.PutUint64(nonceLE[8:], 0)
	nonceHash := keyedHash(nonceSecret[:], nonceLE[:])
	var nonce cipherNonce
	copy(nonce[:], nonceHash[:16])

	reply := &cookieReply{
		receiverIndex: msgSenderIndex,
		nonce:         nonce,
	}

	tempKey := blake3Hash(labelCookie, responderStaticPublic.Bytes())
	ck := cipherKeyFromHash(tempKey)
	reply.encryptedCookie = cookie
	reply.encryptedCookieTag = encryptInPlace(&ck, &reply.nonce, reply.encryptedCookie[:], msgMAC1[:])
	return reply
}

// acceptCookieReply decrypts the cookie in place and returns it.
func acceptCookieReply(
	responderStaticPublic crypto.SecpPubKey,
	reply *cookieReply,
	msgMAC1 [16]byte,
) ([16]byte, error) {
	tempKey := blake3Hash(labelCookie, responderStaticPublic.Bytes())
	ck := cipherKeyFromHash(tempKey)
	if err := decryptInPlace(&ck, &reply.nonce, reply.encryptedCookie[:], &reply.encryptedCookieTag, msgMAC1[:]); err != nil {
		return [16]byte{}, errCookieDecryptionFailed
	}
	return reply.encryptedCookie, nil
}

// generateCookie = keyed_hash(cookie_secret, nonce_le64 || addr16)[:16].
// IPv4-mapped-in-16: v4 occupies the first 4 bytes of a 16-byte array.
func generateCookie(cookieSecret *[32]byte, nonce uint64, remoteIP netip.Addr) [16]byte {
	var addrBytes [16]byte
	if remoteIP.Is4() {
		a := remoteIP.As4()
		copy(addrBytes[:4], a[:])
	} else {
		a := remoteIP.As16()
		copy(addrBytes[:], a[:])
	}
	var nonceLE [8]byte
	binary.LittleEndian.PutUint64(nonceLE[:], nonce)
	h := keyedHash(cookieSecret[:], nonceLE[:], addrBytes[:])
	var cookie [16]byte
	copy(cookie[:], h[:16])
	return cookie
}

// verifyCookie recomputes the expected cookie and checks the message's mac2.
func verifyCookie(
	cookieSecret *[32]byte,
	nonce uint64,
	remoteIP netip.Addr,
	staticPublic crypto.SecpPubKey,
	m macMessage,
) error {
	expected := generateCookie(cookieSecret, nonce, remoteIP)
	return verifyMAC2(m, staticPublic, expected)
}

// Cookies — the responder-side cookie issuer/verifier (Rust src/cookie.rs).
type cookies struct {
	nonceSecret       [32]byte
	cookieSecret      [32]byte
	nonce             uint64
	localStaticPublic crypto.SecpPubKey
	refreshDuration   time.Duration
}

func newCookies(r rng, localStaticPublic crypto.SecpPubKey, refreshDuration time.Duration) *cookies {
	var c cookies
	if _, err := r.Read(c.cookieSecret[:]); err != nil {
		panic(err)
	}
	if _, err := r.Read(c.nonceSecret[:]); err != nil {
		panic(err)
	}
	c.localStaticPublic = localStaticPublic
	c.refreshDuration = refreshDuration
	return &c
}

// create issues a CookieReply for `message`'s mac1 to `ip`.
func (c *cookies) create(ip netip.Addr, senderIndex uint32, m macMessage, sinceStart time.Duration) *cookieReply {
	timeCounter := uint64(sinceStart / c.refreshDuration)
	cookie := generateCookie(&c.cookieSecret, timeCounter, ip)

	nonceCounter := c.nonce
	c.nonce++
	return sendCookieReply(&c.nonceSecret, nonceCounter, c.localStaticPublic, senderIndex, m.mac1Tag(), cookie)
}

// verify checks the message's mac2 against the cookie valid at sinceStart.
func (c *cookies) verify(remoteIP netip.Addr, m macMessage, sinceStart time.Duration) error {
	timeCounter := uint64(sinceStart / c.refreshDuration)
	return verifyCookie(&c.cookieSecret, timeCounter, remoteIP, c.localStaticPublic, m)
}
