package wireauth

// Ported from monad-bft/monad-wireauth/src/session/responder.rs.

import (
	"net/netip"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
)

// validatedHandshakeInit is the decrypted initiator identity + transcript.
type validatedHandshakeInit struct {
	handshakeState  handshakeState
	remotePublicKey crypto.SecpPubKey
	timestamp       tai64n
}

// responderState is a session that answered an initiation but has not yet
// received a data packet proving the initiator owns the keys.
type responderState struct {
	transport *transportState
}

func validateInit(
	localStaticKey *crypto.SecpKeyPair,
	msg *handshakeInitiation,
) (*validatedHandshakeInit, error) {
	hs, timestamp, err := acceptHandshakeInit(localStaticKey, msg)
	if err != nil {
		return nil, err
	}
	if hs.remoteStatic == nil {
		return nil, errInvalidPublicKey
	}
	return &validatedHandshakeInit{
		handshakeState:  *hs,
		remotePublicKey: *hs.remoteStatic,
		timestamp:       timestamp,
	}, nil
}

func newResponderState(
	r rng,
	now time.Duration,
	config *Config,
	localSessionIndex SessionIndex,
	storedCookie *[16]byte,
	vi *validatedHandshakeInit,
	remoteAddr netip.AddrPort,
) (*responderState, time.Duration, *handshakeResponse, error) {
	hs := vi.handshakeState
	responseMsg, transportKeys, err := sendHandshakeResponse(
		r, uint32(localSessionIndex), &hs, config.PSK, storedCookie,
	)
	if err != nil {
		return nil, 0, nil, err
	}
	responseMAC1 := [16]byte(responseMsg.mac1)

	common := newSessionState(
		remoteAddr, vi.remotePublicKey, localSessionIndex, now,
		0, &vi.timestamp, false,
	)
	common.lastHandshakeMAC1 = &responseMAC1

	common.resetSessionTimeout(now,
		addJitter(r, config.SessionTimeout, config.SessionTimeoutJitter))
	timer, _ := common.nextDeadline()

	transport := newTransportState(
		hs.receiverIndexAsSessionIndex(),
		transportKeys.sendKey,
		transportKeys.recvKey,
		common,
	)
	return &responderState{transport: transport}, timer, responseMsg, nil
}

func (s *responderState) decrypt(
	config *Config,
	now time.Duration,
	pkt dataPacket,
) (RenewedTimer, []byte, error) {
	return s.transport.decrypt(config, now, pkt)
}

// establish promotes the responder to a full transport session once the first
// authenticated data packet arrives.
func (s *responderState) establish(
	r rng,
	config *Config,
	now time.Duration,
) (*transportState, time.Duration) {
	s.transport.common.resetSessionTimeout(now, config.SessionTimeout)
	s.transport.common.resetKeepalive(now,
		addJitter(r, config.KeepaliveInterval, config.KeepaliveJitter))
	s.transport.common.setMaxSessionDur(now, config.MaxSessionDuration)
	s.transport.common.resetGCDeadline(now, config.GCIdleTimeout)
	timer, _ := s.transport.common.nextDeadline()
	return s.transport, timer
}

func (s *responderState) tick(now time.Duration) (*time.Duration, *SessionTimeoutResult) {
	if !s.transport.common.hasSessionTimeout || s.transport.common.sessionTimeoutDeadline > now {
		return nil, nil
	}
	s.transport.common.clearSessionTimeout()
	terminated, rekey := s.transport.common.handleSessionTimeout()
	next, ok := s.transport.common.nextDeadline()
	var nextp *time.Duration
	if ok {
		nextp = &next
	}
	return nextp, &SessionTimeoutResult{Terminated: terminated, Rekey: rekey}
}

func (s *responderState) handleCookie(reply *cookieReply) error {
	return s.transport.common.handleCookie(reply)
}
