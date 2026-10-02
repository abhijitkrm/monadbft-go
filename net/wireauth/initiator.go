package wireauth

// Ported from monad-bft/monad-wireauth/src/session/initiator.rs.

import (
	"net/netip"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
)

// validatedHandshakeResponse carries the transport keys + remote index out of
// response validation.
type validatedHandshakeResponse struct {
	transportKeys transportKeys
	remoteIndex   SessionIndex
}

// initiatorState is a session whose handshake initiation is in flight.
type initiatorState struct {
	handshakeState   handshakeState
	common           sessionState
	bufferedMessages [][]byte
	bufferedBytes    int
}

func newInitiatorState(
	r rng,
	systemTime time.Time,
	now time.Duration,
	config *Config,
	localSessionIndex SessionIndex,
	localStaticKey *crypto.SecpKeyPair,
	remoteStaticKey crypto.SecpPubKey,
	remoteAddr netip.AddrPort,
	cookieSecret *[16]byte,
	retryAttempts uint64,
) (*initiatorState, time.Duration, *handshakeInitiation, error) {
	initMsg, hs, err := sendHandshakeInit(
		r,
		tai64nFromTime(systemTime),
		uint32(localSessionIndex),
		localStaticKey,
		remoteStaticKey,
		cookieSecret,
	)
	if err != nil {
		return nil, 0, nil, err
	}

	common := newSessionState(
		remoteAddr, remoteStaticKey, localSessionIndex, now,
		retryAttempts, nil, true,
	)
	common.storedCookie = cookieSecret
	mac1 := [16]byte(initMsg.mac1)
	common.lastHandshakeMAC1 = &mac1

	s := &initiatorState{handshakeState: *hs, common: common}
	s.common.resetSessionTimeout(now,
		addJitter(r, config.SessionTimeout, config.SessionTimeoutJitter))

	timer, _ := s.common.nextDeadline()
	return s, timer, initMsg, nil
}

func (s *initiatorState) validateResponse(
	config *Config,
	localStaticKey *crypto.SecpKeyPair,
	msg *handshakeResponse,
) (*validatedHandshakeResponse, error) {
	keys, err := acceptHandshakeResponse(
		localStaticKey,
		s.handshakeState.ephemeralPrivate,
		s.handshakeState.hash,
		s.handshakeState.chainingKey,
		msg,
		config.PSK,
	)
	if err != nil {
		return nil, err
	}
	return &validatedHandshakeResponse{
		transportKeys: keys,
		remoteIndex:   SessionIndex(msg.senderIndex),
	}, nil
}

// establish converts the initiator into a transport session and returns
// buffered messages (or a single keepalive if none were buffered).
func (s *initiatorState) establish(
	r rng,
	config *Config,
	now time.Duration,
	vr *validatedHandshakeResponse,
) (*transportState, [][]byte, bool) {
	s.common.resetSessionTimeout(now,
		addJitter(r, config.SessionTimeout, config.SessionTimeoutJitter))
	s.common.resetRekey(now,
		addJitter(r, config.RekeyInterval, config.RekeyJitter))
	s.common.setMaxSessionDur(now, config.MaxSessionDuration)
	s.common.resetGCDeadline(now, config.GCIdleTimeout)

	transport := newTransportState(
		vr.remoteIndex,
		vr.transportKeys.sendKey,
		vr.transportKeys.recvKey,
		s.common,
	)
	if len(s.bufferedMessages) == 0 {
		return transport, [][]byte{{}}, false // single empty keepalive
	}
	return transport, s.bufferedMessages, true
}

func (s *initiatorState) handleCookie(reply *cookieReply) error {
	return s.common.handleCookie(reply)
}

// tick — initiators only check the session timeout deadline.
func (s *initiatorState) tick(now time.Duration) (*time.Duration, *SessionTimeoutResult) {
	if !s.common.hasSessionTimeout || s.common.sessionTimeoutDeadline > now {
		return nil, nil
	}
	s.common.clearSessionTimeout()
	terminated, rekey := s.common.handleSessionTimeout()
	next, ok := s.common.nextDeadline()
	var nextp *time.Duration
	if ok {
		nextp = &next
	}
	return nextp, &SessionTimeoutResult{Terminated: terminated, Rekey: rekey}
}

func (s *initiatorState) bufferMessage(msg []byte) {
	s.bufferedBytes += len(msg) // saturating_add — len can't overflow on 64-bit
	s.bufferedMessages = append(s.bufferedMessages, msg)
}
