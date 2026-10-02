package wireauth

// Ported from monad-bft/monad-wireauth/src/session/transport.rs.

import (
	"time"
)

// transportState is an established session — send/recv keys + replay filter.
type transportState struct {
	remoteIndex  SessionIndex
	sendKey      cipherKey
	sendNonce    uint64
	recvKey      cipherKey
	replayFilter replayFilter
	common       sessionState
}

func newTransportState(remoteIndex SessionIndex, sendKey, recvKey cipherKey, common sessionState) *transportState {
	return &transportState{
		remoteIndex: remoteIndex,
		sendKey:     sendKey,
		recvKey:     recvKey,
		common:      common,
	}
}

// encrypt encrypts plaintext in place, returns the packet header + renewed
// keepalive timer.
func (t *transportState) encrypt(
	r rng,
	config *Config,
	now time.Duration,
	plaintext []byte,
) (dataPacketHeader, RenewedTimer) {
	nonce := cipherNonceFromU64(t.sendNonce)
	tag := encryptInPlace(&t.sendKey, &nonce, plaintext, nil)
	header := dataPacketHeader{
		receiverIndex: uint32(t.remoteIndex),
		nonce:         t.sendNonce,
		tag:           tag,
	}
	t.sendNonce++

	if len(plaintext) > 0 {
		t.common.resetGCDeadline(now, config.GCIdleTimeout)
	}

	keepaliveTimer := t.common.resetKeepalive(now,
		addJitter(r, config.KeepaliveInterval, config.KeepaliveJitter))

	nextDeadline, _ := t.common.nextDeadline()
	return header, RenewedTimer{
		Previous: keepaliveTimer.Previous,
		HasPrev:  keepaliveTimer.HasPrev,
		Current:  nextDeadline,
	}
}

// decrypt verifies the replay filter, decrypts payload in place, returns the
// renewed session timer + plaintext slice (aliases packet payload).
func (t *transportState) decrypt(
	config *Config,
	now time.Duration,
	pkt dataPacket,
) (RenewedTimer, []byte, error) {
	if err := t.replayFilter.check(pkt.header.nonce); err != nil {
		return RenewedTimer{}, nil, err
	}
	counter := pkt.header.nonce
	tag := pkt.header.tag
	nonce := cipherNonceFromU64(counter)
	if err := decryptInPlace(&t.recvKey, &nonce, pkt.payload, &tag, nil); err != nil {
		return RenewedTimer{}, nil, ErrInvalidMac
	}
	t.replayFilter.update(counter)

	if len(pkt.payload) > 0 {
		t.common.resetGCDeadline(now, config.GCIdleTimeout)
	}

	sessionTimer := t.common.resetSessionTimeout(now, config.SessionTimeout)
	nextDeadline, _ := t.common.nextDeadline()
	return RenewedTimer{
		Previous: sessionTimer.Previous,
		HasPrev:  sessionTimer.HasPrev,
		Current:  nextDeadline,
	}, pkt.payload, nil
}

// tick evaluates deadlines. Returns (nextDeadline, keepalive, rekey, terminated).
func (t *transportState) tick(
	r rng,
	config *Config,
	now time.Duration,
) (*time.Duration, *MessageEvent, *RekeyEvent, *TerminatedEvent) {
	// Termination takes precedence over all other work.
	if t.common.hasMaxSessionDuration && t.common.maxSessionDurationDeadline <= now {
		t.common.clearMaxSessionDur()
		terminated, _ := t.common.handleSessionTimeout()
		return nil, nil, nil, &terminated
	}
	if t.common.hasSessionTimeout && t.common.sessionTimeoutDeadline <= now {
		t.common.clearSessionTimeout()
		terminated, rekey := t.common.handleSessionTimeout()
		return nil, nil, rekey, &terminated
	}
	if t.common.hasGC && t.common.gcDeadline <= now {
		t.common.clearGCDeadline()
		return nil, nil, nil, &TerminatedEvent{
			RemotePublicKey: t.common.remotePublicKey,
			RemoteAddr:      t.common.remoteAddr,
		}
	}

	var message *MessageEvent
	var rekey *RekeyEvent

	if t.common.hasKeepalive && t.common.keepaliveDeadline <= now {
		t.common.clearKeepalive()
		header, _ := t.encrypt(r, config, now, nil)
		message = &MessageEvent{
			RemoteAddr: t.common.remoteAddr,
			Header:     header,
		}
	}

	if t.common.hasRekey && t.common.rekeyDeadline <= now {
		t.common.clearRekey()
		rekey = &RekeyEvent{
			RemotePublicKey: t.common.remotePublicKey,
			RemoteAddr:      t.common.remoteAddr,
			RetryAttempts:   t.common.retryAttempts,
			StoredCookie:    t.common.storedCookie,
		}
	}

	nextDeadline, ok := t.common.nextDeadline()
	var next *time.Duration
	if ok {
		next = &nextDeadline
	}
	return next, message, rekey, nil
}
