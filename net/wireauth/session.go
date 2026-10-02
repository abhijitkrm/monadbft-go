package wireauth

// Ported from monad-bft/monad-wireauth/src/session/common.rs.

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
)

// TerminatedEvent signals a session teardown.
type TerminatedEvent struct {
	RemotePublicKey crypto.SecpPubKey
	RemoteAddr      netip.AddrPort
}

// SessionTimeoutResult bundles the effects of a session-timeout firing.
type SessionTimeoutResult struct {
	Terminated TerminatedEvent
	Rekey      *RekeyEvent
}

// RekeyEvent asks the API layer to start a fresh handshake.
type RekeyEvent struct {
	RemotePublicKey crypto.SecpPubKey
	RemoteAddr      netip.AddrPort
	RetryAttempts   uint64
	StoredCookie    *[16]byte
}

// MessageEvent is an outbound packet produced by session timers (keepalive).
type MessageEvent struct {
	RemoteAddr netip.AddrPort
	Header     dataPacketHeader
}

// RenewedTimer records a deadline change: Previous was replaced by Current.
type RenewedTimer struct {
	Previous time.Duration // zero value + HasPrevious flag
	HasPrev  bool
	Current  time.Duration
}

// Session errors.
var (
	ErrNonceOutsideWindow = errors.New("nonce outside replay window")
	ErrNonceDuplicate     = errors.New("duplicate nonce")
	ErrInvalidMac         = errors.New("MAC verification failed")
	ErrInvalidCookie      = errors.New("cookie validation failed")
	ErrHandshake          = errors.New("handshake validation failed")
)

func nonceOutsideWindowErr(counter, next uint64) error {
	return fmt.Errorf("%w: counter %d outside window (next=%d)", ErrNonceOutsideWindow, counter, next)
}

// sessionState holds the timers and identity shared by all session kinds.
// Deadlines are absolute durations since Context start (Rust Option<Duration>
// → zero + bool).
type sessionState struct {
	keepaliveDeadline          time.Duration
	hasKeepalive               bool
	rekeyDeadline              time.Duration
	hasRekey                   bool
	sessionTimeoutDeadline     time.Duration
	hasSessionTimeout          bool
	maxSessionDurationDeadline time.Duration
	hasMaxSessionDuration      bool
	gcDeadline                 time.Duration
	hasGC                      bool

	storedCookie       *[16]byte
	lastHandshakeMAC1  *[16]byte
	retryAttempts      uint64
	initiatorTimestamp *tai64n
	remoteAddr         netip.AddrPort
	remotePublicKey    crypto.SecpPubKey
	localIndex         SessionIndex
	created            time.Duration
	isInitiator        bool
}

func newSessionState(
	remoteAddr netip.AddrPort,
	remotePublicKey crypto.SecpPubKey,
	localIndex SessionIndex,
	created time.Duration,
	retryAttempts uint64,
	initiatorTimestamp *tai64n,
	isInitiator bool,
) sessionState {
	return sessionState{
		retryAttempts:      retryAttempts,
		initiatorTimestamp: initiatorTimestamp,
		remoteAddr:         remoteAddr,
		remotePublicKey:    remotePublicKey,
		localIndex:         localIndex,
		created:            created,
		isInitiator:        isInitiator,
	}
}

func (s *sessionState) resetKeepalive(now, d time.Duration) RenewedTimer {
	prev, has := s.keepaliveDeadline, s.hasKeepalive
	s.keepaliveDeadline = now + d
	s.hasKeepalive = true
	return RenewedTimer{Previous: prev, HasPrev: has, Current: s.keepaliveDeadline}
}

func (s *sessionState) resetRekey(now, d time.Duration) {
	s.rekeyDeadline = now + d
	s.hasRekey = true
}

func (s *sessionState) resetSessionTimeout(now, d time.Duration) RenewedTimer {
	prev, has := s.sessionTimeoutDeadline, s.hasSessionTimeout
	s.sessionTimeoutDeadline = now + d
	s.hasSessionTimeout = true
	return RenewedTimer{Previous: prev, HasPrev: has, Current: s.sessionTimeoutDeadline}
}

func (s *sessionState) clearKeepalive()      { s.hasKeepalive = false }
func (s *sessionState) clearRekey()          { s.hasRekey = false }
func (s *sessionState) clearSessionTimeout() { s.hasSessionTimeout = false }
func (s *sessionState) clearMaxSessionDur()  { s.hasMaxSessionDuration = false }
func (s *sessionState) clearGCDeadline()     { s.hasGC = false }
func (s *sessionState) setMaxSessionDur(now, d time.Duration) {
	s.maxSessionDurationDeadline = now + d
	s.hasMaxSessionDuration = true
}

func (s *sessionState) resetGCDeadline(now, d time.Duration) {
	s.gcDeadline = now + d
	s.hasGC = true
}

func (s *sessionState) nextDeadline() (time.Duration, bool) {
	var min time.Duration
	found := false
	for _, d := range []struct {
		v  time.Duration
		ok bool
	}{
		{s.keepaliveDeadline, s.hasKeepalive},
		{s.rekeyDeadline, s.hasRekey},
		{s.sessionTimeoutDeadline, s.hasSessionTimeout},
		{s.maxSessionDurationDeadline, s.hasMaxSessionDuration},
		{s.gcDeadline, s.hasGC},
	} {
		if d.ok && (!found || d.v < min) {
			min, found = d.v, true
		}
	}
	return min, found
}

// handleCookie accepts a CookieReply and stores the decrypted cookie.
func (s *sessionState) handleCookie(reply *cookieReply) error {
	if s.lastHandshakeMAC1 == nil {
		return fmt.Errorf("%w: no last_handshake_mac1 stored", ErrInvalidCookie)
	}
	cookie, err := acceptCookieReply(s.remotePublicKey, reply, *s.lastHandshakeMAC1)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCookie, err)
	}
	s.storedCookie = &cookie
	return nil
}

// handleSessionTimeout produces the terminated event and, for initiators,
// optionally a rekey request. Mirrors SessionState::handle_session_timeout.
func (s *sessionState) handleSessionTimeout() (TerminatedEvent, *RekeyEvent) {
	terminated := TerminatedEvent{
		RemotePublicKey: s.remotePublicKey,
		RemoteAddr:      s.remoteAddr,
	}
	if !s.isInitiator {
		return terminated, nil
	}
	shouldRetry := s.retryAttempts > 0 || s.retryAttempts == RetryAlways
	if s.retryAttempts > 0 && s.retryAttempts != RetryAlways {
		s.retryAttempts--
	}
	if !shouldRetry {
		return terminated, nil
	}
	return terminated, &RekeyEvent{
		RemotePublicKey: s.remotePublicKey,
		RemoteAddr:      s.remoteAddr,
		RetryAttempts:   s.retryAttempts,
		StoredCookie:    s.storedCookie,
	}
}

// addJitter returns base + uniform [0, jitter] (millisecond granularity).
func addJitter(r rng, base, jitter time.Duration) time.Duration {
	jitterMillis := uint64(jitter / time.Millisecond)
	randomJitter := r.Uint64() % (jitterMillis + 1)
	return base + time.Duration(randomJitter)*time.Millisecond
}
