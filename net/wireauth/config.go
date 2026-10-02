package wireauth

// Ported from monad-bft/monad-wireauth/src/config/mod.rs.

import "time"

const (
	// RetryAlways means rekey attempts never stop (Rust RETRY_ALWAYS = u64::MAX).
	RetryAlways = ^uint64(0)
	// DefaultRetryAttempts mirrors upstream's default of 3.
	DefaultRetryAttempts = 3
)

// Config — all durations are measured against Context.DurationSinceStart.
type Config struct {
	// idle time before session expires (reset on any packet exchange)
	SessionTimeout time.Duration
	// randomization to prevent thundering herd on timeout
	SessionTimeoutJitter time.Duration
	// send empty packet after this idle time to maintain session
	KeepaliveInterval time.Duration
	// randomization to spread keepalive traffic
	KeepaliveJitter time.Duration
	// time before initiating new handshake to rotate keys
	RekeyInterval time.Duration
	// randomization to avoid synchronized rekey storms
	RekeyJitter time.Duration
	// absolute session lifetime regardless of activity (forces rekey)
	MaxSessionDuration time.Duration
	// global rate limit (per reset interval) for initiations without a valid cookie
	HandshakeCookieUnverifiedRateLimit uint64
	// global rate limit (per reset interval) for initiations with a valid cookie
	HandshakeCookieVerifiedRateLimit uint64
	// window for handshake rate limiting
	HandshakeRateResetInterval time.Duration
	// max outbound connect attempts per window (dos protection)
	ConnectRateLimit uint64
	// window for outbound connect rate limiting
	ConnectRateResetInterval time.Duration
	// cookie validity period (responder rotates cookie key)
	CookieRefreshDuration time.Duration
	// below this threshold, accept all handshakes without cookie challenge
	LowWatermarkSessions int
	// at this threshold, drop all incoming handshake requests
	HighWatermarkSessions int
	// limit concurrent sessions from single ip (anti-amplification)
	MaxSessionsPerIP int
	// time window for counting handshake requests per ip
	IPRateLimitWindow time.Duration
	// lru cache size for tracking handshake request timestamps per ip
	IPHistoryCapacity int
	// optional pre-shared key mixed into handshake for additional auth
	PSK [32]byte
	// max concurrent initiated sessions (handshakes in progress)
	MaxInitiatedSessions int
	// max bytes of buffered messages per initiated session
	MaxBufferedBytesPerSession int
	// idle time (without useful data) before session is garbage collected
	GCIdleTimeout time.Duration
	// cap how many expired timers are processed per tick (dos protection)
	MaxExpiredTimersPerTick int
}

func DefaultConfig() Config {
	return Config{
		SessionTimeout:                     10 * time.Second,
		SessionTimeoutJitter:               1 * time.Second,
		KeepaliveInterval:                  3 * time.Second,
		KeepaliveJitter:                    300 * time.Millisecond,
		RekeyInterval:                      6 * time.Hour,
		RekeyJitter:                        60 * time.Second,
		MaxSessionDuration:                 6*time.Hour + 5*time.Minute,
		HandshakeCookieUnverifiedRateLimit: 300,
		HandshakeCookieVerifiedRateLimit:   300,
		HandshakeRateResetInterval:         1 * time.Second,
		ConnectRateLimit:                   300,
		ConnectRateResetInterval:           1 * time.Second,
		CookieRefreshDuration:              120 * time.Second,
		LowWatermarkSessions:               5_000,
		HighWatermarkSessions:              40_000,
		MaxSessionsPerIP:                   4,
		IPRateLimitWindow:                  10 * time.Second,
		IPHistoryCapacity:                  1_000_000,
		MaxInitiatedSessions:               1000,
		MaxBufferedBytesPerSession:         128 * 1024,
		GCIdleTimeout:                      120 * time.Second,
		MaxExpiredTimersPerTick:            10_000,
	}
}
