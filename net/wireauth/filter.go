package wireauth

// Ported from monad-bft/monad-wireauth/src/filter.rs.
// Admission control: watermarks, cookie rate limits, per-IP limits.

import (
	"container/list"
	"net/netip"
	"time"
)

type filterAction int

const (
	filterPass filterAction = iota
	filterSendCookie
	filterDrop
)

// lru — minimal LRU keyed by IP storing a timestamp (Rust LruCache<IpAddr, Duration>).
type lru struct {
	cap   int
	ll    *list.List
	items map[netip.Addr]*list.Element
}

type lruEntry struct {
	ip    netip.Addr
	value time.Duration
}

func newLRU(cap int) *lru {
	if cap < 1 {
		cap = 1
	}
	return &lru{cap: cap, ll: list.New(), items: make(map[netip.Addr]*list.Element)}
}

func (l *lru) get(ip netip.Addr) (time.Duration, bool) {
	if e, ok := l.items[ip]; ok {
		l.ll.MoveToFront(e)
		return e.Value.(*lruEntry).value, true
	}
	return 0, false
}

// update — get_mut semantics: touch + mutate.
func (l *lru) update(ip netip.Addr, v time.Duration) {
	if e, ok := l.items[ip]; ok {
		l.ll.MoveToFront(e)
		e.Value.(*lruEntry).value = v
		return
	}
	l.put(ip, v)
}

func (l *lru) put(ip netip.Addr, v time.Duration) {
	if e, ok := l.items[ip]; ok {
		l.ll.MoveToFront(e)
		e.Value.(*lruEntry).value = v
		return
	}
	e := l.ll.PushFront(&lruEntry{ip: ip, value: v})
	l.items[ip] = e
	if l.ll.Len() > l.cap {
		old := l.ll.Back()
		if old != nil {
			l.ll.Remove(old)
			delete(l.items, old.Value.(*lruEntry).ip)
		}
	}
}

func (l *lru) len() int { return l.ll.Len() }

type filter struct {
	cookieUnverifiedCounter            uint64
	cookieVerifiedCounter              uint64
	lastReset                          time.Duration
	handshakeCookieUnverifiedRateLimit uint64
	handshakeCookieVerifiedRateLimit   uint64
	handshakeRateResetInterval         time.Duration
	ipRequestHistory                   *lru
	ipRateLimitWindow                  time.Duration
	maxSessionsPerIP                   int
	lowWatermarkSessions               int
	highWatermarkSessions              int
}

func newFilter(cfg *Config) *filter {
	return &filter{
		handshakeCookieUnverifiedRateLimit: cfg.HandshakeCookieUnverifiedRateLimit,
		handshakeCookieVerifiedRateLimit:   cfg.HandshakeCookieVerifiedRateLimit,
		handshakeRateResetInterval:         cfg.HandshakeRateResetInterval,
		ipRequestHistory:                   newLRU(cfg.IPHistoryCapacity),
		ipRateLimitWindow:                  cfg.IPRateLimitWindow,
		maxSessionsPerIP:                   cfg.MaxSessionsPerIP,
		lowWatermarkSessions:               cfg.LowWatermarkSessions,
		highWatermarkSessions:              cfg.HighWatermarkSessions,
	}
}

func (f *filter) tick(now time.Duration) {
	if now >= f.lastReset+f.handshakeRateResetInterval {
		f.cookieUnverifiedCounter = 0
		f.cookieVerifiedCounter = 0
		f.lastReset = now
	}
}

func (f *filter) nextResetTime() time.Duration {
	return f.lastReset + f.handshakeRateResetInterval
}

// apply runs the ordered checks and returns the admission action.
func (f *filter) apply(s *state, remoteAddr netip.AddrPort, now time.Duration, cookieValid bool) filterAction {
	totalSessions := s.totalSessions
	ip := remoteAddr.Addr()

	if totalSessions >= f.highWatermarkSessions {
		return filterDrop
	}
	if a := f.checkCookieRateLimit(cookieValid); a != filterPass {
		return a
	}
	if totalSessions < f.lowWatermarkSessions {
		return filterPass
	}
	if !cookieValid {
		return filterSendCookie
	}
	if a := f.checkIPRateLimit(ip, now); a != filterPass {
		return a
	}
	if s.ipSessionCounts[ip] >= f.maxSessionsPerIP {
		return filterDrop
	}
	return filterPass
}

func (f *filter) checkCookieRateLimit(cookieValid bool) filterAction {
	if cookieValid {
		if f.cookieVerifiedCounter >= f.handshakeCookieVerifiedRateLimit {
			return filterDrop
		}
		f.cookieVerifiedCounter++
		return filterPass
	}
	if f.cookieUnverifiedCounter >= f.handshakeCookieUnverifiedRateLimit {
		if f.cookieVerifiedCounter < f.handshakeCookieVerifiedRateLimit {
			return filterSendCookie
		}
		return filterDrop
	}
	f.cookieUnverifiedCounter++
	return filterPass
}

func (f *filter) checkIPRateLimit(ip netip.Addr, now time.Duration) filterAction {
	windowStart := now - f.ipRateLimitWindow
	if windowStart < 0 {
		windowStart = 0
	}
	if last, ok := f.ipRequestHistory.get(ip); ok {
		if last >= windowStart {
			return filterDrop
		}
		f.ipRequestHistory.update(ip, now)
		return filterPass
	}
	f.ipRequestHistory.put(ip, now)
	return filterPass
}
