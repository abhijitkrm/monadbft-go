package dataplane

// Ported from monad-bft/monad-dataplane/src/addrlist.rs + ban_expiry.rs.
// Trusted/banned IP bookkeeping. Ban expiry re-checks banned_at so renewals
// extend the ban (upstream semantics preserved).

import (
	"net/netip"
	"sync"
	"time"
)

type ipStatus int

const (
	statusBanned ipStatus = iota
	statusTrusted
	statusUnknown
)

type addrEntry struct {
	trusted  bool
	bannedAt time.Time
	hasBan   bool
}

func (e *addrEntry) isBanned() bool  { return e.hasBan }
func (e *addrEntry) isTrusted() bool { return e.trusted }

// addrlist is safe for concurrent use — readers/writers share the mutex.
type addrlist struct {
	mu      sync.Mutex
	entries map[netip.Addr]*addrEntry
}

func newAddrlist(trusted []netip.Addr) *addrlist {
	a := &addrlist{entries: make(map[netip.Addr]*addrEntry)}
	for _, ip := range trusted {
		a.addTrusted(ip)
	}
	return a
}

func (a *addrlist) addTrusted(ip netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.entries[ip]
	if !ok {
		e = &addrEntry{}
		a.entries[ip] = e
	}
	e.trusted = true
}

func (a *addrlist) removeTrusted(ip netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.entries[ip]; ok {
		e.trusted = false
		if a.statusLocked(ip) == statusUnknown {
			delete(a.entries, ip)
		}
	}
}

func (a *addrlist) ban(ip netip.Addr, at time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.entries[ip]
	if !ok {
		e = &addrEntry{}
		a.entries[ip] = e
	}
	e.bannedAt, e.hasBan = at, true
}

func (a *addrlist) unban(ip netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.entries[ip]; ok {
		e.hasBan = false
		if !e.trusted {
			delete(a.entries, ip)
		}
	}
}

func (a *addrlist) bannedAt(ip netip.Addr) (time.Time, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.entries[ip]; ok && e.hasBan {
		return e.bannedAt, true
	}
	return time.Time{}, false
}

func (a *addrlist) status(ip netip.Addr) ipStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.statusLocked(ip)
}

func (a *addrlist) statusLocked(ip netip.Addr) ipStatus {
	if e, ok := a.entries[ip]; ok {
		if e.isBanned() {
			return statusBanned
		}
		if e.isTrusted() {
			return statusTrusted
		}
	}
	return statusUnknown
}

// banExpiry runs the timed unban loop. Each ban enters a FIFO queue; when the
// head's age reaches banDuration, the entry is unbanned only if its recorded
// banned_at is also older than banDuration (a renewed ban stays).
type banExpiry struct {
	mu          sync.Mutex
	addrlist    *addrlist
	banDuration time.Duration
	queue       []banItem
	timer       *time.Timer
	now         func() time.Time // injectable for tests
}

type banItem struct {
	ip netip.Addr
	at time.Time
}

func newBanExpiry(a *addrlist, banDuration time.Duration) *banExpiry {
	return &banExpiry{addrlist: a, banDuration: banDuration, now: time.Now}
}

// enqueue records a ban for later expiry (Rust: banned_connections.send).
func (b *banExpiry) enqueue(ip netip.Addr, at time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.queue = append(b.queue, banItem{ip, at})
	if b.timer != nil {
		b.timer.Stop()
	}
	head := b.queue[0]
	b.timer = time.AfterFunc(b.banDuration-b.now().Sub(head.at), b.process)
}

func (b *banExpiry) process() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.queue) > 0 {
		head := b.queue[0]
		elapsed := b.now().Sub(head.at)
		if elapsed < b.banDuration {
			b.timer = time.AfterFunc(b.banDuration-elapsed, b.process)
			return
		}
		if bannedAt, ok := b.addrlist.bannedAt(head.ip); ok && b.now().Sub(bannedAt) >= b.banDuration {
			b.addrlist.unban(head.ip)
		}
		b.queue = b.queue[1:]
	}
	b.timer = nil
}
