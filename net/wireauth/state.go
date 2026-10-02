package wireauth

// Ported from monad-bft/monad-wireauth/src/state.rs.
// Session bookkeeping: index allocation and the by-key/by-socket lookups.

import (
	"net/netip"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
)

// roleSessions tracks (current, previous) per role — the two most recent
// session indexes for one direction.
type roleSessions struct {
	current  *sessionSlot
	previous *sessionSlot
}

type sessionSlot struct {
	id      SessionIndex
	created time.Duration
}

func (r *roleSessions) push(id SessionIndex, created time.Duration) (SessionIndex, bool) {
	var evicted SessionIndex
	var hasEvicted bool
	if r.previous != nil {
		evicted, hasEvicted = r.previous.id, true
	}
	r.previous = r.current
	r.current = &sessionSlot{id: id, created: created}
	return evicted, hasEvicted
}

func (r *roleSessions) remove(id SessionIndex) {
	if r.current != nil && r.current.id == id {
		r.current = r.previous
		r.previous = nil
	} else if r.previous != nil && r.previous.id == id {
		r.previous = nil
	}
}

func (r *roleSessions) isEmpty() bool { return r.current == nil && r.previous == nil }

func (r *roleSessions) slots() []sessionSlot {
	var out []sessionSlot
	if r.current != nil {
		out = append(out, *r.current)
	}
	if r.previous != nil {
		out = append(out, *r.previous)
	}
	return out
}

// establishedSessions holds initiator+responder slots for one peer.
type establishedSessions struct {
	initiator roleSessions
	responder roleSessions
}

// getLatest returns the index of the most recently created current session.
func (e *establishedSessions) getLatest() (SessionIndex, bool) {
	switch {
	case e.initiator.current != nil && e.responder.current != nil:
		if e.initiator.current.created >= e.responder.current.created {
			return e.initiator.current.id, true
		}
		return e.responder.current.id, true
	case e.initiator.current != nil:
		return e.initiator.current.id, true
	case e.responder.current != nil:
		return e.responder.current.id, true
	}
	return 0, false
}

func (e *establishedSessions) isEmpty() bool {
	return e.initiator.isEmpty() && e.responder.isEmpty()
}

// state is the session table. All session indexes are allocated from
// nextSessionIndex, wrapping until a free slot is found.
type state struct {
	initiatingSessions map[SessionIndex]*initiatorState
	respondingSessions map[SessionIndex]*responderState
	transportSessions  map[SessionIndex]*transportState

	lastEstablishedSessionByPublicKey map[crypto.SecpPubKey]*establishedSessions
	lastEstablishedSessionBySocket    map[netip.AddrPort]*establishedSessions

	allocatedIndices map[SessionIndex]struct{}
	nextSessionIndex SessionIndex

	initiatedSessionByPeer map[crypto.SecpPubKey]SessionIndex
	acceptedSessionsByPeer map[crypto.SecpPubKey]map[SessionIndex]struct{}
	ipSessionCounts        map[netip.Addr]int
	totalSessions          int
}

func newState() *state {
	return &state{
		initiatingSessions:                make(map[SessionIndex]*initiatorState),
		respondingSessions:                make(map[SessionIndex]*responderState),
		transportSessions:                 make(map[SessionIndex]*transportState),
		lastEstablishedSessionByPublicKey: make(map[crypto.SecpPubKey]*establishedSessions),
		lastEstablishedSessionBySocket:    make(map[netip.AddrPort]*establishedSessions),
		allocatedIndices:                  make(map[SessionIndex]struct{}),
		initiatedSessionByPeer:            make(map[crypto.SecpPubKey]SessionIndex),
		acceptedSessionsByPeer:            make(map[crypto.SecpPubKey]map[SessionIndex]struct{}),
		ipSessionCounts:                   make(map[netip.Addr]int),
	}
}

func (s *state) initiatedSessionsCount() int { return len(s.initiatingSessions) }

func (s *state) getTransportMut(index SessionIndex) *transportState {
	return s.transportSessions[index]
}

func (s *state) hasTransportByPublicKey(pub crypto.SecpPubKey) bool {
	sess := s.lastEstablishedSessionByPublicKey[pub]
	if sess == nil {
		return false
	}
	id, ok := sess.getLatest()
	if !ok {
		return false
	}
	_, ok = s.transportSessions[id]
	return ok
}

func (s *state) hasAnySessionByPublicKey(pub crypto.SecpPubKey) bool {
	if s.hasTransportByPublicKey(pub) {
		return true
	}
	if _, ok := s.initiatedSessionByPeer[pub]; ok {
		return true
	}
	return len(s.acceptedSessionsByPeer[pub]) > 0
}

func (s *state) hasInitiatorSessionByPublicKey(pub crypto.SecpPubKey) bool {
	_, ok := s.initiatedSessionByPeer[pub]
	return ok
}

func (s *state) hasInitiatorSessionBySocketAndPublicKey(addr netip.AddrPort, pub crypto.SecpPubKey) bool {
	id, ok := s.initiatedSessionByPeer[pub]
	if !ok {
		return false
	}
	init := s.initiatingSessions[id]
	return init != nil && init.common.remoteAddr == addr
}

func (s *state) hasTransportBySocket(addr netip.AddrPort) bool {
	sess := s.lastEstablishedSessionBySocket[addr]
	if sess == nil {
		return false
	}
	id, ok := sess.getLatest()
	if !ok {
		return false
	}
	_, ok = s.transportSessions[id]
	return ok
}

func (s *state) hasTransportBySocketAndPublicKey(addr netip.AddrPort, pub crypto.SecpPubKey) bool {
	sess := s.lastEstablishedSessionBySocket[addr]
	if sess == nil {
		return false
	}
	id, ok := sess.getLatest()
	if !ok {
		return false
	}
	t := s.transportSessions[id]
	return t != nil && t.common.remotePublicKey == pub
}

func (s *state) getTransportByPublicKey(pub crypto.SecpPubKey) *transportState {
	sess := s.lastEstablishedSessionByPublicKey[pub]
	if sess == nil {
		return nil
	}
	id, ok := sess.getLatest()
	if !ok {
		return nil
	}
	return s.transportSessions[id]
}

func (s *state) getSocketByPublicKey(pub crypto.SecpPubKey) (netip.AddrPort, bool) {
	sess := s.lastEstablishedSessionByPublicKey[pub]
	if sess == nil {
		return netip.AddrPort{}, false
	}
	id, ok := sess.getLatest()
	if !ok {
		return netip.AddrPort{}, false
	}
	t := s.transportSessions[id]
	if t == nil {
		return netip.AddrPort{}, false
	}
	return t.common.remoteAddr, true
}

func (s *state) getTransportBySocket(addr netip.AddrPort) *transportState {
	sess := s.lastEstablishedSessionBySocket[addr]
	if sess == nil {
		return nil
	}
	id, ok := sess.getLatest()
	if !ok {
		return nil
	}
	return s.transportSessions[id]
}

// reserveSessionIndex scans forward from nextSessionIndex for a free slot.
// The caller must call commitSessionIndex on success.
func (s *state) reserveSessionIndex() (SessionIndex, bool) {
	start := s.nextSessionIndex
	candidate := start
	for {
		if _, used := s.allocatedIndices[candidate]; !used {
			return candidate, true
		}
		candidate++
		if candidate == start {
			return 0, false
		}
	}
}

func (s *state) commitSessionIndex(index SessionIndex) {
	s.nextSessionIndex = index
	s.nextSessionIndex++
	s.allocatedIndices[index] = struct{}{}
}

func (s *state) insertTransport(id SessionIndex, transport *transportState) {
	remotePublicKey := transport.common.remotePublicKey
	remoteAddr := transport.common.remoteAddr
	created := transport.common.created
	isInitiator := transport.common.isInitiator

	if isInitiator {
		delete(s.initiatingSessions, id)
	} else {
		delete(s.respondingSessions, id)
	}

	var evicted []SessionIndex

	sess := s.lastEstablishedSessionByPublicKey[remotePublicKey]
	if sess == nil {
		sess = &establishedSessions{}
		s.lastEstablishedSessionByPublicKey[remotePublicKey] = sess
	}
	var ev SessionIndex
	var hasEv bool
	if isInitiator {
		ev, hasEv = sess.initiator.push(id, created)
	} else {
		ev, hasEv = sess.responder.push(id, created)
	}
	if hasEv {
		evicted = append(evicted, ev)
	}

	sess = s.lastEstablishedSessionBySocket[remoteAddr]
	if sess == nil {
		sess = &establishedSessions{}
		s.lastEstablishedSessionBySocket[remoteAddr] = sess
	}
	if isInitiator {
		ev, hasEv = sess.initiator.push(id, created)
	} else {
		ev, hasEv = sess.responder.push(id, created)
	}
	if hasEv && !containsSessionIndex(evicted, ev) {
		evicted = append(evicted, ev)
	}

	for _, evictedID := range evicted {
		if session := s.transportSessions[evictedID]; session != nil {
			pk := session.common.remotePublicKey
			addr := session.common.remoteAddr
			s.terminateSession(evictedID, &pk, addr)
		}
	}

	s.transportSessions[id] = transport
}

func containsSessionIndex(l []SessionIndex, x SessionIndex) bool {
	for _, v := range l {
		if v == x {
			return true
		}
	}
	return false
}

func (s *state) terminateSession(id SessionIndex, remotePublicKey *crypto.SecpPubKey, remoteAddr netip.AddrPort) {
	if count, ok := s.ipSessionCounts[remoteAddr.Addr()]; ok {
		count--
		if count <= 0 {
			delete(s.ipSessionCounts, remoteAddr.Addr())
		} else {
			s.ipSessionCounts[remoteAddr.Addr()] = count
		}
	}
	if s.totalSessions > 0 {
		s.totalSessions--
	}

	transport := s.transportSessions[id]
	delete(s.transportSessions, id)
	delete(s.initiatingSessions, id)
	delete(s.respondingSessions, id)
	delete(s.allocatedIndices, id)

	if transport != nil {
		if sess := s.lastEstablishedSessionBySocket[remoteAddr]; sess != nil {
			if transport.common.isInitiator {
				sess.initiator.remove(id)
			} else {
				sess.responder.remove(id)
			}
			if sess.isEmpty() {
				delete(s.lastEstablishedSessionBySocket, remoteAddr)
			}
		}
		if sess := s.lastEstablishedSessionByPublicKey[*remotePublicKey]; sess != nil {
			if transport.common.isInitiator {
				sess.initiator.remove(id)
			} else {
				sess.responder.remove(id)
			}
			if sess.isEmpty() {
				delete(s.lastEstablishedSessionByPublicKey, *remotePublicKey)
			}
		}
	}

	if initiatedID, ok := s.initiatedSessionByPeer[*remotePublicKey]; ok && initiatedID == id {
		delete(s.initiatedSessionByPeer, *remotePublicKey)
	}
	if set := s.acceptedSessionsByPeer[*remotePublicKey]; set != nil {
		delete(set, id)
		if len(set) == 0 {
			delete(s.acceptedSessionsByPeer, *remotePublicKey)
		}
	}
}

func (s *state) getInitiatorMut(index SessionIndex) *initiatorState {
	return s.initiatingSessions[index]
}

func (s *state) getResponderMut(index SessionIndex) *responderState {
	return s.respondingSessions[index]
}

func (s *state) getInitiatorByPublicKeyMut(pub crypto.SecpPubKey) *initiatorState {
	id, ok := s.initiatedSessionByPeer[pub]
	if !ok {
		return nil
	}
	return s.initiatingSessions[id]
}

func (s *state) removeInitiator(index SessionIndex) *initiatorState {
	session, ok := s.initiatingSessions[index]
	if !ok {
		return nil
	}
	delete(s.initiatingSessions, index)
	remotePublicKey := session.common.remotePublicKey
	if stored, ok := s.initiatedSessionByPeer[remotePublicKey]; ok && stored == index {
		delete(s.initiatedSessionByPeer, remotePublicKey)
	}
	return session
}

func (s *state) removeResponder(index SessionIndex) *responderState {
	session, ok := s.respondingSessions[index]
	if !ok {
		return nil
	}
	delete(s.respondingSessions, index)
	remotePublicKey := session.transport.common.remotePublicKey
	if set := s.acceptedSessionsByPeer[remotePublicKey]; set != nil {
		delete(set, index)
		if len(set) == 0 {
			delete(s.acceptedSessionsByPeer, remotePublicKey)
		}
	}
	return session
}

func (s *state) insertInitiator(index SessionIndex, session *initiatorState, remoteKey crypto.SecpPubKey) {
	s.initiatingSessions[index] = session
	s.initiatedSessionByPeer[remoteKey] = index
	s.ipSessionCounts[session.common.remoteAddr.Addr()]++
	s.totalSessions++
}

func (s *state) insertResponder(index SessionIndex, session *responderState, remoteKey crypto.SecpPubKey) {
	s.respondingSessions[index] = session
	set := s.acceptedSessionsByPeer[remoteKey]
	if set == nil {
		set = make(map[SessionIndex]struct{})
		s.acceptedSessionsByPeer[remoteKey] = set
	}
	set[index] = struct{}{}
	s.ipSessionCounts[session.transport.common.remoteAddr.Addr()]++
	s.totalSessions++
}

func (s *state) lookupCookieFromInitiatedSessions(remoteKey crypto.SecpPubKey) *[16]byte {
	id, ok := s.initiatedSessionByPeer[remoteKey]
	if !ok {
		return nil
	}
	sess := s.initiatingSessions[id]
	if sess == nil {
		return nil
	}
	return sess.common.storedCookie
}

func (s *state) lookupCookieFromAcceptedSessions(remoteKey crypto.SecpPubKey) *[16]byte {
	for id := range s.acceptedSessionsByPeer[remoteKey] {
		if sess := s.respondingSessions[id]; sess != nil && sess.transport.common.storedCookie != nil {
			return sess.transport.common.storedCookie
		}
	}
	return nil
}

// getMaxTimestamp returns the newest initiator timestamp seen for remoteKey
// across accepted sessions and the open responder transport session.
func (s *state) getMaxTimestamp(remoteKey crypto.SecpPubKey) *tai64n {
	var max *tai64n
	for id := range s.acceptedSessionsByPeer[remoteKey] {
		if sess := s.respondingSessions[id]; sess != nil && sess.transport.common.initiatorTimestamp != nil {
			if max == nil || sess.transport.common.initiatorTimestamp.cmp(*max) > 0 {
				cp := *sess.transport.common.initiatorTimestamp
				max = &cp
			}
		}
	}
	if sess := s.lastEstablishedSessionByPublicKey[remoteKey]; sess != nil && sess.responder.current != nil {
		if t := s.transportSessions[sess.responder.current.id]; t != nil && t.common.initiatorTimestamp != nil {
			if max == nil || t.common.initiatorTimestamp.cmp(*max) > 0 {
				cp := *t.common.initiatorTimestamp
				max = &cp
			}
		}
	}
	return max
}

// terminateByPublicKey removes every session (any stage) for remoteKey,
// returning the affected socket addresses.
func (s *state) terminateByPublicKey(pub crypto.SecpPubKey) []netip.AddrPort {
	ids := make(map[SessionIndex]struct{})
	if id, ok := s.initiatedSessionByPeer[pub]; ok {
		ids[id] = struct{}{}
	}
	for id := range s.acceptedSessionsByPeer[pub] {
		ids[id] = struct{}{}
	}
	if sess := s.lastEstablishedSessionByPublicKey[pub]; sess != nil {
		for _, sl := range sess.initiator.slots() {
			ids[sl.id] = struct{}{}
		}
		for _, sl := range sess.responder.slots() {
			ids[sl.id] = struct{}{}
		}
	}

	var addrs []netip.AddrPort
	for id := range ids {
		var addr netip.AddrPort
		found := false
		if t := s.transportSessions[id]; t != nil {
			addr, found = t.common.remoteAddr, true
		} else if i := s.initiatingSessions[id]; i != nil {
			addr, found = i.common.remoteAddr, true
		} else if r := s.respondingSessions[id]; r != nil {
			addr, found = r.transport.common.remoteAddr, true
		}
		if found {
			s.terminateSession(id, &pub, addr)
			addrs = append(addrs, addr)
		}
	}
	return addrs
}
