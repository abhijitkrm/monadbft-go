package wireauth

// Ported from monad-bft/monad-wireauth/src/api.rs.
// The public API: connect/encrypt/decrypt/dispatch + packet queue + timers.

import (
	"container/heap"
	"net/netip"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
)

// timerEntry is an ordered (deadline, sessionIndex) pair, Rust's
// BTreeSet<(Duration, SessionIndex)>.
type timerEntry struct {
	deadline     time.Duration
	sessionIndex SessionIndex
	pos          int // heap index
}

type timerHeap struct {
	entries []*timerEntry
	pos     map[timerEntry]int // key lookup uses deadline+index fields
}

func newTimerHeap() *timerHeap {
	return &timerHeap{pos: make(map[timerEntry]int)}
}

type timerKey struct {
	deadline     time.Duration
	sessionIndex SessionIndex
}

// We keep entries sorted min-first by (deadline, index) via container/heap;
// pos maps a key to its entry for removal.

type timerSet struct {
	h     *timerHeap
	byKey map[timerKey]*timerEntry
}

func newTimerSet() *timerSet {
	return &timerSet{h: newTimerHeap(), byKey: make(map[timerKey]*timerEntry)}
}

func (h *timerHeap) Len() int { return len(h.entries) }
func (h *timerHeap) Less(i, j int) bool {
	a, b := h.entries[i], h.entries[j]
	if a.deadline != b.deadline {
		return a.deadline < b.deadline
	}
	return a.sessionIndex < b.sessionIndex
}
func (h *timerHeap) Swap(i, j int) {
	h.entries[i], h.entries[j] = h.entries[j], h.entries[i]
	h.entries[i].pos = i
	h.entries[j].pos = j
}
func (h *timerHeap) Push(x any) {
	e := x.(*timerEntry)
	e.pos = len(h.entries)
	h.entries = append(h.entries, e)
}
func (h *timerHeap) Pop() any {
	old := h.entries
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	h.entries = old[:n-1]
	return e
}

func (ts *timerSet) insert(deadline time.Duration, index SessionIndex) {
	key := timerKey{deadline, index}
	if _, ok := ts.byKey[key]; ok {
		return
	}
	e := &timerEntry{deadline: deadline, sessionIndex: index}
	ts.byKey[key] = e
	heap.Push(ts.h, e)
}

func (ts *timerSet) remove(deadline time.Duration, index SessionIndex) {
	key := timerKey{deadline, index}
	e, ok := ts.byKey[key]
	if !ok {
		return
	}
	delete(ts.byKey, key)
	heap.Remove(ts.h, e.pos)
}

func (ts *timerSet) first() (timerEntry, bool) {
	if ts.h.Len() == 0 {
		return timerEntry{}, false
	}
	return *ts.h.entries[0], true
}

func (ts *timerSet) popFirst() (timerEntry, bool) {
	e, ok := ts.first()
	if !ok {
		return timerEntry{}, false
	}
	ts.remove(e.deadline, e.sessionIndex)
	return e, true
}

func (ts *timerSet) replaceTimer(t RenewedTimer, index SessionIndex) {
	if t.HasPrev {
		ts.remove(t.Previous, index)
	}
	ts.insert(t.Current, index)
}

func (ts *timerSet) len() int { return ts.h.Len() }

// API — one instance per socket. Single-threaded like upstream; callers drive
// Tick() at NextDeadline() and drain NextPacket().
type API struct {
	state                *state
	timers               *timerSet
	packetQueue          []queuedPacket
	config               Config
	localStaticKey       *crypto.SecpKeyPair
	cookies              *cookies
	filter               *filter
	context              Context
	lastTick             *time.Duration
	connectRateCounter   uint64
	connectRateLastReset time.Duration
}

type queuedPacket struct {
	addr netip.AddrPort
	data []byte
}

func NewAPI(config Config, localStaticKey *crypto.SecpKeyPair, ctx Context) *API {
	localStaticPublic := localStaticKey.PubKey()
	return &API{
		state:          newState(),
		timers:         newTimerSet(),
		config:         config,
		localStaticKey: localStaticKey,
		cookies:        newCookies(ctx.RNG(), localStaticPublic, config.CookieRefreshDuration),
		filter:         newFilter(&config),
		context:        ctx,
	}
}

// NextPacket pops the next outbound (addr, packet) pair.
func (a *API) NextPacket() (netip.AddrPort, []byte, bool) {
	if len(a.packetQueue) == 0 {
		return netip.AddrPort{}, nil, false
	}
	p := a.packetQueue[0]
	a.packetQueue = a.packetQueue[1:]
	return p.addr, p.data, true
}

func (a *API) enqueuePacket(addr netip.AddrPort, pkt []byte) {
	a.packetQueue = append(a.packetQueue, queuedPacket{addr, pkt})
}

// NextDeadline returns the next wall-clock instant to call Tick.
func (a *API) NextDeadline() (time.Time, bool) {
	var deadline time.Duration
	found := false
	if first, ok := a.timers.first(); ok {
		deadline, found = first.deadline, true
	}
	filterDeadline := a.filter.nextResetTime()
	if !found || filterDeadline < deadline {
		deadline, found = filterDeadline, true
	}
	if !found {
		return time.Time{}, false
	}
	return a.context.Deadline(deadline), true
}

// Tick processes expired session timers. Mirrors API::tick.
func (a *API) Tick() {
	now := a.context.DurationSinceStart()
	a.filter.tick(now)
	maxPerTick := a.config.MaxExpiredTimersPerTick

	processed := 0
	for processed < maxPerTick {
		first, ok := a.timers.first()
		if !ok || first.deadline > now {
			break
		}
		entry, _ := a.timers.popFirst()
		processed++
		sessionID := entry.sessionIndex

		var timer *time.Duration
		var message *MessageEvent
		var rekey *RekeyEvent
		var terminated *TerminatedEvent

		if s := a.state.getInitiatorMut(sessionID); s != nil {
			if next, res := s.tick(now); res != nil {
				timer, rekey, terminated = next, res.Rekey, &res.Terminated
			}
		} else if s := a.state.getResponderMut(sessionID); s != nil {
			if next, res := s.tick(now); res != nil {
				timer, rekey, terminated = next, res.Rekey, &res.Terminated
			}
		} else if t := a.state.getTransportMut(sessionID); t != nil {
			next, msg, rk, term := t.tick(a.context.RNG(), &a.config, now)
			timer, message, rekey, terminated = next, msg, rk, term
		} else {
			continue
		}

		if message != nil {
			a.enqueuePacket(message.RemoteAddr, message.Header.marshal())
		}

		if rekey != nil {
			if newIndex, newTimer, msg, err := a.initSessionWithCookie(
				rekey.RemotePublicKey, rekey.RemoteAddr, rekey.StoredCookie, rekey.RetryAttempts,
			); err == nil {
				a.enqueuePacket(rekey.RemoteAddr, msg.marshal())
				a.timers.insert(newTimer, newIndex)
			}
		}

		if timer != nil {
			a.timers.insert(*timer, sessionID)
		}

		if terminated != nil {
			a.state.terminateSession(sessionID, &terminated.RemotePublicKey, terminated.RemoteAddr)
		}
	}
	a.lastTick = &now
}

// Connect initiates a handshake to remoteStaticKey at remoteAddr.
func (a *API) Connect(remoteStaticKey crypto.SecpPubKey, remoteAddr netip.AddrPort, retryAttempts uint64) error {
	if err := a.checkConnectRateLimit(); err != nil {
		return err
	}
	if a.state.initiatedSessionsCount() >= a.config.MaxInitiatedSessions {
		return errTooManyInitiated(a.config.MaxInitiatedSessions)
	}
	cookie := a.state.lookupCookieFromInitiatedSessions(remoteStaticKey)

	index, timer, msg, err := a.initSessionWithCookie(remoteStaticKey, remoteAddr, cookie, retryAttempts)
	if err != nil {
		return err
	}
	a.enqueuePacket(remoteAddr, msg.marshal())
	a.timers.insert(timer, index)
	return nil
}

func (a *API) checkConnectRateLimit() error {
	now := a.context.DurationSinceStart()
	if now-a.connectRateLastReset >= a.config.ConnectRateResetInterval {
		a.connectRateCounter = 0
		a.connectRateLastReset = now
	}
	if a.connectRateCounter >= a.config.ConnectRateLimit {
		return errConnectRateLimited(a.config.ConnectRateLimit)
	}
	a.connectRateCounter++
	return nil
}

func (a *API) initSessionWithCookie(
	remoteStaticKey crypto.SecpPubKey,
	remoteAddr netip.AddrPort,
	cookie *[16]byte,
	retryAttempts uint64,
) (SessionIndex, time.Duration, *handshakeInitiation, error) {
	index, ok := a.state.reserveSessionIndex()
	if !ok {
		return 0, 0, nil, ErrSessionIndexExhausted
	}
	session, timer, msg, err := newInitiatorState(
		a.context.RNG(),
		a.context.SystemTime(),
		a.context.DurationSinceStart(),
		&a.config,
		index,
		a.localStaticKey,
		remoteStaticKey,
		remoteAddr,
		cookie,
		retryAttempts,
	)
	if err != nil {
		return 0, 0, nil, err
	}
	a.state.commitSessionIndex(index)
	a.state.insertInitiator(index, session, remoteStaticKey)
	return index, timer, msg, nil
}

// isUnderLoad runs the admission filter; on SendCookie it enqueues a cookie
// reply. Returns false when the message must not proceed.
func (a *API) isUnderLoad(remoteAddr netip.AddrPort, senderIndex uint32, m macMessage) bool {
	now := a.context.DurationSinceStart()
	cookieValid := a.cookies.verify(remoteAddr.Addr(), m, now) == nil
	action := a.filter.apply(a.state, remoteAddr, now, cookieValid)
	switch action {
	case filterSendCookie:
		reply := a.cookies.create(remoteAddr.Addr(), senderIndex, m, now)
		a.enqueuePacket(remoteAddr, reply.marshal())
		return false
	case filterDrop:
		return false
	}
	return true
}

func (a *API) acceptHandshakeInit(msg *handshakeInitiation, remoteAddr netip.AddrPort) error {
	if err := verifyMAC1(msg, a.localStaticKey.PubKey()); err != nil {
		return err
	}
	if !a.isUnderLoad(remoteAddr, msg.senderIndex, msg) {
		return nil
	}
	now := a.context.DurationSinceStart()

	vi, err := validateInit(a.localStaticKey, msg)
	if err != nil {
		return err
	}
	remoteKey := vi.remotePublicKey
	if max := a.state.getMaxTimestamp(remoteKey); max != nil && vi.timestamp.cmp(*max) <= 0 {
		return ErrTimestampReplay
	}
	storedCookie := a.state.lookupCookieFromAcceptedSessions(remoteKey)

	index, ok := a.state.reserveSessionIndex()
	if !ok {
		return ErrSessionIndexExhausted
	}
	a.state.commitSessionIndex(index)

	session, timer, respMsg, err := newResponderState(
		a.context.RNG(), now, &a.config, index, storedCookie, vi, remoteAddr,
	)
	if err != nil {
		return err
	}
	a.state.insertResponder(index, session, remoteKey)
	a.enqueuePacket(remoteAddr, respMsg.marshal())
	a.timers.insert(timer, index)
	return nil
}

func (a *API) acceptCookie(reply *cookieReply) error {
	receiverIndex := SessionIndex(reply.receiverIndex)
	if s := a.state.getInitiatorMut(receiverIndex); s != nil {
		return s.handleCookie(reply)
	}
	if s := a.state.getResponderMut(receiverIndex); s != nil {
		return s.handleCookie(reply)
	}
	return nil
}

// Dispatch — Rust WireAuthProtocol::dispatch: classify the datagram payload,
// run control packets through the handshake machine, and decrypt data
// packets. Returns (nil, nil, nil) for consumed control packets.
func (a *API) Dispatch(packet []byte, remoteAddr netip.AddrPort) ([]byte, *crypto.SecpPubKey, error) {
	c, d, err := parsePacket(packet)
	if err != nil {
		return nil, nil, err
	}
	if c != nil {
		return nil, nil, a.DispatchControl(c, remoteAddr)
	}
	plaintext, pub, err := a.Decrypt(*d, remoteAddr)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, &pub, nil
}

// DispatchControl processes a parsed control packet (handshakes, cookie
// replies, keepalives).
func (a *API) DispatchControl(c *controlPacket, remoteAddr netip.AddrPort) error {
	var err error
	switch c.kind {
	case controlInitiation:
		err = a.acceptHandshakeInit(c.initiation, remoteAddr)
	case controlResponse:
		err = a.completeHandshake(c.response, remoteAddr)
	case controlCookie:
		err = a.acceptCookie(c.cookie)
	case controlKeepalive:
		_, _, err = a.Decrypt(c.keepalive, remoteAddr)
	}
	return err
}

// Decrypt decrypts a data packet in place; returns (plaintext, remote pubkey).
func (a *API) Decrypt(pkt dataPacket, remoteAddr netip.AddrPort) ([]byte, crypto.SecpPubKey, error) {
	receiverIndex := SessionIndex(pkt.header.receiverIndex)

	if transport := a.state.getTransportMut(receiverIndex); transport != nil {
		now := a.context.DurationSinceStart()
		timer, plaintext, err := transport.decrypt(&a.config, now, pkt)
		if err != nil {
			return nil, crypto.SecpPubKey{}, err
		}
		remotePublicKey := transport.common.remotePublicKey
		a.timers.replaceTimer(timer, receiverIndex)
		return plaintext, remotePublicKey, nil
	}

	if responder := a.state.getResponderMut(receiverIndex); responder != nil {
		now := a.context.DurationSinceStart()
		_, plaintext, err := responder.decrypt(&a.config, now, pkt)
		if err != nil {
			return nil, crypto.SecpPubKey{}, err
		}
		remotePublicKey := responder.transport.common.remotePublicKey
		responder = a.state.removeResponder(receiverIndex)
		transport, establishTimer := responder.establish(a.context.RNG(), &a.config, now)
		a.state.insertTransport(receiverIndex, transport)
		a.timers.insert(establishTimer, receiverIndex)
		return plaintext, remotePublicKey, nil
	}

	return nil, crypto.SecpPubKey{}, errSessionIndexNotFound(receiverIndex)
}

func (a *API) completeHandshake(response *handshakeResponse, remoteAddr netip.AddrPort) error {
	if err := verifyMAC1(response, a.localStaticKey.PubKey()); err != nil {
		return err
	}
	if !a.isUnderLoad(remoteAddr, response.senderIndex, response) {
		return nil
	}
	receiverIndex := SessionIndex(response.receiverIndex)

	initiator := a.state.getInitiatorMut(receiverIndex)
	if initiator == nil {
		return errInvalidReceiverIndex(receiverIndex)
	}
	expectedAddr := initiator.common.remoteAddr
	if remoteAddr != expectedAddr {
		return errHandshakeResponseAddressMismatch(expectedAddr, remoteAddr)
	}
	vr, err := initiator.validateResponse(&a.config, a.localStaticKey, response)
	if err != nil {
		return err
	}

	initiator = a.state.removeInitiator(receiverIndex)
	now := a.context.DurationSinceStart()
	transport, messages, isBuffered := initiator.establish(a.context.RNG(), &a.config, now, vr)
	a.state.insertTransport(receiverIndex, transport)

	for _, msg := range messages {
		packet := make([]byte, dataPacketHeaderSize+len(msg))
		copy(packet[dataPacketHeaderSize:], msg)
		t := a.state.getTransportMut(receiverIndex)
		header, timer := t.encrypt(a.context.RNG(), &a.config, now, packet[dataPacketHeaderSize:])
		copy(packet[:dataPacketHeaderSize], header.marshal())
		a.timers.replaceTimer(timer, receiverIndex)
		a.enqueuePacket(remoteAddr, packet)
		_ = isBuffered
	}
	return nil
}

// EncryptByPublicKey encrypts plaintext in place for the latest session of
// publicKey, returning the packet header to prepend.
func (a *API) EncryptByPublicKey(publicKey crypto.SecpPubKey, plaintext []byte) (dataPacketHeader, error) {
	transport := a.state.getTransportByPublicKey(publicKey)
	if transport == nil {
		return dataPacketHeader{}, ErrSessionNotFound
	}
	now := a.context.DurationSinceStart()
	header, timer := transport.encrypt(a.context.RNG(), &a.config, now, plaintext)
	a.timers.replaceTimer(timer, transport.common.localIndex)
	return header, nil
}

// EncryptBySocket encrypts plaintext in place for the latest session on
// socketAddr.
func (a *API) EncryptBySocket(socketAddr netip.AddrPort, plaintext []byte) (dataPacketHeader, error) {
	transport := a.state.getTransportBySocket(socketAddr)
	if transport == nil {
		return dataPacketHeader{}, errSessionNotEstablishedForAddress(socketAddr)
	}
	now := a.context.DurationSinceStart()
	header, timer := transport.encrypt(a.context.RNG(), &a.config, now, plaintext)
	a.timers.replaceTimer(timer, transport.common.localIndex)
	return header, nil
}

// EncryptBySocketPacket — Rust AuthenticatedSocketHandle::encrypt_packet:
// copies plaintext into a fresh packet buffer, encrypts the body in place,
// and returns header || ciphertext (caller slices are never mutated).
func (a *API) EncryptBySocketPacket(socketAddr netip.AddrPort, plaintext []byte) ([]byte, error) {
	pkt := make([]byte, dataPacketHeaderSize+len(plaintext))
	copy(pkt[dataPacketHeaderSize:], plaintext)
	hdr, err := a.EncryptBySocket(socketAddr, pkt[dataPacketHeaderSize:])
	if err != nil {
		return nil, err
	}
	copy(pkt[:dataPacketHeaderSize], hdr.marshal())
	return pkt, nil
}

// EncryptByPublicKeyPacket — encrypt_packet_by_public_key analogue.
func (a *API) EncryptByPublicKeyPacket(publicKey crypto.SecpPubKey, plaintext []byte) ([]byte, error) {
	pkt := make([]byte, dataPacketHeaderSize+len(plaintext))
	copy(pkt[dataPacketHeaderSize:], plaintext)
	hdr, err := a.EncryptByPublicKey(publicKey, pkt[dataPacketHeaderSize:])
	if err != nil {
		return nil, err
	}
	copy(pkt[:dataPacketHeaderSize], hdr.marshal())
	return pkt, nil
}

// BufferMessage queues message for a peer whose handshake is in flight.
func (a *API) BufferMessage(publicKey crypto.SecpPubKey, message []byte) error {
	initiator := a.state.getInitiatorByPublicKeyMut(publicKey)
	if initiator == nil {
		return ErrSessionNotFound
	}
	newSize := initiator.bufferedBytes + len(message)
	if newSize > a.config.MaxBufferedBytesPerSession {
		return errBufferLimitExceeded(newSize, a.config.MaxBufferedBytesPerSession)
	}
	initiator.bufferMessage(message)
	return nil
}

// Disconnect removes all sessions for publicKey.
func (a *API) Disconnect(publicKey crypto.SecpPubKey) {
	a.state.terminateByPublicKey(publicKey)
}

func (a *API) IsConnectedSocket(addr netip.AddrPort) bool {
	return a.state.hasTransportBySocket(addr)
}
func (a *API) IsConnectedPublicKey(pub crypto.SecpPubKey) bool {
	return a.state.hasTransportByPublicKey(pub)
}
func (a *API) HasAnySessionByPublicKey(pub crypto.SecpPubKey) bool {
	return a.state.hasAnySessionByPublicKey(pub)
}
func (a *API) HasInitiatorSessionByPublicKey(pub crypto.SecpPubKey) bool {
	return a.state.hasInitiatorSessionByPublicKey(pub)
}
func (a *API) HasInitiatorSessionBySocketAndPublicKey(addr netip.AddrPort, pub crypto.SecpPubKey) bool {
	return a.state.hasInitiatorSessionBySocketAndPublicKey(addr, pub)
}
func (a *API) IsConnectedSocketAndPublicKey(addr netip.AddrPort, pub crypto.SecpPubKey) bool {
	return a.state.hasTransportBySocketAndPublicKey(addr, pub)
}
func (a *API) GetSocketByPublicKey(pub crypto.SecpPubKey) (netip.AddrPort, bool) {
	return a.state.getSocketByPublicKey(pub)
}
