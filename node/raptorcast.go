package node

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/net/dataplane"
	"github.com/abhijitkrm/monadbft-go/net/peerdisc"
	"github.com/abhijitkrm/monadbft-go/net/raptorcast"
	"github.com/abhijitkrm/monadbft-go/net/wireauth"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// RaptorcastTransport is the production node transport — the Go analogue of
// upstream's RaptorCast executor (monad-raptorcast/src/lib.rs). It composes:
//
//   - dataplane    — dual UDP sockets (authenticated + unauthenticated) and a
//     TCP listener with pacing/ban control
//   - wireauth     — authenticated UDP sessions for the raptorcast datapath
//   - peerdisc     — peer discovery; its messages ride inside raptorcast
//     kind-2 envelopes exactly as upstream
//   - raptorcast   — regular (v0) chunk encode/decode, signature verification,
//     rebroadcast
//
// Delivery mirrors upstream DualSocketHandle::write_to_name_record: with an
// established session the payload is encrypted and sent on the authenticated
// socket; otherwise it falls back to plaintext on the unauthenticated socket
// while a handshake is initiated, or is buffered until the session opens when
// the peer has no non-authenticated port. TCP carries
// signature || router-envelope, matching upstream tcp_build_and_send.
//
// All mutable state is owned by a single run goroutine; public methods only
// enqueue work, keeping Send non-blocking for the consensus loop.

const authConnectRetryAttempts = 0 // AUTH_SESSION_CONNECT_RETRY_ATTEMPTS

// RaptorcastTransportConfig — construction knobs for RaptorcastTransport.
type RaptorcastTransportConfig struct {
	SelfID types.NodeId
	Key    *crypto.SecpKeyPair // secp256k1 identity (raptorcast sigs + wireauth static)

	AuthUDP  netip.AddrPort // authenticated UDP socket bind addr (required)
	PlainUDP netip.AddrPort // unauthenticated UDP socket bind addr (required)
	TCPAddr  netip.AddrPort // TcpPointToPoint listener; zero value disables TCP

	// PeerDisc — peer discovery builder; SelfRecord must advertise the ports
	// bound above (upstream builds it from the same config).
	PeerDisc peerdisc.PeerDiscoveryBuilder

	Options         raptorcast.Options // zero value → DefaultOptions()
	Wireauth        *wireauth.Config   // nil → DefaultConfig()
	UpBandwidthMbps uint64             // 0 → 1000
}

type raptorcastInbound struct {
	src    netip.AddrPort
	data   []byte
	stride uint16
	tcp    bool
}

// RaptorcastTransport — the composite Transport implementation.
type RaptorcastTransport struct {
	cfg RaptorcastTransportConfig

	dp        *dataplane.Dataplane
	dpCtl     *dataplane.DataplaneControl
	auth      *wireauth.API
	pd        *peerdisc.PeerDiscoveryDriver
	rc        *raptorcast.Raptorcast
	authSock  *dataplane.UdpSocketHandle
	plainSock *dataplane.UdpSocketHandle
	tcpSock   *dataplane.TcpSocketHandle

	cmds    chan func() // run-loop work queue
	authIn  chan raptorcastInbound
	plainIn chan raptorcastInbound
	tcpIn   chan dataplane.RecvTcpMsg
	kick    chan struct{} // capacity-1 wakeup for the run loop

	// pdOverride — transient name-record override for PingPong emits whose
	// target is not yet in routing_info (upstream with_target_name_record).
	// Owned by the run loop.
	pdOverrideID types.NodeId
	pdOverride   *peerdisc.NameRecord

	// cmdQ — unbounded command queue (upstream Executor::next drains a
	// Vec<Command>): Send must never block the consensus loop.
	cmdMu sync.Mutex
	cmdQ  []func()

	handlerMu sync.Mutex
	handler   func(types.NodeId, []byte)

	mu        sync.Mutex
	peerSnap  []glue.PeerEntry
	fnSnap    []types.NodeId
	epochVals map[types.Epoch]map[types.NodeId]struct{}
	// epoch whose member IPs are currently in the dataplane trusted set
	trustedEpoch types.Epoch
	trustedSet   bool
	started      bool
	closed       bool

	done   chan struct{}
	exited chan struct{}
	wg     sync.WaitGroup
}

// NewRaptorcastTransport builds dataplane/wireauth/peerdisc/raptorcast from
// cfg. Start() launches the run loop and socket readers.
func NewRaptorcastTransport(cfg RaptorcastTransportConfig) (*RaptorcastTransport, error) {
	if cfg.Options == (raptorcast.Options{}) {
		cfg.Options = raptorcast.DefaultOptions()
	}
	wireCfg := wireauth.DefaultConfig()
	if cfg.Wireauth != nil {
		wireCfg = *cfg.Wireauth
	}
	if cfg.UpBandwidthMbps == 0 {
		cfg.UpBandwidthMbps = 1000
	}

	b := dataplane.NewDataplaneBuilder(cfg.UpBandwidthMbps).
		WithUdpSockets(map[dataplane.UdpSocketID]netip.AddrPort{
			dataplane.UdpSocketAuthenticatedRaptorcast: cfg.AuthUDP,
			dataplane.UdpSocketRaptorcast:              cfg.PlainUDP,
		})
	if cfg.TCPAddr.IsValid() {
		b = b.WithTcpSockets(map[dataplane.TcpSocketID]netip.AddrPort{
			dataplane.TcpSocketRaptorcast: cfg.TCPAddr,
		})
	}
	dp, err := b.Build()
	if err != nil {
		return nil, err
	}

	authSock, ok := dp.UdpSockets.Get(dataplane.UdpSocketAuthenticatedRaptorcast)
	if !ok {
		dp.Close()
		return nil, errors.New("raptorcast transport: authenticated UDP socket missing")
	}
	plainSock, ok := dp.UdpSockets.Get(dataplane.UdpSocketRaptorcast)
	if !ok {
		dp.Close()
		return nil, errors.New("raptorcast transport: unauthenticated UDP socket missing")
	}
	var tcpSock *dataplane.TcpSocketHandle
	if cfg.TCPAddr.IsValid() {
		tcpSock, ok = dp.TcpSockets.Get(dataplane.TcpSocketRaptorcast)
		if !ok {
			dp.Close()
			return nil, errors.New("raptorcast transport: TCP socket missing")
		}
	}

	t := &RaptorcastTransport{
		cfg:       cfg,
		dp:        dp,
		dpCtl:     dp.Control,
		auth:      wireauth.NewAPI(wireCfg, cfg.Key, wireauth.NewStdContext()),
		authSock:  authSock,
		plainSock: plainSock,
		tcpSock:   tcpSock,
		kick:      make(chan struct{}, 1),
		authIn:    make(chan raptorcastInbound, 1024),
		plainIn:   make(chan raptorcastInbound, 1024),
		tcpIn:     make(chan dataplane.RecvTcpMsg, 256),
		epochVals: map[types.Epoch]map[types.NodeId]struct{}{},
		done:      make(chan struct{}),
		exited:    make(chan struct{}),
	}

	t.rc = raptorcast.New(cfg.SelfID, cfg.Key, t, t, cfg.Options)
	t.rc.SetHandler(func(from types.NodeId, payload []byte) {
		t.handlerMu.Lock()
		h := t.handler
		t.handlerMu.Unlock()
		if h != nil {
			h(from, payload)
		}
	})
	t.rc.SetPeerDiscHandler(func(author types.NodeId, srcAddr netip.AddrPort, payload []byte) {
		var msg peerdisc.PeerDiscoveryMessage
		if err := msg.DecodeRLP(rlp.NewStream(payload)); err != nil {
			return
		}
		if ev, ok := peerdisc.InboundEvent(
			peerdisc.PeerSource{ID: author, Addr: srcAddr}, msg); ok {
			t.pd.Update(ev)
		}
	})
	t.pd = peerdisc.NewPeerDiscoveryDriver(cfg.PeerDisc)
	return t, nil
}

// ---------------------------------------------------------------------------
// node.Transport
// ---------------------------------------------------------------------------

// enqueue pushes work onto the run loop — unbounded, never blocks, drops
// only after Close.
func (t *RaptorcastTransport) enqueue(f func()) {
	select {
	case <-t.done:
		return
	default:
	}
	t.cmdMu.Lock()
	t.cmdQ = append(t.cmdQ, f)
	t.cmdMu.Unlock()
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

func (t *RaptorcastTransport) drainCmds() {
	t.cmdMu.Lock()
	q := t.cmdQ
	t.cmdQ = nil
	t.cmdMu.Unlock()
	for _, f := range q {
		f()
	}
}

// Send — non-blocking; enqueues the publish onto the run loop. Payload is an
// RLP-encoded app message, as with TCPTransport.
func (t *RaptorcastTransport) Send(target types.RouterTarget, payload []byte) {
	t.SendWithPriority(target, payload, raptorcast.UdpPriorityRegular)
}

// SendWithPriority — RouterPublishWithPriority path (upstream pushes to the
// high lane; drained first in the dataplane egress queues).
func (t *RaptorcastTransport) SendWithPriority(target types.RouterTarget, payload []byte, priority int) {
	t.enqueue(func() { t.send(target, payload, priority) })
}

func (t *RaptorcastTransport) send(target types.RouterTarget, payload []byte, priority int) {
	switch target.Kind {
	case types.RouterTcpPointToPoint:
		t.tcpSend(target.To, raptorcast.MessageTypeApp, payload)
	default:
		_ = t.rc.SendWithPriority(target, payload, priority)
	}
}

// PublishToFullNodes — upstream: point-to-point app message to each dedicated
// full node with a known auth addr, at the command's epoch.
func (t *RaptorcastTransport) PublishToFullNodes(epoch types.Epoch, _ types.Round, _ types.FullnodeBroadcastMode, payload []byte) {
	t.enqueue(func() {
		known := t.pd.KnownAuthUDPAddrs()
		for _, fn := range t.snapshotFullNodes() {
			if fn == t.cfg.SelfID {
				continue
			}
			if _, ok := known[fn]; !ok {
				continue
			}
			_ = t.rc.SendToNode(epoch, fn, payload, raptorcast.UdpPriorityRegular)
		}
	})
}

func (t *RaptorcastTransport) AddEpochValidatorSet(epoch types.Epoch, _ types.Round, validators []glue.ValidatorStake) {
	t.enqueue(func() {
		vd := make([]validator.ValidatorData, len(validators))
		members := make(map[types.NodeId]struct{}, len(validators))
		for i, v := range validators {
			vd[i] = validator.ValidatorData{NodeId: v.NodeId, Stake: v.Stake}
			members[v.NodeId] = struct{}{}
		}
		if vs, err := validator.NewValidatorSet(vd); err == nil {
			t.rc.AddEpochValidatorSet(epoch, vs)
		}
		t.mu.Lock()
		t.epochVals[epoch] = members
		t.mu.Unlock()
		t.pd.Update(peerdisc.UpdateValidatorSetEvent(epoch, validatorIDs(members)))
	})
}

func (t *RaptorcastTransport) UpdateCurrentRound(epoch types.Epoch, round types.Round) {
	t.enqueue(func() {
		t.rc.UpdateCurrentRound(epoch, round)
		t.pd.Update(peerdisc.UpdateCurrentRoundEvent(epoch, round))
		// Upstream refresh_trusted_ips: dataplane trust tracks the validator
		// set of the *current* epoch.
		if epoch != t.trustedEpoch || !t.trustedSet {
			t.refreshTrusted(epoch)
		}
	})
}

// refreshTrusted — Rust iter_ips + UpdateTrusted: adds current-epoch member
// IPs, removes the previous epoch's.
func (t *RaptorcastTransport) refreshTrusted(epoch types.Epoch) {
	var added, removed []netip.Addr
	t.mu.Lock()
	cur := t.epochVals[epoch]
	prev := t.epochVals[t.trustedEpoch]
	t.mu.Unlock()
	for id := range cur {
		if ip, ok := t.pd.PeerIP(id); ok {
			added = append(added, ip)
		}
	}
	for id := range prev {
		if _, ok := cur[id]; ok {
			continue
		}
		if ip, ok := t.pd.PeerIP(id); ok {
			removed = append(removed, ip)
		}
	}
	t.dpCtl.UpdateTrusted(added, removed)
	t.trustedEpoch = epoch
	t.trustedSet = true
}

func (t *RaptorcastTransport) UpdatePeers(peers []glue.PeerEntry, dedicated, prioritized []types.NodeId) {
	t.enqueue(func() {
		t.pd.Update(peerdisc.UpdatePeersEvent(peers))
		t.pd.Update(peerdisc.UpdatePinnedNodesEvent(dedicated, prioritized))
	})
}

func (t *RaptorcastTransport) UpdateFullNodes(dedicated, _ []types.NodeId) {
	t.mu.Lock()
	t.fnSnap = append([]types.NodeId(nil), dedicated...)
	t.mu.Unlock()
}

func (t *RaptorcastTransport) Peers() []glue.PeerEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]glue.PeerEntry(nil), t.peerSnap...)
}

func (t *RaptorcastTransport) FullNodes() []types.NodeId {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]types.NodeId(nil), t.fnSnap...)
}

// IsConnectedTo reports whether a wireauth session is established with the
// peer — routed through the run loop so callers don't race the auth state.
func (t *RaptorcastTransport) IsConnectedTo(id types.NodeId) bool {
	res := make(chan bool, 1)
	t.enqueue(func() { res <- t.auth.IsConnectedPublicKey(id.PubKey) })
	select {
	case v := <-res:
		return v
	case <-t.done:
		return false
	}
}

func (t *RaptorcastTransport) SetHandler(h func(types.NodeId, []byte)) {
	t.handlerMu.Lock()
	t.handler = h
	t.handlerMu.Unlock()
}

// Start launches socket readers and the run loop.
func (t *RaptorcastTransport) Start() error {
	t.mu.Lock()
	if t.started || t.closed {
		t.mu.Unlock()
		return errors.New("raptorcast transport already started or closed")
	}
	t.started = true
	t.mu.Unlock()

	t.wg.Add(1)
	go t.run()
	t.spawnUDPReader(t.authSock, t.authIn)
	t.spawnUDPReader(t.plainSock, t.plainIn)
	if t.tcpSock != nil {
		t.wg.Add(1)
		go t.tcpReader()
	}
	return nil
}

func (t *RaptorcastTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("raptorcast transport already closed")
	}
	t.closed = true
	t.mu.Unlock()
	close(t.done)
	t.dp.Close()
	<-t.exited
	t.wg.Wait()
	return nil
}

// ---------------------------------------------------------------------------
// run loop — owns rc/pd/auth; all mutable state is single-threaded here.
// ---------------------------------------------------------------------------

func (t *RaptorcastTransport) run() {
	defer t.wg.Done()
	defer close(t.exited)

	var pdTimer, authTimer *time.Timer
	var pdC, authC <-chan time.Time
	defer func() {
		if pdTimer != nil {
			pdTimer.Stop()
		}
		if authTimer != nil {
			authTimer.Stop()
		}
	}()

	arm := func() {
		if due := t.pd.NextDue(); !due.IsZero() {
			pdC = armTimer(&pdTimer, time.Until(due))
		} else {
			pdC = disarmTimer(pdTimer)
		}
		if due, ok := t.auth.NextDeadline(); ok {
			authC = armTimer(&authTimer, time.Until(due))
		} else {
			authC = disarmTimer(authTimer)
		}
	}
	arm()

	for {
		select {
		case <-t.kick:
			t.drainCmds()
		case m := <-t.authIn:
			t.onAuthRecv(m)
		case m := <-t.plainIn:
			t.onPlainRecv(m)
		case m := <-t.tcpIn:
			t.onTCPRecv(m)
		case <-pdC:
			for _, ev := range t.pd.DrainEvents() {
				t.pd.Update(ev)
			}
		case <-authC:
			t.auth.Tick()
			t.flushAuth()
		case <-t.done:
			return
		}
		t.drainPDEmits()
		t.snapshotPeers() // routing_info changes on ping/pong promotions
		arm()
	}
}

func armTimer(tp **time.Timer, d time.Duration) <-chan time.Time {
	if d < 0 {
		d = 0
	}
	if *tp == nil {
		*tp = time.NewTimer(d)
		return (*tp).C
	}
	if !(*tp).Stop() {
		select {
		case <-(*tp).C:
		default:
		}
	}
	(*tp).Reset(d)
	return (*tp).C
}

func disarmTimer(tp *time.Timer) <-chan time.Time {
	if tp == nil {
		return nil
	}
	if !tp.Stop() {
		select {
		case <-tp.C:
		default:
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// inbound
// ---------------------------------------------------------------------------

// onAuthRecv — AuthenticatedSocketHandle::recv: one datagram = one wireauth
// packet. Control packets are consumed (and may queue replies); data packets
// decrypt to plaintext raptorcast payloads with an authenticated sender.
func (t *RaptorcastTransport) onAuthRecv(m raptorcastInbound) {
	plain, pub, err := t.auth.Dispatch(m.data, m.src)
	t.flushAuth()
	if err != nil || pub == nil {
		return
	}
	sender := types.NodeId{PubKey: *pub}
	t.rc.HandleDatagram(m.src, &sender, plain, m.stride)
}

// onPlainRecv — unauthenticated socket: payload is a raw raptorcast datagram
// (batched chunks split internally by stride). No authenticated sender.
func (t *RaptorcastTransport) onPlainRecv(m raptorcastInbound) {
	t.rc.HandleDatagram(m.src, nil, m.data, m.stride)
}

// onTCPRecv — upstream handle_inbound_tcp: payload = signature || router
// envelope; sender is recovered from the signature.
func (t *RaptorcastTransport) onTCPRecv(m dataplane.RecvTcpMsg) {
	if len(m.Payload) < crypto.SecpSignatureSize {
		t.dpCtl.Disconnect(m.SrcAddr)
		return
	}
	sigBytes := m.Payload[:crypto.SecpSignatureSize]
	envBytes := m.Payload[crypto.SecpSignatureSize:]
	sig, err := crypto.SecpSignatureFromBytes(sigBytes)
	if err != nil {
		t.dpCtl.Disconnect(m.SrcAddr)
		return
	}
	pub, err := sig.RecoverPubKey(crypto.DomainRaptorcastAppMsg, envBytes)
	if err != nil {
		t.dpCtl.Disconnect(m.SrcAddr)
		return
	}
	from := types.NodeId{PubKey: pub}
	kind, payload, err := raptorcast.DecodeRouterEnvelope(envBytes)
	if err != nil {
		t.dpCtl.Disconnect(m.SrcAddr)
		return
	}
	switch kind {
	case raptorcast.MessageTypeApp:
		t.handlerMu.Lock()
		h := t.handler
		t.handlerMu.Unlock()
		if h != nil {
			h(from, payload)
		}
	case raptorcast.MessageTypePeerDisc:
		var msg peerdisc.PeerDiscoveryMessage
		if err := msg.DecodeRLP(rlp.NewStream(payload)); err != nil {
			return
		}
		if ev, ok := peerdisc.InboundEvent(
			peerdisc.PeerSource{ID: from, Addr: m.SrcAddr}, msg); ok {
			t.pd.Update(ev)
		}
	default:
		// kind 3 (full-node group) — B5 scope; ignore.
	}
}

// tcpSend — upstream tcp_build_and_send: envelope → sign → sig||env to the
// peer's TCP addr from its name record.
func (t *RaptorcastTransport) tcpSend(to types.NodeId, kind uint8, msgRLP []byte) {
	if t.tcpSock == nil {
		return
	}
	nr, ok := t.pd.LookupNameRecord(to)
	if !ok {
		return
	}
	env, err := encodeTCPEnvelope(kind, msgRLP)
	if err != nil {
		return
	}
	sig := t.cfg.Key.Sign(crypto.DomainRaptorcastAppMsg, env)
	wire := make([]byte, 0, crypto.SecpSignatureSize+len(env))
	wire = append(wire, sig.Serialize()...)
	wire = append(wire, env...)
	t.tcpSock.Write(nr.NameRecord.TCPSocket(), dataplane.TcpMsg{Msg: wire})
}

func encodeTCPEnvelope(kind uint8, msgRLP []byte) ([]byte, error) {
	if kind == raptorcast.MessageTypePeerDisc {
		return raptorcast.EncodePeerDiscoveryEnvelope(msgRLP)
	}
	return raptorcast.EncodeAppMessageEnvelope(msgRLP)
}

// ---------------------------------------------------------------------------
// outbound — dual-socket write path
// ---------------------------------------------------------------------------

// writeToNameRecord — Rust DualSocketHandle::write_to_name_record.
func (t *RaptorcastTransport) writeToNameRecord(id types.NodeId, nr peerdisc.NameRecord, payload []byte, stride uint16, prio dataplane.UdpPriority) {
	pub := id.PubKey
	authAddr := nr.AuthUDPSocket()
	hasAuth := t.auth.IsConnectedSocketAndPublicKey(authAddr, pub)
	hasInit := t.auth.HasInitiatorSessionBySocketAndPublicKey(authAddr, pub)
	nonAuthAddr, hasNonAuth := nr.UDPSocket()
	needsConnect := !hasAuth && !hasInit

	if hasNonAuth && !hasAuth {
		// NonAuthenticatedFallback — plaintext on the unauthenticated socket.
		t.plainSock.WriteUnicastWithPriority(dataplane.UnicastMsg{
			Msgs:   []dataplane.UnicastItem{{Dst: nonAuthAddr, Payload: payload}},
			Stride: stride,
		}, prio)
		if needsConnect {
			_ = t.auth.Connect(pub, authAddr, authConnectRetryAttempts)
			t.flushAuth()
		}
		return
	}

	// Authenticated delivery.
	if needsConnect {
		_ = t.auth.Connect(pub, authAddr, authConnectRetryAttempts)
		t.flushAuth()
	}
	if hasAuth {
		t.authWrite(authAddr, payload, stride, prio)
	} else {
		t.authWriteBuffered(pub, payload, stride, prio)
	}
}

// authWrite — Rust write_connected_socket_with_priority: plaintext is split
// into stride pieces, each encrypted as its own wireauth packet.
func (t *RaptorcastTransport) authWrite(addr netip.AddrPort, payload []byte, stride uint16, prio dataplane.UdpPriority) {
	for len(payload) > 0 {
		n := len(payload)
		if uint16(n) > stride && stride > 0 {
			n = int(stride)
		}
		piece := payload[:n]
		payload = payload[n:]
		pkt, err := t.auth.EncryptBySocketPacket(addr, piece)
		if err != nil {
			return
		}
		t.authSock.WriteUnicastWithPriority(dataplane.UnicastMsg{
			Msgs:   []dataplane.UnicastItem{{Dst: addr, Payload: pkt}},
			Stride: uint16(len(pkt)),
		}, prio)
	}
}

// authWriteBuffered — Rust write_with_buffering: connected → encrypt-by-key;
// mid-handshake → buffer plaintext on the initiator session.
func (t *RaptorcastTransport) authWriteBuffered(pub crypto.SecpPubKey, payload []byte, stride uint16, prio dataplane.UdpPriority) {
	connected := t.auth.IsConnectedPublicKey(pub)
	if !connected && !t.auth.HasInitiatorSessionByPublicKey(pub) {
		return
	}
	for len(payload) > 0 {
		n := len(payload)
		if uint16(n) > stride && stride > 0 {
			n = int(stride)
		}
		piece := payload[:n]
		payload = payload[n:]
		if !connected {
			if err := t.auth.BufferMessage(pub, piece); err != nil {
				return
			}
			continue
		}
		pkt, err := t.auth.EncryptByPublicKeyPacket(pub, piece)
		if err != nil {
			return
		}
		addr, ok := t.auth.GetSocketByPublicKey(pub)
		if !ok {
			return
		}
		t.authSock.WriteUnicastWithPriority(dataplane.UnicastMsg{
			Msgs:   []dataplane.UnicastItem{{Dst: addr, Payload: pkt}},
			Stride: uint16(len(pkt)),
		}, prio)
	}
}

// flushAuth — Rust DualSocketHandle::flush: drain queued handshake/control
// packets onto the authenticated socket.
func (t *RaptorcastTransport) flushAuth() {
	for {
		addr, pkt, ok := t.auth.NextPacket()
		if !ok {
			return
		}
		t.authSock.Write(addr, pkt, uint16(len(pkt)))
	}
}

// resolveRecord — name record for a send target: routing_info normally, with
// the PingPongEmit override consulted first (upstream with_target_name_record).
func (t *RaptorcastTransport) resolveRecord(id types.NodeId) (peerdisc.NameRecord, bool) {
	if t.pdOverride != nil && t.pdOverrideID == id {
		return *t.pdOverride, true
	}
	nr, ok := t.pd.LookupNameRecord(id)
	if !ok {
		return peerdisc.NameRecord{}, false
	}
	return nr.NameRecord, true
}

// --- raptorcast.PeerAddrSource ---
func (t *RaptorcastTransport) LookupUDPAddr(id types.NodeId) (netip.AddrPort, bool) {
	nr, ok := t.resolveRecord(id)
	if !ok {
		return netip.AddrPort{}, false
	}
	if addr := nr.AuthUDPSocket(); addr.IsValid() {
		return addr, true
	}
	return nr.UDPSocket()
}

// --- raptorcast.UDPSink ---
func (t *RaptorcastTransport) WriteUnicastWithPriority(batch raptorcast.UDPSendBatch, priority int) {
	prio := dataplane.UdpPriorityRegular
	if priority == raptorcast.UdpPriorityHigh {
		prio = dataplane.UdpPriorityHigh
	}
	for _, item := range batch.Items {
		nr, ok := t.resolveRecord(item.Recipient)
		if !ok {
			continue // upstream drops when the name record is unknown
		}
		t.writeToNameRecord(item.Recipient, nr, item.Payload, batch.Stride, prio)
	}
}

// ---------------------------------------------------------------------------
// peer discovery emit drain — sends over raptorcast point-to-point envelopes
// ---------------------------------------------------------------------------

func (t *RaptorcastTransport) drainPDEmits() {
	for _, e := range t.pd.DrainEmits() {
		msgRLP := e.Message.EncodeRLP(nil)
		// PingPong emits target a record not yet in routing_info — upstream
		// with_target_name_record overrides the sink lookup for the build.
		if e.PingPong {
			nr := e.NameRecord
			t.pdOverrideID, t.pdOverride = e.Target, &nr
			_ = t.rc.SendPeerDiscovery(e.Target, msgRLP, raptorcast.UdpPriorityHigh)
			t.pdOverride = nil
		} else {
			_ = t.rc.SendPeerDiscovery(e.Target, msgRLP, raptorcast.UdpPriorityRegular)
		}
	}
}

// ---------------------------------------------------------------------------
// socket readers
// ---------------------------------------------------------------------------

func (t *RaptorcastTransport) spawnUDPReader(h *dataplane.UdpSocketHandle, out chan<- raptorcastInbound) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		for {
			m, err := h.Recv()
			if err != nil {
				return
			}
			in := raptorcastInbound{src: m.SrcAddr, data: m.Payload, stride: m.Stride}
			select {
			case out <- in:
			case <-t.done:
				return
			default:
				// inbound channel full — drop (upstream drops on backpressure)
			}
		}
	}()
}

func (t *RaptorcastTransport) tcpReader() {
	defer t.wg.Done()
	for {
		m, err := t.tcpSock.Recv()
		if err != nil {
			return
		}
		select {
		case t.tcpIn <- m:
		case <-t.done:
			return
		default:
		}
	}
}

// snapshotPeers refreshes the Peers() snapshot from pd routing state.
func (t *RaptorcastTransport) snapshotPeers() {
	entries := t.pd.PeerEntries()
	t.mu.Lock()
	t.peerSnap = entries
	t.mu.Unlock()
}

func (t *RaptorcastTransport) snapshotFullNodes() []types.NodeId {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]types.NodeId(nil), t.fnSnap...)
}

func validatorIDs(m map[types.NodeId]struct{}) []types.NodeId {
	out := make([]types.NodeId, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	return out
}
