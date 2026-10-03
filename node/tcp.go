package node

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
)

// TCPTransport — a real-socket Transport for multi-process devnets and the
// interim production dataplane before RaptorCast (Track B) lands.
//
// Wire format: after a one-shot handshake exchanging each side's 33-byte
// compressed secp256k1 NodeId, every frame is [u32be length][payload] where
// payload is the already-serialized VerifiedMonadMessage (the transport
// never touches consensus encoding).
//
// Peering is static v1 — Peers maps NodeId → address (upstream's DHT peer
// discovery is Track B scope). Every configured peer gets a persistent dial
// loop with backoff; when both sides connect simultaneously the duplicate
// connection is dropped deterministically (the outbound conn wins iff
// self < peer — both ends compute the same winner).
//
// Semantics match the Transport contract:
//   - Broadcast/Raptorcast fan out to the target epoch's validator set (or
//     every connected peer before the first valset arrives) INCLUDING self —
//     the sender must receive its own proposal/vote (same as the mesh).
//   - Point-to-point targets deliver only to target.To.
//   - Send never blocks: each peer owns a bounded outbound queue; full
//     queues drop (liveness comes from pacemaker retransmission/blocksync).
//   - Unconnected peers drop silently; the dial loop keeps retrying.
type TCPTransport struct {
	self types.NodeId
	cfg  TCPConfig

	ln net.Listener

	mu         sync.Mutex
	handler    func(types.NodeId, []byte)
	conns      map[types.NodeId]*tcpPeer
	validators map[types.Epoch]map[types.NodeId]struct{}
	closed     bool

	done chan struct{}
	wg   sync.WaitGroup
}

// TCPConfig — static peering for the TCP transport.
type TCPConfig struct {
	// Key — this node's secp256k1 keypair; the handshake proves possession
	// (challenger nonce signed under DomainTCPAuth). Required: without it a
	// claimed NodeId can't be authenticated and the id-keyed conn table is
	// an eviction vector.
	Key *crypto.SecpKeyPair
	// Listen is the bind address ("host:port"). Ignored when Listener is set.
	Listen string
	// Listener — optional pre-bound socket (tests can take :0 then advertise
	// Addr()). Nil → net.Listen(Listen).
	Listener net.Listener
	// Peers — static NodeId → "host:port" for every peer to dial. Self's
	// entry, if present, is skipped.
	Peers map[types.NodeId]string
	// MaxMessage — inbound frame cap in bytes. 0 → tcpDefaultMaxMessage.
	MaxMessage int
	// SendQueue — per-peer outbound buffer. 0 → tcpDefaultSendQueue.
	SendQueue int
}

const (
	tcpHandshakeTimeout  = 5 * time.Second
	tcpWriteTimeout      = 10 * time.Second
	tcpDialRetryBase     = 50 * time.Millisecond
	tcpDialRetryMax      = 2 * time.Second
	tcpDefaultMaxMessage = 32 << 20 // 32 MiB
	tcpDefaultSendQueue  = 512
)

// tcpPeer — one live connection.
type tcpPeer struct {
	id     types.NodeId
	conn   net.Conn
	send   chan []byte
	cancel chan struct{}
	once   sync.Once
}

func (p *tcpPeer) drop() {
	p.once.Do(func() {
		close(p.cancel)
		_ = p.conn.Close()
	})
}

func NewTCPTransport(self types.NodeId, cfg TCPConfig) *TCPTransport {
	return &TCPTransport{
		self:       self,
		cfg:        cfg,
		conns:      map[types.NodeId]*tcpPeer{},
		validators: map[types.Epoch]map[types.NodeId]struct{}{},
		done:       make(chan struct{}),
	}
}

// Addr — the bound listen address (valid after Start).
func (t *TCPTransport) Addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ln == nil {
		return ""
	}
	return t.ln.Addr().String()
}

func (t *TCPTransport) maxMessage() int {
	if t.cfg.MaxMessage > 0 {
		return t.cfg.MaxMessage
	}
	return tcpDefaultMaxMessage
}

// Start opens the listener, spawns the accept loop, and launches a dial loop
// for every configured peer.
func (t *TCPTransport) Start() error {
	if t.cfg.Key == nil {
		return fmt.Errorf("tcp transport: Key required (handshake authentication)")
	}
	ln := t.cfg.Listener
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", t.cfg.Listen)
		if err != nil {
			return fmt.Errorf("tcp transport listen %q: %w", t.cfg.Listen, err)
		}
	}
	t.mu.Lock()
	t.ln = ln
	t.mu.Unlock()

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.acceptLoop(ln)
	}()

	for id, addr := range t.cfg.Peers {
		if id == t.self {
			continue
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.dialLoop(id, addr)
		}()
	}
	return nil
}

func (t *TCPTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	ln := t.ln
	peers := make([]*tcpPeer, 0, len(t.conns))
	for _, p := range t.conns {
		peers = append(peers, p)
	}
	t.mu.Unlock()

	close(t.done)
	if ln != nil {
		_ = ln.Close()
	}
	for _, p := range peers {
		p.drop()
	}
	t.wg.Wait()
	return nil
}

// --------------------------------------------------------------------------
// Transport contract
// --------------------------------------------------------------------------

func (t *TCPTransport) Send(target types.RouterTarget, payload []byte) {
	switch target.Kind {
	case types.RouterBroadcast, types.RouterRaptorcast:
		// Fan out to the epoch's validator set when known, else every
		// connected peer — and always self (mesh loopback semantics: the
		// leader must receive its own proposal to vote on it).
		t.mu.Lock()
		set, known := t.validators[target.Epoch]
		var dests []*tcpPeer
		for id, p := range t.conns {
			if known {
				if _, ok := set[id]; !ok {
					continue
				}
			}
			dests = append(dests, p)
		}
		h := t.handler
		t.mu.Unlock()
		for _, p := range dests {
			p.enqueue(payload)
		}
		if h != nil {
			h(t.self, payload)
		}
	default: // point-to-point variants
		if target.To == t.self {
			t.mu.Lock()
			h := t.handler
			t.mu.Unlock()
			if h != nil {
				h(t.self, payload)
			}
			return
		}
		t.mu.Lock()
		p := t.conns[target.To]
		t.mu.Unlock()
		if p != nil {
			p.enqueue(payload)
		}
	}
}

func (t *TCPTransport) PublishToFullNodes(types.Epoch, types.Round, types.FullnodeBroadcastMode, []byte) {
	// no full-node plane on TCP v1
}

func (t *TCPTransport) AddEpochValidatorSet(epoch types.Epoch, _ types.Round, validators []glue.ValidatorStake) {
	set := make(map[types.NodeId]struct{}, len(validators))
	for _, v := range validators {
		set[v.NodeId] = struct{}{}
	}
	t.mu.Lock()
	t.validators[epoch] = set
	t.mu.Unlock()
}

func (t *TCPTransport) UpdateCurrentRound(types.Epoch, types.Round) {}
func (t *TCPTransport) UpdatePeers([]glue.PeerEntry, []types.NodeId, []types.NodeId) {
	// static peering v1 — DHT discovery is Track B
}
func (t *TCPTransport) UpdateFullNodes([]types.NodeId, []types.NodeId) {}

func (t *TCPTransport) Peers() []glue.PeerEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]glue.PeerEntry, 0, len(t.conns))
	for id := range t.conns {
		out = append(out, glue.PeerEntry{Pubkey: id})
	}
	return out
}

func (t *TCPTransport) FullNodes() []types.NodeId { return nil }

func (t *TCPTransport) SetHandler(h func(types.NodeId, []byte)) {
	t.mu.Lock()
	t.handler = h
	t.mu.Unlock()
}

// --------------------------------------------------------------------------
// connection lifecycle
// --------------------------------------------------------------------------

// enqueue — non-blocking outbound queue; a full queue drops the frame
// (consensus liveness survives drops via pacemaker retransmission).
func (p *tcpPeer) enqueue(payload []byte) {
	select {
	case p.send <- payload:
	case <-p.cancel:
	default:
	}
}

// acceptLoop — inbound side.
func (t *TCPTransport) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				return // listener closed permanently
			}
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			id, err := t.handshake(conn)
			if err != nil {
				_ = conn.Close()
				return
			}
			t.serve(conn, id, false)
		}()
	}
}

// dialLoop — outbound side: keep a connection to a configured peer alive.
func (t *TCPTransport) dialLoop(want types.NodeId, addr string) {
	backoff := tcpDialRetryBase
	for {
		select {
		case <-t.done:
			return
		default:
		}
		conn, err := (&net.Dialer{Timeout: tcpHandshakeTimeout}).Dial("tcp", addr)
		if err == nil {
			id, herr := t.handshake(conn)
			if herr == nil && id == want {
				backoff = tcpDialRetryBase
				t.serve(conn, id, true) // blocks until the conn drops
				continue
			}
			_ = conn.Close()
		}
		select {
		case <-t.done:
			return
		case <-time.After(backoff):
		}
		if backoff < tcpDialRetryMax {
			backoff *= 2
		}
	}
}

// handshake — authenticated key exchange. Each side sends
// [u16 idLen][idBytes][32B nonce], then a 65-byte recoverable signature over
// (claimedId || peer nonce) under DomainTCPAuth — proof-of-possession of the
// claimed NodeId, bound to the fresh challenge so it can't be replayed.
// Without it a claimed id could evict a validator's real connection
// (register() keys conns by NodeId).
func (t *TCPTransport) handshake(conn net.Conn) (types.NodeId, error) {
	_ = conn.SetDeadline(time.Now().Add(tcpHandshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return types.NodeId{}, err
	}
	idBytes := t.self.PubKey.Bytes()
	msg := make([]byte, 2+len(idBytes)+32)
	binary.BigEndian.PutUint16(msg[:2], uint16(len(idBytes)))
	copy(msg[2:], idBytes)
	copy(msg[2+len(idBytes):], nonce[:])
	if _, err := conn.Write(msg); err != nil {
		return types.NodeId{}, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return types.NodeId{}, err
	}
	if n := binary.BigEndian.Uint16(hdr[:]); n != uint16(len(idBytes)) {
		return types.NodeId{}, fmt.Errorf("tcp handshake: bad id length %d", n)
	}
	buf := make([]byte, len(idBytes)+32)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return types.NodeId{}, err
	}
	pk, err := crypto.SecpPubKeyFromBytes(buf[:len(idBytes)])
	if err != nil {
		return types.NodeId{}, fmt.Errorf("tcp handshake: bad peer id: %w", err)
	}
	peerNonce := buf[len(idBytes):]

	// Challenge-response: sign the peer's nonce bound to our claimed id.
	sig := t.cfg.Key.Sign(crypto.DomainTCPAuth, authMsg(idBytes, peerNonce))
	smsg := make([]byte, 2+crypto.SecpSignatureSize)
	binary.BigEndian.PutUint16(smsg[:2], crypto.SecpSignatureSize)
	copy(smsg[2:], sig[:])
	if _, err := conn.Write(smsg); err != nil {
		return types.NodeId{}, err
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return types.NodeId{}, err
	}
	if n := binary.BigEndian.Uint16(hdr[:]); n != crypto.SecpSignatureSize {
		return types.NodeId{}, fmt.Errorf("tcp handshake: bad sig length %d", n)
	}
	var sigB [crypto.SecpSignatureSize]byte
	if _, err := io.ReadFull(conn, sigB[:]); err != nil {
		return types.NodeId{}, err
	}
	peerSig, err := crypto.SecpSignatureFromBytes(sigB[:])
	if err != nil {
		return types.NodeId{}, fmt.Errorf("tcp handshake: %w", err)
	}
	if !peerSig.Verify(crypto.DomainTCPAuth, authMsg(buf[:len(idBytes)], nonce[:]), pk) {
		return types.NodeId{}, fmt.Errorf("tcp handshake: peer id %x failed proof-of-possession", pk[:8])
	}
	return types.NewNodeId(pk), nil
}

// authMsg — the handshake signing preimage: claimed pubkey || challenger nonce.
func authMsg(id, nonce []byte) []byte {
	m := make([]byte, 0, len(id)+len(nonce))
	m = append(m, id...)
	return append(m, nonce...)
}

// serve — register the connection, run reader+writer until it dies.
func (t *TCPTransport) serve(conn net.Conn, id types.NodeId, outbound bool) {
	queue := t.cfg.SendQueue
	if queue <= 0 {
		queue = tcpDefaultSendQueue
	}
	p := &tcpPeer{
		id:     id,
		conn:   conn,
		send:   make(chan []byte, queue),
		cancel: make(chan struct{}),
	}
	if !t.register(p, outbound) {
		_ = conn.Close()
		return
	}
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		p.writer()
	}()
	// reader runs inline — returns when the conn dies.
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			break
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > uint32(t.maxMessage()) {
			break
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			break
		}
		t.mu.Lock()
		h := t.handler
		t.mu.Unlock()
		if h != nil {
			h(id, buf)
		}
	}
	p.drop()
	t.unregister(p)
}

func (p *tcpPeer) writer() {
	var hdr [4]byte
	for {
		select {
		case payload := <-p.send:
			_ = p.conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
			binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
			if _, err := p.conn.Write(hdr[:]); err != nil {
				p.drop()
				return
			}
			if _, err := p.conn.Write(payload); err != nil {
				p.drop()
				return
			}
		case <-p.cancel:
			return
		}
	}
}

// register — dedupe simultaneous inbound+outbound conns to the same peer.
// Deterministic on both ends: the outbound conn wins iff self < peer.
func (t *TCPTransport) register(p *tcpPeer, outbound bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	if old, ok := t.conns[p.id]; ok {
		keepOutbound := t.self.PubKey.Cmp(p.id.PubKey) < 0
		if outbound != keepOutbound {
			return false // this conn loses; the registered one stays
		}
		old.drop()
	}
	t.conns[p.id] = p
	return true
}

func (t *TCPTransport) unregister(p *tcpPeer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur, ok := t.conns[p.id]; ok && cur == p {
		delete(t.conns, p.id)
	}
}
