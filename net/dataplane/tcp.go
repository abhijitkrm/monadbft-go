package dataplane

// Ported from monad-bft/monad-dataplane/src/tcp/{mod,rx,tx}.rs.
// Framing: 16-byte header { magic "SSNC" (LE 0x434e5353), version 1,
// length u64 LE } + payload. Same wire format as upstream.

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	tcpMessageLengthLimit = 3 * 1024 * 1024
	headerMagic           = 0x434e5353 // "SSNC"
	headerVersion         = 1
	tcpMsgHdrSize         = 16

	headerTimeout = 10 * time.Second

	// Minimum transfer speed 1 MB/s; at least 10s for small messages.
	minimumTransferSpeed = 1_000_000
	minimumTransferTime  = 10 * time.Second

	queuedMessageLimit     = 150
	queuedMessageWarnLimit = 100
	queuedMessageByteLimit = 4 * 1024 * 1024
	msgWaitTimeout         = 1 * time.Second
	tcpConnectTimeout      = 10 * time.Second
	tcpFailureLingerWait   = 1 * time.Second
)

func messageTimeout(n int) time.Duration {
	d := time.Duration(uint64(n)/(minimumTransferSpeed/1000)) * time.Millisecond
	if d < minimumTransferTime {
		return minimumTransferTime
	}
	return d
}

type tcpMsgHdr struct {
	magic   uint32
	version uint32
	length  uint64
}

func (h tcpMsgHdr) marshal() []byte {
	b := make([]byte, tcpMsgHdrSize)
	binary.LittleEndian.PutUint32(b[0:], h.magic)
	binary.LittleEndian.PutUint32(b[4:], h.version)
	binary.LittleEndian.PutUint64(b[8:], h.length)
	return b
}

// --- token-bucket rate limiter (governor: per_second(rps).allow_burst(burst)) ---

type rateLimiter struct {
	rps     uint32
	burst   uint32
	mu      sync.Mutex
	tokens  float64
	lastNow time.Time
}

func newRateLimiter(rl TcpRateLimit) *rateLimiter {
	return &rateLimiter{rps: rl.RPS, burst: rl.RPSBurst, tokens: float64(rl.RPSBurst), lastNow: time.Now()}
}

func (r *rateLimiter) check() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(r.lastNow).Seconds()
	r.lastNow = now
	r.tokens += elapsed * float64(r.rps)
	if r.tokens > float64(r.burst) {
		r.tokens = float64(r.burst)
	}
	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}

// --- control: per-connection disconnect ---

type tcpID struct {
	ip   netip.Addr
	port uint16
	id   uint64
}

// tcpControl maps (ip, port, connID) → a closer that aborts the conn
// (Rust: per-conn TcpControlMsg channel + select!; here closing the conn
// unblocks its read loop directly).
type tcpControl struct {
	mu      sync.Mutex
	closers map[tcpID]func()
}

func newTCPControl() *tcpControl {
	return &tcpControl{closers: make(map[tcpID]func())}
}

func (c *tcpControl) register(id tcpID, close func()) {
	c.mu.Lock()
	c.closers[id] = close
	c.mu.Unlock()
}

func (c *tcpControl) unregister(id tcpID) {
	c.mu.Lock()
	delete(c.closers, id)
	c.mu.Unlock()
}

func (c *tcpControl) disconnectIP(ip netip.Addr) {
	c.mu.Lock()
	var hits []func()
	for id, close := range c.closers {
		if id.ip == ip {
			hits = append(hits, close)
		}
	}
	c.mu.Unlock()
	for _, close := range hits {
		close()
	}
}

// disconnectAll — dataplane teardown: close every tracked connection.
func (c *tcpControl) disconnectAll() {
	c.mu.Lock()
	closers := make([]func(), 0, len(c.closers))
	for _, close := range c.closers {
		closers = append(closers, close)
	}
	c.mu.Unlock()
	for _, close := range closers {
		close()
	}
}

func (c *tcpControl) disconnectSocket(ip netip.Addr, port uint16) {
	c.mu.Lock()
	var hits []func()
	for id, close := range c.closers {
		if id.ip == ip && id.port == port {
			hits = append(hits, close)
		}
	}
	c.mu.Unlock()
	for _, close := range hits {
		close()
	}
}

// --- rx side: accept limits + per-conn read loop ---

type rxState struct {
	addrlist              *addrlist
	mu                    sync.Mutex
	tcpConnectionsLimit   int
	perIPConnectionsLimit int
	numConnections        int
	numConnectionsPerIP   map[netip.Addr]int
}

func newRxState(a *addrlist, total, perIP int) *rxState {
	return &rxState{
		addrlist:              a,
		tcpConnectionsLimit:   total,
		perIPConnectionsLimit: perIP,
		numConnectionsPerIP:   make(map[netip.Addr]int),
	}
}

// connectionToken releases its accounting slot on Release.
type connectionToken struct {
	state   *rxState
	ip      netip.Addr
	tracked bool // false = trusted (no accounting)
	once    sync.Once
}

func (t *connectionToken) Release() {
	t.once.Do(func() {
		if !t.tracked {
			return
		}
		t.state.mu.Lock()
		defer t.state.mu.Unlock()
		t.state.numConnections--
		if n, ok := t.state.numConnectionsPerIP[t.ip]; ok {
			if n <= 1 {
				delete(t.state.numConnectionsPerIP, t.ip)
			} else {
				t.state.numConnectionsPerIP[t.ip] = n - 1
			}
		}
	})
}

func (s *rxState) applyLimits(ip netip.Addr) (*connectionToken, bool) {
	switch s.addrlist.status(ip) {
	case statusBanned:
		return nil, false
	case statusTrusted:
		return &connectionToken{state: s, ip: ip, tracked: false}, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.numConnections >= s.tcpConnectionsLimit {
		return nil, false
	}
	if s.numConnectionsPerIP[ip] >= s.perIPConnectionsLimit {
		return nil, false
	}
	s.numConnectionsPerIP[ip]++
	s.numConnections++
	return &connectionToken{state: s, ip: ip, tracked: true}, true
}

type tcpEgressMsg struct {
	addr netip.AddrPort
	msg  TcpMsg
}

// tcpAcceptLoop — accepts with limits, spawns a read loop per connection.
func tcpAcceptLoop(rl TcpRateLimit, ctl *tcpControl, rs *rxState, ln net.Listener, ingress chan RecvTcpMsg, stop <-chan struct{}, wg *sync.WaitGroup) {
	var connID uint64
	defer wg.Done() // accept loop counts as a producer: read loops can only outlive it
	go func() { <-stop; _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		remote, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = conn.Close()
			continue
		}
		token, ok := rs.applyLimits(remote.AddrPort().Addr())
		if !ok {
			_ = conn.Close()
			continue
		}
		id := tcpID{ip: remote.AddrPort().Addr(), port: remote.AddrPort().Port(), id: connID}
		connID++
		wg.Add(1)
		go func() {
			defer wg.Done()
			tcpReadLoop(newRateLimiter(rl), ctl, token, id, remote.AddrPort(), conn, ingress, stop)
		}()
	}
}

func tcpReadLoop(rl *rateLimiter, ctl *tcpControl, token *connectionToken, id tcpID, addr netip.AddrPort, conn net.Conn, ingress chan<- RecvTcpMsg, stop <-chan struct{}) {
	defer token.Release()
	defer ctl.unregister(id)
	defer conn.Close()
	ctl.register(id, func() { conn.Close() })
	for {
		payload, ok := readTCPMessage(conn)
		if !ok {
			return
		}
		if !rl.check() {
			return // rate limit exceeded → drop connection
		}
		select {
		case ingress <- RecvTcpMsg{SrcAddr: addr, Payload: payload}:
		case <-stop:
			return
		}
	}
}

// readTCPMessage reads one framed message; returns payload or false (conn dies).
func readTCPMessage(conn net.Conn) ([]byte, bool) {
	var hdr [tcpMsgHdrSize]byte
	_ = conn.SetReadDeadline(time.Now().Add(headerTimeout))
	if _, err := readFull(conn, hdr[:]); err != nil {
		return nil, false
	}
	magic := binary.LittleEndian.Uint32(hdr[0:])
	version := binary.LittleEndian.Uint32(hdr[4:])
	length := binary.LittleEndian.Uint64(hdr[8:])
	if magic != headerMagic || version != headerVersion || length > tcpMessageLengthLimit {
		return nil, false
	}
	payload := make([]byte, length)
	_ = conn.SetReadDeadline(time.Now().Add(messageTimeout(int(length))))
	if _, err := readFull(conn, payload); err != nil {
		return nil, false
	}
	return payload, true
}

func readFull(conn net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := conn.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// --- tx side: per-peer bounded queue + conn task ---

const boundedQueueCap = queuedMessageLimit

type boundedQueue struct {
	ch          chan TcpMsg
	queuedBytes int64 // atomic
	mu          sync.Mutex
	bytes       int
}

func newBoundedQueue() *boundedQueue {
	return &boundedQueue{ch: make(chan TcpMsg, boundedQueueCap)}
}

var (
	errQueueByteLimit = errors.New("peer byte limit reached")
	errQueueFull      = errors.New("peer message limit reached")
)

func (q *boundedQueue) trySend(m TcpMsg) error {
	q.mu.Lock()
	if q.bytes+len(m.Msg) > queuedMessageByteLimit {
		q.mu.Unlock()
		return errQueueByteLimit
	}
	q.bytes += len(m.Msg)
	q.mu.Unlock()
	select {
	case q.ch <- m:
		return nil
	default:
		q.mu.Lock()
		q.bytes -= len(m.Msg)
		q.mu.Unlock()
		return errQueueFull
	}
}

func (q *boundedQueue) recv() (TcpMsg, bool) {
	m, ok := <-q.ch
	if ok {
		q.mu.Lock()
		q.bytes -= len(m.Msg)
		q.mu.Unlock()
	}
	return m, ok
}

func (q *boundedQueue) tryRecv() (TcpMsg, bool) {
	select {
	case m := <-q.ch:
		q.mu.Lock()
		q.bytes -= len(m.Msg)
		q.mu.Unlock()
		return m, true
	default:
		return TcpMsg{}, false
	}
}

func (q *boundedQueue) len() int { return len(q.ch) }

// txState — per-peer queue + running conn task bookkeeping.
type txState struct {
	mu               sync.Mutex
	addrlist         *addrlist
	connectionsLimit int
	peerChannels     map[netip.AddrPort]*boundedQueue
}

func newTxState(a *addrlist, limit int) *txState {
	return &txState{
		addrlist:         a,
		connectionsLimit: limit,
		peerChannels:     make(map[netip.AddrPort]*boundedQueue),
	}
}

// push enqueues msg for addr, spawning a conn task on first use.
func (s *txState) push(addr netip.AddrPort, m TcpMsg, spawn func(*boundedQueue)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, ok := s.peerChannels[addr]
	if !ok {
		if s.addrlist.status(addr.Addr()) != statusTrusted && len(s.peerChannels) >= s.connectionsLimit {
			return // egress drop
		}
		q = newBoundedQueue()
		s.peerChannels[addr] = q
		spawn(q) // must be goroutine-launching; caller guarantees
	}
	_ = q.trySend(m)
}

func (s *txState) remove(addr netip.AddrPort) {
	s.mu.Lock()
	delete(s.peerChannels, addr)
	s.mu.Unlock()
}

// tcpTxLoop drains the shared egress channel into per-peer queues.
func tcpTxLoop(cfg TcpConfig, addrl *addrlist, egress <-chan tcpEgressMsg, stop <-chan struct{}) {
	ts := newTxState(addrl, cfg.ConnectionsLimit)
	var connID uint64
	for {
		select {
		case em := <-egress:
			ts.push(em.addr, em.msg, func(q *boundedQueue) {
				go tcpConnTask(connID, em.addr, q, ts)
				connID++
			})
		case <-stop:
			return
		}
	}
}

// tcpConnTask runs the peer connection: connect → drain queue until idle.
func tcpConnTask(connID uint64, addr netip.AddrPort, q *boundedQueue, ts *txState) {
	defer ts.remove(addr)
	defer func() {
		// drain remaining queued messages (they're dropped)
		for {
			if _, ok := q.tryRecv(); !ok {
				break
			}
		}
	}()

	if err := tcpConnectAndSend(addr, q); err != nil {
		time.Sleep(tcpFailureLingerWait)
	}
}

func tcpConnectAndSend(addr netip.AddrPort, q *boundedQueue) error {
	dialer := net.Dialer{Timeout: tcpConnectTimeout}
	conn, err := dialer.Dial("tcp", addr.String())
	if err != nil {
		return err
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(false) // cork
	}
	for {
		msg, ok := q.tryRecv()
		if !ok {
			// idle — wait briefly for more messages
			select {
			case m, ok2 := <-q.ch:
				if !ok2 {
					return nil
				}
				q.mu.Lock()
				q.bytes -= len(m.Msg)
				q.mu.Unlock()
				msg = m
			case <-time.After(msgWaitTimeout):
				return nil
			}
		}
		if len(msg.Msg) > tcpMessageLengthLimit {
			continue // skip oversize
		}
		if err := sendTCPMessage(conn, msg.Msg); err != nil {
			return err
		}
		if msg.Completion != nil {
			close(msg.Completion)
		}
	}
}

func sendTCPMessage(conn net.Conn, payload []byte) error {
	hdr := tcpMsgHdr{magic: headerMagic, version: headerVersion, length: uint64(len(payload))}
	_ = conn.SetWriteDeadline(time.Now().Add(messageTimeout(len(payload))))
	if _, err := conn.Write(hdr.marshal()); err != nil {
		return err
	}
	total := 0
	for total < len(payload) {
		n, err := conn.Write(payload[total:])
		total += n
		if err != nil {
			return err
		}
	}
	return nil
}

// --- TCP handles ---

// TcpSocketReader — inbound framed messages for this listener.
type TcpSocketReader struct {
	socketID TcpSocketID
	ingress  <-chan RecvTcpMsg
}

func (r *TcpSocketReader) Recv() (RecvTcpMsg, error) {
	m, ok := <-r.ingress
	if !ok {
		return RecvTcpMsg{}, errors.New("tcp ingress channel closed")
	}
	return m, nil
}

// TcpSocketWriter — queues outbound messages by peer addr.
type TcpSocketWriter struct {
	socketID   TcpSocketID
	socketAddr netip.AddrPort
	egress     chan<- tcpEgressMsg
}

// Write queues msg for delivery to addr (Rust TcpSocketWriter::write).
func (w *TcpSocketWriter) Write(addr netip.AddrPort, msg TcpMsg) {
	select {
	case w.egress <- tcpEgressMsg{addr: addr, msg: msg}:
	default:
		// egress channel full — drop
	}
}

func (w *TcpSocketWriter) LocalAddr() netip.AddrPort { return w.socketAddr }

// TcpSocketHandle bundles reader+writer.
type TcpSocketHandle struct {
	Reader *TcpSocketReader
	Writer *TcpSocketWriter
}

func (h *TcpSocketHandle) ID() TcpSocketID                     { return h.Writer.socketID }
func (h *TcpSocketHandle) LocalAddr() netip.AddrPort           { return h.Writer.socketAddr }
func (h *TcpSocketHandle) Write(addr netip.AddrPort, m TcpMsg) { h.Writer.Write(addr, m) }
func (h *TcpSocketHandle) Recv() (RecvTcpMsg, error)           { return h.Reader.Recv() }
func (h *TcpSocketHandle) Split() (*TcpSocketReader, *TcpSocketWriter) {
	return h.Reader, h.Writer
}
