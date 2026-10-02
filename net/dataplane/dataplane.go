package dataplane

// Ported from monad-bft/monad-dataplane/src/lib.rs.
// Builder + socket handles + control plane; monoio/io_uring runtime is
// replaced with plain Go sockets and goroutines.

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// TcpSocketID identifies a registered TCP listener (Rust TcpSocketId).
type TcpSocketID int

const (
	TcpSocketRaptorcast TcpSocketID = iota
	TcpSocketAuthenticatedRaptorcast
)

// UdpSocketID identifies a registered UDP socket (Rust UdpSocketId).
type UdpSocketID int

const (
	UdpSocketRaptorcast UdpSocketID = iota
	UdpSocketAuthenticatedRaptorcast
	UdpSocketDirect
)

// UdpPriority — High messages always drain before Regular (Rust UdpPriority).
type UdpPriority int

const (
	UdpPriorityHigh UdpPriority = iota
	UdpPriorityRegular
)

// BroadcastMsg — one payload to many targets (Rust BroadcastMsg).
type BroadcastMsg struct {
	Targets []netip.AddrPort
	Payload []byte
	Stride  uint16
}

// UnicastItem is one (dst, payload) pair in a UnicastMsg.
type UnicastItem struct {
	Dst     netip.AddrPort
	Payload []byte
}

// UnicastMsg — many distinct payloads, one stride (Rust UnicastMsg).
type UnicastMsg struct {
	Msgs   []UnicastItem
	Stride uint16
}

// RecvUdpMsg — an inbound datagram. Stride is the segment size the sender
// used (with plain sockets it equals the datagram length).
type RecvUdpMsg struct {
	SrcAddr netip.AddrPort
	Payload []byte
	Stride  uint16
}

// RecvTcpMsg — an inbound framed TCP message.
type RecvTcpMsg struct {
	SrcAddr netip.AddrPort
	Payload []byte
}

// TcpMsg — outbound framed TCP message; Completion is signalled (closed)
// after the message is written to the socket (Rust oneshot completion).
type TcpMsg struct {
	Msg        []byte
	Completion chan struct{}
}

const (
	defaultUdpUpBandwidthMbps = 10_000 // builder arg
	defaultSegmentSize        = 1472   // DEFAULT_SEGMENT_SIZE at 1500 MTU

	tcpIngressChannelSize = 1024
	tcpEgressChannelSize  = 256
)

// SocketHandles — ordered id→handle lookup (Rust SocketHandles).
type SocketHandles[I comparable, H any] struct {
	handles []struct {
		id I
		h  H
	}
}

func (s *SocketHandles[I, H]) push(id I, h H) {
	s.handles = append(s.handles, struct {
		id I
		h  H
	}{id, h})
}

func (s *SocketHandles[I, H]) Get(id I) (H, bool) {
	for _, e := range s.handles {
		if e.id == id {
			return e.h, true
		}
	}
	var zero H
	return zero, false
}

// UdpSocketHandles / TcpSocketHandles.
type UdpSocketHandles = SocketHandles[UdpSocketID, *UdpSocketHandle]
type TcpSocketHandles = SocketHandles[TcpSocketID, *TcpSocketHandle]

// TcpConfig — TCP limits (Rust TcpConfig).
type TcpConfig struct {
	RateLimit             TcpRateLimit
	ConnectionsLimit      int
	PerIPConnectionsLimit int
}

// TcpRateLimit — per-connection message rate (Rust TcpRateLimit; rps + burst).
type TcpRateLimit struct {
	RPS      uint32
	RPSBurst uint32
}

// DataplaneBuilder mirrors upstream DataplaneBuilder.
type DataplaneBuilder struct {
	trustedAddresses   []netip.Addr
	udpUpBandwidthMbps uint64
	udpBufferSize      int
	tcpConfig          TcpConfig
	banDuration        time.Duration
	udpSockets         []struct {
		id   UdpSocketID
		addr netip.AddrPort
	}
	tcpSockets []struct {
		id   TcpSocketID
		addr netip.AddrPort
	}
}

// NewDataplaneBuilder — upBandwidthMbps is the UDP egress pacing rate.
func NewDataplaneBuilder(upBandwidthMbps uint64) *DataplaneBuilder {
	return &DataplaneBuilder{
		udpUpBandwidthMbps: upBandwidthMbps,
		tcpConfig: TcpConfig{
			RateLimit:             TcpRateLimit{RPS: 10_000, RPSBurst: 2_000},
			ConnectionsLimit:      10_000,
			PerIPConnectionsLimit: 100,
		},
		banDuration: 5 * time.Minute,
	}
}

func (b *DataplaneBuilder) WithUdpBufferSize(size int) *DataplaneBuilder {
	b.udpBufferSize = size
	return b
}

func (b *DataplaneBuilder) WithTcpConnectionsLimit(total, perIP int) *DataplaneBuilder {
	b.tcpConfig.ConnectionsLimit = total
	if perIP == 0 {
		perIP = total
	}
	b.tcpConfig.PerIPConnectionsLimit = perIP
	return b
}

func (b *DataplaneBuilder) WithTcpRPSBurst(rps, burst uint32) *DataplaneBuilder {
	b.tcpConfig.RateLimit = TcpRateLimit{RPS: rps, RPSBurst: burst}
	return b
}

func (b *DataplaneBuilder) WithTrustedIPs(ips []netip.Addr) *DataplaneBuilder {
	b.trustedAddresses = ips
	return b
}

func (b *DataplaneBuilder) WithBanDuration(d time.Duration) *DataplaneBuilder {
	b.banDuration = d
	return b
}

func (b *DataplaneBuilder) WithUdpSockets(socks map[UdpSocketID]netip.AddrPort) *DataplaneBuilder {
	for id, addr := range socks {
		b.udpSockets = append(b.udpSockets, struct {
			id   UdpSocketID
			addr netip.AddrPort
		}{id, addr})
	}
	return b
}

func (b *DataplaneBuilder) WithTcpSockets(socks map[TcpSocketID]netip.AddrPort) *DataplaneBuilder {
	for id, addr := range socks {
		b.tcpSockets = append(b.tcpSockets, struct {
			id   TcpSocketID
			addr netip.AddrPort
		}{id, addr})
	}
	return b
}

// Dataplane — built, running sockets + control.
type Dataplane struct {
	UdpSockets UdpSocketHandles
	TcpSockets TcpSocketHandles
	Control    *DataplaneControl

	udpEgress chan udpMsg
	tcpEgress chan tcpEgressMsg
	stop      chan struct{}
	listeners []interface{ Close() error }
	ready     atomic.Bool
}

// Build opens all registered sockets and starts the tx/rx goroutines.
func (b *DataplaneBuilder) Build() (*Dataplane, error) {
	d := &Dataplane{
		udpEgress: make(chan udpMsg, udpEgressChannelSize),
		tcpEgress: make(chan tcpEgressMsg, tcpEgressChannelSize),
		stop:      make(chan struct{}),
	}

	udpConns := map[UdpSocketID]*net.UDPConn{}
	for _, cfg := range b.udpSockets {
		sock, err := udpSocketListen(cfg.id, cfg.addr, b.udpBufferSize)
		if err != nil {
			return nil, err
		}
		udpConns[cfg.id] = sock.conn
		ingress := make(chan RecvUdpMsg, udpIngressChannelSize)
		handle := &UdpSocketHandle{
			Reader: &UdpSocketReader{socketID: cfg.id, ingress: ingress},
			Writer: &UdpSocketWriter{
				socketID:    cfg.id,
				socketAddr:  sock.conn.LocalAddr().(*net.UDPAddr).AddrPort(),
				egress:      d.udpEgress,
				msgsDropped: &atomic.Uint64{},
			},
		}
		d.UdpSockets.push(cfg.id, handle)
		go sock.rxLoop(ingress, defaultSegmentSize, d.stop)
		d.listeners = append(d.listeners, sock.conn)
	}

	addrl := newAddrlist(b.trustedAddresses)
	expiry := newBanExpiry(addrl, b.banDuration)

	tcpCtl := newTCPControl()
	rxState := newRxState(addrl, b.tcpConfig.ConnectionsLimit, b.tcpConfig.PerIPConnectionsLimit)
	for _, cfg := range b.tcpSockets {
		ln, err := net.Listen("tcp", cfg.addr.String())
		if err != nil {
			return nil, err
		}
		ingress := make(chan RecvTcpMsg, tcpIngressChannelSize)
		handle := &TcpSocketHandle{
			Reader: &TcpSocketReader{socketID: cfg.id, ingress: ingress},
			Writer: &TcpSocketWriter{
				socketID:   cfg.id,
				socketAddr: ln.Addr().(*net.TCPAddr).AddrPort(),
				egress:     d.tcpEgress,
			},
		}
		d.TcpSockets.push(cfg.id, handle)
		d.listeners = append(d.listeners, ln)
		var wg sync.WaitGroup
		wg.Add(1)
		go tcpAcceptLoop(b.tcpConfig.RateLimit, tcpCtl, rxState, ln, ingress, d.stop, &wg)
		go func() { wg.Wait(); close(ingress) }()
	}

	d.Control = newDataplaneControl(addrl, expiry, tcpCtl)

	go udpTxLoop(udpConns, d.udpEgress, b.udpUpBandwidthMbps, defaultSegmentSize, d.stop)
	go tcpTxLoop(b.tcpConfig, addrl, d.tcpEgress, d.stop)

	d.ready.Store(true)
	return d, nil
}

// Ready reports whether all sockets are bound and serving (Rust readiness).
func (d *Dataplane) Ready() bool { return d.ready.Load() }

// Close tears down sockets and goroutines.
func (d *Dataplane) Close() {
	close(d.stop)
	for _, l := range d.listeners {
		_ = l.Close()
	}
	d.Control.tcpCtl.disconnectAll()
}

// DataplaneControl — ban/disconnect/trusted management (Rust DataplaneControl).
type DataplaneControl struct {
	addrlist *addrlist
	expiry   *banExpiry
	tcpCtl   *tcpControl
}

func newDataplaneControl(a *addrlist, e *banExpiry, t *tcpControl) *DataplaneControl {
	return &DataplaneControl{addrlist: a, expiry: e, tcpCtl: t}
}

func (c *DataplaneControl) AddTrusted(ip netip.Addr)    { c.addrlist.addTrusted(ip) }
func (c *DataplaneControl) RemoveTrusted(ip netip.Addr) { c.addrlist.removeTrusted(ip) }
func (c *DataplaneControl) UpdateTrusted(added, removed []netip.Addr) {
	for _, ip := range removed {
		c.addrlist.removeTrusted(ip)
	}
	for _, ip := range added {
		c.addrlist.addTrusted(ip)
	}
}

// Ban marks the IP banned and schedules expiry; also drops its conns.
func (c *DataplaneControl) Ban(ip netip.Addr) {
	now := time.Now()
	c.addrlist.ban(ip, now)
	c.expiry.enqueue(ip, now)
	c.tcpCtl.disconnectIP(ip)
}

func (c *DataplaneControl) DisconnectIP(ip netip.Addr) { c.tcpCtl.disconnectIP(ip) }
func (c *DataplaneControl) Disconnect(addr netip.AddrPort) {
	c.tcpCtl.disconnectSocket(addr.Addr(), addr.Port())
}
