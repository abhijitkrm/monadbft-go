package dataplane

// Ported from monad-bft/monad-dataplane/src/udp.rs (+ the UdpSocket* handle
// layer in lib.rs). Same queueing/pacing semantics; Go netpoll goroutines
// replace monoio/io_uring + GSO batching — on the wire each stride-sized
// chunk is one datagram either way.

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

const (
	priorityQueueBytesCapacity = 100 * 1024 * 1024
	// maxAggregatedWriteSize = 65535 - IPv4(20) - UDP(8); batches cap at
	// min(that/seg, 128) * seg bytes.
	maxAggregatedWriteSize = 65535 - 20 - 8
	maxAggregatedSegments  = 128

	udpEgressChannelSize  = 12_800
	udpIngressChannelSize = 12_800

	// pacingSleepOvershootDetectionWindow — if the tx loop overslept by more
	// than this, reset the pacing baseline (Rust: 100ms).
	pacingOvershootWindow = 100 * time.Millisecond
)

var errQueueCapacityExceeded = errors.New("priority queue capacity exceeded")

// udpMsg is one queued egress datagram (Rust UdpMsg).
type udpMsg struct {
	socketID UdpSocketID
	dst      netip.AddrPort
	payload  []byte
	stride   uint16
	priority UdpPriority
}

func maxWriteSizeForSegmentSize(segmentSize uint16) uint16 {
	segs := maxAggregatedWriteSize / int(segmentSize)
	if segs > maxAggregatedSegments {
		segs = maxAggregatedSegments
	}
	return uint16(segs) * segmentSize
}

// priorityQueues — two FIFO byte-bounded queues; index 0 = High.
type priorityQueues struct {
	queues       [2][]udpMsg
	currentBytes [2]int
	capacity     int
}

func newPriorityQueues() *priorityQueues {
	return &priorityQueues{capacity: priorityQueueBytesCapacity}
}

func (q *priorityQueues) tryPush(m udpMsg) error {
	idx := int(m.priority)
	if q.currentBytes[idx]+len(m.payload) > q.capacity {
		return errQueueCapacityExceeded
	}
	q.currentBytes[idx] += len(m.payload)
	q.queues[idx] = append(q.queues[idx], m)
	return nil
}

func (q *priorityQueues) popHighestPriority() (udpMsg, bool) {
	for idx := range q.queues {
		if len(q.queues[idx]) > 0 {
			m := q.queues[idx][0]
			q.queues[idx] = q.queues[idx][1:]
			q.currentBytes[idx] -= len(m.payload)
			return m, true
		}
	}
	return udpMsg{}, false
}

func (q *priorityQueues) isEmpty() bool {
	return len(q.queues[0]) == 0 && len(q.queues[1]) == 0
}

// UdpSocketWriter is the safe-for-concurrent-use egress handle.
type UdpSocketWriter struct {
	socketID    UdpSocketID
	socketAddr  netip.AddrPort
	egress      chan<- udpMsg
	msgsDropped *atomic.Uint64
}

func (w *UdpSocketWriter) Write(dst netip.AddrPort, payload []byte, stride uint16) {
	w.trySend(udpMsg{
		socketID: w.socketID,
		dst:      dst,
		payload:  payload,
		stride:   stride,
		priority: UdpPriorityRegular,
	})
}

func (w *UdpSocketWriter) trySend(m udpMsg) bool {
	select {
	case w.egress <- m:
		return true
	default:
		w.msgsDropped.Add(1)
		return false
	}
}

// WriteBroadcast fans payload out to every target; on a full channel the
// remaining targets are dropped (upstream behavior).
func (w *UdpSocketWriter) WriteBroadcast(msg BroadcastMsg) {
	w.WriteBroadcastWithPriority(msg, UdpPriorityRegular)
}

func (w *UdpSocketWriter) WriteBroadcastWithPriority(msg BroadcastMsg, priority UdpPriority) {
	for i, dst := range msg.Targets {
		if !w.trySend(udpMsg{
			socketID: w.socketID, dst: dst, payload: msg.Payload,
			stride: msg.Stride, priority: priority,
		}) {
			w.msgsDropped.Add(uint64(len(msg.Targets) - i - 1))
			return
		}
	}
}

func (w *UdpSocketWriter) WriteUnicast(msg UnicastMsg) {
	w.WriteUnicastWithPriority(msg, UdpPriorityRegular)
}

func (w *UdpSocketWriter) WriteUnicastWithPriority(msg UnicastMsg, priority UdpPriority) {
	for _, m := range msg.Msgs {
		if !w.trySend(udpMsg{
			socketID: w.socketID, dst: m.Dst, payload: m.Payload,
			stride: msg.Stride, priority: priority,
		}) {
			break
		}
	}
}

func (w *UdpSocketWriter) LocalAddr() netip.AddrPort { return w.socketAddr }

// Dropped reports egress messages dropped due to a full channel.
func (w *UdpSocketWriter) Dropped() uint64 { return w.msgsDropped.Load() }

// UdpSocketReader — one Recv call delivers one received datagram group.
type UdpSocketReader struct {
	socketID UdpSocketID
	ingress  <-chan RecvUdpMsg
}

func (r *UdpSocketReader) Recv() (RecvUdpMsg, error) {
	m, ok := <-r.ingress
	if !ok {
		return RecvUdpMsg{}, errors.New("udp ingress channel closed")
	}
	return m, nil
}

// UdpSocketHandle bundles reader+writer (Rust UdpSocketHandle::split).
type UdpSocketHandle struct {
	Reader *UdpSocketReader
	Writer *UdpSocketWriter
}

func (h *UdpSocketHandle) ID() UdpSocketID           { return h.Writer.socketID }
func (h *UdpSocketHandle) LocalAddr() netip.AddrPort { return h.Writer.socketAddr }
func (h *UdpSocketHandle) Write(dst netip.AddrPort, payload []byte, stride uint16) {
	h.Writer.Write(dst, payload, stride)
}
func (h *UdpSocketHandle) WriteBroadcast(m BroadcastMsg) { h.Writer.WriteBroadcast(m) }
func (h *UdpSocketHandle) WriteBroadcastWithPriority(m BroadcastMsg, p UdpPriority) {
	h.Writer.WriteBroadcastWithPriority(m, p)
}
func (h *UdpSocketHandle) WriteUnicast(m UnicastMsg) { h.Writer.WriteUnicast(m) }
func (h *UdpSocketHandle) WriteUnicastWithPriority(m UnicastMsg, p UdpPriority) {
	h.Writer.WriteUnicastWithPriority(m, p)
}
func (h *UdpSocketHandle) Recv() (RecvUdpMsg, error) { return h.Reader.Recv() }
func (h *UdpSocketHandle) Split() (*UdpSocketReader, *UdpSocketWriter) {
	return h.Reader, h.Writer
}

// --- internal socket + tx loop ---

type udpSocket struct {
	conn   *net.UDPConn
	id     UdpSocketID
	handle *UdpSocketHandle
}

func udpSocketListen(id UdpSocketID, addr netip.AddrPort, bufSize int) (*udpSocket, error) {
	udpAddr := net.UDPAddrFromAddrPort(addr)
	// Bind the matching address family: "udp" on an IPv4-unspecified addr
	// ends up on the IPv6 wildcard on some platforms (e.g. macOS) where
	// IPv4 datagrams to peers' advertised v4 records are never delivered.
	network := "udp4"
	if udpAddr.IP != nil && udpAddr.IP.To4() == nil {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return nil, err
	}
	if bufSize > 0 {
		_ = conn.SetReadBuffer(bufSize)
		_ = conn.SetWriteBuffer(bufSize)
	}
	return &udpSocket{conn: conn, id: id}, nil
}

// rxLoop reads datagrams and forwards them into the socket's ingress channel.
// stride mirrors upstream's RecvUdpMsg.stride (GRO segment size); with plain
// recvmsg each datagram is its own segment.
func (s *udpSocket) rxLoop(ingress chan<- RecvUdpMsg, segmentSize uint16, stop <-chan struct{}) {
	defer close(ingress) // socket teardown ends the read stream
	buf := make([]byte, 1<<16)
	for {
		n, src, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				continue // transient read error — keep serving
			}
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		stride := segmentSize
		if uint16(n) < stride {
			stride = uint16(n)
		}
		select {
		case ingress <- RecvUdpMsg{SrcAddr: src, Payload: payload, Stride: stride}:
		default:
			// ingress full — drop (upstream drops on channel pressure too)
		}
	}
}

// txLoop drains the egress channel through the priority queues and paces
// sends to upBandwidthMbps.
func udpTxLoop(
	sockets map[UdpSocketID]*net.UDPConn,
	egress <-chan udpMsg,
	upBandwidthMbps uint64,
	segmentSize uint16,
	stop <-chan struct{},
) {
	pq := newPriorityQueues()
	maxBatchBytes := int(maxWriteSizeForSegmentSize(segmentSize))
	nextTransmit := time.Now()
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	// drainEgress moves all immediately-available egress msgs into the queues.
	drainEgress := func() {
		for {
			select {
			case m := <-egress:
				_ = pq.tryPush(m)
			default:
				return
			}
		}
	}

	for {
		// block until at least one message is queued
		if pq.isEmpty() {
			select {
			case m := <-egress:
				_ = pq.tryPush(m)
			case <-stop:
				return
			}
		}
		drainEgress()

		// pace
		now := time.Now()
		if nextTransmit.After(now) {
			timer.Reset(nextTransmit.Sub(now))
			select {
			case <-timer.C:
			case m := <-egress:
				_ = pq.tryPush(m)
				drainEgress()
				<-timer.C // still wait out the pace
			case <-stop:
				return
			}
		} else if now.Sub(nextTransmit) > pacingOvershootWindow {
			nextTransmit = now
		}

		totalBytes := 0
		batch := 0
		for !pq.isEmpty() && totalBytes < maxBatchBytes && batch < maxAggregatedSegments {
			m, _ := pq.popHighestPriority()
			chunkSize := min3(len(m.payload), int(m.stride), maxBatchBytes)
			if chunkSize+totalBytes > maxBatchBytes {
				_ = pq.tryPush(m) // re-queue whole msg
				break
			}
			chunk := m.payload[:chunkSize]
			rest := m.payload[chunkSize:]
			totalBytes += len(chunk)
			if len(rest) > 0 {
				m.payload = rest
				_ = pq.tryPush(m)
			}
			conn := sockets[m.socketID]
			if conn != nil {
				_, _ = conn.WriteToUDPAddrPort(chunk, m.dst)
			}
			batch++
		}

		if totalBytes > 0 {
			nextTransmit = nextTransmit.Add(
				time.Duration(uint64(totalBytes) * 8 * 1000 / upBandwidthMbps))
		}
	}
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}
