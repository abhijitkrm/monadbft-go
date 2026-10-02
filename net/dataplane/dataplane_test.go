package dataplane

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func mustAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

// --- priority queues ---

func TestPriorityQueuesOrderAndCapacity(t *testing.T) {
	pq := newPriorityQueues()
	pq.capacity = 10

	reg := udpMsg{payload: []byte("aaaa"), priority: UdpPriorityRegular}
	high := udpMsg{payload: []byte("bb"), priority: UdpPriorityHigh}

	if err := pq.tryPush(reg); err != nil {
		t.Fatal(err)
	}
	if err := pq.tryPush(high); err != nil {
		t.Fatal(err)
	}
	// capacity is PER-PRIORITY: regular has 4/10 bytes, so +7B fails…
	if err := pq.tryPush(udpMsg{payload: []byte("ccccccc"), priority: UdpPriorityRegular}); err != errQueueCapacityExceeded {
		t.Fatalf("want capacity err, got %v", err)
	}
	// …but high has its own budget (2/10) and still accepts
	if err := pq.tryPush(udpMsg{payload: []byte("dd"), priority: UdpPriorityHigh}); err != nil {
		t.Fatalf("high-priority budget is independent: %v", err)
	}

	for _, want := range []string{"bb", "dd", "aaaa"} {
		m, ok := pq.popHighestPriority()
		if !ok || string(m.payload) != want {
			t.Fatalf("want %q, got %q", want, m.payload)
		}
	}
	if _, ok := pq.popHighestPriority(); ok {
		t.Fatal("queue should be empty")
	}
	// byte accounting released → push succeeds again
	if err := pq.tryPush(udpMsg{payload: []byte("0123456789"), priority: UdpPriorityRegular}); err != nil {
		t.Fatal(err)
	}
}

func TestMaxWriteSize(t *testing.T) {
	// 65507/1472 = 44 → 44*1472 = 64768 (< 128-seg cap)
	if got := maxWriteSizeForSegmentSize(1472); got != 64768 {
		t.Fatalf("got %d", got)
	}
	// tiny segments hit the 128-segment cap
	if got := maxWriteSizeForSegmentSize(100); got != 128*100 {
		t.Fatalf("got %d", got)
	}
}

// --- addrlist ---

func TestAddrlistStatusTransitions(t *testing.T) {
	a := newAddrlist(nil)
	ip := netip.MustParseAddr("10.0.0.1")

	if a.status(ip) != statusUnknown {
		t.Fatal("want unknown")
	}
	a.addTrusted(ip)
	if a.status(ip) != statusTrusted {
		t.Fatal("want trusted")
	}
	a.ban(ip, time.Now())
	if a.status(ip) != statusBanned {
		t.Fatal("banned takes precedence over trusted")
	}
	a.removeTrusted(ip)
	if a.status(ip) != statusBanned {
		t.Fatal("removing trust keeps ban")
	}
	a.unban(ip)
	if a.status(ip) != statusUnknown {
		t.Fatal("unban+untrusted → unknown, entry dropped")
	}
	if _, ok := a.entries[ip]; ok {
		t.Fatal("entry should be deleted")
	}
}

func TestBanExpiry(t *testing.T) {
	a := newAddrlist(nil)
	b := newBanExpiry(a, 60*time.Millisecond)
	ip := netip.MustParseAddr("10.0.0.2")

	a.ban(ip, time.Now())
	b.enqueue(ip, time.Now())
	time.Sleep(120 * time.Millisecond)
	if a.status(ip) != statusUnknown {
		t.Fatal("ban should have expired")
	}
}

func TestBanExpiryRenewed(t *testing.T) {
	a := newAddrlist(nil)
	b := newBanExpiry(a, 80*time.Millisecond)
	ip := netip.MustParseAddr("10.0.0.3")

	a.ban(ip, time.Now())
	b.enqueue(ip, time.Now())
	time.Sleep(40 * time.Millisecond)
	// renew the ban before the queued entry expires
	a.ban(ip, time.Now())
	time.Sleep(80 * time.Millisecond)
	if a.status(ip) != statusBanned {
		t.Fatal("renewed ban must survive the first queue entry's expiry")
	}
}

// --- rate limiter ---

func TestRateLimiterBurst(t *testing.T) {
	rl := newRateLimiter(TcpRateLimit{RPS: 10, RPSBurst: 3})
	for i := 0; i < 3; i++ {
		if !rl.check() {
			t.Fatalf("burst token %d should pass", i)
		}
	}
	if rl.check() {
		t.Fatal("bucket exhausted — should reject")
	}
	time.Sleep(150 * time.Millisecond) // ~1.5 tokens at 10 rps
	if !rl.check() {
		t.Fatal("refill should admit one")
	}
}

// --- end-to-end over real sockets ---

func buildDataplane(t *testing.T) *Dataplane {
	t.Helper()
	d, err := NewDataplaneBuilder(defaultUdpUpBandwidthMbps).
		WithUdpSockets(map[UdpSocketID]netip.AddrPort{
			UdpSocketRaptorcast: mustAddrPort(t, "127.0.0.1:0"),
		}).
		WithTcpSockets(map[TcpSocketID]netip.AddrPort{
			TcpSocketRaptorcast: mustAddrPort(t, "127.0.0.1:0"),
		}).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

func TestUDPRoundTrip(t *testing.T) {
	a, b := buildDataplane(t), buildDataplane(t)
	ha, _ := a.UdpSockets.Get(UdpSocketRaptorcast)
	hb, _ := b.UdpSockets.Get(UdpSocketRaptorcast)

	payload := make([]byte, 2000) // > stride → chunked
	for i := range payload {
		payload[i] = byte(i)
	}
	ha.Write(hb.LocalAddr(), payload, 1472)

	// chunked send → first datagram is 1472 bytes
	m, err := hb.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Payload) != 1472 {
		t.Fatalf("want 1472-byte chunk, got %d", len(m.Payload))
	}
	if m.SrcAddr.Addr() != ha.LocalAddr().Addr() {
		t.Fatalf("src %v", m.SrcAddr)
	}
	// remainder follows
	m, err = hb.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Payload) != 528 {
		t.Fatalf("want 528-byte remainder, got %d", len(m.Payload))
	}
}

func TestUDPBroadcast(t *testing.T) {
	a, b, c := buildDataplane(t), buildDataplane(t), buildDataplane(t)
	ha, _ := a.UdpSockets.Get(UdpSocketRaptorcast)
	hb, _ := b.UdpSockets.Get(UdpSocketRaptorcast)
	hc, _ := c.UdpSockets.Get(UdpSocketRaptorcast)

	ha.WriteBroadcast(BroadcastMsg{
		Targets: []netip.AddrPort{hb.LocalAddr(), hc.LocalAddr()},
		Payload: []byte("hello"),
		Stride:  1472,
	})
	for _, h := range []*UdpSocketHandle{hb, hc} {
		m, err := h.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if string(m.Payload) != "hello" {
			t.Fatalf("got %q", m.Payload)
		}
	}
}

func TestTCPRoundTrip(t *testing.T) {
	a, b := buildDataplane(t), buildDataplane(t)
	ha, _ := a.TcpSockets.Get(TcpSocketRaptorcast)
	hb, _ := b.TcpSockets.Get(TcpSocketRaptorcast)

	done := make(chan struct{})
	ha.Write(hb.LocalAddr(), TcpMsg{Msg: []byte("ping"), Completion: done})

	m, err := hb.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if string(m.Payload) != "ping" {
		t.Fatalf("got %q", m.Payload)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("completion never signalled")
	}
}

func TestTCPBadMagicDrops(t *testing.T) {
	_, b := buildDataplane(t), buildDataplane(t)
	hb, _ := b.TcpSockets.Get(TcpSocketRaptorcast)

	conn, err := net.DialTimeout("tcp", hb.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// wrong magic
	_, _ = conn.Write([]byte{0, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0})
	_, _ = conn.Write([]byte("xxxxx"))
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var buf [1]byte
	if _, err := conn.Read(buf[:]); err == nil {
		t.Fatal("bad-magic conn should have been closed")
	}
}

func TestTCPBanDisconnects(t *testing.T) {
	a, b := buildDataplane(t), buildDataplane(t)
	ha, _ := a.TcpSockets.Get(TcpSocketRaptorcast)
	hb, _ := b.TcpSockets.Get(TcpSocketRaptorcast)

	ha.Write(hb.LocalAddr(), TcpMsg{Msg: []byte("first")})
	if _, err := hb.Recv(); err != nil {
		t.Fatal(err)
	}

	// banning the sender's IP tears down its inbound conn AND refuses new ones
	b.Control.Ban(ha.LocalAddr().Addr())

	ha.Write(hb.LocalAddr(), TcpMsg{Msg: []byte("second")})
	select {
	case m := <-tcpRecvAsync(hb):
		t.Fatalf("banned peer delivered %q", m.Payload)
	case <-time.After(300 * time.Millisecond):
	}
}

// tcpRecvAsync wraps the blocking Recv so tests can bound the wait.
func tcpRecvAsync(h *TcpSocketHandle) <-chan RecvTcpMsg {
	ch := make(chan RecvTcpMsg, 1)
	go func() {
		if m, err := h.Recv(); err == nil {
			ch <- m
		}
	}()
	return ch
}

func TestTCPPerIPConnLimit(t *testing.T) {
	rs := newRxState(newAddrlist(nil), 10, 2)
	ip := netip.MustParseAddr("1.2.3.4")
	t1, ok1 := rs.applyLimits(ip)
	t2, ok2 := rs.applyLimits(ip)
	_, ok3 := rs.applyLimits(ip)
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("per-IP limit: %v %v %v", ok1, ok2, ok3)
	}
	t1.Release()
	t4, ok4 := rs.applyLimits(ip)
	if !ok4 {
		t.Fatal("release should free a slot")
	}
	_ = t2
	_ = t4
}

func TestTCPTrustedBypassesLimits(t *testing.T) {
	a := newAddrlist([]netip.Addr{netip.MustParseAddr("1.2.3.4")})
	rs := newRxState(a, 1, 1)
	ip := netip.MustParseAddr("1.2.3.4")
	for i := 0; i < 5; i++ {
		if _, ok := rs.applyLimits(ip); !ok {
			t.Fatalf("trusted conn %d refused", i)
		}
	}
	// untrusted is capped at 1
	other := netip.MustParseAddr("9.9.9.9")
	if _, ok := rs.applyLimits(other); !ok {
		t.Fatal()
	}
	if _, ok := rs.applyLimits(other); ok {
		t.Fatal("unknown should hit total limit")
	}
}

func TestBoundedQueueLimits(t *testing.T) {
	q := newBoundedQueue()
	// byte limit: 4MiB cap
	big := TcpMsg{Msg: make([]byte, 3*1024*1024)}
	if err := q.trySend(big); err != nil {
		t.Fatal(err)
	}
	if err := q.trySend(TcpMsg{Msg: make([]byte, 2*1024*1024)}); err != errQueueByteLimit {
		t.Fatalf("want byte-limit err, got %v", err)
	}
	// drain one → bytes released
	q.recv()
	if err := q.trySend(TcpMsg{Msg: make([]byte, 2*1024*1024)}); err != nil {
		t.Fatal(err)
	}
}
