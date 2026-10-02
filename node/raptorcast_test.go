package node

// Integration tests for RaptorcastTransport — two real transports bound to
// loopback exchanging peer discovery, wireauth handshakes, raptorcast chunks,
// and TCP fallback traffic over actual sockets.

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeebo/blake3"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/net/peerdisc"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

type rcInbound struct {
	from    types.NodeId
	payload []byte
}

type rcNode struct {
	tr  *RaptorcastTransport
	id  types.NodeId
	key *crypto.SecpKeyPair
	rec peerdisc.MonadNameRecord
	got chan rcInbound
}

func rcKey(t *testing.T, seed uint64) *crypto.SecpKeyPair {
	t.Helper()
	var sb [8]byte
	binary.LittleEndian.PutUint64(sb[:], seed)
	digest := blake3.Sum256(sb[:])
	kp, err := crypto.SecpKeyPairFromBytes(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func freePort(t *testing.T, network string) uint16 {
	t.Helper()
	switch network {
	case "udp":
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return uint16(c.LocalAddr().(*net.UDPAddr).Port)
	default:
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return uint16(l.Addr().(*net.TCPAddr).Port)
	}
}

// newRCNode builds a transport on fresh loopback ports. validators is the
// epoch-1 validator set (including self, which is what makes the node a
// validator-role participant).
func newRCNode(t *testing.T, seed uint64, validators []types.NodeId) *rcNode {
	t.Helper()
	key := rcKey(t, seed)
	id := types.NewNodeId(key.PubKey())

	authP := freePort(t, "udp")
	plainP := freePort(t, "udp")
	tcpP := freePort(t, "tcp")

	rec := peerdisc.NewMonadNameRecord(
		peerdisc.NewNameRecord(netip.MustParseAddr("127.0.0.1"), tcpP, plainP, authP, 0, 1),
		key)

	members := make(map[types.NodeId]struct{}, len(validators))
	for _, v := range validators {
		members[v] = struct{}{}
	}

	n := &rcNode{id: id, key: key, rec: rec, got: make(chan rcInbound, 64)}
	tr, err := NewRaptorcastTransport(RaptorcastTransportConfig{
		SelfID:   id,
		Key:      key,
		AuthUDP:  netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), authP),
		PlainUDP: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), plainP),
		TCPAddr:  netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), tcpP),
		PeerDisc: peerdisc.PeerDiscoveryBuilder{
			SelfID:                     id,
			SelfRecord:                 rec,
			CurrentEpoch:               1,
			EpochValidators:            map[types.Epoch]map[types.NodeId]struct{}{1: members},
			RefreshPeriod:              time.Minute,
			RequestTimeout:             800 * time.Millisecond,
			UnresponsivePruneThreshold: 5,
			MinNumPeers:                1,
			MaxNumPeers:                50,
			MaxGroupSize:               20,
			PingRateLimitPerSecond:     1000,
			RngSeed:                    seed,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tr.SetHandler(func(from types.NodeId, payload []byte) {
		n.got <- rcInbound{from, payload}
	})
	n.tr = tr
	t.Cleanup(func() { tr.Close() })
	return n
}

func peerEntry(t *testing.T, rec peerdisc.MonadNameRecord) glue.PeerEntry {
	t.Helper()
	e, err := rec.PeerEntry()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// waitFor polls cond until it holds or the deadline expires.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func waitMsg(t *testing.T, n *rcNode, what string) rcInbound {
	t.Helper()
	select {
	case m := <-n.got:
		return m
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return rcInbound{}
	}
}

// exchangePeers feeds each node's signed record into the other's peer
// discovery and waits until both promote each other into routing_info.
func exchangePeers(t *testing.T, a, b *rcNode) {
	t.Helper()
	a.tr.UpdatePeers([]glue.PeerEntry{peerEntry(t, b.rec)}, nil, nil)
	b.tr.UpdatePeers([]glue.PeerEntry{peerEntry(t, a.rec)}, nil, nil)
	waitFor(t, "peerdisc promotion", func() bool {
		has := func(n *rcNode, want types.NodeId) bool {
			for _, e := range n.tr.Peers() {
				if e.Pubkey == want {
					return true
				}
			}
			return false
		}
		return has(a, b.id) && has(b, a.id)
	})
}

func addEpoch(t *testing.T, tr *RaptorcastTransport, validators ...types.NodeId) {
	t.Helper()
	vs := make([]glue.ValidatorStake, len(validators))
	for i, id := range validators {
		vs[i] = glue.ValidatorStake{NodeId: id, Stake: types.StakeFromUint64(100)}
	}
	tr.AddEpochValidatorSet(1, 0, vs)
	tr.UpdateCurrentRound(1, 1)
}

func appMsg(body string) []byte {
	// app payloads are already RLP-encoded when they reach the transport
	return rlp.AppendString(nil, []byte("test:"+body))
}

// TestRaptorcastPeerdiscBootstrap — UpdatePeers → ping → pong → promotion to
// routing_info over real loopback UDP (kind-2 raptorcast envelopes).
func TestRaptorcastPeerdiscBootstrap(t *testing.T) {
	a := newRCNode(t, 1, nil)
	b := newRCNode(t, 2, nil)
	if err := a.tr.Start(); err != nil {
		t.Fatal(err)
	}
	if err := b.tr.Start(); err != nil {
		t.Fatal(err)
	}
	exchangePeers(t, a, b)

	waitFor(t, "Peers() snapshot", func() bool {
		peers := a.tr.Peers()
		return len(peers) == 1 && peers[0].Pubkey == b.id
	})
}

// TestRaptorcastP2PLoopback — point-to-point app delivery, first over the
// non-authenticated fallback socket, then over an established wireauth
// session.
func TestRaptorcastP2PLoopback(t *testing.T) {
	a := newRCNode(t, 11, nil)
	b := newRCNode(t, 12, nil)
	if err := a.tr.Start(); err != nil {
		t.Fatal(err)
	}
	if err := b.tr.Start(); err != nil {
		t.Fatal(err)
	}
	exchangePeers(t, a, b)

	// First send lands via the plaintext fallback path (no session yet).
	a.tr.Send(types.PointToPointTarget(b.id), appMsg("first"))
	want := appMsg("first")
	m := waitMsg(t, b, "plaintext-fallback p2p")
	if m.from != a.id {
		t.Fatalf("from = %v, want %v", m.from, a.id)
	}
	if string(m.payload) != string(want) {
		t.Fatalf("payload = %x, want %x", m.payload, want)
	}

	// The fallback send kicked a wireauth handshake; wait for the session.
	waitFor(t, "wireauth session", func() bool {
		return a.tr.IsConnectedTo(b.id) && b.tr.IsConnectedTo(a.id)
	})

	a.tr.Send(types.PointToPointTarget(b.id), appMsg("encrypted"))
	m = waitMsg(t, b, "authenticated p2p")
	if m.from != a.id {
		t.Fatalf("from = %v, want %v", m.from, a.id)
	}
}

// TestRaptorcastBroadcastLoopback — primary broadcast fanout through real
// chunk encode/verify/decode on both nodes.
func TestRaptorcastBroadcastLoopback(t *testing.T) {
	a := newRCNode(t, 21, nil)
	b := newRCNode(t, 22, nil)
	if err := a.tr.Start(); err != nil {
		t.Fatal(err)
	}
	if err := b.tr.Start(); err != nil {
		t.Fatal(err)
	}
	exchangePeers(t, a, b)
	addEpoch(t, a.tr, a.id, b.id)
	addEpoch(t, b.tr, a.id, b.id)

	a.tr.Send(types.BroadcastTarget(1), appMsg("proposal"))

	var sawB bool
	waitFor(t, "broadcast to both validators", func() bool {
		select {
		case m := <-b.got:
			if m.from == a.id {
				sawB = true
			}
		default:
		}
		return sawB
	})
}

// TestRaptorcastTCPFallback — TcpPointToPoint over the dataplane TCP socket
// carrying signature || envelope.
func TestRaptorcastTCPFallback(t *testing.T) {
	a := newRCNode(t, 31, nil)
	b := newRCNode(t, 32, nil)
	if err := a.tr.Start(); err != nil {
		t.Fatal(err)
	}
	if err := b.tr.Start(); err != nil {
		t.Fatal(err)
	}
	exchangePeers(t, a, b)

	a.tr.Send(types.RouterTarget{Kind: types.RouterTcpPointToPoint, To: b.id}, appMsg("via-tcp"))
	m := waitMsg(t, b, "TCP delivery")
	if m.from != a.id {
		t.Fatalf("from = %v, want %v", m.from, a.id)
	}
}

// TestRaptorcastShutdown — Close drains goroutines and is idempotent-safe.
func TestRaptorcastShutdown(t *testing.T) {
	a := newRCNode(t, 41, nil)
	if err := a.tr.Start(); err != nil {
		t.Fatal(err)
	}
	if err := a.tr.Close(); err != nil {
		t.Fatal(err)
	}
	// Sends after close must not block or panic.
	a.tr.Send(types.PointToPointTarget(a.id), appMsg("late"))
	select {
	case <-time.After(50 * time.Millisecond):
	}
	var sent atomic.Int32
	done := make(chan struct{})
	go func() {
		a.tr.Send(types.BroadcastTarget(1), appMsg("late2"))
		sent.Add(1)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Send after Close blocked")
	}
}
