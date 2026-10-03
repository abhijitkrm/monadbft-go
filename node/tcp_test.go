package node

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/swarm"
	"github.com/abhijitkrm/monadbft-go/types"
)

// bindTCP — a TCP transport on a fresh loopback port; the listener is
// pre-bound so the address is known before Start.
func bindTCP(t *testing.T, self *crypto.SecpKeyPair, peers map[types.NodeId]string) *TCPTransport {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tr := NewTCPTransport(types.NewNodeId(self.PubKey()), TCPConfig{Key: self, Listener: ln, Peers: peers})
	return tr
}

// rebindTCP — listen on an address again after a restart (port may need a
// moment to be released by the OS).
func rebindTCP(t *testing.T, self *crypto.SecpKeyPair, addr string, peers map[types.NodeId]string) *TCPTransport {
	t.Helper()
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ {
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("rebind %q: %v", addr, err)
	}
	return NewTCPTransport(types.NewNodeId(self.PubKey()), TCPConfig{Key: self, Listener: ln, Peers: peers})
}

func TestNodeFourValidatorsTCP(t *testing.T) {
	const numNodes = 4
	const target = 8
	gv := swarm.CreateKeysWithValidators(numNodes)
	execDelay := types.SeqNum(4)

	// Pre-bind all listeners to learn addresses, then build full peer maps.
	lns := make([]net.Listener, numNodes)
	addrs := make([]string, numNodes)
	selfs := make([]types.NodeId, numNodes)
	for i := 0; i < numNodes; i++ {
		var err error
		lns[i], err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addrs[i] = lns[i].Addr().String()
		selfs[i] = types.NewNodeId(gv.Keys[i].PubKey())
	}

	nodes := make([]*Node, numNodes)
	ledgers := make([]*swarm.MockLedger, numNodes)
	for i := 0; i < numNodes; i++ {
		peers := map[types.NodeId]string{}
		for j := 0; j < numNodes; j++ {
			if j != i {
				peers[selfs[j]] = addrs[j]
			}
		}
		tr := NewTCPTransport(selfs[i], TCPConfig{Key: gv.Keys[i], Listener: lns[i], Peers: peers})
		nodes[i], ledgers[i] = openTestNode(t, t.TempDir(), i, gv,
			swarm.NewInMemoryStateGenesis(execDelay), tr, execDelay)
	}
	t.Cleanup(func() {
		for _, n := range nodes {
			if n != nil {
				n.Stop()
			}
		}
	})
	for _, n := range nodes {
		if err := n.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
	}
	for _, l := range ledgers {
		waitFinalized(t, l, target, 60*time.Second)
	}
	for _, n := range nodes {
		n.Stop()
	}
	for i, n := range nodes {
		if err := n.Err(); err != nil {
			t.Fatalf("node %d error: %v", i, err)
		}
	}

	// Convergence over real sockets.
	ref := ledgers[0].GetFinalizedBlocks()
	for i := 1; i < numNodes; i++ {
		got := ledgers[i].GetFinalizedBlocks()
		for j := 0; j < target; j++ {
			gotID, refID := got[j].Block.GetId(), ref[j].Block.GetId()
			if gotID != refID {
				t.Fatalf("node %d block %d diverged: %x vs %x",
					i, j, gotID[:8], refID[:8])
			}
		}
	}
}

// TestNodeTCPRestartResumes — a validator dies, the network continues (3/4
// quorum), and on restart the dial loops re-establish connections and the
// node catches up via blocksync over real TCP.
func TestNodeTCPRestartResumes(t *testing.T) {
	const numNodes = 4
	gv := swarm.CreateKeysWithValidators(numNodes)
	execDelay := types.SeqNum(4)

	lns := make([]net.Listener, numNodes)
	addrs := make([]string, numNodes)
	selfs := make([]types.NodeId, numNodes)
	for i := 0; i < numNodes; i++ {
		var err error
		lns[i], err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addrs[i] = lns[i].Addr().String()
		selfs[i] = types.NewNodeId(gv.Keys[i].PubKey())
	}
	peerMap := func(i int) map[types.NodeId]string {
		out := map[types.NodeId]string{}
		for j := 0; j < numNodes; j++ {
			if j != i {
				out[selfs[j]] = addrs[j]
			}
		}
		return out
	}

	dirs := make([]string, numNodes)
	srs := make([]*swarm.InMemoryState, numNodes)
	nodes := make([]*Node, numNodes)
	ledgers := make([]*swarm.MockLedger, numNodes)
	for i := 0; i < numNodes; i++ {
		dirs[i] = t.TempDir()
		srs[i] = swarm.NewInMemoryStateGenesis(execDelay)
		tr := NewTCPTransport(selfs[i], TCPConfig{Key: gv.Keys[i], Listener: lns[i], Peers: peerMap(i)})
		nodes[i], ledgers[i] = openTestNode(t, dirs[i], i, gv, srs[i], tr, execDelay)
	}
	t.Cleanup(func() {
		for _, n := range nodes {
			if n != nil {
				n.Stop()
			}
		}
	})
	for _, n := range nodes {
		if err := n.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
	}

	waitFinalized(t, ledgers[0], 5, 30*time.Second)
	addr0 := addrs[0]
	nodes[0].Stop() // full teardown: listener closes, conns drop
	if err := nodes[0].Err(); err != nil {
		t.Fatalf("node 0 error: %v", err)
	}

	// Peers advance alone while 0 is down.
	for i := 1; i < numNodes; i++ {
		waitFinalized(t, ledgers[i], 8, 30*time.Second)
	}

	// Reopen on the same dir + same address; peers' dial loops reconnect.
	tr0 := rebindTCP(t, gv.Keys[0], addr0, peerMap(0))
	nodes[0], ledgers[0] = openTestNode(t, dirs[0], 0, gv, srs[0], tr0, execDelay)
	if err := nodes[0].Start(context.Background()); err != nil {
		t.Fatalf("restart Start: %v", err)
	}

	waitFinalized(t, ledgers[0], 10, 60*time.Second)
	for _, n := range nodes {
		n.Stop()
	}
	for i, n := range nodes {
		if err := n.Err(); err != nil {
			t.Fatalf("node %d error: %v", i, err)
		}
	}

	ref := ledgers[1].GetFinalizedBlocks()
	got := ledgers[0].GetFinalizedBlocks()
	for j := 0; j < 10 && j < len(got) && j < len(ref); j++ {
		gotID, refID := got[j].Block.GetId(), ref[j].Block.GetId()
		if gotID != refID {
			t.Fatalf("restarted node diverged at block %d: %x vs %x",
				j, gotID[:8], refID[:8])
		}
	}
}

// TestTCPHandshakeAuth — a peer connecting with key material that doesn't
// match its claimed NodeId must fail the handshake, and must not evict the
// victim's real authenticated connection (register() keys conns by id).
func TestTCPHandshakeAuth(t *testing.T) {
	gv := swarm.CreateKeysWithValidators(3)

	victim := bindTCP(t, gv.Keys[0], nil)
	impostor := bindTCP(t, gv.Keys[1], nil)
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	defer victim.Close() //nolint:errcheck
	if err := impostor.Start(); err != nil {
		t.Fatal(err)
	}
	defer impostor.Close() //nolint:errcheck

	// The impostor dials the victim's listener as itself — that handshake is
	// honest and must succeed (it proves its own key, not a claimed one).
	conn, err := net.Dial("tcp", victim.Addr())
	if err != nil {
		t.Fatal(err)
	}
	// Speak the handshake as node 0's id but sign with node 1's key.
	idBytes := gv.Keys[0].PubKey().Bytes()
	var nonce [32]byte
	copy(nonce[:], "attacker-nonce")
	msg := make([]byte, 2+len(idBytes)+32)
	binary.BigEndian.PutUint16(msg[:2], uint16(len(idBytes)))
	copy(msg[2:], idBytes)
	copy(msg[2+len(idBytes):], nonce[:])
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	// Read victim's id+nonce, then send a signature over the WRONG preimage
	// (signed by attacker key for victim's id).
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatal(err)
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	buf := make([]byte, n+32)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	theirNonce := buf[n:]
	sig := gv.Keys[1].Sign(crypto.DomainTCPAuth, append(append([]byte{}, idBytes...), theirNonce...))
	smsg := make([]byte, 2+65)
	binary.BigEndian.PutUint16(smsg[:2], 65)
	copy(smsg[2:], sig[:])
	if _, err := conn.Write(smsg); err != nil {
		t.Fatal(err)
	}
	// The victim replies with its own auth proof (msg2), then verifies ours
	// and must close the connection on the forged signature.
	var theirSigHdr [2]byte
	if _, err := io.ReadFull(conn, theirSigHdr[:]); err != nil {
		t.Fatal(err)
	}
	theirSig := make([]byte, binary.BigEndian.Uint16(theirSigHdr[:]))
	if _, err := io.ReadFull(conn, theirSig); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	one := make([]byte, 1)
	if _, err := conn.Read(one); err == nil {
		t.Fatal("forged handshake was accepted")
	}
	_ = conn.Close()

	// The real victim conn table is unaffected: only its own honest conns.
	time.Sleep(100 * time.Millisecond)
	if got := len(victim.Peers()); got != 0 {
		t.Fatalf("victim registered %d peers after forged handshake", got)
	}
}
