package node

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/abhijitkrm/monadbft-go/swarm"
	"github.com/abhijitkrm/monadbft-go/types"
)

// bindTCP — a TCP transport on a fresh loopback port; the listener is
// pre-bound so the address is known before Start.
func bindTCP(t *testing.T, self types.NodeId, peers map[types.NodeId]string) *TCPTransport {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tr := NewTCPTransport(self, TCPConfig{Listener: ln, Peers: peers})
	return tr
}

// rebindTCP — listen on an address again after a restart (port may need a
// moment to be released by the OS).
func rebindTCP(t *testing.T, self types.NodeId, addr string, peers map[types.NodeId]string) *TCPTransport {
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
	return NewTCPTransport(self, TCPConfig{Listener: ln, Peers: peers})
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
		tr := NewTCPTransport(selfs[i], TCPConfig{Listener: lns[i], Peers: peers})
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
		tr := NewTCPTransport(selfs[i], TCPConfig{Listener: lns[i], Peers: peerMap(i)})
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
	tr0 := rebindTCP(t, selfs[0], addr0, peerMap(0))
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
