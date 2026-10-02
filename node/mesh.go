package node

import (
	"sync"

	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Mesh — an in-process multi-node Transport hub for tests and local devnets.
// Delivery is synchronous and lossless (bytes are pushed into the peer's
// inbound handler on the sender's goroutine). It exercises the real Transport
// contract — broadcast/point-to-point fan-out, handler callback, start/stop —
// without sockets; latency/fault injection stays with the swarm harness.
type Mesh struct {
	mu    sync.Mutex
	nodes map[types.NodeId]*MeshTransport
}

func NewMesh() *Mesh {
	return &Mesh{nodes: map[types.NodeId]*MeshTransport{}}
}

// Transport registers a node on the mesh and returns its Transport.
func (m *Mesh) Transport(self types.NodeId) *MeshTransport {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := &MeshTransport{mesh: m, self: self}
	m.nodes[self] = t
	return t
}

// MeshTransport — one node's endpoint on a Mesh.
type MeshTransport struct {
	mesh    *Mesh
	self    types.NodeId
	handler func(types.NodeId, []byte)
	running bool
}

var _ Transport = (*MeshTransport)(nil)

func (t *MeshTransport) Send(target types.RouterTarget, payload []byte) {
	t.mesh.mu.Lock()
	defer t.mesh.mu.Unlock()
	if !t.running {
		return
	}
	switch target.Kind {
	case types.RouterBroadcast, types.RouterRaptorcast:
		// Deliver to every node on the mesh INCLUDING self — the sender is
		// a validator that must receive (and vote on) its own proposal.
		// (Same loopback semantics as swarm's allPeers broadcast and
		// upstream raptorcast self-delivery.)
		for _, peer := range t.mesh.nodes {
			if !peer.running || peer.handler == nil {
				continue
			}
			peer.handler(t.self, payload)
		}
	case types.RouterPointToPoint, types.RouterDirectPointToPoint, types.RouterTcpPointToPoint:
		if peer, ok := t.mesh.nodes[target.To]; ok && peer.running && peer.handler != nil {
			peer.handler(t.self, payload)
		}
	}
}

func (t *MeshTransport) PublishToFullNodes(types.Epoch, types.Round, types.FullnodeBroadcastMode, []byte) {
	// no full nodes on the mesh
}
func (t *MeshTransport) AddEpochValidatorSet(types.Epoch, types.Round, []glue.ValidatorStake) {
}
func (t *MeshTransport) UpdateCurrentRound(types.Epoch, types.Round) {}
func (t *MeshTransport) UpdatePeers([]glue.PeerEntry, []types.NodeId, []types.NodeId) {
}
func (t *MeshTransport) UpdateFullNodes([]types.NodeId, []types.NodeId) {}

func (t *MeshTransport) Peers() []glue.PeerEntry {
	t.mesh.mu.Lock()
	defer t.mesh.mu.Unlock()
	out := make([]glue.PeerEntry, 0, len(t.mesh.nodes)-1)
	for id := range t.mesh.nodes {
		if id != t.self {
			out = append(out, glue.PeerEntry{Pubkey: id})
		}
	}
	return out
}

func (t *MeshTransport) FullNodes() []types.NodeId { return nil }

func (t *MeshTransport) SetHandler(h func(types.NodeId, []byte)) { t.handler = h }

func (t *MeshTransport) Start() error {
	t.mesh.mu.Lock()
	defer t.mesh.mu.Unlock()
	t.running = true
	return nil
}

func (t *MeshTransport) Close() error {
	t.mesh.mu.Lock()
	defer t.mesh.mu.Unlock()
	t.running = false
	return nil
}
