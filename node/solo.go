package node

import (
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
)

// SoloTransport — single-node transport: every Send is delivered back to
// self, the same loopback semantics MeshTransport and RaptorCast provide
// (the leader must receive its own proposal to vote on it). No sockets.
type SoloTransport struct {
	self    types.NodeId
	handler func(from types.NodeId, payload []byte)
}

var _ Transport = (*SoloTransport)(nil)

func NewSoloTransport(self types.NodeId) *SoloTransport { return &SoloTransport{self: self} }

// Send — handler enqueues on the node's event queue (non-blocking), so
// calling it inline is safe.
func (t *SoloTransport) Send(_ types.RouterTarget, payload []byte) {
	if t.handler != nil {
		t.handler(t.self, payload)
	}
}

func (t *SoloTransport) PublishToFullNodes(_ types.Epoch, _ types.Round,
	_ types.FullnodeBroadcastMode, _ []byte) {
}
func (t *SoloTransport) AddEpochValidatorSet(types.Epoch, types.Round, []glue.ValidatorStake) {
}
func (t *SoloTransport) UpdateCurrentRound(types.Epoch, types.Round) {}
func (t *SoloTransport) UpdatePeers([]glue.PeerEntry, []types.NodeId, []types.NodeId) {
}
func (t *SoloTransport) UpdateFullNodes([]types.NodeId, []types.NodeId) {}
func (t *SoloTransport) Peers() []glue.PeerEntry                        { return nil }
func (t *SoloTransport) FullNodes() []types.NodeId                      { return nil }
func (t *SoloTransport) SetHandler(h func(types.NodeId, []byte))        { t.handler = h }
func (t *SoloTransport) Start() error                                   { return nil }
func (t *SoloTransport) Close() error                                   { return nil }
