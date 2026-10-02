package node

import (
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Transport — the production counterpart of swarm.RouterScheduler: consumes
// RouterCommands as already-serialized wire bytes and delivers inbound bytes
// back through the handler set by SetHandler.
//
// Contract:
//   - Send must never block the caller (the consensus loop goroutine);
//     implementations enqueue internally. Drops are tolerated: liveness is
//     guaranteed by pacemaker retransmission (timeouts → TC/NEC) and blocksync.
//   - The transport serializes nothing; RouterPublish's VerifiedMonadMessage is
//     already wire-encoded by the node. Inbound bytes are handed to the handler
//     unmodified — decode/validation happens on the node loop.
//   - The `from` argument on inbound identifies the transport-level peer. For
//     the interim TCP transport this is the NodeId exchanged at handshake; real
//     authentication arrives with Track B wireauth. Message signatures are
//     verified inside MonadState regardless, so a spoofed `from` cannot forge.
//   - Router management commands (epoch valsets, current round, peer tables)
//     are advisory to the transport: TCP ignores them, RaptorCast needs them.
//
// priorityTransport — optional high-priority egress lane (upstream pushes
// RouterPublishWithPriority onto UdpPriority::High). Implemented by
// RaptorcastTransport; TCPTransport is single-lane.
type priorityTransport interface {
	SendWithPriority(types.RouterTarget, []byte, int)
}

type Transport interface {
	// Send delivers payload to target. Broadcast/Raptorcast fan out over the
	// transport's peer set for the target epoch; point-to-point kinds deliver
	// to target.To only.
	Send(target types.RouterTarget, payload []byte)

	// PublishToFullNodes — RouterCommand::PublishToFullNodes (Track B B5).
	PublishToFullNodes(epoch types.Epoch, round types.Round, mode types.FullnodeBroadcastMode, payload []byte)

	// Epoch/round + peer table management (advisory; see above).
	AddEpochValidatorSet(epoch types.Epoch, epochStart types.Round, validators []glue.ValidatorStake)
	UpdateCurrentRound(epoch types.Epoch, round types.Round)
	UpdatePeers(peers []glue.PeerEntry, dedicated, prioritized []types.NodeId)
	UpdateFullNodes(dedicated, prioritized []types.NodeId)

	// Control-panel reads — RouterGetPeers/RouterGetFullNodes responses.
	Peers() []glue.PeerEntry
	FullNodes() []types.NodeId

	// SetHandler installs the inbound callback. Called before Start.
	SetHandler(func(from types.NodeId, payload []byte))

	// Start opens listeners/dialers; Close stops everything and returns.
	Start() error
	Close() error
}

// NopTransport — a Transport that drops all outbound traffic. Useful for
// single-node bring-up and unit tests that never leave the process.
type NopTransport struct {
	Handler func(from types.NodeId, payload []byte)
}

func (t *NopTransport) Send(types.RouterTarget, []byte) {}
func (t *NopTransport) PublishToFullNodes(types.Epoch, types.Round, types.FullnodeBroadcastMode, []byte) {
}
func (t *NopTransport) AddEpochValidatorSet(types.Epoch, types.Round, []glue.ValidatorStake) {
}
func (t *NopTransport) UpdateCurrentRound(types.Epoch, types.Round) {}
func (t *NopTransport) UpdatePeers([]glue.PeerEntry, []types.NodeId, []types.NodeId) {
}
func (t *NopTransport) UpdateFullNodes([]types.NodeId, []types.NodeId) {}
func (t *NopTransport) Peers() []glue.PeerEntry                        { return nil }
func (t *NopTransport) FullNodes() []types.NodeId                      { return nil }
func (t *NopTransport) SetHandler(h func(types.NodeId, []byte))        { t.Handler = h }
func (t *NopTransport) Start() error                                   { return nil }
func (t *NopTransport) Close() error                                   { return nil }
