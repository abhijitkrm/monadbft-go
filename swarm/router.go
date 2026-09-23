package swarm

import (
	"fmt"
	"sort"
	"time"

	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
)

// RouterEvent — Rust RouterEvent: Rx (inbound, deserialized) | Tx (outbound
// transport send).
type RouterEvent struct {
	IsRx bool
	From types.NodeId // Rx
	Rx   *glue.MonadMessage
	To   types.NodeId // Tx
	Tx   []byte
}

// RouterScheduler — Rust RouterScheduler specialized to the swarm's concrete
// instantiation: secp NodeIds, []byte transport, MonadMessage inbound,
// VerifiedMonadMessage outbound.
type RouterScheduler interface {
	ProcessInbound(time time.Duration, from types.NodeId, message []byte)
	SendOutbound(time time.Duration, to types.RouterTarget, message *glue.VerifiedMonadMessage)
	AddEpochValidatorSet(epoch types.Epoch, epochStart types.Round, validatorSet []glue.ValidatorStake)
	UpdateCurrentRound(epoch types.Epoch, round types.Round)
	PeekTick() (time.Duration, bool)
	StepUntil(until time.Duration) *RouterEvent
}

// BytesRouterScheduler — port of monad-router-scheduler::BytesRouterScheduler.
// Outbound messages are RLP-serialized; inbound bytes are decoded to
// MonadMessage — exercising the full wire round-trip per message.
type BytesRouterScheduler struct {
	allPeers []types.NodeId // sorted set semantics
	events   []routerQueueEntry
	ep       *exec.Protocol
}

type routerQueueEntry struct {
	tick  time.Duration
	event RouterEvent
}

func NewBytesRouterScheduler(allPeers []types.NodeId, ep *exec.Protocol) *BytesRouterScheduler {
	peers := append([]types.NodeId(nil), allPeers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Cmp(peers[j]) < 0 })
	return &BytesRouterScheduler{allPeers: peers, ep: ep}
}

func (r *BytesRouterScheduler) lastTick() time.Duration {
	if len(r.events) == 0 {
		return 0
	}
	return r.events[len(r.events)-1].tick
}

func (r *BytesRouterScheduler) ProcessInbound(t time.Duration, from types.NodeId, message []byte) {
	if t < r.lastTick() {
		panic(fmt.Sprintf("process_inbound: time %v before last event %v", t, r.lastTick()))
	}
	msg, err := glue.DecodeMonadMessage(message, r.ep)
	if err != nil {
		panic(err)
	}
	r.events = append(r.events, routerQueueEntry{t, RouterEvent{IsRx: true, From: from, Rx: msg}})
}

func (r *BytesRouterScheduler) SendOutbound(t time.Duration, to types.RouterTarget, message *glue.VerifiedMonadMessage) {
	if t < r.lastTick() {
		panic(fmt.Sprintf("send_outbound: time %v before last event %v", t, r.lastTick()))
	}
	ser := message.Serialize()
	switch to.Kind {
	case types.RouterBroadcast, types.RouterRaptorcast:
		for _, peer := range r.allPeers {
			r.events = append(r.events, routerQueueEntry{t, RouterEvent{To: peer, Tx: ser}})
		}
	case types.RouterPointToPoint, types.RouterDirectPointToPoint, types.RouterTcpPointToPoint:
		r.events = append(r.events, routerQueueEntry{t, RouterEvent{To: to.To, Tx: ser}})
	}
}

// AddEpochValidatorSet — nop in the mock (default trait impl upstream).
func (r *BytesRouterScheduler) AddEpochValidatorSet(_ types.Epoch, _ types.Round, _ []glue.ValidatorStake) {
}

// UpdateCurrentRound — nop in the mock.
func (r *BytesRouterScheduler) UpdateCurrentRound(_ types.Epoch, _ types.Round) {}

func (r *BytesRouterScheduler) PeekTick() (time.Duration, bool) {
	if len(r.events) == 0 {
		return 0, false
	}
	return r.events[0].tick, true
}

func (r *BytesRouterScheduler) StepUntil(until time.Duration) *RouterEvent {
	if len(r.events) == 0 || r.events[0].tick > until {
		return nil
	}
	ev := r.events[0].event
	r.events = r.events[1:]
	return &ev
}
