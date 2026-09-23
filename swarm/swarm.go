package swarm

import (
	"fmt"
	"time"

	"github.com/abhijitkrm/monadbft-go/glue"
)

// Nodes — port of monad-mock-swarm::mock_swarm::Nodes: the multi-node
// deterministic driver.
type Nodes struct {
	states           map[ID]*Node
	order            []ID // sorted insertion order for deterministic iteration
	tick             time.Duration
	mustDeliver      bool
	noDuplicatePeers bool
}

// SwarmBuilder — Rust SwarmBuilder.
type SwarmBuilder []NodeBuilder

func (b SwarmBuilder) Build() *Nodes {
	nodes := &Nodes{
		states:           map[ID]*Node{},
		mustDeliver:      true,
		noDuplicatePeers: true,
	}
	for _, peer := range b {
		nodes.AddState(peer)
	}
	return nodes
}

// CanFailDeliver — Rust can_fail_deliver.
func (n *Nodes) CanFailDeliver() *Nodes { n.mustDeliver = false; return n }

// CanHaveDuplicatePeers — Rust can_have_duplicate_peer.
func (n *Nodes) CanHaveDuplicatePeers() *Nodes { n.noDuplicatePeers = false; return n }

// AddState — Rust add_state.
func (n *Nodes) AddState(peer NodeBuilder) {
	node := peer.Build(n.tick)
	if _, dup := n.states[node.ID]; dup {
		panic("duplicate ID insertion")
	}
	if n.noDuplicatePeers && !node.ID.IsUnique() {
		panic("duplicate peers not allowed")
	}
	n.states[node.ID] = node
	n.order = append(n.order, node.ID)
	SortIDs(n.order)
}

// RemoveState — Rust remove_state.
func (n *Nodes) RemoveState(peerID ID) *Node {
	node := n.states[peerID]
	delete(n.states, peerID)
	for i, id := range n.order {
		if id == peerID {
			n.order = append(n.order[:i], n.order[i+1:]...)
			break
		}
	}
	return node
}

// States — Rust states().
func (n *Nodes) States() map[ID]*Node { return n.states }

// Node — lookup by ID.
func (n *Nodes) Node(id ID) *Node { return n.states[id] }

// OrderedNodes — nodes in deterministic (ID-sorted) order.
func (n *Nodes) OrderedNodes() []*Node {
	out := make([]*Node, 0, len(n.order))
	for _, id := range n.order {
		out = append(out, n.states[id])
	}
	return out
}

func (n *Nodes) Tick() time.Duration { return n.tick }

// peekEvent — Rust Nodes::peek_event: min over all nodes of
// (tick, event_type, id).
func (n *Nodes) peekEvent() (time.Duration, SwarmEventType, ID, bool) {
	var best struct {
		tick  time.Duration
		typ   SwarmEventType
		id    ID
		found bool
	}
	for _, id := range n.order {
		node := n.states[id]
		tick, typ, ok := node.peekEvent()
		if !ok {
			continue
		}
		if !best.found || less3(tick, typ, id, best.tick, best.typ, best.id) {
			best.tick, best.typ, best.id, best.found = tick, typ, id, true
		}
	}
	return best.tick, best.typ, best.id, best.found
}

func less3(t time.Duration, typ SwarmEventType, id ID, bt time.Duration, btyp SwarmEventType, bid ID) bool {
	if t != bt {
		return t < bt
	}
	if typ != btyp {
		return typ < btyp
	}
	return IDCmp(id, bid) < 0
}

// PeekTick — Rust peek_tick.
func (n *Nodes) PeekTick() (time.Duration, bool) {
	tick, _, _, ok := n.peekEvent()
	return tick, ok
}

// StepUntil — Rust Nodes::step_until: step to the next event across all nodes.
func (n *Nodes) StepUntil(terminator NodesTerminator) (time.Duration, ID, glue.MonadEvent, bool) {
	for {
		tick, _, id, ok := n.peekEvent()
		if !ok {
			return 0, ID{}, nil, false
		}
		if terminator.ShouldTerminate(n, tick) {
			return 0, ID{}, nil, false
		}
		node := n.states[id]

		var emitted []ScheduledOutbound
		evTick, ev, hasEv := node.StepUntil(tick, &emitted)
		n.tick = tick

		for _, so := range emitted {
			m := so.Message
			if m.From == m.To {
				panic("self-message emitted to swarm")
			}
			target := n.states[m.To]
			if n.mustDeliver && target == nil {
				panic(fmt.Sprintf("message to unknown node %v", m.To))
			}
			if target != nil {
				target.PushInboundMessage(so.SchedTick, m)
			}
		}
		if hasEv {
			return evTick, id, ev, true
		}
	}
}

// BatchStepUntil — Rust batch_step_until (sequential port): step all nodes to
// the max safe tick, then deliver emitted messages.
func (n *Nodes) BatchStepUntil(terminator NodesTerminator) (time.Duration, bool) {
	for {
		tick, _, id, ok := n.peekEvent()
		if !ok {
			return 0, false
		}
		// max safe tick = min tick + outbound min_external_delay - epsilon
		node := n.states[id]
		minUnsafe := tick + node.OutboundPipeline.MinExternalDelay()
		batchTick := minUnsafe - time.Nanosecond

		if terminator.ShouldTerminate(n, batchTick) {
			return n.tick, true
		}

		var emitted []ScheduledOutbound
		for _, nid := range n.order {
			var nodeEmitted []ScheduledOutbound
			for {
				_, _, hasEv := n.states[nid].StepUntil(batchTick, &nodeEmitted)
				if !hasEv {
					break
				}
			}
			emitted = append(emitted, nodeEmitted...)
		}
		n.tick = batchTick

		for _, so := range emitted {
			target := n.states[so.Message.To]
			if n.mustDeliver && target == nil {
				panic(fmt.Sprintf("message to unknown node %v", so.Message.To))
			}
			if target != nil {
				target.PushInboundMessage(so.SchedTick, so.Message)
			}
		}
	}
}

// SendTransaction — Rust send_transaction.
func (n *Nodes) SendTransaction(nodeID ID, tx []byte) {
	n.states[nodeID].Executor.SendTransaction(tx)
}

// UpdateOutboundPipelineForAll — Rust update_outbound_pipeline_for_all.
func (n *Nodes) UpdateOutboundPipelineForAll(p Pipeline) {
	for _, node := range n.states {
		node.OutboundPipeline = p
	}
}

// UpdateOutboundPipeline — Rust update_outbound_pipeline.
func (n *Nodes) UpdateOutboundPipeline(id ID, p Pipeline) {
	if node := n.states[id]; node != nil {
		node.OutboundPipeline = p
	}
}

// SortedKeys — deterministic ID iteration for callers.
func (n *Nodes) SortedKeys() []ID { return append([]ID(nil), n.order...) }
