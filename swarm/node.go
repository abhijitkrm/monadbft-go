package swarm

import (
	"math/rand/v2"
	"time"

	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/monadstate"
)

// ScheduledOutbound — Rust (sched_tick, LinkMessage) tuple emitted by
// Node::step_until: the delivery tick plus the (pipeline-transformed) message,
// whose FromTick remains the original send time.
type ScheduledOutbound struct {
	SchedTick time.Duration
	Message   LinkMessage
}

// SwarmEventType — Rust SwarmEventType (ExecutorEvent < ScheduledMessage).
type SwarmEventType int

const (
	SwarmExecutorEvent SwarmEventType = iota
	SwarmScheduledMessage
)

// pendingQueue — Rust BTreeMap<Duration, VecDeque<LinkMessage>>.
type pendingQueue struct {
	keys []time.Duration // sorted
	msgs map[time.Duration][]LinkMessage
}

func newPendingQueue() *pendingQueue {
	return &pendingQueue{msgs: map[time.Duration][]LinkMessage{}}
}

func (q *pendingQueue) push(tick time.Duration, m LinkMessage) {
	if _, ok := q.msgs[tick]; !ok {
		// insert keeping keys sorted
		i := 0
		for i < len(q.keys) && q.keys[i] < tick {
			i++
		}
		q.keys = append(q.keys, 0)
		copy(q.keys[i+1:], q.keys[i:])
		q.keys[i] = tick
	}
	q.msgs[tick] = append(q.msgs[tick], m)
}

func (q *pendingQueue) firstKey() (time.Duration, bool) {
	if len(q.keys) == 0 {
		return 0, false
	}
	return q.keys[0], true
}

func (q *pendingQueue) popFront() (time.Duration, LinkMessage) {
	tick := q.keys[0]
	msgs := q.msgs[tick]
	m := msgs[0]
	msgs = msgs[1:]
	if len(msgs) == 0 {
		delete(q.msgs, tick)
		q.keys = q.keys[1:]
	} else {
		q.msgs[tick] = msgs
	}
	return tick, m
}

// Node — Rust monad-mock-swarm::node::Node: one consensus instance + its
// executor + outbound/inbound pipelines.
type Node struct {
	ID       ID
	Executor *MockExecutor
	State    *monadstate.MonadState

	OutboundPipeline Pipeline
	InboundPipeline  Pipeline

	pendingInbound *pendingQueue

	rng         *rand.ChaCha8
	currentSeed uint64
	nonce       int
}

// NodeBuilder — Rust NodeBuilder.
type NodeBuilder struct {
	ID                ID
	StateBuilder      *monadstate.Builder
	RouterScheduler   RouterScheduler
	ValSetUpdater     ValSetUpdater
	TxPoolExecutor    TxPool
	Ledger            Ledger
	StateSyncExecutor StateSync
	OutboundPipeline  Pipeline
	InboundPipeline   Pipeline
	TimestamperConfig TimestamperConfig
	Seed              [32]byte
}

// Build — Rust NodeBuilder::build: construct node, run init commands through
// the executor.
func (b NodeBuilder) Build(tick time.Duration) *Node {
	state, initCmds := b.StateBuilder.Build()
	executor := NewMockExecutor(
		b.RouterScheduler,
		b.ValSetUpdater,
		b.TxPoolExecutor,
		b.Ledger,
		b.StateSyncExecutor,
		b.TimestamperConfig,
		tick,
	)
	executor.Exec(initCmds)
	return &Node{
		ID:               b.ID,
		Executor:         executor,
		State:            state,
		OutboundPipeline: b.OutboundPipeline,
		InboundPipeline:  b.InboundPipeline,
		pendingInbound:   newPendingQueue(),
		rng:              rand.NewChaCha8(b.Seed),
	}
}

func (n *Node) updateRNG() { n.currentSeed = n.rng.Uint64() }

// peekEvent — Rust peek_event: min over (executor tick, ExecutorEvent) and
// (earliest pending inbound tick, ScheduledMessage), tie-broken by the node
// rng over the min set.
func (n *Node) peekEvent() (time.Duration, SwarmEventType, bool) {
	type cand struct {
		tick time.Duration
		typ  SwarmEventType
	}
	var cands []cand
	if tick, ok := n.Executor.PeekTick(); ok {
		cands = append(cands, cand{tick, SwarmExecutorEvent})
	}
	if tick, ok := n.pendingInbound.firstKey(); ok {
		cands = append(cands, cand{tick, SwarmScheduledMessage})
	}
	if len(cands) == 0 {
		return 0, 0, false
	}
	// min_set: keep only candidates at the minimum tick
	minTick := cands[0].tick
	for _, c := range cands[1:] {
		if c.tick < minTick {
			minTick = c.tick
		}
	}
	var minSet []cand
	for _, c := range cands {
		if c.tick == minTick {
			minSet = append(minSet, c)
		}
	}
	pick := minSet[n.currentSeed%uint64(len(minSet))]
	return pick.tick, pick.typ, true
}

// PushInboundMessage — Rust push_inbound_message: apply inbound pipeline, then
// schedule each resulting message at sched_tick + inbound_delay.
func (n *Node) PushInboundMessage(schedTick time.Duration, message LinkMessage) {
	for _, sm := range n.InboundPipeline.Process(message) {
		n.pendingInbound.push(schedTick+sm.Delay, sm.Message)
	}
}

// StepUntil — Rust Node::step_until: drive the node until `until`, emitting
// transport sends into `emitted` and returning the first real MonadEvent.
func (n *Node) StepUntil(until time.Duration, emitted *[]ScheduledOutbound) (time.Duration, glue.MonadEvent, bool) {
	for {
		tick, eventType, ok := n.peekEvent()
		if !ok || tick > until {
			return 0, nil, false
		}
		n.updateRNG()

		switch eventType {
		case SwarmExecutorEvent:
			execEv := n.Executor.StepUntil(tick)
			if execEv == nil {
				continue
			}
			if !execEv.IsSend {
				cmds := n.State.Update(execEv.Event)
				n.Executor.Exec(cmds)
				return tick, execEv.Event, true
			}
			// Send: wrap in LinkMessage, run outbound pipeline
			lm := LinkMessage{
				From:     n.ID,
				To:       NewID(execEv.To),
				Message:  execEv.Tx,
				FromTick: tick,
				Nonce:    n.nonce,
			}
			n.nonce++
			for _, sm := range n.OutboundPipeline.Process(lm) {
				schedTick := tick + sm.Delay
				if sm.Message.To == n.ID {
					n.PushInboundMessage(schedTick, sm.Message)
				} else {
					*emitted = append(*emitted, ScheduledOutbound{SchedTick: schedTick, Message: sm.Message})
				}
			}
		case SwarmScheduledMessage:
			schedTick, m := n.pendingInbound.popFront()
			if schedTick != tick {
				panic("scheduled message tick mismatch")
			}
			n.Executor.SendMessage(schedTick, m.From.PeerID, m.Message)
		}
	}
}

// GetForkpoint — Rust get_forkpoint: the node's last written checkpoint as a
// restart forkpoint.
func (n *Node) GetForkpoint() monadstate.Forkpoint {
	cp := n.Executor.Checkpoint()
	if cp == nil {
		panic("no forkpoint generated")
	}
	return monadstate.Forkpoint{Checkpoint: *cp}
}
