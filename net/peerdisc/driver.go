package peerdisc

// Ported from monad-peer-discovery/src/driver.rs — the embedding layer:
// PeerDiscoveryEvent in → emits out; TimerCommands drive a (node_id, kind)-
// keyed resettable timer queue (tokio DelayQueue equivalent).

import (
	"container/heap"
	"time"

	"github.com/abhijitkrm/monadbft-go/types"
)

// PeerDiscoveryEmit — what the outer runtime sends (Rust PeerDiscoveryEmit).
type PeerDiscoveryEmit struct {
	PingPong   bool // true → PingPongCommand, false → RouterCommand
	Target     types.NodeId
	NameRecord NameRecord // PingPongCommand only — send msg to this record's UDP addr
	Message    PeerDiscoveryMessage
}

type timerKey struct {
	node types.NodeId
	kind TimerKind
}

type timerItem struct {
	key      timerKey
	deadline time.Time
	ev       PeerDiscoveryEvent
	idx      int
}

type timerHeap []*timerItem

func (h timerHeap) Len() int           { return len(h) }
func (h timerHeap) Less(i, j int) bool { return h[i].deadline.Before(h[j].deadline) }
func (h timerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].idx, h[j].idx = i, j
}
func (h *timerHeap) Push(x any) {
	it := x.(*timerItem)
	it.idx = len(*h)
	*h = append(*h, it)
}
func (h *timerHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return it
}

// PeerDiscTimers — DelayQueue keyed by (node, kind); scheduling replaces.
type PeerDiscTimers struct {
	items   timerHeap
	byKey   map[timerKey]*timerItem
	now     func() time.Time
	pending []PeerDiscoveryEvent // expired, waiting to be polled
}

func NewPeerDiscTimers() *PeerDiscTimers {
	return &PeerDiscTimers{byKey: map[timerKey]*timerItem{}, now: time.Now}
}

func (t *PeerDiscTimers) exec(cmd TimerCommand) {
	k := timerKey{cmd.NodeID, cmd.Kind}
	if cmd.Reset {
		t.reset(k)
		return
	}
	t.reset(k)
	it := &timerItem{key: k, deadline: t.now().Add(cmd.Duration), ev: cmd.OnTimeout}
	t.byKey[k] = it
	heap.Push(&t.items, it)
}

func (t *PeerDiscTimers) reset(k timerKey) {
	if it, ok := t.byKey[k]; ok {
		heap.Remove(&t.items, it.idx)
		delete(t.byKey, k)
	}
}

// PollExpired moves elapsed timers into the pending queue.
func (t *PeerDiscoveryDriver) pollExpired() {
	for len(t.timers.items) > 0 && !t.timers.items[0].deadline.After(t.timers.now()) {
		it := heap.Pop(&t.timers.items).(*timerItem)
		delete(t.timers.byKey, it.key)
		t.timers.pending = append(t.timers.pending, it.ev)
	}
}

// PeerDiscoveryDriver — events in, emits + timer events out.
type PeerDiscoveryDriver struct {
	pd     *PeerDiscovery
	timers *PeerDiscTimers
	emits  []PeerDiscoveryEmit
	events []PeerDiscoveryEvent
}

func NewPeerDiscoveryDriver(b PeerDiscoveryBuilder) *PeerDiscoveryDriver {
	pd, cmds := b.Build()
	d := &PeerDiscoveryDriver{pd: pd, timers: NewPeerDiscTimers()}
	d.exec(cmds)
	return d
}

// PD exposes the state machine for address lookups etc.
func (d *PeerDiscoveryDriver) PD() *PeerDiscovery { return d.pd }

// Update feeds an event through the algo and queues resulting commands.
func (d *PeerDiscoveryDriver) Update(ev PeerDiscoveryEvent) {
	d.exec(d.pd.Update(ev))
}

func (d *PeerDiscoveryDriver) exec(cmds []PeerDiscoveryCommand) {
	for _, c := range cmds {
		switch c.Kind {
		case CmdTimer:
			d.timers.exec(c.Timer)
		case CmdRouter:
			d.emits = append(d.emits, PeerDiscoveryEmit{Target: c.Target, Message: c.Message})
		case CmdPingPong:
			d.emits = append(d.emits, PeerDiscoveryEmit{
				PingPong: true, Target: c.Target, NameRecord: c.NameRecord, Message: c.Message,
			})
		}
	}
}

// ExpireTimers surfaces due timer events (call before NextDue each tick).
func (d *PeerDiscoveryDriver) ExpireTimers() {
	d.pollExpired()
	d.events = append(d.events, d.timers.pending...)
	d.timers.pending = nil
}

// NextDue is the earliest pending timer deadline (zero if none).
func (d *PeerDiscoveryDriver) NextDue() time.Time {
	if len(d.timers.items) == 0 {
		return time.Time{}
	}
	return d.timers.items[0].deadline
}

// DrainEmits returns and clears queued emits.
func (d *PeerDiscoveryDriver) DrainEmits() []PeerDiscoveryEmit {
	out := d.emits
	d.emits = nil
	return out
}

// DrainEvents returns and clears expired timer events to feed back into Update.
func (d *PeerDiscoveryDriver) DrainEvents() []PeerDiscoveryEvent {
	d.ExpireTimers()
	out := d.events
	d.events = nil
	return out
}
