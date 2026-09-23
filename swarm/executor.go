package swarm

import (
	"container/heap"
	"fmt"
	"time"

	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
)

// EventSource — the deterministic analogue of Rust's
// `Stream<Item = MonadEvent>`: Ready() reports whether Next() will produce an
// event.
type EventSource interface {
	Ready() bool
	Next() glue.MonadEvent
}

// Ledger — MockableLedger specialized to the concrete mocks.
type Ledger interface {
	Exec([]glue.LedgerCommand)
	EventSource
	GetFinalizedBlocks() []FinalizedBlock
	FinalizedBlocksLen() int
}

// ValSetUpdater — MockableValSetUpdater.
type ValSetUpdater interface {
	Exec([]glue.ValSetCommand)
	EventSource
	GetValidatorSetData(epoch types.Epoch) glue.ValidatorSetData
}

// TxPool — MockableTxPool.
type TxPool interface {
	Exec([]glue.TxPoolCommand)
	EventSource
	SendTransaction(tx []byte)
}

// StateSync — MockableStateSync.
type StateSync interface {
	Exec([]glue.StateSyncCommand)
	EventSource
}

// ---------------------------------------------------------------------------
// Timer priority queue — Rust PriorityQueue<TimerEvent, Reverse<Duration>>
// keyed on TimeoutVariant.
// ---------------------------------------------------------------------------

// TimerEvent — Rust TimerEvent { variant, callback, was_scheduled_at }.
type TimerEvent struct {
	Variant        glue.TimeoutVariant
	Callback       glue.MonadEvent
	WasScheduledAt time.Duration

	// heap bookkeeping
	timesOutAt time.Duration
	heapIndex  int
}

type timerHeap []*TimerEvent

func (h timerHeap) Len() int           { return len(h) }
func (h timerHeap) Less(i, j int) bool { return h[i].timesOutAt < h[j].timesOutAt }
func (h timerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex, h[j].heapIndex = i, j
}
func (h *timerHeap) Push(x any) {
	e := x.(*TimerEvent)
	e.heapIndex = len(*h)
	*h = append(*h, e)
}
func (h *timerHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}

// timerQueue — keyed removal + min-pop, mirroring PriorityQueue<TimerEvent,
// Reverse<Duration>>.
type timerQueue struct {
	h     timerHeap
	byKey map[glue.TimeoutVariant]*TimerEvent
}

func newTimerQueue() *timerQueue {
	return &timerQueue{byKey: map[glue.TimeoutVariant]*TimerEvent{}}
}

func (q *timerQueue) push(e *TimerEvent) {
	heap.Push(&q.h, e)
	q.byKey[e.Variant] = e
}

func (q *timerQueue) remove(variant glue.TimeoutVariant) {
	if e, ok := q.byKey[variant]; ok {
		heap.Remove(&q.h, e.heapIndex)
		delete(q.byKey, variant)
	}
}

func (q *timerQueue) peek() *TimerEvent {
	if len(q.h) == 0 {
		return nil
	}
	return q.h[0]
}

func (q *timerQueue) pop() *TimerEvent {
	e := heap.Pop(&q.h).(*TimerEvent)
	delete(q.byKey, e.Variant)
	return e
}

// ---------------------------------------------------------------------------
// MockExecutor — port of monad-mock-swarm::mock::MockExecutor.
// ---------------------------------------------------------------------------

// executorEventType — Rust ExecutorEventType ordering (tie-break on equal
// ticks: Router first, StateSync last).
type executorEventType int

const (
	evRouter executorEventType = iota
	evLedger
	evTimer
	evValSet
	evTxPool
	evLoopback
	evTimestamp
	evStateSync
)

// MockExecutorEvent — Rust MockExecutorEvent: Event (feed MonadState) or Send
// (transport send to `to`).
type MockExecutorEvent struct {
	IsSend bool
	Event  glue.MonadEvent
	To     types.NodeId
	Tx     []byte
}

// RoundTimer — Rust RoundTimer (test introspection).
type RoundTimer struct {
	WasScheduledAt time.Duration
	TimesOutAt     time.Duration
}

// ConfigFilePersister — the config-file executor seam: MockConfigFile for
// pure-in-memory tests, store.ConfigFile for durable forkpoint/valset writes.
type ConfigFilePersister interface {
	Exec([]glue.ConfigFileCommand)
	LastCheckpoint() *cstypes.Checkpoint
}

// MockExecutor owns every per-node updater and advances deterministic time.
type MockExecutor struct {
	ledger     Ledger
	configFile ConfigFilePersister
	valSet     ValSetUpdater
	loopback   *LoopbackExecutor
	txpool     TxPool
	statesync  StateSync

	tick  time.Duration
	timer *timerQueue

	timestamper *Timestamper
	router      RouterScheduler
}

func NewMockExecutor(
	router RouterScheduler,
	valSet ValSetUpdater,
	txpool TxPool,
	ledger Ledger,
	statesync StateSync,
	timestampConfig TimestamperConfig,
	tick time.Duration,
) *MockExecutor {
	return &MockExecutor{
		configFile:  NewMockConfigFile(),
		ledger:      ledger,
		valSet:      valSet,
		txpool:      txpool,
		loopback:    NewLoopbackExecutor(),
		statesync:   statesync,
		tick:        tick,
		timer:       newTimerQueue(),
		timestamper: NewTimestamper(tick, timestampConfig),
		router:      router,
	}
}

// WithConfigFile swaps in a durable ConfigFile persister (A3 persistence).
func (e *MockExecutor) WithConfigFile(cf ConfigFilePersister) *MockExecutor {
	e.configFile = cf
	return e
}

// Checkpoint — Rust checkpoint() (the config_file's last written checkpoint).
func (e *MockExecutor) Checkpoint() *cstypes.Checkpoint {
	return e.configFile.LastCheckpoint()
}

// NextRoundTimeout — Rust next_round_timeout (pacemaker timer introspection).
func (e *MockExecutor) NextRoundTimeout() *RoundTimer {
	for _, ev := range e.timer.h {
		if ev.Variant.Kind == glue.TVPacemaker {
			return &RoundTimer{WasScheduledAt: ev.WasScheduledAt, TimesOutAt: ev.timesOutAt}
		}
	}
	return nil
}

func (e *MockExecutor) Tick() time.Duration { return e.tick }

// SendMessage — Rust send_message: inject an inbound transport message.
func (e *MockExecutor) SendMessage(tick time.Duration, from types.NodeId, message []byte) {
	if tick < e.tick {
		panic(fmt.Sprintf("send_message tick %v before executor tick %v", tick, e.tick))
	}
	e.router.ProcessInbound(tick, from, message)
}

// SendTransaction — Rust send_transaction.
func (e *MockExecutor) SendTransaction(tx []byte) { e.txpool.SendTransaction(tx) }

// peekEvent — Rust peek_event: min over all event sources by (tick, type).
func (e *MockExecutor) peekEvent() (time.Duration, executorEventType, bool) {
	var bestTick time.Duration
	var bestType executorEventType
	found := false
	consider := func(tick time.Duration, t executorEventType, ok bool) {
		if !ok {
			return
		}
		if !found || tick < bestTick || (tick == bestTick && t < bestType) {
			bestTick, bestType, found = tick, t, true
		}
	}
	if tick, ok := e.router.PeekTick(); ok {
		consider(tick, evRouter, true)
	}
	if ev := e.timer.peek(); ev != nil {
		consider(ev.timesOutAt, evTimer, true)
	}
	if tick, ok := e.timestamper.PeekNext(); ok {
		consider(tick, evTimestamp, true)
	}
	consider(e.tick, evLedger, e.ledger.Ready())
	consider(e.tick, evTxPool, e.txpool.Ready())
	consider(e.tick, evValSet, e.valSet.Ready())
	consider(e.tick, evLoopback, e.loopback.Ready())
	consider(e.tick, evStateSync, e.statesync.Ready())
	return bestTick, bestType, found
}

// PeekTick — Rust peek_tick.
func (e *MockExecutor) PeekTick() (time.Duration, bool) {
	tick, _, ok := e.peekEvent()
	return tick, ok
}

// Exec — Rust Executor::exec(Command): split into per-executor families and
// apply in Rust's order (timer → timestamp → ledger → txpool → config_file →
// val_set → loopback → statesync → router).
func (e *MockExecutor) Exec(commands []glue.Command) {
	g := glue.SplitCommands(commands)

	for _, cmd := range g.Timer {
		switch c := cmd.(type) {
		case glue.TimerScheduleReset:
			e.timer.remove(c.Variant)
		case glue.TimerSchedule:
			// only one timeout variant may be armed at any time; scheduling
			// resets the previous one
			e.timer.remove(c.Variant)
			e.timer.push(&TimerEvent{
				Variant:        c.Variant,
				Callback:       c.OnTimeout,
				WasScheduledAt: e.tick,
				timesOutAt:     e.tick + c.Duration,
			})
		}
	}

	for _, cmd := range g.Timestamp {
		if c, ok := cmd.(glue.TimestampAdjustDelta); ok {
			e.timestamper.Adjuster().HandleAdjustment(c.Adj)
		}
	}

	e.ledger.Exec(g.Ledger)
	e.txpool.Exec(g.TxPool)
	e.configFile.Exec(g.ConfigFile)
	e.valSet.Exec(g.ValSet)
	e.loopback.Exec(g.Loopback)
	e.statesync.Exec(g.StateSync)

	for _, cmd := range g.Router {
		switch c := cmd.(type) {
		case glue.RouterPublish:
			e.router.SendOutbound(e.tick, c.Target, c.Message)
		case glue.RouterPublishWithPriority:
			e.router.SendOutbound(e.tick, c.Target, c.Message) // priority ignored in mock
		case glue.RouterAddEpochValidatorSet:
			e.router.AddEpochValidatorSet(c.Epoch, c.EpochStart, c.ValidatorSet)
		case glue.RouterUpdateCurrentRound:
			e.router.UpdateCurrentRound(c.Epoch, c.Round)
		case glue.RouterGetPeers, glue.RouterUpdatePeers, glue.RouterGetFullNodes,
			glue.RouterUpdateFullNodes, glue.RouterPublishToFullNodes:
			// TODO upstream — nop
		}
	}
}

// StepUntil — Rust step_until: advance deterministic time, returning the next
// MonadEvent (to feed MonadState) or transport Send (to route).
func (e *MockExecutor) StepUntil(until time.Duration) *MockExecutorEvent {
	for {
		tick, eventType, ok := e.peekEvent()
		if !ok || tick > until {
			return nil
		}
		e.tick = tick

		switch eventType {
		case evRouter:
			ev := e.router.StepUntil(tick)
			if ev == nil {
				continue
			}
			if ev.IsRx {
				return &MockExecutorEvent{Event: ev.Rx.Event(ev.From)}
			}
			return &MockExecutorEvent{IsSend: true, To: ev.To, Tx: ev.Tx}
		case evTimer:
			return &MockExecutorEvent{Event: e.timer.pop().Callback}
		case evLedger:
			if ev := e.ledger.Next(); ev != nil {
				return &MockExecutorEvent{Event: ev}
			}
			return nil
		case evValSet:
			if ev := e.valSet.Next(); ev != nil {
				return &MockExecutorEvent{Event: ev}
			}
			return nil
		case evLoopback:
			if ev := e.loopback.Next(); ev != nil {
				return &MockExecutorEvent{Event: ev}
			}
			return nil
		case evTxPool:
			if ev := e.txpool.Next(); ev != nil {
				return &MockExecutorEvent{Event: ev}
			}
			return nil
		case evTimestamp:
			t := e.timestamper.NextTick()
			return &MockExecutorEvent{Event: glue.EvTimestampUpdate{Timestamp: types.U128FromUint64(uint64(t.Nanoseconds()))}}
		case evStateSync:
			if ev := e.statesync.Next(); ev != nil {
				return &MockExecutorEvent{Event: ev}
			}
			return nil
		}
	}
}

// Ledger / ValSet accessors — Rust ledger() / val_set_updater().
func (e *MockExecutor) Ledger() Ledger               { return e.ledger }
func (e *MockExecutor) ValSetUpdater() ValSetUpdater { return e.valSet }
func (e *MockExecutor) Router() RouterScheduler      { return e.router }
